package auth

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	// maxQuotaResetHorizon bounds how far in the future a quota window reset may be
	// to avoid mistaking monthly billing boundaries or malformed timestamps for active
	// rate-limit windows (5h / 7d).
	maxQuotaResetHorizon = 14 * 24 * time.Hour
	remainingTieEpsilon  = 1e-9
)

// SoonestResetSelector selects the eligible credential whose relevant quota window
// resets soonest so quota that would otherwise expire unused is spent first.
//
// It relies solely on passive quota signals already observed from upstream responses
// (zero extra network calls per request):
//   - Claude: prefers the 7-day unified window (Anthropic-Ratelimit-Unified-7d-*),
//     falling back to the 5-hour window and then Anthropic-Ratelimit-Unified-Reset.
//   - Codex: inspects X-Codex-Primary-* and X-Codex-Secondary-* (both HTTP headers
//     and normalized WebSocket codex.rate_limits frames) and prefers the longest
//     active window (e.g. 7-day / 10080m over 5-hour / 300m).
//
// When reset information is missing or stale (reset timestamp already in the past),
// selection falls back deterministically to round-robin. Ties on reset timestamp
// break by higher remaining quota, then round-robin.
type SoonestResetSelector struct {
	mu                 sync.Mutex
	lastPicked         map[string]string
	lastPickedProvider map[string]string
	maxKeys            int
	nowFunc            func() time.Time
}

type quotaResetInfo struct {
	hasReset     bool
	resetAt      time.Time
	hasRemaining bool
	remaining    float64
	rejected     bool
}

type codexWindowInfo struct {
	hasReset      bool
	resetAt       time.Time
	hasRemaining  bool
	remaining     float64
	usedPercent   float64
	hasUsed       bool
	windowMinutes int
	expired       bool
}

func (s *SoonestResetSelector) now() time.Time {
	if s != nil && s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

// Pick selects the eligible credential whose relevant quota window resets soonest,
// preserving provider isolation, priority tiers, transport preferences, and
// deterministic round-robin fallback.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := s.now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}

	effectiveProvider, candidates := s.selectProviderCandidates(provider, model, available)
	candidates = preferCodexWebsocketAuths(ctx, effectiveProvider, candidates)
	return s.pickWithinProvider(effectiveProvider, model, candidates, now), nil
}

func (s *SoonestResetSelector) selectProviderCandidates(provider, model string, available []*Auth) (string, []*Auth) {
	if len(available) == 0 {
		return canonicalSchedulingProvider(provider), available
	}

	fallbackProvider := canonicalSchedulingProvider(provider)
	if fallbackProvider == "mixed" {
		fallbackProvider = ""
	}

	byProvider := make(map[string][]*Auth, 2)
	providerKeys := make([]string, 0, 2)
	for _, candidate := range available {
		p := canonicalSchedulingProvider(executorKeyFromAuth(candidate))
		if p == "" {
			p = fallbackProvider
		}
		if _, exists := byProvider[p]; !exists {
			providerKeys = append(providerKeys, p)
		}
		byProvider[p] = append(byProvider[p], candidate)
	}

	if len(providerKeys) == 1 {
		only := providerKeys[0]
		if only == "" {
			only = canonicalSchedulingProvider(provider)
		}
		return only, available
	}

	// Multiple distinct providers in a mixed-provider request: isolate providers
	// by rotating across providers first, then applying soonest-reset strictly
	// within the chosen provider's candidates.
	sort.Strings(providerKeys)
	rrKey := "mixed-provider:" + canonicalModelLookupKey(model)
	chosenProvider := s.pickRoundRobinProvider(rrKey, providerKeys)
	return chosenProvider, byProvider[chosenProvider]
}

type scoredResetCandidate struct {
	auth *Auth
	info quotaResetInfo
}

func (s *SoonestResetSelector) pickWithinProvider(provider, model string, candidates []*Auth, now time.Time) *Auth {
	rrKey := provider + ":" + canonicalModelLookupKey(model)
	if len(candidates) == 1 {
		s.recordPickedAuth(rrKey, candidates[0].ID)
		return candidates[0]
	}

	var (
		healthyKnown    []scoredResetCandidate
		healthyUnknown  []*Auth
		rejectedKnown   []scoredResetCandidate
		rejectedUnknown []*Auth
	)

	for _, candidate := range candidates {
		info := extractAuthQuotaResetInfo(provider, candidate, model, now)
		switch {
		case !info.rejected && info.hasReset:
			healthyKnown = append(healthyKnown, scoredResetCandidate{auth: candidate, info: info})
		case !info.rejected:
			healthyUnknown = append(healthyUnknown, candidate)
		case info.hasReset:
			rejectedKnown = append(rejectedKnown, scoredResetCandidate{auth: candidate, info: info})
		default:
			rejectedUnknown = append(rejectedUnknown, candidate)
		}
	}

	if len(healthyKnown) > 0 {
		return s.pickBestResetCandidate(rrKey, healthyKnown)
	}
	if len(healthyUnknown) > 0 {
		return s.pickRoundRobinAuth(rrKey, healthyUnknown)
	}
	if len(rejectedKnown) > 0 {
		return s.pickBestResetCandidate(rrKey, rejectedKnown)
	}
	return s.pickRoundRobinAuth(rrKey, rejectedUnknown)
}

func (s *SoonestResetSelector) pickBestResetCandidate(rrKey string, scored []scoredResetCandidate) *Auth {
	if len(scored) == 1 {
		s.recordPickedAuth(rrKey, scored[0].auth.ID)
		return scored[0].auth
	}

	// 1. Keep candidates tied for the soonest reset timestamp.
	soonest := scored[0].info.resetAt
	for i := 1; i < len(scored); i++ {
		if scored[i].info.resetAt.Before(soonest) {
			soonest = scored[i].info.resetAt
		}
	}

	soonestTied := scored[:0]
	for _, entry := range scored {
		if entry.info.resetAt.Equal(soonest) {
			soonestTied = append(soonestTied, entry)
		}
	}
	if len(soonestTied) == 1 {
		s.recordPickedAuth(rrKey, soonestTied[0].auth.ID)
		return soonestTied[0].auth
	}

	// 2. Break ties by higher remaining quota fraction when available.
	hasAnyRemaining := false
	bestRemaining := -1.0
	for _, entry := range soonestTied {
		if !entry.info.hasRemaining {
			continue
		}
		if !hasAnyRemaining || entry.info.remaining > bestRemaining {
			hasAnyRemaining = true
			bestRemaining = entry.info.remaining
		}
	}

	finalTied := make([]*Auth, 0, len(soonestTied))
	for _, entry := range soonestTied {
		if hasAnyRemaining {
			if !entry.info.hasRemaining || bestRemaining-entry.info.remaining > remainingTieEpsilon {
				continue
			}
		}
		finalTied = append(finalTied, entry.auth)
	}
	if len(finalTied) == 1 {
		s.recordPickedAuth(rrKey, finalTied[0].ID)
		return finalTied[0]
	}

	// 3. Final tie-breaker: deterministic round-robin (finalTied preserves ID order).
	return s.pickRoundRobinAuth(rrKey, finalTied)
}

func (s *SoonestResetSelector) pickRoundRobinProvider(key string, providers []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPickedProvider == nil {
		s.lastPickedProvider = make(map[string]string)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.lastPickedProvider[key]; !ok && len(s.lastPickedProvider) >= limit {
		s.lastPickedProvider = make(map[string]string)
	}
	last := s.lastPickedProvider[key]
	index := 0
	if last != "" {
		index = sort.Search(len(providers), func(i int) bool { return providers[i] > last })
		if index >= len(providers) {
			index = 0
		}
	}
	picked := providers[index]
	s.lastPickedProvider[key] = picked
	return picked
}

func (s *SoonestResetSelector) pickRoundRobinAuth(key string, candidates []*Auth) *Auth {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPicked == nil {
		s.lastPicked = make(map[string]string)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.lastPicked[key]; !ok && len(s.lastPicked) >= limit {
		s.lastPicked = make(map[string]string)
	}
	picked := candidates[successorIndex(candidates, s.lastPicked[key])]
	s.lastPicked[key] = picked.ID
	return picked
}

func (s *SoonestResetSelector) recordPickedAuth(key, authID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPicked == nil {
		s.lastPicked = make(map[string]string)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.lastPicked[key]; !ok && len(s.lastPicked) >= limit {
		s.lastPicked = make(map[string]string)
	}
	s.lastPicked[key] = authID
}

func extractAuthQuotaResetInfo(provider string, auth *Auth, model string, now time.Time) quotaResetInfo {
	if auth == nil {
		return quotaResetInfo{}
	}
	effectiveProvider := canonicalSchedulingProvider(executorKeyFromAuth(auth))
	if effectiveProvider == "" {
		effectiveProvider = canonicalSchedulingProvider(provider)
	}

	authInfo := extractProviderQuotaResetInfo(effectiveProvider, auth.Quota, now)
	if model != "" && len(auth.ModelStates) > 0 {
		if state := existingModelState(auth, model); state != nil {
			modelInfo := extractProviderQuotaResetInfo(effectiveProvider, state.Quota, now)
			if modelInfo.hasReset || modelInfo.rejected {
				if (!authInfo.hasReset && !authInfo.rejected) || state.Quota.ObservedAt.After(auth.Quota.ObservedAt) {
					return modelInfo
				}
			}
		}
	}
	return authInfo
}

func extractProviderQuotaResetInfo(provider string, quota QuotaState, now time.Time) quotaResetInfo {
	if len(quota.Signals) == 0 {
		return quotaResetInfo{}
	}
	if !quota.ObservedAt.IsZero() && now.Sub(quota.ObservedAt) > maxQuotaResetHorizon {
		return quotaResetInfo{}
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		return extractClaudeQuotaResetInfo(quota, now)
	case "codex":
		return extractCodexQuotaResetInfo(quota, now)
	default:
		return quotaResetInfo{}
	}
}

func extractClaudeQuotaResetInfo(quota QuotaState, now time.Time) quotaResetInfo {
	signals := quota.Signals

	reset7d, ok7d, expired7d := parseValidResetTimestamp(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-7d-Reset"), now)
	status7d := strings.ToLower(strings.TrimSpace(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-7d-Status")))
	util7d, hasUtil7d := parseQuotaFraction(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-7d-Utilization"))

	reset5h, ok5h, expired5h := parseValidResetTimestamp(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-5h-Reset"), now)
	status5h := strings.ToLower(strings.TrimSpace(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-5h-Status")))
	util5h, hasUtil5h := parseQuotaFraction(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-5h-Utilization"))

	unifiedStatus := strings.ToLower(strings.TrimSpace(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Status")))
	unifiedResetRaw := quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Reset")
	unifiedReset, okUnified, expiredUnified := parseValidResetTimestamp(unifiedResetRaw, now)
	if okUnified && claudeSignalsUnifiedResetIsOverageBoundary(signals, unifiedResetRaw) {
		okUnified = false
	}

	// Determine whether an active (non-expired) shared window is explicitly rejected
	// or at 100% utilization. Note that Overage-Status: rejected is normal on
	// subscription accounts without extra usage billing and does not indicate exhaustion.
	active5hRejected := !expired5h && (status5h == "rejected" || (ok5h && hasUtil5h && util5h >= 1.0))
	active7dRejected := !expired7d && (status7d == "rejected" || (ok7d && hasUtil7d && util7d >= 1.0))
	activeUnifiedRejected := !expiredUnified && unifiedStatus == "rejected" && !claudeSignalsOverageOnly(signals)
	if activeUnifiedRejected && expired5h && !active7dRejected && (status5h == "rejected" || strings.EqualFold(strings.TrimSpace(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Representative-Claim")), "five_hour")) {
		// The previous 5h rejection window already elapsed and 7d is healthy.
		activeUnifiedRejected = false
	}
	rejected := active5hRejected || active7dRejected || activeUnifiedRejected

	// Prefer the 7-day weekly window so accounts whose weekly allowance expires soonest
	// are consumed first, matching subscription reset economics.
	if ok7d {
		info := quotaResetInfo{
			hasReset: true,
			resetAt:  reset7d,
			rejected: rejected,
		}
		if hasUtil7d {
			info.hasRemaining = true
			info.remaining = clampFraction(1.0 - util7d)
		}
		return info
	}

	if ok5h {
		info := quotaResetInfo{
			hasReset: true,
			resetAt:  reset5h,
			rejected: rejected,
		}
		if hasUtil5h {
			info.hasRemaining = true
			info.remaining = clampFraction(1.0 - util5h)
		}
		return info
	}

	if okUnified {
		info := quotaResetInfo{
			hasReset: true,
			resetAt:  unifiedReset,
			rejected: rejected,
		}
		claim := strings.ToLower(strings.TrimSpace(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Representative-Claim")))
		switch claim {
		case "seven_day":
			if hasUtil7d {
				info.hasRemaining = true
				info.remaining = clampFraction(1.0 - util7d)
			}
		case "five_hour":
			if hasUtil5h {
				info.hasRemaining = true
				info.remaining = clampFraction(1.0 - util5h)
			}
		}
		return info
	}

	return quotaResetInfo{rejected: rejected}
}

func claudeSignalsUnifiedResetIsOverageBoundary(signals map[string]string, unifiedReset string) bool {
	claim := strings.ToLower(strings.TrimSpace(quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Representative-Claim")))
	if !strings.Contains(claim, "overage") {
		return false
	}
	overageReset := quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Overage-Reset")
	unifiedAt, okUnified := parseQuotaResetTimestamp(unifiedReset)
	overageAt, okOverage := parseQuotaResetTimestamp(overageReset)
	if !okUnified || !okOverage {
		return false
	}
	return unifiedAt.Equal(overageAt)
}

func claudeSignalsOverageOnly(signals map[string]string) bool {
	headers := make(http.Header, len(signals))
	for key, value := range signals {
		headers.Set(key, value)
	}
	return isClaudeOverageOnlyHeaders(headers)
}

func extractCodexQuotaResetInfo(quota QuotaState, now time.Time) quotaResetInfo {
	signals := quota.Signals
	primary := parseCodexWindow(signals, "X-Codex-Primary-", quota.ObservedAt, now)
	secondary := parseCodexWindow(signals, "X-Codex-Secondary-", quota.ObservedAt, now)

	activePrimaryExhausted := primary.hasReset && primary.hasUsed && primary.usedPercent >= 100
	activeSecondaryExhausted := secondary.hasReset && secondary.hasUsed && secondary.usedPercent >= 100

	limitFlag := strings.EqualFold(strings.TrimSpace(quotaSignalValue(signals, "X-Codex-Limit-Reached")), "true") ||
		strings.EqualFold(strings.TrimSpace(quotaSignalValue(signals, "X-Codex-Allowed")), "false")

	// A past limit flag only remains active if an observed future window is still
	// open (or exhausted). If all known windows have already elapsed, treat the
	// snapshot as stale rather than permanently rejected.
	anyFutureWindow := primary.hasReset || secondary.hasReset
	anyExpiredWindow := primary.expired || secondary.expired
	rejected := activePrimaryExhausted || activeSecondaryExhausted
	if limitFlag && (anyFutureWindow || !anyExpiredWindow) {
		// If limitFlag was set due to a shorter window that has since expired while
		// the remaining future window is below 100%, do not treat it as rejected.
		if !anyExpiredWindow || activePrimaryExhausted || activeSecondaryExhausted || (!primary.hasUsed && !secondary.hasUsed) {
			rejected = true
		}
	}

	chosen, ok := chooseCodexResetWindow(primary, secondary)
	if !ok {
		return quotaResetInfo{rejected: rejected}
	}
	return quotaResetInfo{
		hasReset:     true,
		resetAt:      chosen.resetAt,
		hasRemaining: chosen.hasRemaining,
		remaining:    chosen.remaining,
		rejected:     rejected,
	}
}

func parseCodexWindow(signals map[string]string, prefix string, observedAt, now time.Time) codexWindowInfo {
	var info codexWindowInfo

	if rawMinutes := strings.TrimSpace(quotaSignalValue(signals, prefix+"Window-Minutes")); rawMinutes != "" {
		if minutes, err := strconv.Atoi(rawMinutes); err == nil && minutes > 0 {
			info.windowMinutes = minutes
		}
	}

	if rawUsed := strings.TrimSpace(quotaSignalValue(signals, prefix+"Used-Percent")); rawUsed != "" {
		if used, err := strconv.ParseFloat(rawUsed, 64); err == nil && !math.IsNaN(used) && !math.IsInf(used, 0) && used >= 0 && used <= 100 {
			info.hasUsed = true
			info.usedPercent = used
			info.hasRemaining = true
			info.remaining = clampFraction((100.0 - used) / 100.0)
		}
	}

	if rawResetAt := quotaSignalValue(signals, prefix+"Reset-At"); rawResetAt != "" {
		if resetAt, ok, expired := parseValidResetTimestamp(rawResetAt, now); ok {
			info.hasReset = true
			info.resetAt = resetAt
			return info
		} else if expired {
			info.expired = true
			return info
		}
	}

	if rawResetAfter := strings.TrimSpace(quotaSignalValue(signals, prefix+"Reset-After-Seconds")); rawResetAfter != "" && !observedAt.IsZero() {
		if seconds, err := strconv.ParseFloat(rawResetAfter, 64); err == nil && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) && seconds >= 0 {
			resetAt := observedAt.Truncate(time.Second).Add(time.Duration(seconds) * time.Second)
			if !resetAt.After(now) {
				info.expired = true
				return info
			}
			if resetAt.Sub(now) <= maxQuotaResetHorizon {
				info.hasReset = true
				info.resetAt = resetAt
				return info
			}
		}
	}

	return info
}

// chooseCodexResetWindow picks the dominant Codex window when both primary and
// secondary windows are present. Codex may report the 7-day (10080m) window in
// either primary or secondary depending on the account plan, so we prefer the
// larger window_minutes (e.g. weekly over 5-hour), falling back to the later
// reset horizon if window_minutes is omitted.
func chooseCodexResetWindow(primary, secondary codexWindowInfo) (codexWindowInfo, bool) {
	switch {
	case primary.hasReset && !secondary.hasReset:
		return primary, true
	case !primary.hasReset && secondary.hasReset:
		return secondary, true
	case !primary.hasReset && !secondary.hasReset:
		return codexWindowInfo{}, false
	}

	if primary.windowMinutes > 0 && secondary.windowMinutes > 0 && primary.windowMinutes != secondary.windowMinutes {
		if secondary.windowMinutes > primary.windowMinutes {
			return secondary, true
		}
		return primary, true
	}
	if secondary.resetAt.After(primary.resetAt) {
		return secondary, true
	}
	return primary, true
}

func quotaSignalValue(signals map[string]string, canonicalKey string) string {
	if len(signals) == 0 {
		return ""
	}
	if value, ok := signals[canonicalKey]; ok {
		return strings.TrimSpace(value)
	}
	for key, value := range signals {
		if strings.EqualFold(strings.TrimSpace(key), canonicalKey) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseValidResetTimestamp(raw string, now time.Time) (resetAt time.Time, valid bool, expired bool) {
	parsed, ok := parseQuotaResetTimestamp(raw)
	if !ok {
		return time.Time{}, false, false
	}
	parsed = parsed.Truncate(time.Second)
	if !parsed.After(now) {
		return time.Time{}, false, true
	}
	if parsed.Sub(now) > maxQuotaResetHorizon {
		return time.Time{}, false, false
	}
	return parsed, true, false
}

func parseQuotaResetTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if sec, err := strconv.ParseFloat(raw, 64); err == nil && !math.IsNaN(sec) && !math.IsInf(sec, 0) && sec > 0 {
		secInt := int64(sec)
		if secInt > 1_000_000_000_000 {
			return time.UnixMilli(secInt), true
		}
		return time.Unix(secInt, 0), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	if t, err := http.ParseTime(raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func parseQuotaFraction(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, false
	}
	return value, true
}

func clampFraction(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
