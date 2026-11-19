package auth

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func newTestSoonestResetSelector(now time.Time) *SoonestResetSelector {
	return &SoonestResetSelector{
		nowFunc: func() time.Time { return now },
	}
}

func TestSoonestResetSelector_ClaudePrefersSoonest7dWindowOverSooner5h(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	// auth-a resets 7d in 4 days, even though its 5h window resets in 30 minutes.
	// auth-b resets 7d in 18 hours, with 5h resetting in 4 hours.
	// Soonest-reset must prefer auth-b because its weekly window expires sooner.
	auths := []*Auth{
		{
			ID:       "claude-a",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-5 * time.Minute),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":                  "allowed",
					"Anthropic-Ratelimit-Unified-5h-Status":               "allowed",
					"Anthropic-Ratelimit-Unified-5h-Utilization":          "0.20",
					"Anthropic-Ratelimit-Unified-5h-Reset":                strconv.FormatInt(now.Add(30*time.Minute).Unix(), 10),
					"Anthropic-Ratelimit-Unified-7d-Status":               "allowed",
					"Anthropic-Ratelimit-Unified-7d-Utilization":          "0.10",
					"Anthropic-Ratelimit-Unified-7d-Reset":                strconv.FormatInt(now.Add(4*24*time.Hour).Unix(), 10),
					"Anthropic-Ratelimit-Unified-Overage-Status":          "rejected",
					"Anthropic-Ratelimit-Unified-Overage-Disabled-Reason": "member_zero_credit_limit",
				},
			},
		},
		{
			ID:       "claude-b",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-5 * time.Minute),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":                  "allowed",
					"Anthropic-Ratelimit-Unified-5h-Status":               "allowed",
					"Anthropic-Ratelimit-Unified-5h-Utilization":          "0.15",
					"Anthropic-Ratelimit-Unified-5h-Reset":                strconv.FormatInt(now.Add(4*time.Hour).Unix(), 10),
					"Anthropic-Ratelimit-Unified-7d-Status":               "allowed",
					"Anthropic-Ratelimit-Unified-7d-Utilization":          "0.55",
					"Anthropic-Ratelimit-Unified-7d-Reset":                strconv.FormatInt(now.Add(18*time.Hour).Unix(), 10),
					"Anthropic-Ratelimit-Unified-Overage-Status":          "rejected",
					"Anthropic-Ratelimit-Unified-Overage-Disabled-Reason": "member_zero_credit_limit",
				},
			},
		},
		{
			ID:       "claude-c",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-5 * time.Minute),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":         "allowed",
					"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.05",
					"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(now.Add(6*24*time.Hour).Unix(), 10),
				},
			},
		},
	}

	picked, err := selector.Pick(context.Background(), "claude", "claude-opus-4-6", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "claude-b" {
		t.Fatalf("Pick() = %v, want claude-b", picked)
	}
}

func TestSoonestResetSelector_ClaudeFallbacks5hUnifiedAndIgnoresOverageBillingBoundary(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	billingBoundary := strconv.FormatInt(now.Add(10*time.Hour).Unix(), 10)
	auths := []*Auth{
		{
			ID:       "claude-overage-boundary",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-time.Minute),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":               "allowed",
					"Anthropic-Ratelimit-Unified-Representative-Claim": "overage",
					"Anthropic-Ratelimit-Unified-Reset":                billingBoundary,
					"Anthropic-Ratelimit-Unified-Overage-Reset":        billingBoundary,
				},
			},
		},
		{
			ID:       "claude-5h-only",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-time.Minute),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":         "allowed",
					"Anthropic-Ratelimit-Unified-5h-Status":      "allowed",
					"Anthropic-Ratelimit-Unified-5h-Utilization": "0.30",
					"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:       "claude-unified-only",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-time.Minute),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":               "allowed",
					"Anthropic-Ratelimit-Unified-Representative-Claim": "five_hour",
					"Anthropic-Ratelimit-Unified-Reset":                strconv.FormatInt(now.Add(3*time.Hour).Unix(), 10),
				},
			},
		},
	}

	picked, err := selector.Pick(context.Background(), "claude", "claude-sonnet-4-6", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "claude-5h-only" {
		t.Fatalf("Pick() = %v, want claude-5h-only", picked)
	}

	// Remove claude-5h-only: claude-unified-only must beat claude-overage-boundary
	// because the overage billing boundary is ignored as a rate-limit window.
	picked2, err := selector.Pick(context.Background(), "claude", "claude-sonnet-4-6", cliproxyexecutor.Options{}, []*Auth{auths[0], auths[2]})
	if err != nil {
		t.Fatalf("Pick() #2 error = %v", err)
	}
	if picked2 == nil || picked2.ID != "claude-unified-only" {
		t.Fatalf("Pick() #2 = %v, want claude-unified-only", picked2)
	}
}

func TestSoonestResetSelector_ClaudeRecoveredAfter5hRejectionKeeps7dPriority(t *testing.T) {
	now := time.Date(2026, 11, 19, 15, 5, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	// claude-soonest hit its 5h limit at 12:00 (reset at 15:00), and its cooldown
	// has now expired at 15:05. Its passive Signals snapshot still holds the 12:00
	// response headers, where 5h-Reset is in the past and 7d-Reset is in 12 hours.
	auths := []*Auth{
		{
			ID:       "claude-later",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-10 * time.Minute),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":         "allowed",
					"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.10",
					"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(now.Add(5*24*time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:       "claude-soonest",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now.Add(-3 * time.Hour),
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-Status":               "rejected",
					"Anthropic-Ratelimit-Unified-Representative-Claim": "five_hour",
					"Anthropic-Ratelimit-Unified-Reset":                strconv.FormatInt(now.Add(-5*time.Minute).Unix(), 10),
					"Anthropic-Ratelimit-Unified-5h-Status":            "rejected",
					"Anthropic-Ratelimit-Unified-5h-Utilization":       "1.0",
					"Anthropic-Ratelimit-Unified-5h-Reset":             strconv.FormatInt(now.Add(-5*time.Minute).Unix(), 10),
					"Anthropic-Ratelimit-Unified-7d-Status":            "allowed",
					"Anthropic-Ratelimit-Unified-7d-Utilization":       "0.40",
					"Anthropic-Ratelimit-Unified-7d-Reset":             strconv.FormatInt(now.Add(12*time.Hour).Unix(), 10),
				},
			},
		},
	}

	picked, err := selector.Pick(context.Background(), "claude", "claude-opus-4-6", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "claude-soonest" {
		t.Fatalf("Pick() = %v, want claude-soonest", picked)
	}
}

func TestSoonestResetSelector_CodexPrefersLongestWeeklyWindowRegardlessOfSlot(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	// codex-a has 5h in Primary (resets in 1h) and 7d in Secondary (resets in 4d).
	// codex-b has 7d in Primary via Reset-After-Seconds from ObservedAt (resets in 20h).
	auths := []*Auth{
		{
			ID:       "codex-a",
			Provider: "codex",
			Quota: QuotaState{
				ObservedAt: now.Add(-2 * time.Minute),
				Signals: map[string]string{
					"X-Codex-Primary-Window-Minutes":      "300",
					"X-Codex-Primary-Used-Percent":        "30",
					"X-Codex-Primary-Reset-At":            strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
					"X-Codex-Secondary-Window-Minutes":    "10080",
					"X-Codex-Secondary-Used-Percent":      "10",
					"X-Codex-Secondary-Reset-At":          strconv.FormatInt(now.Add(4*24*time.Hour).Unix(), 10),
					"X-Codex-Limit-Reached":               "false",
					"X-Codex-Allowed":                     "true",
					"X-Codex-Primary-Reset-After-Seconds": "3600",
				},
			},
		},
		{
			ID:       "codex-b",
			Provider: "codex",
			Quota: QuotaState{
				ObservedAt: now.Add(-10 * time.Minute),
				Signals: map[string]string{
					"X-Codex-Primary-Window-Minutes":      "10080",
					"X-Codex-Primary-Used-Percent":        "45",
					"X-Codex-Primary-Reset-After-Seconds": strconv.Itoa(int((20*time.Hour + 10*time.Minute).Seconds())),
				},
			},
		},
	}

	picked, err := selector.Pick(context.Background(), "codex", "gpt-5.3-codex", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "codex-b" {
		t.Fatalf("Pick() = %v, want codex-b", picked)
	}
}

func TestSoonestResetSelector_CodexRecoveredAfter5hLimitKeeps7dPriority(t *testing.T) {
	now := time.Date(2026, 11, 19, 15, 5, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	auths := []*Auth{
		{
			ID:       "codex-later",
			Provider: "codex",
			Quota: QuotaState{
				ObservedAt: now.Add(-5 * time.Minute),
				Signals: map[string]string{
					"X-Codex-Primary-Window-Minutes": "10080",
					"X-Codex-Primary-Used-Percent":   "15",
					"X-Codex-Primary-Reset-At":       strconv.FormatInt(now.Add(5*24*time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:       "codex-soonest",
			Provider: "codex",
			Quota: QuotaState{
				ObservedAt: now.Add(-3 * time.Hour),
				Signals: map[string]string{
					"X-Codex-Allowed":                  "false",
					"X-Codex-Limit-Reached":            "true",
					"X-Codex-Primary-Window-Minutes":   "300",
					"X-Codex-Primary-Used-Percent":     "100",
					"X-Codex-Primary-Reset-At":         strconv.FormatInt(now.Add(-5*time.Minute).Unix(), 10),
					"X-Codex-Secondary-Window-Minutes": "10080",
					"X-Codex-Secondary-Used-Percent":   "40",
					"X-Codex-Secondary-Reset-At":       strconv.FormatInt(now.Add(14*time.Hour).Unix(), 10),
				},
			},
		},
	}

	picked, err := selector.Pick(context.Background(), "codex", "gpt-5.3-codex", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "codex-soonest" {
		t.Fatalf("Pick() = %v, want codex-soonest", picked)
	}
}

func TestSoonestResetSelector_TieBreakByRemainingQuotaThenRoundRobin(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)
	sameReset := strconv.FormatInt(now.Add(10*time.Hour).Unix(), 10)

	// First: same reset timestamp, different remaining quota -> higher remaining (lower utilization) wins.
	authsDiffRemaining := []*Auth{
		{
			ID:       "claude-a",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset":       sameReset,
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.70",
				},
			},
		},
		{
			ID:       "claude-b",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset":       sameReset,
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.20",
				},
			},
		},
	}
	picked, err := selector.Pick(context.Background(), "claude", "claude-opus-4-6", cliproxyexecutor.Options{}, authsDiffRemaining)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "claude-b" {
		t.Fatalf("Pick() = %v, want claude-b (higher remaining quota)", picked)
	}

	// Second: same reset timestamp AND same remaining quota -> stable round-robin rotation.
	selectorRR := newTestSoonestResetSelector(now)
	authsExactTie := []*Auth{
		{
			ID:       "claude-a",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset":       sameReset,
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.25",
				},
			},
		},
		{
			ID:       "claude-b",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset":       sameReset,
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.25",
				},
			},
		},
		{
			ID:       "claude-c",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset":       sameReset,
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.25",
				},
			},
		},
	}

	wantOrder := []string{"claude-a", "claude-b", "claude-c", "claude-a"}
	for i, want := range wantOrder {
		got, errPick := selectorRR.Pick(context.Background(), "claude", "claude-opus-4-6", cliproxyexecutor.Options{}, authsExactTie)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		if got == nil || got.ID != want {
			t.Fatalf("Pick() #%d = %v, want %s", i, got, want)
		}
	}
}

func TestSoonestResetSelector_MissingOrStaleResetFallsBackToRoundRobin(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	// Mix of missing signals, expired reset timestamp, and relative reset with zero ObservedAt.
	auths := []*Auth{
		{
			ID:       "codex-a",
			Provider: "codex",
			Quota:    QuotaState{},
		},
		{
			ID:       "codex-b",
			Provider: "codex",
			Quota: QuotaState{
				ObservedAt: now.Add(-2 * time.Hour),
				Signals: map[string]string{
					"X-Codex-Primary-Window-Minutes": "10080",
					"X-Codex-Primary-Reset-At":       strconv.FormatInt(now.Add(-time.Minute).Unix(), 10),
				},
			},
		},
		{
			ID:       "codex-c",
			Provider: "codex",
			Quota: QuotaState{
				// Zero ObservedAt makes Reset-After-Seconds unusable.
				Signals: map[string]string{
					"X-Codex-Primary-Window-Minutes":      "10080",
					"X-Codex-Primary-Reset-After-Seconds": "3600",
				},
			},
		},
	}

	wantOrder := []string{"codex-a", "codex-b", "codex-c", "codex-a"}
	for i, want := range wantOrder {
		got, err := selector.Pick(context.Background(), "codex", "gpt-5.3-codex", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() #%d error = %v", i, err)
		}
		if got == nil || got.ID != want {
			t.Fatalf("Pick() #%d = %v, want %s", i, got, want)
		}
	}
}

func TestSoonestResetSelector_KnownResetBeatsUnknownAndRespectsPriorityAndCooldown(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	// Priority tier is respected first; cooldown & disabled credentials are excluded.
	auths := []*Auth{
		{
			ID:             "claude-high-cooling",
			Provider:       "claude",
			Attributes:     map[string]string{"priority": "10"},
			Unavailable:    true,
			NextRetryAfter: now.Add(30 * time.Minute),
			Quota: QuotaState{
				Exceeded:      true,
				Reason:        "quota",
				NextRecoverAt: now.Add(30 * time.Minute),
				ObservedAt:    now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:         "claude-disabled",
			Provider:   "claude",
			Disabled:   true,
			Attributes: map[string]string{"priority": "10"},
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(30*time.Minute).Unix(), 10),
				},
			},
		},
		{
			ID:       "claude-unknown",
			Provider: "claude",
		},
		{
			ID:       "claude-known-later",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(72*time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:       "claude-known-soonest",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(24*time.Hour).Unix(), 10),
				},
			},
		},
	}

	picked, err := selector.Pick(context.Background(), "claude", "claude-opus-4-6", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "claude-known-soonest" {
		t.Fatalf("Pick() = %v, want claude-known-soonest", picked)
	}

	// Higher priority tier always wins over a lower priority tier with a sooner reset.
	authsWithHighTier := append([]*Auth(nil), auths...)
	authsWithHighTier = append(authsWithHighTier, &Auth{
		ID:         "claude-high-ready",
		Provider:   "claude",
		Attributes: map[string]string{"priority": "10"},
		Quota: QuotaState{
			ObservedAt: now,
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(6*24*time.Hour).Unix(), 10),
			},
		},
	})
	pickedHigh, err := selector.Pick(context.Background(), "claude", "claude-opus-4-6", cliproxyexecutor.Options{}, authsWithHighTier)
	if err != nil {
		t.Fatalf("Pick() high tier error = %v", err)
	}
	if pickedHigh == nil || pickedHigh.ID != "claude-high-ready" {
		t.Fatalf("Pick() high tier = %v, want claude-high-ready", pickedHigh)
	}
}

func TestSoonestResetSelector_ProviderIsolation(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)

	// In a mixed-provider call, Claude reset signals must never starve xAI (or vice-versa).
	// Providers rotate round-robin, and within Claude the soonest-reset account is selected.
	mixedAuths := []*Auth{
		{
			ID:       "claude-later",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(96*time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:       "claude-soonest",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(12*time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:       "xai-a",
			Provider: "xai",
		},
		{
			ID:       "xai-b",
			Provider: "xai",
		},
	}

	wantOrder := []string{"claude-soonest", "xai-a", "claude-soonest", "xai-b"}
	for i, want := range wantOrder {
		got, err := selector.Pick(context.Background(), "mixed", "shared-model", cliproxyexecutor.Options{}, mixedAuths)
		if err != nil {
			t.Fatalf("Pick() mixed #%d error = %v", i, err)
		}
		if got == nil || got.ID != want {
			t.Fatalf("Pick() mixed #%d = %v, want %s", i, got, want)
		}
	}
}

func TestSoonestResetSelector_SessionAffinityPreservedAndFailover(t *testing.T) {
	now := time.Now()
	soonest := &SoonestResetSelector{}
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: soonest,
		TTL:      time.Hour,
	})
	defer affinity.Stop()

	authA := &Auth{
		ID:       "claude-a",
		Provider: "claude",
		Quota: QuotaState{
			ObservedAt: now,
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(24*time.Hour).Unix(), 10),
			},
		},
	}
	authB := &Auth{
		ID:       "claude-b",
		Provider: "claude",
		Quota: QuotaState{
			ObservedAt: now,
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(72*time.Hour).Unix(), 10),
			},
		},
	}
	authC := &Auth{
		ID:       "claude-c",
		Provider: "claude",
		Quota: QuotaState{
			ObservedAt: now,
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(120*time.Hour).Unix(), 10),
			},
		},
	}

	session1Opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Claude-Code-Session-Id": {"session-1"}},
	}
	// Cold session 1 binds to claude-a (soonest reset: 24h).
	picked1, err := affinity.Pick(context.Background(), "claude", "claude-opus-4-6", session1Opts, []*Auth{authA, authB, authC})
	if err != nil || picked1 == nil || picked1.ID != "claude-a" {
		t.Fatalf("cold session 1 pick = %v, err=%v; want claude-a", picked1, err)
	}

	// Even if authB now resets sooner (6h vs 24h), session 1 MUST stay stuck to claude-a
	// to preserve prompt cache.
	authB.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Reset"] = strconv.FormatInt(now.Add(6*time.Hour).Unix(), 10)
	picked1Sticky, err := affinity.Pick(context.Background(), "claude", "claude-opus-4-6", session1Opts, []*Auth{authA, authB, authC})
	if err != nil || picked1Sticky == nil || picked1Sticky.ID != "claude-a" {
		t.Fatalf("sticky session 1 pick = %v, err=%v; want claude-a", picked1Sticky, err)
	}

	// Meanwhile a brand-new session 2 picks authB (now soonest reset: 6h).
	session2Opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Claude-Code-Session-Id": {"session-2"}},
	}
	picked2, err := affinity.Pick(context.Background(), "claude", "claude-opus-4-6", session2Opts, []*Auth{authA, authB, authC})
	if err != nil || picked2 == nil || picked2.ID != "claude-b" {
		t.Fatalf("cold session 2 pick = %v, err=%v; want claude-b", picked2, err)
	}

	// Failover: put authA into cooldown; session 1 must fail over to the next soonest (claude-b).
	authA.Unavailable = true
	authA.NextRetryAfter = now.Add(time.Hour)
	authA.Quota.Exceeded = true
	authA.Quota.Reason = "credential_quota"
	authA.Quota.NextRecoverAt = now.Add(time.Hour)

	picked1Failover, err := affinity.Pick(context.Background(), "claude", "claude-opus-4-6", session1Opts, []*Auth{authA, authB, authC})
	if err != nil || picked1Failover == nil || picked1Failover.ID != "claude-b" {
		t.Fatalf("failover session 1 pick = %v, err=%v; want claude-b", picked1Failover, err)
	}
}

func TestManager_SoonestResetObservesMarkResultAcrossModels(t *testing.T) {
	for _, withAffinity := range []bool{false, true} {
		name := "bare"
		if withAffinity {
			name = "session-affinity"
		}
		t.Run(name, func(t *testing.T) {
			var sel Selector = &SoonestResetSelector{}
			if withAffinity {
				sel = NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
					Fallback: sel,
					TTL:      time.Hour,
				})
				defer sel.(StoppableSelector).Stop()
			}
			manager := NewManager(nil, sel, nil)
			manager.RegisterExecutor(&testDummyExecutor{id: "claude"})

			for _, id := range []string{"claude-1", "claude-2", "claude-3"} {
				if _, err := manager.Register(context.Background(), &Auth{
					ID:       id,
					Provider: "claude",
				}); err != nil {
					t.Fatalf("Register(%s) error = %v", id, err)
				}
			}

			now := time.Now()
			observe := func(authID string, resetIn time.Duration, util string) {
				ctx := internallogging.WithResponseHeadersHolder(context.Background())
				internallogging.SetResponseHeaders(ctx, http.Header{
					"Anthropic-Ratelimit-Unified-Status":         {"allowed"},
					"Anthropic-Ratelimit-Unified-7d-Status":      {"allowed"},
					"Anthropic-Ratelimit-Unified-7d-Reset":       {strconv.FormatInt(now.Add(resetIn).Unix(), 10)},
					"Anthropic-Ratelimit-Unified-7d-Utilization": {util},
				})
				manager.MarkResult(ctx, Result{
					AuthID:   authID,
					Provider: "claude",
					Model:    "claude-opus-4-6",
					Success:  true,
				})
			}

			// Observe headers via claude-opus-4-6 responses.
			observe("claude-1", 5*24*time.Hour, "0.10")
			observe("claude-2", 10*time.Hour, "0.40")
			observe("claude-3", 3*24*time.Hour, "0.05")

			// Select on a sibling model (claude-sonnet-4-6): must still see the fresh
			// account-level 7d reset signals and pick claude-2.
			opts := cliproxyexecutor.Options{
				Headers: http.Header{"X-Claude-Code-Session-Id": {"sess-cross-model"}},
			}
			picked, _, provider, err := manager.pickNextMixed(context.Background(), []string{"claude"}, "", opts, nil)
			if err != nil {
				t.Fatalf("pickNextMixed() error = %v", err)
			}
			if provider != "claude" || picked == nil || picked.ID != "claude-2" {
				t.Fatalf("pickNextMixed() = (%v, %q), want (claude-2, claude)", picked, provider)
			}

			// Exclude claude-2 (simulating retry failover): must pick next soonest (claude-3).
			tried := map[string]struct{}{"claude-2": {}}
			pickedFailover, _, _, err := manager.pickNextMixed(context.Background(), []string{"claude"}, "", opts, tried)
			if err != nil {
				t.Fatalf("pickNextMixed() failover error = %v", err)
			}
			if pickedFailover == nil || pickedFailover.ID != "claude-3" {
				t.Fatalf("pickNextMixed() failover = %v, want claude-3", pickedFailover)
			}
		})
	}
}

func TestSoonestResetSelector_Concurrent(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	selector := newTestSoonestResetSelector(now)
	sameReset := strconv.FormatInt(now.Add(12*time.Hour).Unix(), 10)
	auths := []*Auth{
		{
			ID:       "claude-a",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset":       sameReset,
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.30",
				},
			},
		},
		{
			ID:       "claude-b",
			Provider: "claude",
			Quota: QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset":       sameReset,
					"Anthropic-Ratelimit-Unified-7d-Utilization": "0.30",
				},
			},
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				picked, err := selector.Pick(context.Background(), "claude", "claude-opus-4-6", cliproxyexecutor.Options{}, auths)
				if err != nil || picked == nil {
					t.Errorf("concurrent Pick() failed: auth=%v err=%v", picked, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

type testDummyExecutor struct {
	id string
}

func (e *testDummyExecutor) Identifier() string { return e.id }
func (e *testDummyExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *testDummyExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e *testDummyExecutor) Refresh(context.Context, *Auth) (*Auth, error) { return nil, nil }
func (e *testDummyExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *testDummyExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}
