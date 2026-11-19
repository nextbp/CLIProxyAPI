package cliproxy

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestSoonestResetRoutingConfigNormalization(t *testing.T) {
	for _, raw := range []string{"soonest-reset", "Soonest-Reset", "soonestreset", "sr", "  soonest-reset  "} {
		state := normalizedRoutingRuntimeState(&internalconfig.Config{
			Routing: internalconfig.RoutingConfig{Strategy: raw},
		})
		if state.strategy != "soonest-reset" {
			t.Fatalf("normalizedRoutingRuntimeState(%q).strategy = %q, want soonest-reset", raw, state.strategy)
		}
		selector := newRoutingSelector(state)
		if _, ok := selector.(*coreauth.SoonestResetSelector); !ok {
			t.Fatalf("newRoutingSelector(%q) = %T, want *auth.SoonestResetSelector", raw, selector)
		}
	}

	// Default strategy remains round-robin when omitted or unknown.
	defaultState := normalizedRoutingRuntimeState(&internalconfig.Config{})
	if defaultState.strategy != "round-robin" {
		t.Fatalf("default strategy = %q, want round-robin", defaultState.strategy)
	}
	if _, ok := newRoutingSelector(defaultState).(*coreauth.RoundRobinSelector); !ok {
		t.Fatalf("default selector = %T, want *auth.RoundRobinSelector", newRoutingSelector(defaultState))
	}
}

func TestSoonestResetRoutingSelectorWithSessionAffinity(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:           "soonest-reset",
			SessionAffinity:    true,
			SessionAffinityTTL: "1h",
		},
	})
	selector := newRoutingSelector(state)
	affinity, ok := selector.(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector = %T, want *auth.SessionAffinitySelector", selector)
	}
	defer affinity.Stop()

	now := time.Now()
	auths := []*coreauth.Auth{
		{
			ID:       "claude-later",
			Provider: "claude",
			Quota: coreauth.QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(96*time.Hour).Unix(), 10),
				},
			},
		},
		{
			ID:       "claude-soonest",
			Provider: "claude",
			Quota: coreauth.QuotaState{
				ObservedAt: now,
				Signals: map[string]string{
					"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(12*time.Hour).Unix(), 10),
				},
			},
		},
	}

	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Claude-Code-Session-Id": {"cfg-session-1"}},
	}
	picked, err := affinity.Pick(context.Background(), "claude", "claude-opus-4-6", opts, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked == nil || picked.ID != "claude-soonest" {
		t.Fatalf("Pick() = %v, want claude-soonest", picked)
	}
}
