// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logs

import (
	"slices"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
)

func mustMaskingHash(t *testing.T, v any, key string) string {
	t.Helper()

	h, err := topdown.MaskingHash(v, key)
	if err != nil {
		t.Fatal(err)
	}

	return h
}

func newPreviewPlugin(t *testing.T, policy []byte) *Plugin {
	t.Helper()

	ctx := t.Context()
	store := inmem.New()

	if err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		return store.UpsertPolicy(ctx, txn, "test.rego", policy)
	}); err != nil {
		t.Fatal(err)
	}

	// Start is required so stored policies get compiled and made available to
	// the plugin.
	manager, err := plugins.New(nil, "test", store)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Service: "svc"}
	trigger := plugins.DefaultTriggerMode
	if err := cfg.validateAndInjectDefaults([]string{"svc"}, nil, &trigger, nil); err != nil {
		t.Fatal(err)
	}

	return New(cfg, manager)
}

func verdictFor(preview *MaskPreview, path string) (MaskPathVerdict, bool) {
	for _, v := range preview.Paths {
		if v.Path == path {
			return v, true
		}
	}

	return MaskPathVerdict{}, false
}

func ruleFor(preview *MaskPreview, path string) (MaskRulePreview, bool) {
	for _, r := range preview.Rules {
		if r.Path == path {
			return r, true
		}
	}

	return MaskRulePreview{}, false
}

func TestPreviewMaskNestedObjectsAndArrays(t *testing.T) {
	t.Parallel()

	policy := []byte(`
		package system.log
		import rego.v1

		mask contains {"op": "hash", "path": "/input/users/0/ssn", "key": "k"}
		mask contains {"op": "retain", "path": "/input/users/0/name"}
		mask contains "/input/password"
	`)

	plugin := newPreviewPlugin(t, policy)

	var input any = map[string]any{
		"password": "p",
		"users": []any{
			map[string]any{"name": "bob", "ssn": "111", "email": "bob@example.com"},
		},
		"nested": map[string]any{
			"deep": map[string]any{"secret": 42, "ok": true},
		},
	}

	preview, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{
		Event: &EventV1{Input: &input},
	})
	if err != nil {
		t.Fatal(err)
	}

	if preview.DefaultAction != MaskActionRemove {
		t.Fatalf("expected secure default %q, got %q", MaskActionRemove, preview.DefaultAction)
	}

	if got, want := preview.Decision, defaultMaskDecisionPath; got != want {
		t.Fatalf("expected decision %q, got %q", want, got)
	}

	checks := []struct {
		path    string
		action  MaskAction
		matched bool
	}{
		{"/input", MaskActionRemove, false}, // no rule covers the root itself
		{"/input/password", MaskActionRemove, true},
		{"/input/users", MaskActionRemove, false},
		{"/input/users/0/ssn", MaskActionHash, true},
		{"/input/users/0/name", MaskActionRetain, true},
		{"/input/users/0/email", MaskActionRemove, false}, // unmatched leaf defaults safe
		{"/input/nested/deep/secret", MaskActionRemove, false},
		{"/input/nested/deep/ok", MaskActionRemove, false},
	}

	for _, c := range checks {
		v, ok := verdictFor(preview, c.path)
		if !ok {
			t.Fatalf("missing verdict for %s", c.path)
		}

		if v.Action != c.action || v.Matched != c.matched {
			t.Fatalf("verdict for %s: expected action=%s matched=%v, got action=%s matched=%v (%s)",
				c.path, c.action, c.matched, v.Action, v.Matched, v.Reason)
		}

		if c.matched && !slices.Contains([]MaskAction{MaskActionRemove, MaskActionHash, MaskActionRetain}, v.Action) {
			t.Fatalf("unexpected action for %s: %s", c.path, v.Action)
		}

		if v.Reason == "" {
			t.Fatalf("missing reason for %s", c.path)
		}
	}

	// The hashed ssn reason cites its own rule exactly.
	ssn, _ := verdictFor(preview, "/input/users/0/ssn")
	if ssn.RuleIndex < 0 || preview.Rules[ssn.RuleIndex].Path != "/input/users/0/ssn" {
		t.Fatalf("ssn verdict points at wrong rule: %+v", ssn)
	}

	// Every rule path is present in the sample.
	for _, r := range preview.Rules {
		if !r.Present {
			t.Errorf("rule %d (%s) reported absent although present in sample", r.Index, r.Path)
		}
	}

	// The sample event must not be mutated, and nothing reaches a log sink.
	if input.(map[string]any)["password"] != "p" {
		t.Fatalf("sample input was mutated: %v", input)
	}

	if events := plugin.b.Flush(); len(events) != 0 {
		t.Fatalf("expected no buffered events, got %d", len(events))
	}

	// Sanity check: the action the preview predicts matches what the mask
	// engine does to a logged event with the same shape.
	logged := &EventV1{Input: &input}
	loggedInput, err := logged.AST()
	if err != nil {
		t.Fatal(err)
	}
	if err := plugin.maskEvent(t.Context(), nil, loggedInput, logged); err != nil {
		t.Fatal(err)
	}

	maskedInput := (*logged.Input).(map[string]any)
	if _, ok := maskedInput["password"]; ok {
		t.Fatal("engine did not remove /input/password as previewed")
	}

	users := maskedInput["users"].([]any)
	first := users[0].(map[string]any)
	if first["ssn"] != mustMaskingHash(t, "111", "k") {
		t.Fatal("engine did not hash /input/users/0/ssn as previewed")
	}

	if first["name"] != "bob" {
		t.Fatal("engine did not retain /input/users/0/name as previewed")
	}
}

func TestPreviewMaskInheritedAndArrayRules(t *testing.T) {
	t.Parallel()

	policy := []byte(`
		package system.log
		import rego.v1

		# hashing a container covers all of its descendants
		mask contains {"op": "hash", "path": "/input/items", "key": "k"}

		# removing a single array element
		mask contains "/input/scores/1"
	`)

	plugin := newPreviewPlugin(t, policy)

	var input any = map[string]any{
		"items":  []any{"a", map[string]any{"nested": "b"}},
		"scores": []any{1, 2, 3},
	}

	preview, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{
		Event: &EventV1{Input: &input},
	})
	if err != nil {
		t.Fatal(err)
	}

	root, ok := verdictFor(preview, "/input/items")
	if !ok || root.Action != MaskActionHash || !root.Matched {
		t.Fatalf("expected /input/items hashed, got %+v", root)
	}

	for _, p := range []string{"/input/items/0", "/input/items/1", "/input/items/1/nested"} {
		v, ok := verdictFor(preview, p)
		if !ok {
			t.Fatalf("missing verdict for %s", p)
		}
		if v.Action != MaskActionHash || !v.Matched {
			t.Fatalf("expected %s inherited hash, got %+v", p, v)
		}
	}

	scores := []struct {
		path    string
		matched bool
	}{
		{"/input/scores/0", false},
		{"/input/scores/1", true},
		{"/input/scores/2", false},
	}
	for _, c := range scores {
		v, _ := verdictFor(preview, c.path)
		if v.Matched != c.matched || v.Action != MaskActionRemove {
			t.Fatalf("%s: expected matched=%v action=remove, got matched=%v action=%s", c.path, c.matched, v.Matched, v.Action)
		}
	}

	// The sample slice must be untouched.
	if input.(map[string]any)["scores"].([]any)[1] != 2 {
		t.Fatalf("sample array mutated: %v", input)
	}
}

func TestPreviewMaskUpsertAbsentPath(t *testing.T) {
	t.Parallel()

	policy := []byte(`
		package system.log
		import rego.v1

		mask contains {"op": "upsert", "path": "/input/redacted", "value": "**REDACTED**"}
		mask contains "/input/missing"
	`)

	plugin := newPreviewPlugin(t, policy)

	var input any = map[string]any{"name": "bob"}

	preview, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{
		Event: &EventV1{Input: &input},
	})
	if err != nil {
		t.Fatal(err)
	}

	upsertRule, ok := ruleFor(preview, "/input/redacted")
	if !ok || upsertRule.Present {
		t.Fatalf("expected absent upsert rule in rules, got %+v", upsertRule)
	}

	v, ok := verdictFor(preview, "/input/redacted")
	if !ok || !v.Matched || v.Action != MaskActionUpsert {
		t.Fatalf("expected synthetic upsert verdict, got %+v", v)
	}

	// remove on an absent path is a no-op and must not produce a verdict.
	if _, ok := verdictFor(preview, "/input/missing"); ok {
		t.Fatal("did not expect a verdict for a remove rule on an absent path")
	}

	removeRule, ok := ruleFor(preview, "/input/missing")
	if !ok || removeRule.Present {
		t.Fatalf("expected remove rule listed as absent, got %+v", removeRule)
	}

	// The preview must not have upserted anything into the sample.
	if len(input.(map[string]any)) != 1 {
		t.Fatalf("sample input mutated: %v", input)
	}
}

func TestPreviewMaskTenantPolicy(t *testing.T) {
	t.Parallel()

	policy := []byte(`
		package system.log
		import rego.v1

		mask contains {"op": "hash", "path": "/input/email", "key": "tenant-key"} if {
			input.input.tenant == "pseudonymize"
		}

		mask contains "/input/email" if {
			input.input.tenant == "redact"
		}

		mask contains {"op": "retain", "path": "/input/email"} if {
			input.input.tenant == "open"
		}
	`)

	plugin := newPreviewPlugin(t, policy)

	for _, tc := range []struct {
		tenant string
		action MaskAction
	}{
		{"pseudonymize", MaskActionHash},
		{"redact", MaskActionRemove},
		{"open", MaskActionRetain},
	} {
		t.Run(tc.tenant, func(t *testing.T) {
			var input any = map[string]any{"tenant": tc.tenant, "email": "user@example.com", "device": "phone"}

			preview, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{
				Event: &EventV1{Input: &input},
			})
			if err != nil {
				t.Fatal(err)
			}

			v, ok := verdictFor(preview, "/input/email")
			if !ok {
				t.Fatal("missing /input/email verdict")
			}

			if v.Action != tc.action || !v.Matched {
				t.Fatalf("tenant %s: expected matched %s, got %+v", tc.tenant, tc.action, v)
			}

			// When hashed, the digest is computed with the tenant-specific key.
			if tc.action == MaskActionHash {
				event := &EventV1{Input: &input}
				value, err := event.AST()
				if err != nil {
					t.Fatal(err)
				}
				if err := plugin.maskEvent(t.Context(), nil, value, event); err != nil {
					t.Fatal(err)
				}
				got := (*event.Input).(map[string]any)["email"]
				if want := mustMaskingHash(t, "user@example.com", "tenant-key"); got != want {
					t.Fatalf("expected digest %s, got %v", want, got)
				}
			}

			// An uncovered field stays classified with the secure default.
			device, ok := verdictFor(preview, "/input/device")
			if !ok || device.Matched || device.Action != MaskActionRemove {
				t.Fatalf("tenant %s: expected unmatched /input/device to default to remove, got %+v", tc.tenant, device)
			}
		})
	}
}

func TestPreviewMaskDefaultActionOverride(t *testing.T) {
	t.Parallel()

	plugin := newPreviewPlugin(t, []byte(`
		package system.log
		import rego.v1
		mask contains "/input/password"
	`))

	var input any = map[string]any{"password": "p", "name": "bob"}

	preview, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{
		Event:         &EventV1{Input: &input},
		DefaultAction: MaskActionRetain,
	})
	if err != nil {
		t.Fatal(err)
	}

	if preview.DefaultAction != MaskActionRetain {
		t.Fatalf("expected retain default, got %s", preview.DefaultAction)
	}

	name, _ := verdictFor(preview, "/input/name")
	if name.Matched || name.Action != MaskActionRetain {
		t.Fatalf("expected /input/name retained by default, got %+v", name)
	}

	password, _ := verdictFor(preview, "/input/password")
	if !password.Matched || password.Action != MaskActionRemove {
		t.Fatalf("explicit remove rule must beat default, got %+v", password)
	}

	if _, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{
		Event:         &EventV1{Input: &input},
		DefaultAction: "bogus",
	}); err == nil {
		t.Fatal("expected error for invalid default action")
	}

	if _, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{}); err == nil {
		t.Fatal("expected error without a sample event")
	}
}

func TestPreviewMaskResultRoot(t *testing.T) {
	t.Parallel()

	policy := []byte(`
		package system.log
		import rego.v1

		mask contains {"op": "hash", "path": "/result/token", "key": "k"}
	`)

	plugin := newPreviewPlugin(t, policy)

	var result any = map[string]any{"token": "abc", "ok": true}

	preview, err := plugin.PreviewMask(t.Context(), PreviewMaskOptions{
		Event: &EventV1{Result: &result},
	})
	if err != nil {
		t.Fatal(err)
	}

	token, ok := verdictFor(preview, "/result/token")
	if !ok || !token.Matched || token.Action != MaskActionHash {
		t.Fatalf("expected matched hash for /result/token, got %+v", token)
	}

	ok2, ok := verdictFor(preview, "/result/ok")
	if !ok || ok2.Matched || ok2.Action != MaskActionRemove {
		t.Fatalf("expected secure default for /result/ok, got %+v", ok2)
	}

	if result.(map[string]any)["token"] != "abc" {
		t.Fatal("result mutated by preview")
	}
}

func TestPreviewMaskConcurrentPolicyUpdates(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := inmem.New()

	// Two policy versions. Both classify /input/secret, differently, and each
	// adds an extra rule so previews taken from the two versions are
	// distinguishable.
	policyV1 := []byte(`
		package system.log
		import rego.v1

		mask contains {"op": "hash", "path": "/input/secret", "key": "k"}
		mask contains {"op": "retain", "path": "/input/name"}
	`)
	policyV2 := []byte(`
		package system.log
		import rego.v1

		mask contains "/input/secret"
		mask contains {"op": "retain", "path": "/input/name"}
		mask contains "/input/internal"
	`)

	if err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		return store.UpsertPolicy(ctx, txn, "test.rego", policyV1)
	}); err != nil {
		t.Fatal(err)
	}

	manager, err := plugins.New(nil, "test", store)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Service: "svc"}
	trigger := plugins.DefaultTriggerMode
	if err := cfg.validateAndInjectDefaults([]string{"svc"}, nil, &trigger, nil); err != nil {
		t.Fatal(err)
	}

	plugin := New(cfg, manager)

	upsert := func(policy []byte) error {
		return storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
			return store.UpsertPolicy(ctx, txn, "test.rego", policy)
		})
	}

	const updates = 50

	var (
		sawMu              sync.Mutex
		sawHash, sawRemove bool
	)

	var wg sync.WaitGroup

	// Writer: keep activating new bundle/policy revisions.
	wg.Go(func() {
		for i := range updates {
			policy := policyV1
			if i%2 != 0 {
				policy = policyV2
			}
			if err := upsert(policy); err != nil {
				t.Errorf("upsert policy: %v", err)
			}
		}
	})

	// Readers: preview against one consistent snapshot per call.
	const readers = 8
	const iterations = 50

	for range readers {
		wg.Go(func() {
			for range iterations {
				var input any = map[string]any{"secret": "s", "name": "bob", "internal": "x", "other": "o"}

				preview, err := plugin.PreviewMask(ctx, PreviewMaskOptions{
					Event: &EventV1{Input: &input},
				})
				if err != nil {
					t.Errorf("preview: %v", err)
					return
				}

				for _, v := range preview.Paths {
					if v.Matched {
						if v.RuleIndex < 0 || v.RuleIndex >= len(preview.Rules) {
							t.Errorf("verdict %s references out-of-range rule %d", v.Path, v.RuleIndex)
							continue
						}

						rule := preview.Rules[v.RuleIndex]
						if !ruleCoversPath(escapedForTest(t, rule.Path), escapedForTest(t, v.Path)) {
							t.Errorf("verdict %s claims rule %s that does not cover it", v.Path, rule.Path)
						}
					} else if v.Action != DefaultMaskAction {
						t.Errorf("unmatched %s classified %s, want default %s", v.Path, v.Action, DefaultMaskAction)
					}
				}

				secret, ok := verdictFor(preview, "/input/secret")
				if !ok || !secret.Matched {
					t.Errorf("secret field unmatched: %+v", secret)
					continue
				}

				sawMu.Lock()
				switch secret.Action {
				case MaskActionHash:
					sawHash = true
				case MaskActionRemove:
					sawRemove = true
				default:
					t.Errorf("unexpected secret action %s", secret.Action)
				}
				sawMu.Unlock()

				if input.(map[string]any)["secret"] != "s" {
					t.Error("sample input mutated during preview")
				}
			}
		})
	}

	wg.Wait()

	if !sawHash || !sawRemove {
		t.Fatalf("expected previews from both policy versions, saw hash=%v remove=%v", sawHash, sawRemove)
	}
}

// escapedForTest turns a JSON-pointer style preview path into rule path
// segments, reusing the engine's own escaping convention.
func escapedForTest(t *testing.T, path string) []string {
	t.Helper()

	r, err := newMaskRule(path)
	if err != nil {
		t.Fatalf("invalid path %s: %v", path, err)
	}

	return r.escapedParts
}
