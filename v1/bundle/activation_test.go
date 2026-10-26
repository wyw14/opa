// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package bundle

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/internal/file/archive"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

const testBundleName = "test"

func newTestActivation(t *testing.T) (*Activation, storage.Store) {
	t.Helper()

	store := inmem.New()
	act := NewActivation(store).WithParserOptions(ast.ParserOptions{RegoVersion: ast.RegoV1})

	return act, store
}

// compressedBundleFiles returns the files of a gzipped tar bundle rooted at
// "roles": a valid v1 module, a data document and a manifest with the given
// revision.
func compressedBundleFiles(revision string) [][2]string {
	return [][2]string{
		{"/.manifest", fmt.Sprintf(`{"roots":["roles"],"revision":%q}`, revision)},
		{"/roles.rego", `package roles

default allow := true
`},
		{"/roles/data.json", `{"permits":["read"]}`},
	}
}

func loadCompressedBundle(t *testing.T, files [][2]string) *Bundle {
	t.Helper()

	b, err := NewCustomReader(NewTarballLoader(archive.MustWriteTarGz(files))).
		WithRegoVersion(ast.RegoV1).
		Read()
	if err != nil {
		t.Fatalf("failed to read compressed bundle: %v", err)
	}

	return &b
}

func activationOpts(b *Bundle) *ActivationOpts {
	return &ActivationOpts{
		Name:   testBundleName,
		Bundle: b,
	}
}

func readRoot(t *testing.T, store storage.Store, path string) (any, bool) {
	t.Helper()

	ctx := t.Context()
	txn := storage.NewTransactionOrDie(ctx, store)
	defer store.Abort(ctx, txn)

	v, err := store.Read(ctx, txn, storage.MustParsePath(path))
	if storage.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return v, true
}

func activeRevision(t *testing.T, act *Activation) string {
	t.Helper()

	status, err := act.Status(t.Context(), testBundleName)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return status.Revision
}

func findDiagnostic(report *ActivationReport, file string, stage ActivationStage) *FileDiagnostic {
	for i := range report.Diagnostics {
		d := &report.Diagnostics[i]
		if d.Stage == stage && d.File == file {
			return d
		}
	}
	return nil
}

func TestActivationDryRunCompressedBundle(t *testing.T) {
	ctx := t.Context()
	act, store := newTestActivation(t)

	b := loadCompressedBundle(t, compressedBundleFiles("r1"))

	// Nothing activated yet.
	status, err := act.Status(ctx, testBundleName)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Active {
		t.Fatalf("expected inactive bundle, got %+v", status)
	}

	// Dry-run the full pipeline against a throw-away copy of the store.
	report, err := act.DryRun(ctx, activationOpts(b))
	if err != nil {
		t.Fatalf("dry-run: %v\n%+v", err, report.Diagnostics)
	}

	if !report.DryRun {
		t.Errorf("expected dry-run report")
	}
	if report.Revision != "r1" || report.PreviousRevision != "" {
		t.Errorf("unexpected revisions: %q / %q", report.Revision, report.PreviousRevision)
	}
	if !report.Activated || report.Skipped {
		t.Errorf("expected report to indicate the bundle would activate, got activated=%v skipped=%v", report.Activated, report.Skipped)
	}
	if report.Signature.Signed {
		t.Errorf("did not expect a signed bundle")
	}
	if len(report.Modules) != 1 || !report.Modules[0].Parsed || !report.Modules[0].Compiled {
		t.Errorf("unexpected module results: %+v", report.Modules)
	}
	if !slices.Contains(report.Data.Roots, "roles") {
		t.Errorf("expected roles root in data migration result, got %+v", report.Data.Roots)
	}
	if len(report.Diagnostics) != 0 {
		t.Errorf("unexpected diagnostics: %+v", report.Diagnostics)
	}

	// The active store must be untouched.
	if v, ok := readRoot(t, store, "/roles"); ok {
		t.Errorf("dry-run wrote data to the active store: %v", v)
	}
	policyTxn := storage.NewTransactionOrDie(ctx, store)
	ids, _ := store.ListPolicies(ctx, policyTxn)
	store.Abort(ctx, policyTxn)
	if len(ids) != 0 {
		t.Errorf("dry-run wrote policies to the active store: %v", ids)
	}
	if status, _ := act.Status(ctx, testBundleName); status.Active {
		t.Errorf("dry-run changed the bundle status: %+v", status)
	}

	// Real activation commits the same revision.
	report, err = act.Activate(ctx, activationOpts(b))
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !report.Activated || report.PreviousRevision != "" {
		t.Errorf("unexpected activation report: %+v", report)
	}

	statuses, err := act.Statuses(ctx)
	if err != nil {
		t.Fatalf("statuses: %v", err)
	}
	if status := statuses[testBundleName]; !status.Active || status.Revision != "r1" || !slices.Contains(status.Roots, "roles") {
		t.Errorf("unexpected status after activation: %+v", status)
	}

	v, ok := readRoot(t, store, "/roles/permits")
	if !ok {
		t.Fatal("expected migrated data at /roles/permits")
	}
	permits, _ := v.([]any)
	if len(permits) != 1 || permits[0] != "read" {
		t.Errorf("unexpected migrated data: %v", v)
	}
}

func TestActivationFailurePreservesRevisionAndPerFileDiagnostics(t *testing.T) {
	ctx := t.Context()
	act, _ := newTestActivation(t)

	good := loadCompressedBundle(t, compressedBundleFiles("r1"))
	if _, err := act.Activate(ctx, activationOpts(good)); err != nil {
		t.Fatalf("activate r1: %v", err)
	}

	// Two modules, each with an undefined function call: the bundle parses
	// but fails to compile, producing a diagnostic per file.
	badFiles := [][2]string{
		{"/.manifest", `{"roots":["roles"],"revision":"r2"}`},
		{"/roles.rego", `package roles

allow if missing_helper([1, 2])
`},
		{"/roles/extra.rego", `package roles

deny if other_missing([3])
`},
		{"/roles/data.json", `{"permits":["write"]}`},
	}
	bad := loadCompressedBundle(t, badFiles)

	report, err := act.Activate(ctx, activationOpts(bad))
	if err == nil {
		t.Fatal("expected activation to fail")
	}
	if report.Err() == nil {
		t.Errorf("expected report.Err() to carry the failure")
	}
	if report.PreviousRevision != "r1" || report.Activated {
		t.Errorf("expected failed activation to keep r1, got %+v", report)
	}

	if findDiagnostic(report, "roles.rego", StageCompile) == nil {
		t.Errorf("expected compile diagnostic for roles.rego: %+v", report.Diagnostics)
	}
	if findDiagnostic(report, "roles/extra.rego", StageCompile) == nil {
		t.Errorf("expected compile diagnostic for roles/extra.rego: %+v", report.Diagnostics)
	}
	for _, d := range report.Diagnostics {
		if d.Stage != StageCompile || d.Row == 0 || d.Message == "" {
			t.Errorf("malformed diagnostic: %+v", d)
		}
	}
	for _, m := range report.Modules {
		if m.Compiled {
			t.Errorf("module %s should not be reported as compiled", m.File)
		}
	}

	// The previous revision, its data and policies remain active.
	if rev := activeRevision(t, act); rev != "r1" {
		t.Errorf("expected active revision r1, got %q", rev)
	}
	v, ok := readRoot(t, act.store, "/roles/permits")
	if !ok {
		t.Fatal("expected previous data to survive failed activation")
	}
	if permits, _ := v.([]any); len(permits) != 1 || permits[0] != "read" {
		t.Errorf("failed activation changed the data: %v", v)
	}

	// Dry-running the same bad bundle yields the same diagnostics without
	// touching the active store.
	report, err = act.DryRun(ctx, activationOpts(bad))
	if err == nil {
		t.Fatal("expected dry-run to fail")
	}
	if findDiagnostic(report, "roles.rego", StageCompile) == nil ||
		findDiagnostic(report, "roles/extra.rego", StageCompile) == nil {
		t.Errorf("expected per-file compile diagnostics: %+v", report.Diagnostics)
	}
	if rev := activeRevision(t, act); rev != "r1" {
		t.Errorf("dry-run changed the active revision: %q", rev)
	}
}

func TestActivationPerFileParseDiagnostics(t *testing.T) {
	ctx := t.Context()
	act, store := newTestActivation(t)

	roots := []string{"roles"}
	b := &Bundle{
		Manifest: Manifest{Revision: "rx", Roots: &roots},
		Data: map[string]any{
			"roles": map[string]any{"permits": []any{"read"}},
		},
		Modules: []ModuleFile{
			{Path: "good.rego", Raw: []byte("package roles.good\n")},
			{Path: "bad.rego", Raw: []byte("package roles.bad\ndefault x :=\n")},
		},
	}

	report, err := act.DryRun(ctx, activationOpts(b))
	if err == nil {
		t.Fatal("expected dry-run to report parse errors")
	}
	if d := findDiagnostic(report, "bad.rego", StageCompile); d == nil || d.Row == 0 {
		t.Errorf("expected parse diagnostic for bad.rego, got %+v", report.Diagnostics)
	}
	for _, m := range report.Modules {
		switch m.File {
		case "good.rego":
			if !m.Parsed || m.Compiled {
				t.Errorf("good module result unexpected: %+v", m)
			}
		case "bad.rego":
			if m.Parsed || m.Compiled {
				t.Errorf("bad module result unexpected: %+v", m)
			}
		default:
			t.Errorf("unexpected module result: %+v", m)
		}
	}

	if _, ok := readRoot(t, store, "/roles"); ok {
		t.Error("dry-run wrote data to the active store")
	}

	if _, err := act.Activate(ctx, activationOpts(b)); err == nil {
		t.Fatal("expected activation to fail")
	}
	if status, _ := act.Status(ctx, testBundleName); status.Active {
		t.Errorf("failed parse activated the bundle: %+v", status)
	}
}

func TestActivationDuplicateRevision(t *testing.T) {
	ctx := t.Context()
	act, _ := newTestActivation(t)

	b1 := loadCompressedBundle(t, compressedBundleFiles("r1"))
	if report, err := act.Activate(ctx, activationOpts(b1)); err != nil || !report.Activated {
		t.Fatalf("first activation: %v %+v", err, report)
	}

	// A different bundle carrying the same revision must be skipped without
	// writing to the store.
	dupFiles := compressedBundleFiles("r1")
	dupFiles[2] = [2]string{"/roles/data.json", `{"permits":["write"]}`}
	dup := loadCompressedBundle(t, dupFiles)

	report, err := act.Activate(ctx, activationOpts(dup))
	if err != nil {
		t.Fatalf("duplicate activation: %v", err)
	}
	if !report.Skipped || report.Activated || report.PreviousRevision != "r1" {
		t.Errorf("expected duplicate revision to be skipped: %+v", report)
	}

	v, _ := readRoot(t, act.store, "/roles/permits")
	if permits, _ := v.([]any); len(permits) != 1 || permits[0] != "read" {
		t.Errorf("skipped activation must not change data, got %v", v)
	}
	if rev := activeRevision(t, act); rev != "r1" {
		t.Errorf("revision changed after skip: %q", rev)
	}

	// Dry-run reports the same skip decision.
	report, err = act.DryRun(ctx, activationOpts(dup))
	if err != nil {
		t.Fatalf("duplicate dry-run: %v", err)
	}
	if !report.Skipped || report.Activated {
		t.Errorf("expected dry-run skip, got %+v", report)
	}
}

func TestActivationConcurrent(t *testing.T) {
	ctx := t.Context()
	act, _ := newTestActivation(t)

	// Seed with r1 so that every subsequent activation has a previous
	// revision to preserve.
	if _, err := act.Activate(ctx, activationOpts(loadCompressedBundle(t, compressedBundleFiles("r1")))); err != nil {
		t.Fatalf("seed activation: %v", err)
	}

	const n = 25

	bundles := make([]*Bundle, n)
	for i := range n {
		revision := fmt.Sprintf("r-%d", i)
		bundles[i] = loadCompressedBundle(t, compressedBundleFiles(revision))
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2*n)
	dryBundle := loadCompressedBundle(t, compressedBundleFiles("dry"))

	// Concurrent activations, each with a distinct revision.
	for i := range n {
		wg.Go(func() {
			<-start
			revision := fmt.Sprintf("r-%d", i)
			report, err := act.Activate(ctx, activationOpts(bundles[i]))
			if err != nil {
				results <- fmt.Errorf("activate %s: %w", revision, err)
				return
			}
			if !report.Activated {
				results <- fmt.Errorf("activate %s not reported as activated: %+v", revision, report)
			}
		})
	}

	// Concurrent dry-runs must always succeed and never write.
	for range n {
		wg.Go(func() {
			<-start
			report, err := act.DryRun(ctx, activationOpts(dryBundle))
			if err != nil {
				results <- fmt.Errorf("dry-run: %w", err)
				return
			}
			if !report.DryRun || report.Skipped {
				results <- fmt.Errorf("unexpected dry-run report: %+v", report)
			}
		})
	}

	close(start)
	wg.Wait()
	close(results)

	for err := range results {
		t.Error(err)
	}

	// The final revision is one of the concurrently committed revisions and
	// the store is internally consistent with it.
	final := activeRevision(t, act)
	found := final == "r1"
	for i := range n {
		if final == fmt.Sprintf("r-%d", i) {
			found = true
		}
	}
	if !found {
		t.Errorf("final revision %q is not one of the activated revisions", final)
	}

	v, ok := readRoot(t, act.store, "/roles/permits")
	if !ok {
		t.Fatal("expected data after concurrent activations")
	}
	if permits, _ := v.([]any); len(permits) != 1 {
		t.Errorf("corrupt data after concurrent activations: %v", v)
	}
}

func TestActivationSignature(t *testing.T) {
	ctx := t.Context()
	act, store := newTestActivation(t)

	b := loadCompressedBundle(t, compressedBundleFiles("r1"))

	// Tampered signature: verification fails before the store is touched.
	bad := *b
	bad.Signatures = SignaturesConfig{Signatures: []string{"not-a-jwt"}}
	report, err := act.DryRun(ctx, &ActivationOpts{
		Name:         testBundleName,
		Bundle:       &bad,
		Verification: NewVerificationConfig(map[string]*KeyConfig{"foo": {Key: "secret", Algorithm: "HS256"}}, "foo", "", nil),
	})
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	if !report.Signature.Signed || report.Signature.Verified {
		t.Errorf("unexpected signature result: %+v", report.Signature)
	}
	if d := findDiagnostic(report, ".signatures.json", StageSignature); d == nil {
		t.Errorf("expected signature diagnostic, got %+v", report.Diagnostics)
	}
	if _, ok := readRoot(t, store, "/roles"); ok {
		t.Error("failed signature verification wrote to the store")
	}

	// Valid HMAC signature over one of the bundle files.
	token, err := GenerateSignedToken([]FileInfo{{Name: "roles.rego"}}, NewSigningConfig("secret", "HS256", ""), "foo")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	signed := *b
	signed.Signatures = SignaturesConfig{Signatures: []string{token}}

	report, err = act.DryRun(ctx, &ActivationOpts{
		Name:         testBundleName,
		Bundle:       &signed,
		Verification: NewVerificationConfig(map[string]*KeyConfig{"foo": {Key: "secret", Algorithm: "HS256"}}, "foo", "", nil),
	})
	if err != nil {
		t.Fatalf("verified dry-run: %v\n%+v", err, report.Diagnostics)
	}
	if !report.Signature.Signed || !report.Signature.Verified {
		t.Errorf("expected verified signature, got %+v", report.Signature)
	}
	if !slices.Contains(report.Signature.Files, "roles.rego") {
		t.Errorf("expected roles.rego in signed files, got %v", report.Signature.Files)
	}
	if _, ok := readRoot(t, store, "/roles"); ok {
		t.Error("dry-run wrote to the store")
	}
}

func TestActivationDefaultRegoVersion(t *testing.T) {
	// An Activation without explicit parser options defaults to Rego v1.
	store := inmem.New()
	act := NewActivation(store)

	b := loadCompressedBundle(t, compressedBundleFiles("r1"))

	report, err := act.DryRun(t.Context(), activationOpts(b))
	if err != nil {
		t.Fatalf("dry-run with default parser options: %v", err)
	}
	if len(report.Diagnostics) != 0 || !report.Activated {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestActivationValidation(t *testing.T) {
	act, _ := newTestActivation(t)
	ctx := t.Context()

	if _, err := act.DryRun(ctx, nil); err == nil {
		t.Error("expected error for nil options")
	}
	if _, err := act.Activate(ctx, &ActivationOpts{Bundle: &Bundle{}}); err == nil {
		t.Error("expected error for empty bundle name")
	}
	if _, err := act.DryRun(ctx, &ActivationOpts{Name: testBundleName}); err == nil {
		t.Error("expected error for nil bundle")
	}
	if _, err := act.Activate(ctx, &ActivationOpts{Name: testBundleName, Bundle: &Bundle{}}); err == nil {
		t.Error("expected error for bundle without manifest roots")
	}

	status, err := act.Status(ctx, testBundleName)
	if err != nil {
		t.Errorf("status of unknown bundle should not error: %v", err)
	}
	if status.Active {
		t.Errorf("unknown bundle should not be active: %+v", status)
	}
}
