// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package bundle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/metrics"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/util"
)

// ActivationStage identifies the stage of bundle activation that a
// [FileDiagnostic] was produced by.
type ActivationStage string

const (
	// StageSignature is the JWT signature verification stage.
	StageSignature ActivationStage = "signature"
	// StageCompile is the module parse and compilation stage.
	StageCompile ActivationStage = "compile"
	// StageData is the data migration (store write) stage.
	StageData ActivationStage = "data"
	// StageRoots is the bundle roots overlap check stage.
	StageRoots ActivationStage = "roots"
	// StageManifest is the manifest validation stage.
	StageManifest ActivationStage = "manifest"
)

// FileDiagnostic is a per-file finding collected while dry-running or
// activating a bundle. File is empty when the diagnostic cannot be attributed
// to a single file.
type FileDiagnostic struct {
	File    string          `json:"file,omitempty"`
	Stage   ActivationStage `json:"stage"`
	Message string          `json:"message"`
	Row     int             `json:"row,omitempty"`
	Col     int             `json:"col,omitempty"`
}

// SignatureResult reports the outcome of bundle signature verification.
type SignatureResult struct {
	// Signed reports whether the bundle carried a signatures file.
	Signed bool `json:"signed"`
	// Verified reports whether the signature was cryptographically verified.
	Verified bool `json:"verified"`
	// Files is the set of files covered by the verified signature.
	Files []string `json:"files,omitempty"`
}

// ModuleResult reports the parse and compilation outcome of one module.
type ModuleResult struct {
	File     string `json:"file"`
	Parsed   bool   `json:"parsed"`
	Compiled bool   `json:"compiled"`
}

// DataMigrationResult reports the outcome of migrating bundle data into the
// store. Files is populated for lazily loaded bundles (one entry per data file
// in the archive); Roots lists the roots under which data was found after the
// migration ran.
type DataMigrationResult struct {
	Files []string `json:"files,omitempty"`
	Roots []string `json:"roots,omitempty"`
}

// ActivationReport is the structured result of [Activation.DryRun] or
// [Activation.Activate]. It reports the bundle revision, signature
// verification, per-module compilation and data migration results, together
// with per-file diagnostics for any failures.
type ActivationReport struct {
	// Name is the bundle name the activation was requested for.
	Name string `json:"name"`
	// DryRun is true if the report was produced by a dry-run.
	DryRun bool `json:"dry_run"`
	// Revision is the revision carried by the candidate bundle.
	Revision string `json:"revision"`
	// PreviousRevision is the revision that was active before the attempt.
	// When activation fails, this revision remains active.
	PreviousRevision string `json:"previous_revision"`
	// Signature reports signature verification.
	Signature SignatureResult `json:"signature"`
	// Modules reports per-module parse and compilation results.
	Modules []ModuleResult `json:"modules"`
	// Data reports the data migration result.
	Data DataMigrationResult `json:"data"`
	// Diagnostics holds per-file errors collected while processing the bundle.
	Diagnostics []FileDiagnostic `json:"diagnostics,omitempty"`
	// Activated reports that the bundle was activated (or, for a dry-run,
	// would have been activated).
	Activated bool `json:"activated"`
	// Skipped reports that activation was skipped because the candidate
	// revision was already active.
	Skipped bool `json:"skipped"`

	err error
	// parseFailed is set when one or more modules failed to parse, meaning
	// compilation never ran.
	parseFailed bool
}

// Err returns the error that prevented activation, or nil. The error is also
// returned directly from [Activation.DryRun] and [Activation.Activate].
func (r *ActivationReport) Err() error {
	return r.err
}

// HasDiagnostics reports whether the report contains diagnostics.
func (r *ActivationReport) HasDiagnostics() bool {
	return len(r.Diagnostics) > 0
}

// ActivationOpts are the options for [Activation.DryRun] and
// [Activation.Activate].
type ActivationOpts struct {
	// Name is the bundle name under which the bundle is activated.
	Name string
	// Bundle is the loaded candidate bundle.
	Bundle *Bundle
	// Verification configures signature verification when the bundle is
	// signed. When nil, the default verification config is used.
	Verification *VerificationConfig
	// ExtraModules are additional modules compiled together with the bundle
	// modules (e.g. modules injected by plugins).
	ExtraModules map[string]*ast.Module
	// Metrics optionally captures bundle processing timings.
	Metrics metrics.Metrics
}

// Status is the activation status of a single bundle, as read from the
// bundle metadata in the store.
type Status struct {
	Name     string   `json:"name"`
	Active   bool     `json:"active"`
	Revision string   `json:"revision,omitempty"`
	Roots    []string `json:"roots,omitempty"`
	Etag     string   `json:"etag,omitempty"`
}

// Activation coordinates bundle activation against a single store. It wires
// together bundle loading/verification, the compiler and storage, providing:
//
//   - status reporting for activated bundles ([Activation.Status]),
//   - dry-run validation that never writes to the active store
//     ([Activation.DryRun]), and
//   - serialized, transactional activation that preserves the previously
//     active revision when activation fails ([Activation.Activate]).
//
// An Activation value must not be copied after first use.
type Activation struct {
	store         storage.Store
	parserOptions ast.ParserOptions
	metrics       metrics.Metrics

	// activateMtx serializes Activate calls so that two bundles cannot be
	// activated concurrently; stores (e.g. the in-memory store) typically
	// only permit a single open write transaction at a time.
	activateMtx sync.Mutex
}

// NewActivation returns a new Activation coordinator for store.
func NewActivation(store storage.Store) *Activation {
	return &Activation{store: store}
}

// WithParserOptions sets the parser options used when parsing bundle modules
// that have not been parsed yet. It returns the Activation for convenient
// chaining and must be called before the first DryRun or Activate call.
func (a *Activation) WithParserOptions(opts ast.ParserOptions) *Activation {
	a.parserOptions = opts
	return a
}

// WithMetrics sets the metrics object used when a call does not provide its
// own. It returns the Activation for convenient chaining.
func (a *Activation) WithMetrics(m metrics.Metrics) *Activation {
	a.metrics = m
	return a
}

// Store returns the store the activation coordinator is bound to.
func (a *Activation) Store() storage.Store {
	return a.store
}

// Status returns the activation status of the named bundle. When no bundle
// with that name has been activated, the returned Status has Active set to
// false.
func (a *Activation) Status(ctx context.Context, name string) (Status, error) {
	var status Status

	err := storage.Txn(ctx, a.store, storage.TransactionParams{}, func(txn storage.Transaction) error {
		s, err := a.statusTxn(ctx, txn, name)
		if err != nil {
			return err
		}
		status = s
		return nil
	})

	return status, err
}

// Statuses returns the activation status of every bundle recorded in the
// store, keyed by bundle name.
func (a *Activation) Statuses(ctx context.Context) (map[string]Status, error) {
	statuses := map[string]Status{}

	err := storage.Txn(ctx, a.store, storage.TransactionParams{}, func(txn storage.Transaction) error {
		names, err := ReadBundleNamesFromStore(ctx, a.store, txn)
		if err != nil {
			if storage.IsNotFound(err) {
				return nil
			}
			return err
		}

		for _, name := range names {
			s, err := a.statusTxn(ctx, txn, name)
			if err != nil {
				return err
			}
			statuses[name] = s
		}
		return nil
	})

	return statuses, err
}

// DryRun validates the candidate bundle without modifying the active store.
// The full activation pipeline (signature verification, module compilation
// and data migration) is executed against a throw-away copy of the active
// store; the returned report describes what would happen if the bundle were
// activated.
func (a *Activation) DryRun(ctx context.Context, opts *ActivationOpts) (*ActivationReport, error) {
	if err := validateOpts(opts); err != nil {
		return nil, err
	}

	opts = withDefaults(opts, a.metrics)
	report := newReport(opts, true)

	// Signature verification and parsing do not touch the store and are run
	// before the active store is snapshotted.
	if err := verifyStage(report, opts); err != nil {
		return report, report.fail(err)
	}

	if err := a.parseStage(report, opts); err != nil {
		return report, report.fail(err)
	}

	scratch, err := a.snapshotStore(ctx)
	if err != nil {
		return nil, err
	}

	err = storage.Txn(ctx, scratch, storage.WriteParams, func(txn storage.Transaction) error {
		return a.apply(ctx, opts, scratch, txn, report)
	})

	return report, report.fail(err)
}

// Activate activates the candidate bundle in a single write transaction. The
// call is serialized against other Activate calls on the same coordinator.
// If any stage fails the transaction is aborted, leaving the previously
// active revision in place, and the returned report carries per-file
// diagnostics. When the candidate bundle's revision is already active the
// call is a no-op and the report has Skipped set to true.
func (a *Activation) Activate(ctx context.Context, opts *ActivationOpts) (*ActivationReport, error) {
	if err := validateOpts(opts); err != nil {
		return nil, err
	}

	opts = withDefaults(opts, a.metrics)
	report := newReport(opts, false)

	a.activateMtx.Lock()
	defer a.activateMtx.Unlock()

	// Signature verification and parsing run before opening the write
	// transaction: a bundle that fails either stage cannot be trusted and
	// must not reach the store at all.
	if err := verifyStage(report, opts); err != nil {
		return report, report.fail(err)
	}

	if err := a.parseStage(report, opts); err != nil {
		return report, report.fail(err)
	}

	err := storage.Txn(ctx, a.store, storage.WriteParams, func(txn storage.Transaction) error {
		return a.apply(ctx, opts, a.store, txn, report)
	})

	return report, report.fail(err)
}

// apply runs the authoritative activation against target (the active store
// for Activate and the scratch store for DryRun) inside txn. It assumes the
// signature and parse stages have already run successfully.
func (a *Activation) apply(ctx context.Context, opts *ActivationOpts, target storage.Store, txn storage.Transaction, report *ActivationReport) error {
	if prev, err := ReadBundleRevisionFromStore(ctx, target, txn, opts.Name); err == nil {
		report.PreviousRevision = prev
	} else if suppressNotFound(err) != nil {
		return err
	}

	if rev := opts.Bundle.Manifest.Revision; rev != "" && rev == report.PreviousRevision {
		// The candidate revision is already active: nothing to do. The
		// store is left untouched, keeping the previous revision.
		report.Skipped = true
		return nil
	}

	compiler := ast.NewCompiler().
		WithPathConflictsCheck(storage.NonEmpty(ctx, target, txn))

	if roots := opts.Bundle.Manifest.Roots; roots != nil {
		compiler = compiler.WithPathConflictsCheckRoots(*roots)
	}

	// Normalize the Rego version against the bundle manifest the same way
	// the bundle Reader does, so that modules already in the store are
	// parsed with the expected version when no parser options were given.
	parserOpts := a.parserOptions
	if parserOpts.RegoVersion == ast.RegoUndefined {
		parserOpts.RegoVersion = opts.Bundle.RegoVersion(ast.DefaultRegoVersion)
	}

	activateOpts := &ActivateOpts{
		Ctx:           ctx,
		Store:         target,
		Txn:           txn,
		Compiler:      compiler,
		Metrics:       opts.Metrics,
		Bundles:       map[string]*Bundle{opts.Name: opts.Bundle},
		ExtraModules:  opts.ExtraModules,
		ParserOptions: parserOpts,
	}

	if err := Activate(activateOpts); err != nil {
		report.addActivationError(opts.Bundle, err)
		return err
	}

	report.Activated = true
	report.collectDataRoots(ctx, target, txn, opts.Bundle)

	return nil
}

func (a *Activation) statusTxn(ctx context.Context, txn storage.Transaction, name string) (Status, error) {
	s := Status{Name: name}

	revision, err := ReadBundleRevisionFromStore(ctx, a.store, txn, name)
	if err != nil {
		if storage.IsNotFound(err) {
			return s, nil
		}
		return s, err
	}

	s.Active = true
	s.Revision = revision

	if roots, err := ReadBundleRootsFromStore(ctx, a.store, txn, name); err == nil {
		s.Roots = roots
	} else if suppressNotFound(err) != nil {
		return s, err
	}

	if etag, err := ReadBundleEtagFromStore(ctx, a.store, txn, name); err == nil {
		s.Etag = etag
	} else if suppressNotFound(err) != nil {
		return s, err
	}

	return s, nil
}

// snapshotStore builds a throw-away in-memory store containing a deep copy of
// the active store's current data and policies. It is the target for
// dry-runs so that the active store is never written to.
func (a *Activation) snapshotStore(ctx context.Context) (storage.Store, error) {
	var data map[string]any

	type policy struct {
		id  string
		raw []byte
	}

	var policies []policy

	err := storage.Txn(ctx, a.store, storage.TransactionParams{}, func(txn storage.Transaction) error {
		value, err := read(ctx, a.store, txn, storage.RootPath)
		if err != nil {
			if storage.IsNotFound(err) {
				value = nil
			} else {
				return err
			}
		}

		if value != nil {
			m, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("dry-run snapshot: expected object at store root, got %T", value)
			}
			data = m
			var snapshot any = data
			if err := util.RoundTrip(&snapshot); err != nil {
				return err
			}
			data = snapshot.(map[string]any)
		}

		ids, err := a.store.ListPolicies(ctx, txn)
		if err != nil {
			return err
		}

		policies = make([]policy, 0, len(ids))
		for _, id := range ids {
			raw, err := a.store.GetPolicy(ctx, txn, id)
			if err != nil {
				return err
			}
			policies = append(policies, policy{id: id, raw: raw})
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if data == nil {
		data = map[string]any{}
	}

	scratch := inmem.NewFromObject(data)

	err = storage.Txn(ctx, scratch, storage.WriteParams, func(txn storage.Transaction) error {
		for _, p := range policies {
			if err := scratch.UpsertPolicy(ctx, txn, p.id, p.raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return scratch, nil
}

// verifyStage runs signature verification for a signed bundle.
func verifyStage(report *ActivationReport, opts *ActivationOpts) error {
	if opts.Bundle.Signatures.isEmpty() {
		return nil
	}

	report.Signature.Signed = true

	files, err := VerifyBundleSignature(opts.Bundle.Signatures, opts.Verification)
	if err != nil {
		report.Signature.Verified = false
		report.Diagnostics = append(report.Diagnostics, FileDiagnostic{
			File:    signaturesFilename,
			Stage:   StageSignature,
			Message: err.Error(),
		})
		return err
	}

	report.Signature.Verified = true
	report.Signature.Files = util.KeysSorted(files)

	return nil
}

// parseStage parses any bundle modules that have not already been parsed,
// recording per-module results and per-file diagnostics instead of aborting
// on the first parse error.
func (a *Activation) parseStage(report *ActivationReport, opts *ActivationOpts) error {
	b := opts.Bundle
	popts := a.parserOptions
	bundleRegoVersion := b.RegoVersion(popts.EffectiveRegoVersion())
	popts.RegoVersion = bundleRegoVersion

	var errs []error

	for i := range b.Modules {
		mf := &b.Modules[i]
		file := moduleDisplayName(*mf)

		if mf.Parsed != nil {
			report.Modules = append(report.Modules, ModuleResult{File: file, Parsed: true})
			continue
		}

		mpopts := popts
		versionPath := mf.RelativePath
		if versionPath == "" {
			versionPath = strings.TrimPrefix(filepath.ToSlash(mf.Path), "/")
		}

		if rv, err := b.RegoVersionForFile(versionPath, bundleRegoVersion); err != nil {
			return err
		} else if rv != ast.RegoUndefined {
			mpopts.RegoVersion = rv
		}

		parsed, err := ast.ParseModuleWithOpts(mf.Path, string(mf.Raw), mpopts)
		if err != nil {
			report.parseFailed = true
			report.addASTError(file, err)
			errs = append(errs, err)
		} else {
			b.Modules[i].Parsed = parsed
		}

		report.Modules = append(report.Modules, ModuleResult{File: file, Parsed: err == nil})
	}

	return errors.Join(errs...)
}

// collectDataRoots records the roots under which data exists after the
// activation ran, and the data files carried by lazily loaded bundles.
func (r *ActivationReport) collectDataRoots(ctx context.Context, store storage.Store, txn storage.Transaction, b *Bundle) {
	r.Data.Files = dataFiles(b)

	if b.Manifest.Roots == nil {
		return
	}

	for _, root := range *b.Manifest.Roots {
		path, ok := storage.ParsePathEscaped("/" + root)
		if !ok {
			continue
		}

		if _, err := read(ctx, store, txn, path); err == nil {
			r.Data.Roots = append(r.Data.Roots, root)
		}
	}

	slices.Sort(r.Data.Roots)
}

// addActivationError attributes an activation error to per-file diagnostics.
func (r *ActivationReport) addActivationError(b *Bundle, err error) {
	if astErrs, ok := err.(ast.Errors); ok {
		// Compile errors carry the file name the module was parsed with
		// (ModuleFile.Path), or, for some error codes, the prefixed module
		// key used during compilation. Map both back to the bundle-relative
		// display name.
		fileByName := map[string]string{}
		for _, mf := range b.Modules {
			name := moduleDisplayName(mf)
			fileByName[mf.Path] = name
			fileByName[modulePathWithPrefix(r.Name, mf.Path)] = name
		}

		for _, ae := range astErrs {
			d := FileDiagnostic{Stage: StageCompile, Message: ae.Message}
			if ae.Location != nil {
				d.Row = ae.Location.Row
				d.Col = ae.Location.Col
				d.File = ae.Location.File
			}
			if rel, ok := fileByName[d.File]; ok {
				d.File = rel
			}
			r.Diagnostics = append(r.Diagnostics, d)
		}
		return
	}

	r.Diagnostics = append(r.Diagnostics, FileDiagnostic{
		Stage:   classifyActivationError(err),
		Message: err.Error(),
	})
}

// addASTError attributes a parse error to per-file diagnostics.
func (r *ActivationReport) addASTError(file string, err error) {
	if astErrs, ok := err.(ast.Errors); ok {
		for _, ae := range astErrs {
			d := FileDiagnostic{File: file, Stage: StageCompile, Message: ae.Message}
			if ae.Location != nil {
				d.Row = ae.Location.Row
				d.Col = ae.Location.Col
			}
			r.Diagnostics = append(r.Diagnostics, d)
		}
		return
	}

	r.Diagnostics = append(r.Diagnostics, FileDiagnostic{
		File:    file,
		Stage:   StageCompile,
		Message: err.Error(),
	})
}

func classifyActivationError(err error) ActivationStage {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "overlapping roots"):
		return StageRoots
	case strings.Contains(msg, "delta bundle"):
		return StageManifest
	default:
		// Data writes, path conflicts that do not carry compiler errors,
		// root violations and storage failures all surface during the data
		// migration.
		return StageData
	}
}

// finalize fills derived per-module results once all stages have run.
func (r *ActivationReport) finalizeModules() {
	failed := map[string]bool{}
	compileRan := !r.parseFailed && !r.Skipped

	for _, d := range r.Diagnostics {
		switch d.Stage {
		case StageCompile:
			failed[d.File] = true
		case StageRoots, StageManifest, StageSignature:
			// These checks run before compilation in Activate.
			compileRan = false
		}
	}

	for i := range r.Modules {
		r.Modules[i].Compiled = compileRan && r.Modules[i].Parsed && !failed[r.Modules[i].File]
	}
}

// fail records the activation error on the report.
func (r *ActivationReport) fail(err error) error {
	r.finalizeModules()
	if err != nil {
		r.Activated = false
		r.err = err
	}
	return err
}

func newReport(opts *ActivationOpts, dryRun bool) *ActivationReport {
	return &ActivationReport{
		Name:     opts.Name,
		DryRun:   dryRun,
		Revision: opts.Bundle.Manifest.Revision,
		Data:     DataMigrationResult{Files: dataFiles(opts.Bundle)},
	}
}

func validateOpts(opts *ActivationOpts) error {
	if opts == nil {
		return errors.New("activation options must not be nil")
	}
	if opts.Name == "" {
		return errors.New("activation bundle name must not be empty")
	}
	if opts.Bundle == nil {
		return errors.New("activation bundle must not be nil")
	}
	if opts.Bundle.Manifest.Roots == nil {
		return errors.New("activation bundle manifest roots must not be nil")
	}
	return nil
}

func withDefaults(opts *ActivationOpts, fallback metrics.Metrics) *ActivationOpts {
	cpy := *opts
	if cpy.Metrics == nil {
		if fallback != nil {
			cpy.Metrics = fallback
		} else {
			cpy.Metrics = metrics.New()
		}
	}
	return &cpy
}

func moduleDisplayName(mf ModuleFile) string {
	if mf.RelativePath != "" {
		return strings.TrimPrefix(filepath.ToSlash(mf.RelativePath), "/")
	}
	return strings.TrimPrefix(filepath.ToSlash(mf.Path), "/")
}

func dataFiles(b *Bundle) []string {
	if !b.lazyLoadingMode {
		return nil
	}

	var files []string
	for _, raw := range b.Raw {
		p := filepath.ToSlash(raw.Path)
		if base := filepath.Base(p); base == dataFile || IsYAMLDataFile(p) {
			files = append(files, strings.TrimPrefix(p, "/"))
		}
	}
	slices.Sort(files)
	return files
}
