// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package bundle

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/internal/file/archive"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func TestRead_DefaultRegoVersion(t *testing.T) {
	tests := []struct {
		note    string
		module  string
		expErrs []string
	}{
		{
			note: "v0", // v0 is the default rego-version
			module: `package example

p[x] {
	x := "a"
}`,
		},
		{
			note: "rego.v1 import",
			module: `package example
import rego.v1

p contains x if {
	x := "a"
}`,
		},
		{
			note: "v1",
			module: `package example

p contains x if {
	x := "a"
}`,
			expErrs: []string{
				"test.rego:3: rego_parse_error: var cannot be used for rule name",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			module := tc.module
			files := [][2]string{
				{"test.rego", module},
			}

			buf := archive.MustWriteTarGz(files)
			loader := NewTarballLoaderWithBaseURL(buf, "")
			br := NewCustomReader(loader)

			bundle, err := br.Read()

			if len(tc.expErrs) > 0 {
				if err == nil {
					t.Fatalf("Expected error(s):\n\n%v\n\nbut got nil", tc.expErrs)
				}

				for _, expErr := range tc.expErrs {
					if !strings.Contains(err.Error(), expErr) {
						t.Fatalf("Expected error:\n\n%s\n\nbut got:\n\n%s", expErr, err)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %s", err)
				}

				if len(bundle.Modules) != 1 {
					t.Fatalf("expected 1 module but got %d", len(bundle.Modules))
				}
			}
		})
	}
}

func TestActivationWrapper(t *testing.T) {
	ctx := t.Context()

	files := [][2]string{
		{"/.manifest", `{"roots":["roles"],"revision":"r1"}`},
		{"/roles.rego", "package roles\n\nallow = true\n"},
		{"/roles/data.json", `{"permits":["read"]}`},
	}

	b, err := NewCustomReader(NewTarballLoader(archive.MustWriteTarGz(files))).Read()
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	store := inmem.New()
	act := NewActivation(store) // defaults to the package's default (v0) Rego version

	report, err := act.DryRun(ctx, &ActivationOpts{Name: "test", Bundle: &b})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !report.Activated || report.Skipped || len(report.Diagnostics) != 0 {
		t.Fatalf("unexpected dry-run report: %+v", report)
	}

	// The dry-run must not have written to the active store.
	txn := storage.NewTransactionOrDie(ctx, store)
	if values, err := store.Read(ctx, txn, storage.MustParsePath("/roles")); !storage.IsNotFound(err) {
		t.Fatalf("dry-run wrote to the active store: %v (err: %v)", values, err)
	}
	store.Abort(ctx, txn)

	if report, err = act.Activate(ctx, &ActivationOpts{Name: "test", Bundle: &b}); err != nil {
		t.Fatalf("activate: %v", err)
	} else if !report.Activated || report.Revision != "r1" {
		t.Fatalf("unexpected activation report: %+v", report)
	}

	status, err := act.Status(ctx, "test")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Active || status.Revision != "r1" {
		t.Fatalf("unexpected status: %+v", status)
	}

	// Activating the same revision again is a no-op.
	if report, err := act.Activate(ctx, &ActivationOpts{Name: "test", Bundle: &b}); err != nil || !report.Skipped {
		t.Fatalf("expected duplicate revision skip, got %+v, %v", report, err)
	}
}
