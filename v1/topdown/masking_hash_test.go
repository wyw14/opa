// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestMaskingHashUnkeyed(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte(`"secret"`))
	expected := hex.EncodeToString(sum[:])

	got, err := MaskingHash("secret", "")
	if err != nil {
		t.Fatal(err)
	}

	if got != expected {
		t.Fatalf("expected %x but got %s", sum, got)
	}
}

func TestMaskingHashKeyed(t *testing.T) {
	t.Parallel()

	mac := hmac.New(sha256.New, []byte("tenant-key"))
	bs, err := json.Marshal("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = mac.Write(bs)
	expected := hex.EncodeToString(mac.Sum(nil))

	got, err := MaskingHash("secret", "tenant-key")
	if err != nil {
		t.Fatal(err)
	}

	if got != expected {
		t.Fatalf("expected %s but got %s", expected, got)
	}

	// An unkeyed hash must differ from a keyed one.
	unkeyed, err := MaskingHash("secret", "")
	if err != nil {
		t.Fatal(err)
	}

	if got == unkeyed {
		t.Fatal("keyed and unkeyed hashes unexpectedly equal")
	}
}

func TestMaskingHashDeterministic(t *testing.T) {
	t.Parallel()

	// Map key order must not affect the digest.
	a := map[string]any{"b": 1, "a": []any{1, 2, 3}}
	b := map[string]any{"a": []any{1, 2, 3}, "b": 1}

	ha, err := MaskingHash(a, "k")
	if err != nil {
		t.Fatal(err)
	}

	hb, err := MaskingHash(b, "k")
	if err != nil {
		t.Fatal(err)
	}

	if ha != hb {
		t.Fatalf("expected stable digest for equal values, got %s and %s", ha, hb)
	}

	// Different inputs must not collide.
	hc, err := MaskingHash(map[string]any{"a": []any{1, 2}}, "k")
	if err != nil {
		t.Fatal(err)
	}

	if ha == hc {
		t.Fatal("expected different digests for different values")
	}
}
