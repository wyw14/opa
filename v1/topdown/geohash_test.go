// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"strconv"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

func TestGeoHashEncodeBuiltin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		note     string
		rule     string
		expected string
	}{
		{
			note:     "classic vector",
			rule:     `p = x { geohash.encode(37.8324, 112.5584, 9, x) }`,
			expected: `"ww8p1r4t8"`,
		},
		{
			note:     "11-character vector",
			rule:     `p = x { geohash.encode(57.64911, 10.40744, 11, x) }`,
			expected: `"u4pruydqqvj"`,
		},
		{
			note:     "origin, midpoints are assigned to the upper half",
			rule:     `p = x { geohash.encode(0, 0, 6, x) }`,
			expected: `"s00000"`,
		},
		{
			note:     "south-western corner is all zeros",
			rule:     `p = x { geohash.encode(-90, -180, 12, x) }`,
			expected: `"000000000000"`,
		},
		{
			note:     "longitude -180 is included",
			rule:     `p = x { geohash.encode(0, -180, 1, x) }`,
			expected: `"8"`,
		},
		{
			note:     "latitude 90 is included",
			rule:     `p = x { geohash.encode(90, 0, 1, x) }`,
			expected: `"u"`,
		},
	}

	for _, tc := range tests {
		runTopDownTestCase(t, map[string]any{}, tc.note, []string{tc.rule}, tc.expected)
	}
}

func TestGeoHashDecodeBuiltin(t *testing.T) {
	t.Parallel()

	// decode("ezs42") denotes the cell centered on 42.60498046875/-5.60302734375.
	rules := []string{`
p {
	d := geohash.decode("ezs42")
	d.lat == 42.60498046875
	d.lon == -5.60302734375
	d.north == 42.626953125
	d.south == 42.5830078125
	d.east == -5.5810546875
	d.west == -5.625
	geohash.encode(d.lat, d.lon, 5) == "ezs42"
}`}

	runTopDownTestCase(t, map[string]any{}, "center and bounds, center re-encodes", rules, "true")
}

func TestGeoHashEncodeDecodeRoundtrip(t *testing.T) {
	t.Parallel()

	coords := [][2]float64{
		{0, 0},
		{37.8324, 112.5584},
		{-33.8688, 151.2093},
		{51.5074, -0.1278},
		{-90, -180},
		{90, 179.999999},
		{89.999999, -179.999999},
	}

	for _, c := range coords {
		for precision := 1; precision <= geoHashMaxPrecision; precision++ {
			hash := geoHashEncode(c[0], c[1], precision)
			if len(hash) != precision {
				t.Fatalf("expected hash of length %d but got %q", precision, hash)
			}

			box, err := geoHashDecode(hash)
			if err != nil {
				t.Fatalf("unexpected error decoding %q: %v", hash, err)
			}

			lat := (box.lat[0] + box.lat[1]) / 2
			lon := (box.lon[0] + box.lon[1]) / 2

			if !(box.lat[0] <= lat && lat <= box.lat[1]) || !(box.lon[0] <= lon && lon <= box.lon[1]) {
				t.Fatalf("center %v/%v outside cell bounds %v for hash %q", lat, lon, box, hash)
			}

			if got := geoHashEncode(lat, lon, precision); got != hash {
				t.Fatalf("center of %q re-encoded to %q", hash, got)
			}

			if precision > 1 {
				if prefix := geoHashEncode(c[0], c[1], precision-1); hash[:precision-1] != prefix {
					t.Fatalf("expected %q to be prefixed by %q", hash, prefix)
				}
			}
		}
	}
}

func TestGeoHashEncodeBuiltinErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		note    string
		rule    string
		message string
	}{
		{
			note:    "latitude too large",
			rule:    `p = x { geohash.encode(91, 0, 6, x) }`,
			message: "geohash.encode: operand 1 latitude must be between -90 and 90 but got 91",
		},
		{
			note:    "latitude too small",
			rule:    `p = x { geohash.encode(-90.1, 0, 6, x) }`,
			message: "geohash.encode: operand 1 latitude must be between -90 and 90 but got -90.1",
		},
		{
			note:    "longitude 180 is excluded",
			rule:    `p = x { geohash.encode(0, 180, 6, x) }`,
			message: "geohash.encode: operand 2 longitude must be greater than or equal to -180 and less than 180 but got 180",
		},
		{
			note:    "longitude too small",
			rule:    `p = x { geohash.encode(0, -180.1, 6, x) }`,
			message: "geohash.encode: operand 2 longitude must be greater than or equal to -180 and less than 180 but got -180.1",
		},
		{
			note:    "precision zero",
			rule:    `p = x { geohash.encode(0, 0, 0, x) }`,
			message: "geohash.encode: operand 3 geohash precision must be an integer between 1 and 12 but got 0",
		},
		{
			note:    "precision too large",
			rule:    `p = x { geohash.encode(0, 0, 13, x) }`,
			message: "geohash.encode: operand 3 geohash precision must be an integer between 1 and 12 but got 13",
		},
		{
			note:    "precision must be integer",
			rule:    `p = x { geohash.encode(0, 0, 1.5, x) }`,
			message: "geohash.encode: operand 3 must be integer number but got floating-point number",
		},
	}

	for _, tc := range tests {
		runTopDownTestCase(t, map[string]any{}, tc.note, []string{tc.rule},
			&Error{Code: TypeErr, Message: tc.message})
	}

	// Without strict built-in errors, invalid calls are undefined rather than errors.
	runTopDownTestCase(t, map[string]any{}, "invalid coordinate is undefined by default",
		[]string{`p = x { geohash.encode(200, 0, 6, x) }`}, "")
}

func TestGeoHashEncodeOperandValidation(t *testing.T) {
	t.Parallel()

	operands := func(lat ast.Value) []*ast.Term {
		return []*ast.Term{
			ast.NewTerm(lat),
			ast.FloatNumberTerm(0),
			ast.InternedTerm(6),
		}
	}

	if err := builtinGeoHashEncode(BuiltinContext{}, operands(ast.FloatNumberTerm(0).Value), noOpIter); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Numbers whose magnitude cannot be represented as a finite float64
	// must be rejected.
	if err := builtinGeoHashEncode(BuiltinContext{}, operands(ast.Number("1e99999")), noOpIter); err == nil {
		t.Fatal("expected error for non-finite coordinate")
	}

	for _, pos := range []int{1, 2, 3} {
		ops := []*ast.Term{
			ast.FloatNumberTerm(0),
			ast.FloatNumberTerm(0),
			ast.InternedTerm(6),
		}
		ops[pos-1] = ast.InternedTerm("0")

		err := builtinGeoHashEncode(BuiltinContext{}, ops, noOpIter)
		if err == nil {
			t.Fatalf("expected type error for operand %d", pos)
		}
		if expected := "operand " + strconv.Itoa(pos) + " must be number but got string"; err.Error() != expected {
			t.Fatalf("expected %q but got %q", expected, err.Error())
		}
	}

	if err := builtinGeoHashDecode(BuiltinContext{},
		[]*ast.Term{ast.InternedTerm(42)}, noOpIter); err == nil {
		t.Fatal("expected type error for decode operand")
	} else if err.Error() != "operand 1 must be string but got number" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGeoHashDecodeBuiltinErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		note    string
		rule    string
		message string
	}{
		{
			note:    "empty string",
			rule:    `p = x { geohash.decode("", x) }`,
			message: "geohash.decode: operand 1 geohash must be a non-empty string",
		},
		{
			note:    "invalid character a",
			rule:    `p = x { geohash.decode("a", x) }`,
			message: "geohash.decode: operand 1 geohash contains invalid character \"a\"",
		},
		{
			note:    "invalid character i",
			rule:    `p = x { geohash.decode("ezsi2", x) }`,
			message: "geohash.decode: operand 1 geohash contains invalid character \"i\"",
		},
		{
			note:    "invalid character o",
			rule:    `p = x { geohash.decode("oz", x) }`,
			message: "geohash.decode: operand 1 geohash contains invalid character \"o\"",
		},
		{
			note:    "invalid character l",
			rule:    `p = x { geohash.decode("l0", x) }`,
			message: "geohash.decode: operand 1 geohash contains invalid character \"l\"",
		},
		{
			note:    "uppercase character",
			rule:    `p = x { geohash.decode("EZS42", x) }`,
			message: "geohash.decode: operand 1 geohash contains invalid character \"E\"",
		},
	}

	for _, tc := range tests {
		runTopDownTestCase(t, map[string]any{}, tc.note, []string{tc.rule},
			&Error{Code: TypeErr, Message: tc.message})
	}

	// Without strict built-in errors, invalid calls are undefined rather than errors.
	runTopDownTestCase(t, map[string]any{}, "invalid hash is undefined by default",
		[]string{`p = x { geohash.decode("a", x) }`}, "")
}
