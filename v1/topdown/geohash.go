// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"math"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
)

const (
	geoHashAlphabet     = "0123456789bcdefghjkmnpqrstuvwxyz"
	geoHashMinPrecision = 1
	geoHashMaxPrecision = 12
)

// geoHashAlphabetIndex maps geohash characters to their 5-bit value; entries
// for characters outside of the geohash alphabet are -1.
var geoHashAlphabetIndex = func() [256]int8 {
	var index [256]int8
	for i := range index {
		index[i] = -1
	}
	for i := 0; i < len(geoHashAlphabet); i++ {
		index[geoHashAlphabet[i]] = int8(i)
	}
	return index
}()

// geoHashBox is the axis-aligned grid cell denoted by a geohash. The latitude
// interval is [lat[0], lat[1]] (south/north) and the longitude interval is
// [lon[0], lon[1]] (west/east).
type geoHashBox struct {
	lat [2]float64
	lon [2]float64
}

func builtinGeoHashEncode(_ BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	lat, err := geoHashCoordinateOperand(operands[0].Value, 1, "latitude", -90, 90, true)
	if err != nil {
		return err
	}

	lon, err := geoHashCoordinateOperand(operands[1].Value, 2, "longitude", -180, 180, false)
	if err != nil {
		return err
	}

	precision, err := builtins.IntOperand(operands[2].Value, 3)
	if err != nil {
		return err
	}

	if precision < geoHashMinPrecision || precision > geoHashMaxPrecision {
		return builtins.NewOperandErr(3, "geohash precision must be an integer between %d and %d but got %v",
			geoHashMinPrecision, geoHashMaxPrecision, precision)
	}

	return iter(ast.StringTerm(geoHashEncode(lat, lon, precision)))
}

func builtinGeoHashDecode(_ BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	hash, err := builtins.StringOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	box, err := geoHashDecode(string(hash))
	if err != nil {
		return err
	}

	result := ast.NewObject()
	result.Insert(ast.StringTerm("lat"), ast.FloatNumberTerm((box.lat[0]+box.lat[1])/2))
	result.Insert(ast.StringTerm("lon"), ast.FloatNumberTerm((box.lon[0]+box.lon[1])/2))
	result.Insert(ast.StringTerm("north"), ast.FloatNumberTerm(box.lat[1]))
	result.Insert(ast.StringTerm("east"), ast.FloatNumberTerm(box.lon[1]))
	result.Insert(ast.StringTerm("south"), ast.FloatNumberTerm(box.lat[0]))
	result.Insert(ast.StringTerm("west"), ast.FloatNumberTerm(box.lon[0]))

	return iter(ast.NewTerm(result))
}

// geoHashEncode returns the geohash of the given coordinate, alternating
// longitude/latitude bisections (starting with longitude) and emitting one
// character for every 5 bits. A coordinate equal to a bisection midpoint is
// assigned to the upper half.
func geoHashEncode(lat, lon float64, precision int) string {
	var buf strings.Builder
	buf.Grow(precision)

	box := geoHashBox{
		lat: [2]float64{-90, 90},
		lon: [2]float64{-180, 180},
	}

	bit := 0
	code := 0
	longitudeTurn := true

	for buf.Len() < precision {
		if longitudeTurn {
			mid := (box.lon[0] + box.lon[1]) / 2
			if lon >= mid {
				code = code<<1 | 1
				box.lon[0] = mid
			} else {
				code <<= 1
				box.lon[1] = mid
			}
		} else {
			mid := (box.lat[0] + box.lat[1]) / 2
			if lat >= mid {
				code = code<<1 | 1
				box.lat[0] = mid
			} else {
				code <<= 1
				box.lat[1] = mid
			}
		}

		longitudeTurn = !longitudeTurn
		bit++

		if bit == 5 {
			buf.WriteByte(geoHashAlphabet[code])
			code = 0
			bit = 0
		}
	}

	return buf.String()
}

// geoHashDecode narrows the latitude/longitude intervals according to the 5-bit
// value of each character of hash, in the same order as geoHashEncode.
func geoHashDecode(hash string) (geoHashBox, error) {
	if hash == "" {
		return geoHashBox{}, builtins.NewOperandErr(1, "geohash must be a non-empty string")
	}

	box := geoHashBox{
		lat: [2]float64{-90, 90},
		lon: [2]float64{-180, 180},
	}

	longitudeTurn := true

	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if geoHashAlphabetIndex[c] < 0 {
			return geoHashBox{}, builtins.NewOperandErr(1, "geohash contains invalid character %q", string(c))
		}

		code := int(geoHashAlphabetIndex[c])

		for bit := 4; bit >= 0; bit-- {
			upper := code&(1<<uint(bit)) != 0

			if longitudeTurn {
				mid := (box.lon[0] + box.lon[1]) / 2
				if upper {
					box.lon[0] = mid
				} else {
					box.lon[1] = mid
				}
			} else {
				mid := (box.lat[0] + box.lat[1]) / 2
				if upper {
					box.lat[0] = mid
				} else {
					box.lat[1] = mid
				}
			}

			longitudeTurn = !longitudeTurn
		}
	}

	return box, nil
}

// geoHashCoordinateOperand validates that x is a finite number within the
// given range. maxInclusive controls whether the upper bound is part of the
// valid range (longitude is bounded by [-180, 180)).
func geoHashCoordinateOperand(x ast.Value, pos int, name string, min, max float64, maxInclusive bool) (float64, error) {
	n, err := builtins.NumberOperand(x, pos)
	if err != nil {
		return 0, err
	}

	v, ok := n.Float64()
	if !ok {
		return 0, builtins.NewOperandErr(pos, "%s must be a finite number but got %v", name, n)
	}

	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, builtins.NewOperandErr(pos, "%s must be a finite number but got %v", name, v)
	}

	if v < min || v > max || (!maxInclusive && v == max) {
		if maxInclusive {
			return 0, builtins.NewOperandErr(pos, "%s must be between %v and %v but got %v", name, min, max, v)
		}

		return 0, builtins.NewOperandErr(pos, "%s must be greater than or equal to %v and less than %v but got %v",
			name, min, max, v)
	}

	return v, nil
}

func init() {
	RegisterBuiltinFunc(ast.GeoHashEncode.Name, builtinGeoHashEncode)
	RegisterBuiltinFunc(ast.GeoHashDecode.Name, builtinGeoHashDecode)
}
