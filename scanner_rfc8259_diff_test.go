package zerojwt

import (
	"encoding/json"
	"testing"
)

// TestScanner_RFC8259Differential documents and verifies the differential behavior
// between zerojwt's zero-alloc streaming lexer and Go stdlib's full RFC 8259 parser (encoding/json).
//
// zerojwt's payload scanner is optimized for extreme throughput (~18M ops/s) and zero memory allocations
// on cryptographically authenticated tokens. As such, it intentionally tolerates duplicate or omitted
// commas in payload bodies, whereas unauthenticated header top-level separators are strictly validated against RFC 8259 syntax.
func TestScanner_RFC8259Differential(t *testing.T) {
	t.Run("EquivalentStandardJSON", func(t *testing.T) {
		validJSON := []byte(`{"sub":"user_123","iss":"auth.service","roles":"admin","active":true,"count":42}`)

		// stdlib parsing
		var stdMap map[string]any
		if err := json.Unmarshal(validJSON, &stdMap); err != nil {
			t.Fatalf("stdlib json.Unmarshal failed: %v", err)
		}

		// zerojwt in-place scanner
		body, ok := TrimJSONObject(validJSON)
		if !ok {
			t.Fatal("TrimJSONObject failed on valid JSON")
		}

		zeroMap := make(map[string]string)
		for len(body) > 0 {
			k, v, isStr, rest, ok := NextJSONProp(body)
			if !ok {
				break
			}
			body = rest
			_ = isStr
			zeroMap[string(k)] = string(v)
		}

		if len(zeroMap) != len(stdMap) {
			t.Fatalf("key count mismatch: zerojwt=%d stdlib=%d", len(zeroMap), len(stdMap))
		}
		if zeroMap["sub"] != "user_123" || zeroMap["iss"] != "auth.service" {
			t.Fatalf("claim values mismatch: %v", zeroMap)
		}
	})

	t.Run("DocumentedPayloadTolerancesVsRFC8259", func(t *testing.T) {
		// 1. Duplicate commas: rejected by RFC 8259 (stdlib), accepted by zerojwt payload scanner
		dupCommas := []byte(`{"sub":"user_1",,"user":"alice"}`)
		var m1 map[string]any
		if err := json.Unmarshal(dupCommas, &m1); err == nil {
			t.Fatal("stdlib must reject duplicate commas per RFC 8259")
		}
		body1, ok := TrimJSONObject(dupCommas)
		if !ok {
			t.Fatal("TrimJSONObject failed")
		}
		k1, v1, _, rest1, ok1 := NextJSONProp(body1)
		if !ok1 || string(k1) != "sub" || string(v1) != "user_1" {
			t.Fatalf("zerojwt payload scanner expected to read first prop, got k=%s v=%s", k1, v1)
		}
		k2, v2, _, _, ok2 := NextJSONProp(rest1)
		if !ok2 || string(k2) != "user" || string(v2) != "alice" {
			t.Fatalf("zerojwt payload scanner expected to tolerate duplicate comma, got k=%s v=%s", k2, v2)
		}

		// 2. Missing comma with space: rejected by RFC 8259 (stdlib), tolerated by zerojwt payload scanner
		missingComma := []byte(`{"sub":"user_2" "user":"bob"}`)
		var m2 map[string]any
		if err := json.Unmarshal(missingComma, &m2); err == nil {
			t.Fatal("stdlib must reject missing commas per RFC 8259")
		}
		body2, ok := TrimJSONObject(missingComma)
		if !ok {
			t.Fatal("TrimJSONObject failed")
		}
		k3, _, _, rest2, ok3 := NextJSONProp(body2)
		if !ok3 || string(k3) != "sub" {
			t.Fatalf("zerojwt payload scanner expected to read first prop, got k=%s", k3)
		}
		k4, _, _, _, ok4 := NextJSONProp(rest2)
		if !ok4 || string(k4) != "user" {
			t.Fatalf("zerojwt payload scanner expected to tolerate missing comma, got k=%s", k4)
		}

		// 3. Trailing comma: rejected by RFC 8259 (stdlib), tolerated by zerojwt payload scanner
		trailingComma := []byte(`{"sub":"user_3",}`)
		var m3 map[string]any
		if err := json.Unmarshal(trailingComma, &m3); err == nil {
			t.Fatal("stdlib must reject trailing comma per RFC 8259")
		}
		body3, ok := TrimJSONObject(trailingComma)
		if !ok {
			t.Fatal("TrimJSONObject failed")
		}
		k5, v5, _, _, ok5 := NextJSONProp(body3)
		if !ok5 || string(k5) != "sub" || string(v5) != "user_3" {
			t.Fatalf("zerojwt payload scanner expected to extract sub before trailing comma, got k=%s v=%s", k5, v5)
		}
	})

	t.Run("SurrogatePairsAndEscapeEquivalence", func(t *testing.T) {
		// Unicode surrogate pair: musical symbol G-clef U+1D11E encoded as \uD834\uDD1E
		escapedJSON := []byte(`{"clef":"\uD834\uDD1E","newline":"line1\nline2","quote":"say \"hi\""}`)

		var stdMap map[string]string
		if err := json.Unmarshal(escapedJSON, &stdMap); err != nil {
			t.Fatalf("stdlib json.Unmarshal failed: %v", err)
		}

		body, ok := TrimJSONObject(escapedJSON)
		if !ok {
			t.Fatal("TrimJSONObject failed")
		}

		for len(body) > 0 {
			k, v, isStr, rest, ok := NextJSONProp(body)
			if !ok {
				break
			}
			body = rest
			if isStr {
				unescaped := UnescapeJSONInPlace(append([]byte(nil), v...))
				keyStr := string(k)
				if string(unescaped) != stdMap[keyStr] {
					t.Fatalf("unescaped value mismatch for %s: zerojwt=%q stdlib=%q", keyStr, unescaped, stdMap[keyStr])
				}
			}
		}
	})
}
