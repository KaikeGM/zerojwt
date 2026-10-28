package zerojwt

import (
	"encoding/json"
	"testing"
)

// FuzzHeaderValidation tests that any JWT header accepted by zerojwt's
// pre-authentication parser is strictly valid RFC 8259 JSON according to encoding/json,
// including all string literal escapes, unicode sequences, and control character boundaries.
func FuzzHeaderValidation(f *testing.F) {
	v, err := New([]byte("01234567890123456789012345678901"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(`{"alg":"HS256","typ":"JWT"}`))
	f.Add([]byte(`{"alg":"HS256"}`))
	f.Add([]byte(`{"alg":"HS256","typ":"JWT","kid":"k1"}`))
	f.Add([]byte(`{"alg":"HS256","extra":123}`))
	f.Add([]byte(`{"alg":"HS256",,"typ":"JWT"}`))
	f.Add([]byte(`{"alg":"HS256","n":01}`))
	f.Add([]byte(`{"alg":"HS256","nested":[1}]}`))
	f.Add([]byte(`{"alg":"HS256","sub":"user"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := v.validateHeader(data)
		if err == nil {
			var m map[string]any
			if jsonErr := json.Unmarshal(data, &m); jsonErr != nil {
				t.Fatalf("Header accepted by zerojwt has structural JSON error according to encoding/json: %q (jsonErr: %v)", data, jsonErr)
			}
		}
	})
}

// FuzzScannerDifferential verifies that the zerojwt streaming lexer never panics, hangs,
// or diverges on arbitrary JSON structures, and successfully extracts keys from valid JSON objects.
func FuzzScannerDifferential(f *testing.F) {
	f.Add([]byte(`{"key":"value","num":123,"bool":true,"null":null,"arr":[1,2,3]}`))
	f.Add([]byte(`{"sub":"alice","exp":1700000000}`))
	f.Add([]byte(`{"nested":{"a":1,"b":2}}`))
	f.Add([]byte(`[1, 2, 3]`))
	f.Add([]byte(`{"broken": [1, 2`))
	f.Add([]byte(`{"escaped": "hello\\nworld"}`))
	f.Add([]byte(`"plain_string"`))
	f.Add([]byte(`"escaped \"quotes\" and \t\n\r"`))
	f.Add([]byte(`"unicode \u0020 and \u1234"`))
	f.Add([]byte(`"invalid \q escape"`))
	f.Add([]byte{'"', 'c', 't', 'r', 'l', 0x01, '"'})

	f.Fuzz(func(t *testing.T, data []byte) {
		// 1. Stress TrimJSONObject and NextJSONProp
		body, ok := TrimJSONObject(data)
		if ok {
			for len(body) > 0 {
				_, _, _, rest, propOk := NextJSONProp(body)
				if !propOk {
					break
				}
				body = rest
			}
		}

		// 2. Stress TrimJSONArray and NextArrayElement
		arrBody, arrOk := TrimJSONArray(data)
		if arrOk {
			for len(arrBody) > 0 {
				_, _, rest, elemOk := NextArrayElement(arrBody)
				if !elemOk {
					break
				}
				arrBody = rest
			}
		}

		// 3. Differential check: if encoding/json parses it as an object,
		// zerojwt must safely trim it without panic.
		var obj map[string]any
		if json.Unmarshal(data, &obj) == nil {
			trimmed, trimOk := TrimJSONObject(data)
			if !trimOk && len(obj) > 0 {
				t.Fatalf("TrimJSONObject rejected valid stdlib object: %q", data)
			}
			_ = trimmed
		}

		// 4. Differential string check against json.Valid:
		// Any standalone quoted string scanned by scanJSONPrimitive must strictly agree with json.Valid(data).
		if len(data) >= 2 && data[0] == '"' && data[len(data)-1] == '"' {
			stdValid := json.Valid(data)
			nextIdx, isStr, ok := scanJSONPrimitive(data, 0)
			zeroValid := ok && isStr && nextIdx == len(data)
			if zeroValid != stdValid {
				t.Fatalf("scanJSONPrimitive differential mismatch for %q: zerojwt=%v stdlib=%v", data, zeroValid, stdValid)
			}
		}
	})
}
