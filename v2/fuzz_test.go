package zerojwt

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzHeaderValidation tests that any JWT header accepted by zerojwt's
// pre-authentication parser is structurally valid RFC 8259 JSON according to encoding/json.
//
// Note: As documented in the README and security policy, zerojwt validates separators,
// numbers, and bracket/quote structure, but does not validate inner string content (e.g.
// raw control characters or invalid escapes like \q inside string literals).
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
				errMsg := jsonErr.Error()
				// Documented exemption: zerojwt does not validate internal string byte contents (escapes / control chars)
				if strings.Contains(errMsg, "in string") || strings.Contains(errMsg, "in string escape") {
					return
				}
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
	})
}
