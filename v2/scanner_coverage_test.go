package zerojwt_test

import (
	"bytes"
	"testing"

	zerojwt "github.com/KaikeGM/zerojwt/v2"
)

func TestScannerDeepCoverage(t *testing.T) {
	// 1. NextJSONProp parsing permutations
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"unclosed_key`)); ok {
		t.Fatal("expected false for unclosed string key")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"key"\with_no_colon`)); ok {
		t.Fatal("expected false for key with backslash escaping before colon")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"key": `)); ok {
		t.Fatal("expected false for empty value")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"key": "unclosed_str`)); ok {
		t.Fatal("expected false for unclosed string val")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"key": {"unclosed_obj": 1`)); ok {
		t.Fatal("expected false for unclosed nested object")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"key": ["unclosed_arr", 1`)); ok {
		t.Fatal("expected false for unclosed nested array")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"key": unknown_val`)); ok {
		t.Fatal("expected false for unknown JSON value")
	}

	// Nested object with string containing escaped quotes and braces
	propObj := []byte(`"key": {"sub": "nested \"quote\" and } brace", "n": 10}`)
	if k, v, isStr, rest, ok := zerojwt.NextJSONProp(propObj); !ok || isStr || string(k) != "key" || len(v) == 0 || len(rest) != 0 {
		t.Fatalf("expected valid nested object prop, got ok=%v k=%s v=%s", ok, k, v)
	}

	// Nested array with string containing escaped quotes and brackets
	propArr := []byte(`"key": ["elem1", "elem2 with ] bracket", 42]`)
	if k, v, isStr, rest, ok := zerojwt.NextJSONProp(propArr); !ok || isStr || string(k) != "key" || len(v) == 0 || len(rest) != 0 {
		t.Fatalf("expected valid nested array prop, got ok=%v k=%s v=%s", ok, k, v)
	}

	// Booleans and null in scanJSONValue
	if k, v, isStr, _, ok := zerojwt.NextJSONProp([]byte(`"b": true`)); !ok || isStr || string(v) != "true" || string(k) != "b" {
		t.Fatal("expected boolean true")
	}
	if k, v, isStr, _, ok := zerojwt.NextJSONProp([]byte(`"b": false`)); !ok || isStr || string(v) != "false" || string(k) != "b" {
		t.Fatal("expected boolean false")
	}
	if k, v, isStr, _, ok := zerojwt.NextJSONProp([]byte(`"n": null`)); !ok || isStr || string(v) != "null" || string(k) != "n" {
		t.Fatal("expected null")
	}

	// 2. NextArrayElement edge cases
	if _, _, _, ok := zerojwt.NextArrayElement([]byte("")); ok {
		t.Fatal("expected false for empty NextArrayElement")
	}
	if _, _, _, ok := zerojwt.NextArrayElement([]byte("   ,   ")); ok {
		t.Fatal("expected false for commas NextArrayElement")
	}
	if _, _, _, ok := zerojwt.NextArrayElement([]byte(`"unclosed`)); ok {
		t.Fatal("expected false for unclosed string in NextArrayElement")
	}

	// 3. UnescapeJSONInPlace full sequences
	// Test: \", \\, \/, \b, \f, \n, \r, \t, \u0000..\uFFFF, \uD800\uDC00
	testEsc := []byte(`\"\\\/ \b\f\n\r\t \u0041 \uD83D\uDE00 \u123z \uD800\u0041 \uD800\x \`)
	unesc := zerojwt.UnescapeJSONInPlace(testEsc)
	if !bytes.Contains(unesc, []byte(`"`)) || !bytes.Contains(unesc, []byte(`\`)) || !bytes.Contains(unesc, []byte(`/`)) {
		t.Fatalf("unescape failed to preserve basic escapes: %s", string(unesc))
	}
	if !bytes.Contains(unesc, []byte("\b")) || !bytes.Contains(unesc, []byte("\f")) || !bytes.Contains(unesc, []byte("\n")) {
		t.Fatalf("unescape failed to convert whitespace escapes: %s", string(unesc))
	}
	if !bytes.Contains(unesc, []byte("A")) || !bytes.Contains(unesc, []byte("😀")) {
		t.Fatalf("unescape failed to convert unicode runes: %s", string(unesc))
	}

	// 4. AppendEscapedJSON full control chars (< 0x20) and 8-byte vectorized loops
	var rawWithCtrl []byte
	for c := byte(0); c < 0x20; c++ {
		rawWithCtrl = append(rawWithCtrl, c)
	}
	rawWithCtrl = append(rawWithCtrl, '"', '\\', '/', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j')
	escaped := zerojwt.AppendEscapedJSON(nil, rawWithCtrl)
	if !bytes.Contains(escaped, []byte(`\u0000`)) || !bytes.Contains(escaped, []byte(`\u001f`)) {
		t.Fatalf("AppendEscapedJSON failed to escape control characters: %s", string(escaped))
	}
	if !bytes.Contains(escaped, []byte(`\"`)) || !bytes.Contains(escaped, []byte(`\\`)) {
		t.Fatalf("AppendEscapedJSON failed for quotes and slashes: %s", string(escaped))
	}

	// 5. ParseJSONNumber exponent without +/- sign and edge branches
	if num, ok := zerojwt.ParseJSONNumber([]byte("123e2")); !ok || num != 12300 {
		t.Fatalf("expected 12300, got %v (ok=%v)", num, ok)
	}
	if _, ok := zerojwt.ParseJSONNumber([]byte("123e+")); ok {
		t.Fatal("expected false for lone 123e+")
	}
	if _, ok := zerojwt.ParseJSONNumber([]byte("123e-")); ok {
		t.Fatal("expected false for lone 123e-")
	}

	// 6. JSONProp Value() and IsString() aliases
	prop := zerojwt.JSONProp{Key: []byte("foo"), Val: []byte("bar"), IsStr: true}
	if string(prop.Value()) != "bar" || !prop.IsString() {
		t.Fatalf("unexpected JSONProp helper result: val=%s isStr=%v", prop.Value(), prop.IsString())
	}

	// 7. Scanner strictness and rigor (RFC 8259 number validation and bracket balance)
	// Depth limit 32
	deepObj := bytes.Repeat([]byte(`{"a":`), 35)
	deepObj = append(deepObj, []byte(`1`)...)
	deepObj = append(deepObj, bytes.Repeat([]byte(`}`), 35)...)
	if _, _, _, _, ok := zerojwt.NextJSONProp(deepObj[1 : len(deepObj)-1]); ok {
		t.Fatal("expected false for object nesting > 32")
	}

	deepArr := bytes.Repeat([]byte(`[`), 35)
	deepArr = append(deepArr, []byte(`1`)...)
	deepArr = append(deepArr, bytes.Repeat([]byte(`]`), 35)...)
	if _, _, _, _, ok := zerojwt.NextJSONProp(append([]byte(`"a":`), deepArr...)); ok {
		t.Fatal("expected false for array nesting > 32")
	}

	// Mismatched brackets
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"a": [1}`)); ok {
		t.Fatal("expected false for mismatched bracket [1}")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"a": {"b": 1]`)); ok {
		t.Fatal("expected false for mismatched bracket {1]")
	}

	// Invalid true / false / null literals
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"a": truX`)); ok {
		t.Fatal("expected false for invalid true literal")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"a": falsX`)); ok {
		t.Fatal("expected false for invalid false literal")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"a": nulX`)); ok {
		t.Fatal("expected false for invalid null literal")
	}

	// Number validation: leading zero, incomplete minus, decimal, exponent, trailing garbage
	badNumbers := []string{
		"-", "-a", "01", "00", "1.", "1.a", "1e", "1e+", "1e-", "1ea", "1a",
	}
	for _, badNum := range badNumbers {
		if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"n": ` + badNum)); ok {
			t.Fatalf("expected false for bad number %q", badNum)
		}
	}

	// Multi-digit decimal and exponent in scanJSONValue
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"val": 12.3456`)); !ok {
		t.Fatal("expected ok for multi-digit decimal")
	}
	if _, _, _, _, ok := zerojwt.NextJSONProp([]byte(`"val": 12e345`)); !ok {
		t.Fatal("expected ok for multi-digit exponent")
	}

	// ParseJSONNumber trailing characters check
	if _, ok := zerojwt.ParseJSONNumber([]byte("123abc")); ok {
		t.Fatal("expected false for ParseJSONNumber with trailing chars")
	}
}
