package zerojwt

import (
	"bytes"
	"testing"
)

func TestIterators(t *testing.T) {
	// 1. ArrayElements normal iteration
	rawArr := []byte(`["admin", "editor", 123, true]`)
	var elems [][]byte
	var isStrs []bool
	for elem, isStr := range ArrayElements(rawArr) {
		elems = append(elems, elem)
		isStrs = append(isStrs, isStr)
	}
	if len(elems) != 4 {
		t.Fatalf("expected 4 elements, got %d", len(elems))
	}
	if string(elems[0]) != "admin" || !isStrs[0] {
		t.Fatalf("expected admin string, got %s", elems[0])
	}
	if string(elems[1]) != "editor" || !isStrs[1] {
		t.Fatalf("expected editor string, got %s", elems[1])
	}
	if string(elems[2]) != "123" || isStrs[2] {
		t.Fatalf("expected 123 non-string, got %s", elems[2])
	}
	if string(elems[3]) != "true" || isStrs[3] {
		t.Fatalf("expected true non-string, got %s", elems[3])
	}

	// 2. ArrayElements early break
	count := 0
	for elem := range ArrayElements(rawArr) {
		count++
		if string(elem) == "admin" {
			break
		}
	}
	if count != 1 {
		t.Fatalf("expected early break after 1 element, got %d", count)
	}

	// 3. ArrayElements invalid input
	badArrCount := 0
	for range ArrayElements([]byte("not-an-array")) {
		badArrCount++
	}
	if badArrCount != 0 {
		t.Fatalf("expected 0 elements on invalid array, got %d", badArrCount)
	}

	badElemCount := 0
	for range ArrayElements([]byte(`["admin", "unclosed]`)) {
		badElemCount++
	}
	if badElemCount != 1 {
		t.Fatalf("expected 1 element then abort on broken array, got %d", badElemCount)
	}

	// 4. ObjectProps normal iteration
	rawObj := []byte(`{"sub":"123","role":"admin","active":true}`)
	keys := make(map[string]string)
	for k, v := range ObjectProps(rawObj) {
		keys[string(k)] = string(v)
	}
	if len(keys) != 3 || keys["sub"] != "123" || keys["role"] != "admin" || keys["active"] != "true" {
		t.Fatalf("unexpected ObjectProps result: %v", keys)
	}

	// 5. ObjectProps early break
	kCount := 0
	for range ObjectProps(rawObj) {
		kCount++
		break
	}
	if kCount != 1 {
		t.Fatalf("expected break after 1, got %d", kCount)
	}

	// 6. ObjectProps invalid inputs
	for range ObjectProps([]byte("not-an-obj")) {
		t.Fatal("expected no iteration on invalid object")
	}
	brokenObjCount := 0
	for range ObjectProps([]byte(`{"k1":"v1", "unclosed}`)) {
		brokenObjCount++
	}
	if brokenObjCount != 1 {
		t.Fatalf("expected 1 prop then abort on broken object, got %d", brokenObjCount)
	}

	// 7. ObjectProperties (full struct yielding)
	propCount := 0
	for p := range ObjectProperties(rawObj) {
		propCount++
		if bytes.Equal(p.Key, []byte("sub")) && !p.IsStr {
			t.Fatalf("expected sub to be string")
		}
	}
	if propCount != 3 {
		t.Fatalf("expected 3 properties, got %d", propCount)
	}

	// 8. ObjectProperties early break & error branches
	for range ObjectProperties(rawObj) {
		break
	}
	for range ObjectProperties([]byte("invalid")) {
		t.Fatal("expected no iteration")
	}
	brokenPropsCount := 0
	for range ObjectProperties([]byte(`{"k1":"v1", "unclosed}`)) {
		brokenPropsCount++
	}
	if brokenPropsCount != 1 {
		t.Fatalf("expected 1 prop then abort on broken object, got %d", brokenPropsCount)
	}
}

func TestIteratorZeroAllocs(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("skipping allocation check under race detector")
	}
	rawArr := []byte(`["admin", "user", "billing", "auditor"]`)
	rawObj := []byte(`{"sub":"123","tenant":"acme","role":"admin"}`)

	arrAllocs := testing.AllocsPerRun(1000, func() {
		var found bool
		for elem, isStr := range ArrayElements(rawArr) {
			if isStr && bytes.Equal(elem, []byte("billing")) {
				found = true
				break
			}
		}
		_ = found
	})
	if arrAllocs != 0 {
		t.Fatalf("expected 0 allocs/op in ArrayElements iterator, got %v", arrAllocs)
	}

	objAllocs := testing.AllocsPerRun(1000, func() {
		var sub []byte
		for k, v := range ObjectProps(rawObj) {
			if bytes.Equal(k, []byte("tenant")) {
				sub = v
				break
			}
		}
		_ = sub
	})
	if objAllocs != 0 {
		t.Fatalf("expected 0 allocs/op in ObjectProps iterator, got %v", objAllocs)
	}

	propAllocs := testing.AllocsPerRun(1000, func() {
		var cnt int
		for p := range ObjectProperties(rawObj) {
			if p.IsStr {
				cnt++
			}
		}
		_ = cnt
	})
	if propAllocs != 0 {
		t.Fatalf("expected 0 allocs/op in ObjectProperties iterator, got %v", propAllocs)
	}
}
