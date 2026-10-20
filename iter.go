package zerojwt

import "iter"

// ArrayElements returns an iter.Seq2[[]byte, bool] (element, isString) that traverses
// a raw JSON array (e.g., `["admin", "user"]`) in-place with guaranteed 0 B/op and 0 allocs/op.
// If the array is malformed, iteration terminates gracefully without panic.
func ArrayElements(rawArray []byte) iter.Seq2[[]byte, bool] {
	return func(yield func(elem []byte, isStr bool) bool) {
		body, ok := TrimJSONArray(rawArray)
		if !ok {
			return
		}
		for len(body) > 0 {
			elem, isStr, rest, ok := NextArrayElement(body)
			if !ok {
				return
			}
			body = rest
			if !yield(elem, isStr) {
				return
			}
		}
	}
}

// JSONProp represents a key-value property scanned in-place from a JSON object.
type JSONProp struct {
	Key   []byte
	Val   []byte
	IsStr bool
}

// ObjectProps returns an iter.Seq2[[]byte, []byte] (key, val) that traverses
// a raw JSON object (e.g., `{"role": "admin", "tenant": "acme"}`) in-place
// with guaranteed 0 B/op and 0 allocs/op.
func ObjectProps(rawObject []byte) iter.Seq2[[]byte, []byte] {
	return func(yield func(key, val []byte) bool) {
		body, ok := TrimJSONObject(rawObject)
		if !ok {
			return
		}
		for len(body) > 0 {
			key, val, _, rest, ok := NextJSONProp(body)
			if !ok {
				return
			}
			body = rest
			if !yield(key, val) {
				return
			}
		}
	}
}

// ObjectProperties returns an iter.Seq[JSONProp] that traverses a raw JSON object
// in-place, yielding key, value, and isString type information with 0 B/op and 0 allocs/op.
func ObjectProperties(rawObject []byte) iter.Seq[JSONProp] {
	return func(yield func(prop JSONProp) bool) {
		body, ok := TrimJSONObject(rawObject)
		if !ok {
			return
		}
		for len(body) > 0 {
			key, val, isStr, rest, ok := NextJSONProp(body)
			if !ok {
				return
			}
			body = rest
			if !yield(JSONProp{Key: key, Val: val, IsStr: isStr}) {
				return
			}
		}
	}
}
