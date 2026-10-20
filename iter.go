package zerojwt

import "iter"

// ArrayElements returns an iter.Seq2[[]byte, bool] (element, isString) that traverses
// a raw JSON array (e.g., `["admin", "user"]`) in-place with guaranteed 0 B/op and 0 allocs/op.
// String elements are yielded as slices into the underlying buffer (without outer quotes);
// they remain in their raw escaped form to preserve buffer immutability across multiple passes.
// Call UnescapeJSONInPlace(elem) if unescaped content is needed.
// An optional errOut pointer can be passed to capture any JSON syntax error or truncation;
// if omitted or if nil, iteration terminates without assigning an error.
func ArrayElements(rawArray []byte, errOut ...*error) iter.Seq2[[]byte, bool] {
	return func(yield func(elem []byte, isStr bool) bool) {
		body, ok := TrimJSONArray(rawArray)
		if !ok {
			if len(errOut) > 0 && errOut[0] != nil {
				*errOut[0] = ErrInvalidPayload
			}
			return
		}
		for len(body) > 0 {
			elem, isStr, rest, ok := NextArrayElement(body)
			if !ok {
				if len(errOut) > 0 && errOut[0] != nil {
					*errOut[0] = ErrInvalidPayload
				}
				return
			}
			body = rest
			if !yield(elem, isStr) {
				return
			}
		}
	}
}

// ObjectProps returns an iter.Seq2[[]byte, []byte] (key, val) that traverses
// a raw JSON object (e.g., `{"role": "admin", "tenant": "acme"}`) in-place
// with guaranteed 0 B/op and 0 allocs/op.
// Values remain in their raw escaped form to preserve buffer immutability across multiple passes.
// Call UnescapeJSONInPlace(val) if unescaped content is needed.
// An optional errOut pointer can be passed to capture any JSON syntax error or truncation.
func ObjectProps(rawObject []byte, errOut ...*error) iter.Seq2[[]byte, []byte] {
	return func(yield func(key, val []byte) bool) {
		body, ok := TrimJSONObject(rawObject)
		if !ok {
			if len(errOut) > 0 && errOut[0] != nil {
				*errOut[0] = ErrInvalidPayload
			}
			return
		}
		for len(body) > 0 {
			key, val, _, rest, ok := NextJSONProp(body)
			if !ok {
				if len(errOut) > 0 && errOut[0] != nil {
					*errOut[0] = ErrInvalidPayload
				}
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
// An optional errOut pointer can be passed to capture any JSON syntax error or truncation.
func ObjectProperties(rawObject []byte, errOut ...*error) iter.Seq[JSONProp] {
	return func(yield func(prop JSONProp) bool) {
		body, ok := TrimJSONObject(rawObject)
		if !ok {
			if len(errOut) > 0 && errOut[0] != nil {
				*errOut[0] = ErrInvalidPayload
			}
			return
		}
		for len(body) > 0 {
			key, val, isStr, rest, ok := NextJSONProp(body)
			if !ok {
				if len(errOut) > 0 && errOut[0] != nil {
					*errOut[0] = ErrInvalidPayload
				}
				return
			}
			body = rest
			if !yield(JSONProp{Key: key, Val: val, IsStr: isStr}) {
				return
			}
		}
	}
}
