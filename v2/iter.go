package zerojwt

import "iter"

// ArrayElements returns an iter.Seq2[[]byte, bool] (element, isString) that traverses
// a raw JSON array (e.g. `["admin", "user"]`) in-place with guaranteed 0 B/op and 0 allocs/op.
// String elements are yielded as slices into the underlying buffer (without outer quotes);
// they remain in raw form to preserve buffer immutability across multiple passes.
// Call UnescapeJSONInPlace(elem) if unescaped content is needed.
// An optional errOut pointer can be passed to capture any JSON syntax error or truncation.
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
// a raw JSON object (e.g. `{"role": "admin", "tenant": "acme"}`) in-place
// with guaranteed 0 B/op and 0 allocs/op.
// Values remain in raw form to preserve buffer immutability across multiple passes.
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

// IterWithScratch is identical to Iter but uses a caller-supplied Scratch state.
// It guarantees 0 B/op and 0 allocs/op across all Go versions (Go 1.23+).
func (v *Verifier) IterWithScratch(tok []byte, now int64, st *Scratch) iter.Seq2[JSONProp, error] {
	return func(yield func(JSONProp, error) bool) {
		plBytes, err := v.verifySignatureAndDecodePayload(tok, st)
		if err != nil {
			yield(JSONProp{}, err)
			return
		}

		body, ok := TrimJSONObject(plBytes)
		if !ok {
			yield(JSONProp{}, ErrInvalidPayload)
			return
		}

		// Pass 1: Atomic cryptographic & claim validation
		if err := v.validatePayloadClaims(body, now); err != nil {
			yield(JSONProp{}, err)
			return
		}

		// Pass 2: Token is 100% valid; yield verified claims
		body, _ = TrimJSONObject(plBytes)
		for len(body) > 0 {
			key, val, isStr, rest, _ := NextJSONProp(body)
			body = rest
			if !yield(JSONProp{Key: key, Val: val, IsStr: isStr}, nil) {
				return
			}
		}
	}
}

// Iter returns an iterator yielding each verified claim (JSONProp) in the token,
// or an error if verification or validation fails.
//
// Verification is atomic: if the token is not authentic or fails any validation rule,
// the error is yielded once and iteration terminates immediately without yielding claims.
//
// Allocation note: Iter achieves 0 B/op and 0 allocs/op on Go 1.24+ (and ~3 allocs/op on
// Go 1.23 due to compiler closure escape differences). For guaranteed zero allocations on
// all Go versions (Go 1.23+), use IterWithScratch with a reusable *Scratch.
//
// Panic note: Iter intentionally avoids defer to keep the critical loop zero-alloc on Go 1.24+.
// If the caller's iteration loop panics, the leased scratch is abandoned to the garbage collector
// rather than returned to sync.Pool, and with ZeroMemory enabled, claims memory in that scratch
// is not zeroed.
func (v *Verifier) Iter(tok []byte, now int64) iter.Seq2[JSONProp, error] {
	return func(yield func(JSONProp, error) bool) {
		st := v.acquireScratch()
		v.IterWithScratch(tok, now, st)(yield)
		v.releaseScratch(st)
	}
}

// IterSplit returns an iterator yielding each verified claim (JSONProp) in a token
// split across non-contiguous head and tail byte slices (such as circular ring buffers),
// or an error if verification or validation fails.
//
// Verification is atomic: if the token is not authentic or fails any validation rule,
// the error is yielded once and iteration terminates immediately without yielding claims.
//
// Allocation note: IterSplit achieves 0 B/op and 0 allocs/op on Go 1.24+ (and ~3 allocs/op on
// Go 1.23 due to compiler closure escape differences). For guaranteed zero allocations on
// all Go versions (Go 1.23+), use IterSplitWithScratch with a reusable *Scratch.
//
// Panic note: IterSplit intentionally avoids defer to keep the critical loop zero-alloc on Go 1.24+.
// If the caller's iteration loop panics, the leased scratch is abandoned to the garbage collector
// rather than returned to sync.Pool, and with ZeroMemory enabled, claims memory in that scratch
// is not zeroed.
func (v *Verifier) IterSplit(head, tail []byte, now int64) iter.Seq2[JSONProp, error] {
	return func(yield func(JSONProp, error) bool) {
		st := v.acquireScratch()
		v.IterSplitWithScratch(head, tail, now, st)(yield)
		v.releaseScratch(st)
	}
}

// IterSplitWithScratch is identical to IterSplit but uses a caller-supplied Scratch state.
// It guarantees 0 B/op and 0 allocs/op across all Go versions (Go 1.23+).
func (v *Verifier) IterSplitWithScratch(head, tail []byte, now int64, st *Scratch) iter.Seq2[JSONProp, error] {
	return func(yield func(JSONProp, error) bool) {
		var (
			plBytes []byte
			err     error
		)
		if len(head) == 0 {
			plBytes, err = v.verifySignatureAndDecodePayload(tail, st)
		} else if len(tail) == 0 {
			plBytes, err = v.verifySignatureAndDecodePayload(head, st)
		} else {
			plBytes, err = v.verifySplitSignatureAndDecodePayload(head, tail, st)
		}
		if err != nil {
			yield(JSONProp{}, err)
			return
		}

		body, ok := TrimJSONObject(plBytes)
		if !ok {
			yield(JSONProp{}, ErrInvalidPayload)
			return
		}

		// Pass 1: Atomic cryptographic & claim validation
		if err := v.validatePayloadClaims(body, now); err != nil {
			yield(JSONProp{}, err)
			return
		}

		// Pass 2: Token is 100% valid; yield verified claims
		body, _ = TrimJSONObject(plBytes)
		for len(body) > 0 {
			key, val, isStr, rest, _ := NextJSONProp(body)
			body = rest
			if !yield(JSONProp{Key: key, Val: val, IsStr: isStr}, nil) {
				return
			}
		}
	}
}
