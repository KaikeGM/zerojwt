package zerojwt

import "bytes"

var (
	hexLut     [256]uint8
	escapeLut  [256]bool
	wsLut      [256]bool
	wsCommaLut [256]bool
	numEndLut  [256]bool
)

func init() {
	for i := 0; i < 256; i++ {
		hexLut[i] = 0xFF
		if i < 0x20 || i == '"' || i == '\\' {
			escapeLut[i] = true
		}
	}
	for c := byte('0'); c <= '9'; c++ {
		hexLut[c] = c - '0'
	}
	for c := byte('a'); c <= 'f'; c++ {
		hexLut[c] = c - 'a' + 10
	}
	for c := byte('A'); c <= 'F'; c++ {
		hexLut[c] = c - 'A' + 10
	}
	for _, c := range []byte{' ', '\t', '\r', '\n'} {
		wsLut[c] = true
		wsCommaLut[c] = true
		numEndLut[c] = true
	}
	wsCommaLut[','] = true
	numEndLut[','] = true
	numEndLut['}'] = true
	numEndLut[']'] = true
}

// NextJSONProp extracts the next top-level "key": value pair from a JSON object body (inside '{' and '}').
// It operates strictly in-place on b with zero heap allocations (0 B/op, 0 allocs/op).
// If a string value contains escape sequences (e.g., \" or \u00e7), it unescapes the slice in-place.
func NextJSONProp(b []byte) (key, val []byte, isStr bool, rest []byte, ok bool) {
	i := 0
	n := len(b)
	for i < n && wsCommaLut[b[i]] {
		i++
	}
	if i >= n {
		return nil, nil, false, nil, false
	}

	// Key must be a quoted string
	if b[i] != '"' {
		return nil, nil, false, nil, false
	}
	i++
	kStart := i
	for i < n {
		if b[i] == '\\' {
			i += 2
			continue
		}
		if b[i] == '"' {
			break
		}
		i++
	}
	if i >= n {
		return nil, nil, false, nil, false
	}
	key = b[kStart:i]
	i++ // skip closing quote

	// Expect ':'
	for i < n && wsLut[b[i]] {
		i++
	}
	if i >= n || b[i] != ':' {
		return nil, nil, false, nil, false
	}
	i++ // skip ':'

	// Skip whitespace before value
	for i < n && wsLut[b[i]] {
		i++
	}
	if i >= n {
		return nil, nil, false, nil, false
	}

	val, isStr, nextIdx, ok := scanJSONValue(b, i)
	if !ok {
		return nil, nil, false, nil, false
	}
	return key, val, isStr, b[nextIdx:], true
}

// NextArrayElement extracts the next element from a JSON array body (inside '[' and ']').
// It operates strictly in-place on b with zero heap allocations (0 B/op, 0 allocs/op).
func NextArrayElement(b []byte) (val []byte, isStr bool, rest []byte, ok bool) {
	i := 0
	n := len(b)
	for i < n && wsCommaLut[b[i]] {
		i++
	}
	if i >= n {
		return nil, false, nil, false
	}
	val, isStr, nextIdx, ok := scanJSONValue(b, i)
	if !ok {
		return nil, false, nil, false
	}
	return val, isStr, bytes.TrimSpace(b[nextIdx:]), true
}

func scanJSONValue(b []byte, i int) (val []byte, isStr bool, nextIdx int, ok bool) {
	n := len(b)
	if b[i] == '"' {
		isStr = true
		i++
		vStart := i
		hasEscape := false
		// Unrolled 4-byte fast scan for clean ASCII string characters
		for i+4 <= n {
			if escapeLut[b[i]] || escapeLut[b[i+1]] || escapeLut[b[i+2]] || escapeLut[b[i+3]] {
				break
			}
			i += 4
		}
		for i < n {
			if b[i] == '\\' {
				hasEscape = true
				i += 2
				continue
			}
			if b[i] == '"' {
				break
			}
			i++
		}
		if i >= n {
			return nil, false, 0, false
		}
		raw := b[vStart:i]
		if hasEscape {
			val = UnescapeJSONInPlace(raw)
		} else {
			val = raw
		}
		i++ // skip closing quote
		return val, true, i, true
	} else if b[i] == '{' || b[i] == '[' {
		open := b[i]
		closeChar := byte('}')
		if open == '[' {
			closeChar = ']'
		}
		depth := 1
		vStart := i
		i++
		inS := false
		for i < n && depth > 0 {
			if inS {
				if b[i] == '\\' {
					i += 2
					continue
				}
				if b[i] == '"' {
					inS = false
				}
				i++
				continue
			}
			if b[i] == '"' {
				inS = true
			} else if b[i] == open {
				depth++
			} else if b[i] == closeChar {
				depth--
			}
			i++
		}
		if depth != 0 {
			return nil, false, 0, false
		}
		return b[vStart:i], false, i, true
	} else {
		vStart := i
		for i < n && !numEndLut[b[i]] {
			i++
		}
		if i == vStart {
			return nil, false, 0, false
		}
		return b[vStart:i], false, i, true
	}
}

// TrimJSONObject strips surrounding whitespace and outer '{' and '}' braces from a JSON object.
func TrimJSONObject(b []byte) ([]byte, bool) {
	b = bytes.TrimSpace(b)
	if len(b) < 2 || b[0] != '{' || b[len(b)-1] != '}' {
		return nil, false
	}
	return bytes.TrimSpace(b[1 : len(b)-1]), true
}

// TrimJSONArray strips surrounding whitespace and outer '[' and ']' brackets from a JSON array.
func TrimJSONArray(b []byte) ([]byte, bool) {
	b = bytes.TrimSpace(b)
	if len(b) < 2 || b[0] != '[' || b[len(b)-1] != ']' {
		return nil, false
	}
	return bytes.TrimSpace(b[1 : len(b)-1]), true
}

// ParseNumeric parses a JSON number (integer or floating point, e.g. Unix timestamps) without allocations.
func ParseNumeric(b []byte) (float64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	i := 0
	neg := false
	if b[0] == '-' {
		neg = true
		i++
	}
	startDigits := i
	for i < len(b) && uint(b[i]-'0') <= 9 {
		i++
	}
	if i == startDigits {
		return 0, false
	}
	var res float64
	for j := startDigits; j < i; j++ {
		res = res*10 + float64(b[j]-'0')
	}
	if i < len(b) && b[i] == '.' {
		i++
		fracStart := i
		var div float64 = 1
		var frac float64
		for i < len(b) && uint(b[i]-'0') <= 9 {
			frac = frac*10 + float64(b[i]-'0')
			div *= 10
			i++
		}
		if i == fracStart {
			return 0, false
		}
		res += frac / div
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		expNeg := false
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			if b[i] == '-' {
				expNeg = true
			}
			i++
		}
		expStart := i
		var expVal int
		for i < len(b) && uint(b[i]-'0') <= 9 {
			expVal = expVal*10 + int(b[i]-'0')
			i++
		}
		if i == expStart {
			return 0, false
		}
		mult := 1.0
		for k := 0; k < expVal && mult < 1e300; k++ {
			mult *= 10
		}
		if expNeg {
			res /= mult
		} else {
			res *= mult
		}
	}
	if i != len(b) {
		return 0, false
	}
	if neg {
		res = -res
	}
	return res, true
}

// ParsePositiveInt parses a strictly positive 64-bit integer from a byte slice of digits.
func ParsePositiveInt(val []byte) (int64, bool) {
	if len(val) == 0 || len(val) > 18 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(val); i++ {
		d := uint(val[i] - '0')
		if d > 9 {
			return 0, false
		}
		n = n*10 + int64(d)
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// UnescapeJSONInPlace unescapes JSON string escape sequences in-place without allocating memory.
func UnescapeJSONInPlace(s []byte) []byte {
	w := 0
	for r := 0; r < len(s); r++ {
		if s[r] == '\\' && r+1 < len(s) {
			r++
			switch s[r] {
			case '"', '\\', '/':
				s[w] = s[r]
				w++
			case 'b':
				s[w] = '\b'
				w++
			case 'f':
				s[w] = '\f'
				w++
			case 'n':
				s[w] = '\n'
				w++
			case 'r':
				s[w] = '\r'
				w++
			case 't':
				s[w] = '\t'
				w++
			case 'u':
				if r+4 < len(s) {
					rn, ok := parseHex4(s[r+1 : r+5])
					if ok {
						r += 4
						// Check for UTF-16 surrogate pair (\uD800-\uDBFF followed by \uDC00-\uDFFF)
						if rn >= 0xD800 && rn <= 0xDBFF && r+6 < len(s) && s[r+1] == '\\' && s[r+2] == 'u' {
							r2, ok2 := parseHex4(s[r+3 : r+7])
							if ok2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
								rn = 0x10000 + ((rn - 0xD800) << 10) | (r2 - 0xDC00)
								r += 6
							}
						}
						w += encodeRuneUTF8(s[w:], rn)
						continue
					}
				}
				s[w] = s[r]
				w++
			default:
				s[w] = s[r]
				w++
			}
		} else {
			s[w] = s[r]
			w++
		}
	}
	return s[:w]
}

// parseHex4 decodes 4 hex bytes into a rune using branchless 256-byte lookup table access.
func parseHex4(b []byte) (rune, bool) {
	_ = b[3] // bounds check hint
	n0 := hexLut[b[0]]
	n1 := hexLut[b[1]]
	n2 := hexLut[b[2]]
	n3 := hexLut[b[3]]
	if (n0|n1|n2|n3)&0x80 != 0 {
		return 0, false
	}
	return rune(n0)<<12 | rune(n1)<<8 | rune(n2)<<4 | rune(n3), true
}

func encodeRuneUTF8(dst []byte, r rune) int {
	if r <= 0x7F {
		dst[0] = byte(r)
		return 1
	}
	if r <= 0x7FF {
		dst[0] = 0xC0 | byte(r>>6)
		dst[1] = 0x80 | byte(r&0x3F)
		return 2
	}
	if r <= 0xFFFF {
		dst[0] = 0xE0 | byte(r>>12)
		dst[1] = 0x80 | byte((r>>6)&0x3F)
		dst[2] = 0x80 | byte(r&0x3F)
		return 3
	}
	dst[0] = 0xF0 | byte(r>>18)
	dst[1] = 0x80 | byte((r>>12)&0x3F)
	dst[2] = 0x80 | byte((r>>6)&0x3F)
	dst[3] = 0x80 | byte(r&0x3F)
	return 4
}

// AppendEscapedJSONString appends a JSON-escaped string (with surrounding quotes) to dst
// using unrolled 8-byte vectorized span checks and bulk memory copies.
func AppendEscapedJSONString(dst, s []byte) []byte {
	dst = append(dst, '"')
	start := 0
	i := 0
	n := len(s)
	for i < n {
		// Fast-forward 8 bytes at a time when no characters require escaping
		for i+8 <= n &&
			!escapeLut[s[i]] && !escapeLut[s[i+1]] && !escapeLut[s[i+2]] && !escapeLut[s[i+3]] &&
			!escapeLut[s[i+4]] && !escapeLut[s[i+5]] && !escapeLut[s[i+6]] && !escapeLut[s[i+7]] {
			i += 8
		}
		if i >= n {
			break
		}
		c := s[i]
		if escapeLut[c] {
			if i > start {
				dst = append(dst, s[start:i]...)
			}
			switch c {
			case '"':
				dst = append(dst, '\\', '"')
			case '\\':
				dst = append(dst, '\\', '\\')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0x0f])
			}
			start = i + 1
		}
		i++
	}
	if start < n {
		dst = append(dst, s[start:]...)
	}
	return append(dst, '"')
}

const hexDigits = "0123456789abcdef"
