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

// StringLike represents a type that is either string or []byte.
type StringLike interface {
	~string | ~[]byte
}

// JSONProp represents a key-value property scanned in-place from a JSON object.
type JSONProp struct {
	Key   []byte
	Val   []byte
	IsStr bool
}

// NextJSONProp extracts the next top-level "key": value pair from a JSON object body (inside '{' and '}').
// It operates strictly in-place on b with zero heap allocations (0 B/op, 0 allocs/op).
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
		// Unrolled 4-byte fast scan for clean ASCII string characters
		for i+4 <= n {
			if escapeLut[b[i]] || escapeLut[b[i+1]] || escapeLut[b[i+2]] || escapeLut[b[i+3]] {
				break
			}
			i += 4
		}
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
			return nil, false, 0, false
		}
		val = b[vStart:i]
		return val, true, i + 1, true
	}

	// Boolean or Null
	if b[i] == 't' && i+4 <= n && bytes.Equal(b[i:i+4], []byte("true")) {
		return b[i : i+4], false, i + 4, true
	}
	if b[i] == 'f' && i+5 <= n && bytes.Equal(b[i:i+5], []byte("false")) {
		return b[i : i+5], false, i + 5, true
	}
	if b[i] == 'n' && i+4 <= n && bytes.Equal(b[i:i+4], []byte("null")) {
		return b[i : i+4], false, i + 4, true
	}

	// Numbers
	if b[i] == '-' || (b[i] >= '0' && b[i] <= '9') {
		vStart := i
		i++
		for i < n && !numEndLut[b[i]] && !wsLut[b[i]] {
			i++
		}
		return b[vStart:i], false, i, true
	}

	// Nested object
	if b[i] == '{' {
		vStart := i
		depth := 1
		i++
		inStr := false
		for i < n && depth > 0 {
			if inStr {
				if b[i] == '\\' {
					i += 2
					continue
				}
				if b[i] == '"' {
					inStr = false
				}
			} else {
				if b[i] == '"' {
					inStr = true
				} else if b[i] == '{' {
					depth++
				} else if b[i] == '}' {
					depth--
				}
			}
			i++
		}
		if depth != 0 {
			return nil, false, 0, false
		}
		return b[vStart:i], false, i, true
	}

	// Nested array
	if b[i] == '[' {
		vStart := i
		depth := 1
		i++
		inStr := false
		for i < n && depth > 0 {
			if inStr {
				if b[i] == '\\' {
					i += 2
					continue
				}
				if b[i] == '"' {
					inStr = false
				}
			} else {
				if b[i] == '"' {
					inStr = true
				} else if b[i] == '[' {
					depth++
				} else if b[i] == ']' {
					depth--
				}
			}
			i++
		}
		if depth != 0 {
			return nil, false, 0, false
		}
		return b[vStart:i], false, i, true
	}

	return nil, false, 0, false
}

// TrimJSONObject trims outer whitespace and verifies/strips enclosing '{' and '}'.
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
	return ParseJSONNumber(b)
}

// ParseJSONNumber converts a JSON numeric byte slice to float64 without allocations.
func ParseJSONNumber(b []byte) (float64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	i := 0
	neg := false
	if b[0] == '-' {
		neg = true
		i++
		if i == len(b) {
			return 0, false
		}
	}
	var intPart uint64
	hasInt := false
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		hasInt = true
		intPart = intPart*10 + uint64(b[i]-'0')
		i++
	}
	if !hasInt {
		return 0, false
	}
	res := float64(intPart)

	// Fraction
	if i < len(b) && b[i] == '.' {
		i++
		if i == len(b) || b[i] < '0' || b[i] > '9' {
			return 0, false
		}
		frac := 0.0
		div := 1.0
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			frac = frac*10 + float64(b[i]-'0')
			div *= 10
			i++
		}
		res += frac / div
	}

	// Exponent
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		if i == len(b) {
			return 0, false
		}
		expNeg := false
		if b[i] == '+' {
			i++
		} else if b[i] == '-' {
			expNeg = true
			i++
		}
		expStart := i
		expVal := 0
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
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
	if len(val) == 0 || len(val) > 19 {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(val); i++ {
		d := uint(val[i] - '0')
		if d > 9 {
			return 0, false
		}
		n = n*10 + uint64(d)
	}
	if n == 0 || n > 9223372036854775807 {
		return 0, false
	}
	return int64(n), true
}

// UnescapeJSONInPlace unescapes JSON string escape sequences in-place without allocating memory.
func UnescapeJSONInPlace(s []byte) []byte {
	w := 0
	for r := 0; r < len(s); r++ {
		if s[r] == '\\' && r+1 < len(s) {
			r++
			switch s[r] {
			case '"':
				s[w] = '"'
				w++
			case '\\':
				s[w] = '\\'
				w++
			case '/':
				s[w] = '/'
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
					h0, h1, h2, h3 := hexLut[s[r+1]], hexLut[s[r+2]], hexLut[s[r+3]], hexLut[s[r+4]]
					if (h0 | h1 | h2 | h3) != 0xFF {
						cp := (rune(h0) << 12) | (rune(h1) << 8) | (rune(h2) << 4) | rune(h3)
						r += 4

						// Surrogate pair decoding (e.g. \uD83D\uDE00 for emoji)
						if cp >= 0xD800 && cp <= 0xDBFF && r+6 < len(s) && s[r+1] == '\\' && s[r+2] == 'u' {
							l0, l1, l2, l3 := hexLut[s[r+3]], hexLut[s[r+4]], hexLut[s[r+5]], hexLut[s[r+6]]
							if (l0 | l1 | l2 | l3) != 0xFF {
								low := (rune(l0) << 12) | (rune(l1) << 8) | (rune(l2) << 4) | rune(l3)
								if low >= 0xDC00 && low <= 0xDFFF {
									cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
									r += 6
								}
							}
						}

						w += encodeRuneToUTF8(s[w:], cp)
						continue
					}
				}
				s[w] = '\\'
				w++
				s[w] = 'u'
				w++
			default:
				s[w] = '\\'
				w++
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

func encodeRuneToUTF8(dst []byte, r rune) int {
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

// AppendEscapedJSON appends a JSON-escaped string (with enclosing quotes) directly to dst
// from either a string or []byte without allocating heap memory, using 8-byte vectorized checks.
func AppendEscapedJSON[S StringLike](dst []byte, s S) []byte {
	dst = append(dst, '"')
	start := 0
	i := 0
	n := len(s)
	for i < n {
		for i+8 <= n &&
			!escapeLut[s[i]] && !escapeLut[s[i+1]] && !escapeLut[s[i+2]] && !escapeLut[s[i+3]] &&
			!escapeLut[s[i+4]] && !escapeLut[s[i+5]] && !escapeLut[s[i+6]] && !escapeLut[s[i+7]] {
			i += 8
		}
		for i < n && !escapeLut[s[i]] {
			i++
		}
		if i > start {
			dst = append(dst, s[start:i]...)
			start = i
		}
		if i >= n {
			break
		}
		c := s[i]
		switch c {
		case '"':
			dst = append(dst, `\"`...)
		case '\\':
			dst = append(dst, `\\`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			dst = append(dst, `\u00`...)
			const hexDigits = "0123456789abcdef"
			dst = append(dst, hexDigits[c>>4], hexDigits[c&0xF])
		}
		i++
		start = i
	}
	dst = append(dst, '"')
	return dst
}

// AppendEscapedJSONString is a convenience alias for AppendEscapedJSON with []byte.
func AppendEscapedJSONString(dst, s []byte) []byte {
	return AppendEscapedJSON(dst, s)
}
