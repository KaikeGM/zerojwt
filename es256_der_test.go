package zerojwt

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"
)

// The ES256 DER <-> P1363 helpers have branches that random signatures only hit by chance
// (r or s with the high bit set, or with leading zero bytes). With the handful of random
// signatures the other tests produce, a CI run occasionally missed them and the 100% coverage
// gate failed. These fixed vectors make those branches deterministic, and compare the output
// with the canonical DER produced by encoding/asn1.
func TestES256DERHelpersEdgeVectors(t *testing.T) {
	filled := func(first byte, rest byte) (b [32]byte) {
		for i := range b {
			b[i] = rest
		}
		b[0] = first
		return
	}
	one := func() (b [32]byte) { b[31] = 1; return }
	lead0 := func(n int) (b [32]byte) { // n leading zero bytes, then 0x7f...
		for i := n; i < 32; i++ {
			b[i] = 0x7f
		}
		return
	}

	cases := []struct {
		name string
		r, s [32]byte
	}{
		{"both high bit clear", filled(0x7f, 0x11), filled(0x7f, 0x22)},
		{"r high bit set", filled(0x80, 0x11), filled(0x7f, 0x22)},
		{"s high bit set", filled(0x7f, 0x11), filled(0x80, 0x22)},
		{"both high bit set", filled(0xff, 0xff), filled(0xff, 0xff)},
		{"r one leading zero", lead0(1), filled(0x7f, 0x22)},
		{"s one leading zero", filled(0x7f, 0x11), lead0(1)},
		{"r and s several leading zeros", lead0(5), lead0(9)},
		{"r minimal (1)", one(), filled(0x80, 0x01)},
		{"s minimal (1)", filled(0x80, 0x01), one()},
	}
	for _, c := range cases {
		var dst [72]byte
		der, ok := encodeP1363ToDER(&dst, c.r[:], c.s[:])
		if !ok {
			t.Errorf("%s: encodeP1363ToDER failed", c.name)
			continue
		}
		want, err := asn1.Marshal(struct{ R, S *big.Int }{
			new(big.Int).SetBytes(c.r[:]), new(big.Int).SetBytes(c.s[:]),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(der, want) {
			t.Errorf("%s: DER mismatch\n got %x\nwant %x", c.name, der, want)
		}

		var out [64]byte
		if !decodeDERToP1363(want, out[:]) {
			t.Errorf("%s: decodeDERToP1363 failed on canonical DER", c.name)
			continue
		}
		if !bytes.Equal(out[:32], c.r[:]) || !bytes.Equal(out[32:], c.s[:]) {
			t.Errorf("%s: P1363 round trip mismatch: %x", c.name, out)
		}
	}

	// Degenerate / malformed inputs are rejected rather than mis-encoded.
	var zero [32]byte
	unit := one()
	var dst [72]byte
	if _, ok := encodeP1363ToDER(&dst, zero[:], unit[:]); ok {
		t.Error("r == 0 must be rejected")
	}
	if _, ok := encodeP1363ToDER(&dst, unit[:], zero[:]); ok {
		t.Error("s == 0 must be rejected")
	}
	for name, der := range map[string][]byte{
		"empty":          nil,
		"wrong tag":      {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
		"r too long":     append([]byte{0x30, 0x2c, 0x02, 0x21}, append(bytes.Repeat([]byte{0x01}, 33), 0x02, 0x01, 0x01)...),
		"trailing bytes": {0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00},
		"truncated":      {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x05, 0x01},
	} {
		var out [64]byte
		if decodeDERToP1363(der, out[:]) {
			t.Errorf("%s: malformed DER accepted", name)
		}
	}
}
