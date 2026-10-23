package detect

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestKeccak256(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", "abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
		{"fox", "The quick brown fox jumps over the lazy dog", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"},
		// 135, 136 and 137 bytes of "a" straddle the rate: one byte of padding, a
		// full block with a padding-only second block, and one byte over. Computed
		// once with an independent implementation, for n in 135 136 137:
		// uv run --with pycryptodome python -c "from Crypto.Hash import keccak; print(keccak.new(digest_bits=256, data=b'a'*n).hexdigest())"
		{"135 x a", strings.Repeat("a", 135), "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"},
		{"136 x a", strings.Repeat("a", 136), "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"},
		{"137 x a", strings.Repeat("a", 137), "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"},
		// 300 bytes span three blocks of the 136-byte rate. Computed once with an
		// independent implementation:
		// uv run --with pycryptodome python -c "from Crypto.Hash import keccak; print(keccak.new(digest_bits=256, data=b'a'*300).hexdigest())"
		{"300 x a", strings.Repeat("a", 300), "5b7e0e47a96f32a88b4f14ca177982790807c40e1a105742ba0fc1babe1ef826"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := keccak256([]byte(tc.input))
			if got := hex.EncodeToString(sum[:]); got != tc.want {
				t.Errorf("keccak256 = %s, want %s", got, tc.want)
			}
		})
	}
}
