package detect

import (
	"crypto/sha256"
	"math/big"
	"strings"
)

func init() { valueFinders = append(valueFinders, findWallets) }

const (
	base58Alphabet  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	bech32Charset   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	bech32mConstant = 0x2bc830a3
)

var ethKeywords = []string{"eth", "ether", "wallet", "address"}

// findWallets finds Bitcoin and Ethereum addresses: legacy base58 addresses
// and bech32/bech32m segwit addresses with a valid checksum, and 0x-prefixed
// Ethereum addresses (mixed case ones only with a valid EIP-55 checksum).
// A candidate is a whole run of letters and digits, so it never touches one
// on either side.
func findWallets(text string) []Match {
	var ms []Match
	for i := 0; i < len(text); {
		if !isAlnum(text[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(text) && isAlnum(text[j]) {
			j++
		}
		if m, ok := walletMatch(text, i, j); ok {
			ms = append(ms, m)
		}
		i = j
	}
	return ms
}

// walletMatch classifies the run text[start:end] as a wallet address.
func walletMatch(text string, start, end int) (Match, bool) {
	run := text[start:end]
	m := Match{Type: TypeCryptoWallet, Start: start, End: end, Detector: "value/crypto"}
	switch {
	case len(run) == 42 && strings.HasPrefix(run, "0x"):
		score, ok := ethScore(text, start, run[2:])
		m.Rule, m.Score = "crypto/eth", score
		return m, ok
	case (run[0] == '1' || run[0] == '3') && len(run) >= 25 && len(run) <= 34:
		m.Rule, m.Score = "crypto/btc-base58", 0.95
		return m, base58Valid(run)
	case len(run) >= len("bc1")+11 && len(run) <= len("bc1")+71 && equalFoldASCII(run[:3], "bc1"):
		m.Rule, m.Score = "crypto/btc-bech32", 0.95
		return m, bech32Valid(run)
	}
	return m, false
}

// base58Valid reports whether addr is a base58check address: 25 bytes whose
// last 4 are the first 4 of the double SHA-256 of the first 21.
func base58Valid(addr string) bool {
	n := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(addr); i++ {
		d := strings.IndexByte(base58Alphabet, addr[i])
		if d < 0 {
			return false
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(d)))
	}
	if n.BitLen() > 25*8 {
		return false
	}
	var b [25]byte
	n.FillBytes(b[:])
	// Each leading '1' stands for one leading zero byte, and no other byte.
	ones, zeros := 0, 0
	for ones < len(addr) && addr[ones] == '1' {
		ones++
	}
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	if ones != zeros {
		return false
	}
	first := sha256.Sum256(b[:21])
	second := sha256.Sum256(first[:])
	return string(second[:4]) == string(b[21:])
}

// bech32Valid reports whether addr is a segwit address with hrp "bc" and a
// valid checksum: bech32 for witness version 0, bech32m for versions 1 to 16
// (BIP-173, BIP-350). The case must be all lower or all upper.
func bech32Valid(addr string) bool {
	lower, upper := false, false
	for i := 0; i < len(addr); i++ {
		lower = lower || isLower(addr[i])
		upper = upper || isUpperLetter(addr[i])
	}
	if lower && upper {
		return false
	}
	addr = strings.ToLower(addr)
	data := make([]byte, 0, len(addr))
	for i := len("bc1"); i < len(addr); i++ {
		d := strings.IndexByte(bech32Charset, addr[i])
		if d < 0 {
			return false
		}
		data = append(data, byte(d))
	}
	version := data[0]
	if version > 16 {
		return false
	}
	want := uint32(bech32mConstant)
	if version == 0 {
		want = 1
	}
	// The expanded hrp "bc": high bits, a zero, low bits.
	chk := uint32(1)
	for _, v := range [...]byte{'b' >> 5, 'c' >> 5, 0, 'b' & 31, 'c' & 31} {
		chk = bech32Polymod(chk, v)
	}
	for _, v := range data {
		chk = bech32Polymod(chk, v)
	}
	return chk == want
}

// bech32Polymod folds one 5-bit value into the BIP-173 checksum state.
func bech32Polymod(chk uint32, v byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	top := chk >> 25
	chk = (chk&0x1ffffff)<<5 ^ uint32(v)
	for i, g := range gen {
		if top>>i&1 == 1 {
			chk ^= g
		}
	}
	return chk
}

// ethScore validates the 40 hex digits of an Ethereum address starting after
// the 0x at start. Mixed case must satisfy EIP-55 and scores 0.95. A single
// case carries no checksum: 0.8 with a keyword before it, else 0.6.
func ethScore(text string, start int, hexDigits string) (float64, bool) {
	lower, upper := false, false
	for i := 0; i < len(hexDigits); i++ {
		switch c := hexDigits[i]; {
		case isDigit(c):
		case c >= 'a' && c <= 'f':
			lower = true
		case c >= 'A' && c <= 'F':
			upper = true
		default:
			return 0, false
		}
	}
	if !lower || !upper {
		if keywordBefore(text, start, ethKeywords) {
			return 0.8, true
		}
		return 0.6, true
	}
	// EIP-55: a letter is upper case when the matching nibble of the Keccak-256
	// of the lower-case hex digits is 8 or more.
	sum := keccak256([]byte(strings.ToLower(hexDigits)))
	for i := 0; i < len(hexDigits); i++ {
		c := hexDigits[i]
		if isDigit(c) {
			continue
		}
		nibble := sum[i/2] >> (4 * (1 - i%2)) & 0xf
		if (nibble >= 8) != isUpperLetter(c) {
			return 0, false
		}
	}
	return 0.95, true
}
