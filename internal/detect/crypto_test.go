package detect

import (
	"fmt"
	"strings"
	"testing"
)

func TestFindWallets(t *testing.T) {
	const (
		legacy  = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
		p2sh    = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
		bech32  = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
		bech32m = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
		ethLow  = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
		ethCS   = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	)
	for _, tc := range []struct {
		name  string
		input string
		want  string // Rule@Score:value, or "" for none
	}{
		{"btc legacy", legacy, "crypto/btc-base58@0.95:" + legacy},
		{"btc p2sh", p2sh, "crypto/btc-base58@0.95:" + p2sh},
		{"btc base58 burn address", "1111111111111111111114oLvT2", "crypto/btc-base58@0.95:1111111111111111111114oLvT2"},
		{"btc bech32", bech32, "crypto/btc-bech32@0.95:" + bech32},
		{"btc bech32m", bech32m, "crypto/btc-bech32@0.95:" + bech32m},
		{"btc bech32 upper", strings.ToUpper(bech32), "crypto/btc-bech32@0.95:" + strings.ToUpper(bech32)},
		{"btc bech32 mixed case", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdQ", ""},
		{"btc bech32 v0 with bech32m checksum", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzm4yhgz", ""},
		{"btc bech32m with v0 constant", "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusn5pxqu", ""},
		{"btc bech32 bad checksum", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr", ""},
		{"btc bech32 wrong hrp", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", ""},
		{"btc bech32 too short", "bc1qqqqqqqqqq", ""},
		{"btc legacy bad checksum", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", ""},
		{"btc legacy non base58", "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a", ""},
		{"btc legacy too short", "1A1zP1eP5QGefi2DMPTfTL5S", ""},
		{"btc legacy too long", legacy + "a", ""},
		{"btc legacy in sentence", "send to " + legacy + ".", "crypto/btc-base58@0.95:" + legacy},
		{"btc legacy glued to letters", "x" + legacy, ""},
		{"btc legacy glued to digits", legacy + "1", ""},
		{"eth eip55 a", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "crypto/eth@0.95:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"eth eip55 b", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "crypto/eth@0.95:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
		{"eth eip55 c", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "crypto/eth@0.95:0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"},
		{"eth eip55 d", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", "crypto/eth@0.95:0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"},
		{"eth lower", ethLow, "crypto/eth@0.60:" + ethLow},
		{"eth upper", "0x52908400098527886E0F7030069857D2E4169EE7", "crypto/eth@0.60:0x52908400098527886E0F7030069857D2E4169EE7"},
		{"eth digits only", "0x" + strings.Repeat("1", 40), "crypto/eth@0.60:0x" + strings.Repeat("1", 40)},
		{"eth lower with keyword", "wallet " + ethLow, "crypto/eth@0.80:" + ethLow},
		{"eth lower with keyword upper case", "ETH: " + ethLow, "crypto/eth@0.80:" + ethLow},
		{"eth lower keyword on previous line", "wallet\n" + ethLow, "crypto/eth@0.60:" + ethLow},
		{"eth lower keyword part of a word", "wallets " + ethLow, "crypto/eth@0.60:" + ethLow},
		{"eth mixed with keyword stays 0.95", "address " + ethCS, "crypto/eth@0.95:" + ethCS},
		{"eth checksum fails", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", ""},
		{"eth too short", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beae", ""},
		{"eth too long", ethLow + "d", ""},
		{"eth non hex", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaeg", ""},
		{"eth glued to a letter", "x" + ethLow, ""},
		{"eth upper prefix", "0X" + ethLow[2:], ""},
		{"git sha", "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", ""},
		{"git sha after commit", "commit 5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", ""},
		{"two addresses", legacy + " " + ethLow, "crypto/btc-base58@0.95:" + legacy + ",crypto/eth@0.60:" + ethLow},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range findWallets(tc.input) {
				if m.Type != TypeCryptoWallet || m.Detector != "value/crypto" {
					t.Errorf("match %+v: want type CRYPTO_WALLET and detector value/crypto", m)
				}
				got = append(got, fmt.Sprintf("%s@%.2f:%s", m.Rule, m.Score, tc.input[m.Start:m.End]))
			}
			if g := strings.Join(got, ","); g != tc.want {
				t.Errorf("got %q, want %q", g, tc.want)
			}
		})
	}
}

func TestFindWalletsNoPanicOnOddInput(t *testing.T) {
	for _, in := range []string{
		"", "0", "0x", "1", "3", "bc1", "BC1", "bc1q", "bc1zzzzzzzzzzzz", "bc1" + strings.Repeat("q", 80),
		strings.Repeat("z", 34), "1" + strings.Repeat("z", 33), "3" + strings.Repeat("z", 25),
		"0x" + strings.Repeat("F", 40), "\xff\xfe0x", "bc1\x00",
	} {
		findWallets(in)
	}
}
