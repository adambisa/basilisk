package detect

import (
	"fmt"
	"strings"
	"testing"
)

func TestIBANRegistryExamples(t *testing.T) {
	if len(ibanExamples) != len(ibanLengths) {
		t.Errorf("%d examples for %d countries", len(ibanExamples), len(ibanLengths))
	}
	for _, ex := range ibanExamples {
		code := ex[:2]
		if !ibanValid(ex) {
			t.Errorf("ibanValid(%q) = false, want true", ex)
		}
		if n, ok := ibanLengths[code]; !ok || len(ex) != n {
			t.Errorf("%s: example length %d, table length %d (known %v)", code, len(ex), n, ok)
		}
	}
}

func TestIBANValid(t *testing.T) {
	for _, tc := range []struct {
		iban string
		want bool
	}{
		{"DE89370400440532013000", true},
		{"DE89370400440532013001", false},
		{"DE8937040044053201300", false},
		{"XX89370400440532013000", false},
		{"de89370400440532013000", false}, // callers uppercase first
		{"DE8937040044053201300!", false},
		{"", false},
		{"D", false},
	} {
		if got := ibanValid(tc.iban); got != tc.want {
			t.Errorf("ibanValid(%q) = %v, want %v", tc.iban, got, tc.want)
		}
	}
}

func TestFindIBANs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string // Rule@Score:value, or "" for none
	}{
		{"keyword", "IBAN DE89370400440532013000", "iban@0.95:DE89370400440532013000"},
		{"grouped", "DE89 3704 0044 0532 0130 00", "iban@0.95:DE89 3704 0044 0532 0130 00"},
		{"bare", "DE89370400440532013000", "iban@0.90:DE89370400440532013000"},
		{"lowercase", "gb82west12345698765432", "iban@0.90:gb82west12345698765432"},
		{"czech", "CZ6508000000192000145399", "iban@0.90:CZ6508000000192000145399"},
		{"non-ascii before", "číslo:CZ6508000000192000145399", "iban@0.90:CZ6508000000192000145399"},
		{"check digit wrong", "DE89370400440532013001", ""},
		{"length wrong", "DE8937040044053201300", ""},
		{"unknown country", "XX89370400440532013000", ""},
		{"letter before", "xDE89370400440532013000", ""},
		{"letter after", "DE89370400440532013000x", ""},
		{"too long", "DE893704004405320130001", ""},
		{"keyword on other line", "iban\nDE89370400440532013000", "iban@0.90:DE89370400440532013000"},
		{"grouped then word", "DE89 3704 0044 0532 0130 00 paid", "iban@0.95:DE89 3704 0044 0532 0130 00"},
		{"grouped then number", "DE89 3704 0044 0532 0130 00 1234", "iban@0.95:DE89 3704 0044 0532 0130 00"},
		{"full last group then word", "GB82 WEST 1234 5698 7654 32 x", "iban@0.95:GB82 WEST 1234 5698 7654 32"},
		{"grouped, length multiple of 4", "AL47 2121 1009 0000 0002 3569 8741 ok", "iban@0.95:AL47 2121 1009 0000 0002 3569 8741"},
		{"grouped, bad group size", "DE89 3704 004 40532013000", ""},
		{"double space", "DE89  3704 0044 0532 0130 00", ""},
		{"two ibans", "DE89370400440532013000 GB82WEST12345698765432", "iban@0.90:DE89370400440532013000,iban@0.90:GB82WEST12345698765432"},
		{"truncated input", "DE89 3704", ""},
		{"trailing separator excluded", "DE89370400440532013000 ", "iban@0.90:DE89370400440532013000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range findIBANs(tc.input) {
				if m.Type != TypeBankAccount || m.Detector != "value/iban" {
					t.Errorf("match %+v: want type BANK_ACCOUNT, detector value/iban", m)
				}
				got = append(got, fmt.Sprintf("%s@%.2f:%s", m.Rule, m.Score, tc.input[m.Start:m.End]))
			}
			if g := strings.Join(got, ","); g != tc.want {
				t.Errorf("findIBANs(%q) = %q, want %q", tc.input, g, tc.want)
			}
		})
	}
}

func TestFindIBANsKeywordInValues(t *testing.T) {
	ms := Values{}.Find("pay to iban: CZ6508000000192000145399")
	if len(ms) != 1 || ms[0].Score != 0.95 || ms[0].Rule != "iban" {
		t.Errorf("Values.Find = %+v, want one iban match at 0.95", ms)
	}
}
