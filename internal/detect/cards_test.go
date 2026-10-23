package detect

import (
	"fmt"
	"strings"
	"testing"
)

func TestLuhn(t *testing.T) {
	for _, tc := range []struct {
		digits string
		want   bool
	}{
		{"4111111111111111", true},
		{"79927398713", true},
		{"4111111111111112", false},
	} {
		if got := luhn(tc.digits); got != tc.want {
			t.Errorf("luhn(%q) = %v, want %v", tc.digits, got, tc.want)
		}
	}
}

func TestFindCards(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string // Rule@Score:value, or "" for none
	}{
		{"keyword and layout", "card 4111 1111 1111 1111", "card/visa@0.95:4111 1111 1111 1111"},
		{"bare visa", "4111111111111111", "card/visa@0.75:4111111111111111"},
		{"hyphen layout", "pay 4111-1111-1111-1111 now", "card/visa@0.95:4111-1111-1111-1111"},
		{"mastercard 5", "5555555555554444", "card/mastercard@0.75:5555555555554444"},
		{"mastercard 2", "2223003122003222", "card/mastercard@0.75:2223003122003222"},
		{"amex", "378282246310005", "card/amex@0.75:378282246310005"},
		{"amex layout", "3782 822463 10005", "card/amex@0.95:3782 822463 10005"},
		{"discover", "6011111111111117", "card/discover@0.75:6011111111111117"},
		{"jcb", "3530111333300000", "card/jcb@0.75:3530111333300000"},
		{"diners", "30569309025904", "card/diners@0.75:30569309025904"},
		{"unionpay", "6200000000000005", "card/unionpay@0.75:6200000000000005"},
		{"luhn fails", "4111111111111112", ""},
		{"mixed separators", "4111 1111-1111 1111", ""},
		{"too long", "order 12345678901234567890123", ""},
		{"letter before", "x4111111111111111", ""},
		{"letter after", "4111111111111111x", ""},
		{"odd grouping stays a card", "4111 11111111 1111", "card/visa@0.75:4111 11111111 1111"},
		{"odd grouping with keyword", "visa: 4111 11111111 1111", "card/visa@0.95:4111 11111111 1111"},
		{"keyword on bare number", "cvv 4111111111111111", "card/visa@0.95:4111111111111111"},
		{"keyword on other line", "card\n4111111111111111", "card/visa@0.75:4111111111111111"},
		{"19 digit layout", "4111 1111 1111 1111 003", "card/visa@0.95:4111 1111 1111 1111 003"},
		{"too short", "411111111111", ""},
		{"trailing separator excluded", "4111 1111 1111 1111 ", "card/visa@0.95:4111 1111 1111 1111"},
		{"unknown issuer", "1111111111111117", ""},
		{"card and expiry", "4111 1111 1111 1111 12/28", "card/visa@0.95:4111 1111 1111 1111"},
		{"card and cvv", "4111 1111 1111 1111 123", "card/visa@0.95:4111 1111 1111 1111"},
		{"two cards", "4111111111111111 5555555555554444", "card/visa@0.75:4111111111111111,card/mastercard@0.75:5555555555554444"},
		{"leading count", "item 2 4111 1111 1111 1111", "card/visa@0.95:4111 1111 1111 1111"},
		{"interior window scores as bare", "7 4111 1111 1111 1111 9", "card/visa@0.75:4111 1111 1111 1111"},
		{"interior window with keyword stays 0.95", "card 7 4111 1111 1111 1111 9", "card/visa@0.95:4111 1111 1111 1111"},
		{"two grouped cards side by side", "4111 1111 1111 1111 5555 5555 5555 4444", "card/visa@0.95:4111 1111 1111 1111,card/mastercard@0.95:5555 5555 5555 4444"},
		{"three grouped cards side by side", "4111 1111 1111 1111 5555 5555 5555 4444 4012 8888 8888 1881", "card/visa@0.95:4111 1111 1111 1111,card/mastercard@0.95:5555 5555 5555 4444,card/visa@0.95:4012 8888 8888 1881"},
		{"two groups left over", "4111 1111 1111 1111 1234 5678", "card/visa@0.75:4111 1111 1111 1111"},
		{"no window matches", "12345678 90123456 78901234", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range findCards(tc.input) {
				if m.Type != TypeCard || m.Detector != "value/card" {
					t.Errorf("match %+v: want type CARD, detector value/card", m)
				}
				got = append(got, fmt.Sprintf("%s@%.2f:%s", m.Rule, m.Score, tc.input[m.Start:m.End]))
			}
			if g := strings.Join(got, ","); g != tc.want {
				t.Errorf("findCards(%q) = %q, want %q", tc.input, g, tc.want)
			}
		})
	}
}
