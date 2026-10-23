package detect

func init() { valueFinders = append(valueFinders, findCards) }

// cardKeywords are the words that back up a card candidate when they precede it.
var cardKeywords = []string{"card", "credit", "debit", "visa", "mastercard", "amex", "cc", "pan", "cvv"}

// findCards finds payment card numbers: 13 to 19 digits, as one run or in
// groups joined by one repeated separator (space or hyphen), that pass the
// Luhn check and match an issuer's prefix and length. A grouped run that fails
// as a whole is retried on windows of consecutive groups, so a card next to an
// expiry date, a CVV or another number is still found.
func findCards(text string) []Match {
	var ms []Match
	for i := 0; i < len(text); {
		if !isDigit(text[i]) {
			i++
			continue
		}
		groups := scanDigitRun(text, i)
		i = groups[len(groups)-1][1]
		if m, ok := cardCandidate(text, groups, false, true); ok {
			ms = append(ms, m)
			continue
		}
		if len(groups) < 2 {
			continue
		}
		ev := newCardEvidence(text, groups)
		for g := 0; g < len(groups); {
			m, n := cardWindow(text, groups, g, ev)
			if n == 0 {
				g++
				continue
			}
			ms = append(ms, m)
			g += n
		}
	}
	return ms
}

// cardWindowSizes are the numbers of groups a window may span, longest first.
var cardWindowSizes = []int{5, 4, 3, 1}

// cardWindow looks for a card at groups[g]: a window of consecutive groups
// that is a single group or follows a card layout. A layout counts as evidence
// only when ev allows it for the window. It returns the match and the number
// of groups used, or 0.
func cardWindow(text string, groups [][2]int, g int, ev cardEvidence) (Match, int) {
	for _, k := range cardWindowSizes {
		if g+k > len(groups) {
			continue
		}
		if m, ok := cardCandidate(text, groups[g:g+k], k > 1, ev.allows(g, k)); ok {
			return m, k
		}
	}
	return Match{}, 0
}

// cardEvidence decides when a layout window cut out of a longer run counts as
// layout evidence. It does when the rest of the run is one group of at most 4
// digits (a CVV or a leading count), or splits entirely into card layout
// windows (cards side by side). Anything else, such as a list of numbers with a
// card-shaped stretch in it, scores as a bare number.
type cardEvidence struct {
	groups [][2]int
	head   []bool // head[i]: groups[:i] split entirely into layout windows
	tail   []bool // tail[i]: groups[i:] split entirely into layout windows
}

func newCardEvidence(text string, groups [][2]int) cardEvidence {
	n := len(groups)
	ev := cardEvidence{groups: groups, head: make([]bool, n+1), tail: make([]bool, n+1)}
	// layout[i] lists the sizes of the layout windows that start at group i.
	layout := make([][]int, n)
	for i := range layout {
		for _, k := range cardWindowSizes {
			if k > 1 && i+k <= n {
				if _, ok := cardCandidate(text, groups[i:i+k], true, true); ok {
					layout[i] = append(layout[i], k)
				}
			}
		}
	}
	ev.head[0], ev.tail[n] = true, true
	for i := n - 1; i >= 0; i-- {
		for _, k := range layout[i] {
			if ev.tail[i+k] {
				ev.tail[i] = true
			}
		}
	}
	for i := 0; i < n; i++ {
		if !ev.head[i] {
			continue
		}
		for _, k := range layout[i] {
			ev.head[i+k] = true
		}
	}
	return ev
}

// allows reports whether the layout window of k groups at groups[g] counts as
// layout evidence.
func (ev cardEvidence) allows(g, k int) bool {
	rest := len(ev.groups) - k
	switch {
	case rest == 0:
		return true
	case rest == 1:
		left := ev.groups[0]
		if g == 0 {
			left = ev.groups[len(ev.groups)-1]
		}
		return left[1]-left[0] <= 4
	}
	return ev.head[g] && ev.tail[g+k]
}

// cardCandidate validates groups, byte spans of digit groups joined by single
// separators, as one card number. With needLayout it also requires the group
// sizes to follow the card layout. The layout raises the score only when
// evidence is set: a window cut out of a longer run may not count as layout.
func cardCandidate(text string, groups [][2]int, needLayout, evidence bool) (Match, bool) {
	start, end := groups[0][0], groups[len(groups)-1][1]
	var digits []byte
	sizes := make([]int, len(groups))
	for i, g := range groups {
		digits = append(digits, text[g[0]:g[1]]...)
		sizes[i] = g[1] - g[0]
	}
	if len(digits) < 13 || len(digits) > 19 || !atBoundary(text, start, end) {
		return Match{}, false
	}
	rule := cardIssuer(digits)
	if rule == "" || !luhn(string(digits)) {
		return Match{}, false
	}
	layout := cardLayout(rule, sizes)
	if needLayout && !layout {
		return Match{}, false
	}
	score := 0.75
	if layout && evidence || keywordBefore(text, start, cardKeywords) {
		score = 0.95
	}
	return Match{Type: TypeCard, Start: start, End: end, Score: score, Detector: "value/card", Rule: rule}, true
}

// scanDigitRun reads the maximal run that starts at the digit text[from]: digits
// joined by single separators, all the same character (space or hyphen). It
// returns the byte span of each digit group.
func scanDigitRun(text string, from int) [][2]int {
	var groups [][2]int
	var sep byte
	gs, end := from, from
	for end < len(text) {
		c := text[end]
		if isDigit(c) {
			end++
			continue
		}
		if (c == ' ' || c == '-') && (sep == 0 || sep == c) && end+1 < len(text) && isDigit(text[end+1]) {
			sep = c
			groups = append(groups, [2]int{gs, end})
			end++
			gs = end
			continue
		}
		break
	}
	return append(groups, [2]int{gs, end})
}

// cardIssuer returns the rule id of the issuer whose prefix and length match
// digits, or "". A more specific prefix is checked before a broader one.
func cardIssuer(digits []byte) string {
	n := len(digits)
	prefix := func(k int) int {
		v := 0
		for _, d := range digits[:k] {
			v = v*10 + int(d-'0')
		}
		return v
	}
	switch {
	case digits[0] == '4' && (n == 13 || n == 16 || n == 19):
		return "card/visa"
	case n == 16 && (prefix(2) >= 51 && prefix(2) <= 55 || prefix(4) >= 2221 && prefix(4) <= 2720):
		return "card/mastercard"
	case n == 15 && (prefix(2) == 34 || prefix(2) == 37):
		return "card/amex"
	case n >= 16 && (prefix(4) == 6011 || prefix(3) >= 644 && prefix(3) <= 649 || prefix(2) == 65 ||
		prefix(6) >= 622126 && prefix(6) <= 622925):
		return "card/discover"
	case n >= 16 && prefix(4) >= 3528 && prefix(4) <= 3589:
		return "card/jcb"
	case n >= 14 && (prefix(3) >= 300 && prefix(3) <= 305 || prefix(2) == 36 || prefix(2) == 38 || prefix(2) == 39):
		return "card/diners"
	case n >= 16 && prefix(2) == 62:
		return "card/unionpay"
	}
	return ""
}

// cardLayout reports whether the digit groups follow the card layout: 4-4-4-4,
// 4-4-4-4-3 for 19 digits, or 4-6-5 for Amex.
func cardLayout(rule string, groups []int) bool {
	var want []int
	switch {
	case rule == "card/amex":
		want = []int{4, 6, 5}
	case len(groups) == 4:
		want = []int{4, 4, 4, 4}
	default:
		want = []int{4, 4, 4, 4, 3}
	}
	if len(groups) != len(want) {
		return false
	}
	for i := range want {
		if groups[i] != want[i] {
			return false
		}
	}
	return true
}

// luhn reports whether digits, an ASCII digit string, passes the Luhn check.
func luhn(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return len(digits) > 0 && sum%10 == 0
}
