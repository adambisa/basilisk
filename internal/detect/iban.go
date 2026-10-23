package detect

func init() { valueFinders = append(valueFinders, findIBANs) }

// ibanKeywords are the words that back up an IBAN candidate when they precede it.
var ibanKeywords = []string{"iban"}

// findIBANs finds IBANs: a country code in the SWIFT registry, two check
// digits and the BBAN, written compact or in groups of four joined by single
// spaces, in either case. The length must match the country's and the ISO 7064
// mod-97 check must hold.
func findIBANs(text string) []Match {
	var ms []Match
	for i := 0; i+4 <= len(text); {
		if m, ok := ibanAt(text, i); ok {
			ms = append(ms, m)
			i = m.End
			continue
		}
		i++
	}
	return ms
}

// ibanAt reads an IBAN that starts at text[start], or reports false.
func ibanAt(text string, start int) (Match, bool) {
	if start > 0 && isAlnum(text[start-1]) || !isLetter(text[start]) || !isLetter(text[start+1]) ||
		!isDigit(text[start+2]) || !isDigit(text[start+3]) {
		return Match{}, false
	}
	want, ok := ibanLengths[upperASCII(text[start:start+2])]
	if !ok {
		return Match{}, false
	}
	// Collect want alphanumerics: all of them in one run, or in groups of four
	// joined by single spaces. Every group is full except the last, and the
	// last must end where the alphanumerics end.
	compact := make([]byte, 0, want)
	end, grouped := start, false
	for len(compact) < want {
		runEnd := end
		for runEnd < len(text) && isAlnum(text[runEnd]) {
			runEnd++
		}
		n := min(4, want-len(compact))
		if !grouped && runEnd-end == want {
			n = want
		} else if runEnd-end != n {
			return Match{}, false
		}
		compact = append(compact, text[end:runEnd]...)
		end = runEnd
		if len(compact) < want {
			if end+1 >= len(text) || text[end] != ' ' {
				return Match{}, false
			}
			end++
			grouped = true
		}
	}
	if !ibanValid(upperASCII(string(compact))) {
		return Match{}, false
	}
	score := 0.9
	if grouped || keywordBefore(text, start, ibanKeywords) {
		score = 0.95
	}
	return Match{Type: TypeBankAccount, Start: start, End: end, Score: score, Detector: "value/iban", Rule: "iban"}, true
}

// ibanValid reports whether compact, an upper-case IBAN without separators,
// has a registry country code, that country's length, the right character
// classes and a valid ISO 7064 mod-97 check.
func ibanValid(compact string) bool {
	if len(compact) < 4 || ibanLengths[compact[:2]] != len(compact) ||
		!isUpperLetter(compact[0]) || !isUpperLetter(compact[1]) || !isDigit(compact[2]) || !isDigit(compact[3]) {
		return false
	}
	// Move the first four characters to the end, read A-Z as 10-35 and reduce
	// the resulting number mod 97 as it is read.
	rem := 0
	for i := 0; i < len(compact); i++ {
		c := compact[(i+4)%len(compact)]
		switch {
		case isDigit(c):
			rem = (rem*10 + int(c-'0')) % 97
		case isUpperLetter(c):
			rem = (rem*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return rem == 1
}

func isUpperLetter(c byte) bool { return c >= 'A' && c <= 'Z' }

// upperASCII upper-cases the ASCII letters of s.
func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}
