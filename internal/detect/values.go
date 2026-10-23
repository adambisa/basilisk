package detect

// valueFinders are the value detectors. Each detector file appends its finder
// from an init function.
var valueFinders []func(text string) []Match

// Values finds PII and secrets by the value itself: checksum-valid numbers,
// structured identifiers and secrets with a known format.
type Values struct{}

// Find returns the matches of every value detector, sorted by Start, with
// overlapping spans merged into their union.
func (Values) Find(text string) []Match {
	var ms []Match
	for _, find := range valueFinders {
		ms = append(ms, find(text)...)
	}
	return mergeMatches(ms)
}

// All finds PII by field name and by value, merged.
type All struct{}

// Find returns the matches of FieldNames and Values, sorted by Start, with
// overlapping spans merged into their union.
func (All) Find(text string) []Match {
	return mergeMatches(append(FieldNames{}.Find(text), Values{}.Find(text)...))
}

// keywordWindow is how many bytes before a candidate keywordBefore looks.
const keywordWindow = 32

// keywordBefore reports whether one of words, matched case-insensitively
// (ASCII) as a whole word, occurs within the 32 bytes before start on the same
// line. A word is whole when no letter or digit touches it on either side.
func keywordBefore(text string, start int, words []string) bool {
	lo := max(0, start-keywordWindow)
	for i := start - 1; i >= lo; i-- {
		if text[i] == '\n' {
			lo = i + 1
			break
		}
	}
	for _, w := range words {
		for i := lo; i+len(w) <= start; i++ {
			if !equalFoldASCII(text[i:i+len(w)], w) {
				continue
			}
			if i > 0 && isAlnum(text[i-1]) || i+len(w) < len(text) && isAlnum(text[i+len(w)]) {
				continue
			}
			return true
		}
	}
	return false
}

// atBoundary reports whether text[start:end] touches no letter or digit
// ([A-Za-z0-9]) on either side.
func atBoundary(text string, start, end int) bool {
	return (start <= 0 || !isAlnum(text[start-1])) && (end >= len(text) || !isAlnum(text[end]))
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// equalFoldASCII compares a and b, folding only ASCII letters.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
