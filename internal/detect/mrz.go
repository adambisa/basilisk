package detect

func init() { valueFinders = append(valueFinders, findMRZ) }

// mrzLen is the length of each line of a passport (TD3) machine-readable zone.
const mrzLen = 44

// findMRZ finds passport MRZs: two consecutive lines of 44 characters from
// [A-Z0-9<], after trimming leading and trailing spaces and tabs and a
// trailing '\r', the first starting with P, whose four required check digits
// on line 2 hold. The span runs from the first non-blank character of line 1 to
// the last character of line 2, so it includes the line break between them. A line that fails as line 2 is tried as line 1 of
// the next pair; a matched pair is not reused.
func findMRZ(text string) []Match {
	var ms []Match
	// Walk the lines, remembering the start of the previous one when it is a
	// candidate for line 1.
	prevStart, prevOK := 0, false
	for start := 0; start <= len(text); {
		end := len(text)
		next := len(text) + 1
		for i := start; i < len(text); i++ {
			if text[i] == '\n' {
				end, next = i, i+1
				break
			}
		}
		for end > start && (text[end-1] == '\r' || text[end-1] == ' ' || text[end-1] == '\t') {
			end--
		}
		first := start
		for first < end && (text[first] == ' ' || text[first] == '\t') {
			first++
		}
		line := text[first:end]
		switch {
		case !mrzLine(line):
			prevOK = false
		case prevOK && mrzValid(line):
			ms = append(ms, Match{Type: TypePassport, Start: prevStart, End: end, Score: 0.95, Detector: "value/mrz", Rule: "mrz/td3"})
			prevOK = false
		default:
			prevStart, prevOK = first, line[0] == 'P'
		}
		start = next
	}
	return ms
}

// mrzLine reports whether line is 44 characters from [A-Z0-9<].
func mrzLine(line string) bool {
	if len(line) != mrzLen {
		return false
	}
	for i := 0; i < len(line); i++ {
		if c := line[i]; !isUpperLetter(c) && !isDigit(c) && c != '<' {
			return false
		}
	}
	return true
}

// mrzValid reports whether the four required check digits of line2 hold
// (ICAO 9303 part 4): document number, date of birth, expiry date and the
// composite. A '<' in place of a check digit does not count as valid.
func mrzValid(line2 string) bool {
	composite := line2[0:10] + line2[13:20] + line2[21:43]
	for _, f := range [...]struct {
		field string
		check byte
	}{
		{line2[0:9], line2[9]},
		{line2[13:19], line2[19]},
		{line2[21:27], line2[27]},
		{composite, line2[43]},
	} {
		if !isDigit(f.check) || int(f.check-'0') != mrzCheck(f.field) {
			return false
		}
	}
	return true
}

// mrzCheck returns the ICAO 9303 check digit of field: the sum of its
// character values times the repeating weights 7, 3, 1, mod 10. Digits count
// as themselves, A-Z as 10-35 and '<' as 0.
func mrzCheck(field string) int {
	weights := [3]int{7, 3, 1}
	sum := 0
	for i := 0; i < len(field); i++ {
		c := field[i]
		v := 0
		switch {
		case isDigit(c):
			v = int(c - '0')
		case isUpperLetter(c):
			v = int(c-'A') + 10
		}
		sum += v * weights[i%3]
	}
	return sum % 10
}
