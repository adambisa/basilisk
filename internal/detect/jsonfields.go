package detect

// jsonDetector tags matches from the JSON scanner.
const jsonDetector = "fieldname/json"

// jsonCtx is what a value is flagged as. The zero value flags nothing: it is
// both "no context" and the explicit "no type" a skip key gives.
type jsonCtx struct {
	typ   EntityType
	score float64
	field string // the key that made values sensitive
}

// scanJSON finds values under sensitive JSON keys in one forward pass over
// text. It is tolerant: it ignores anything that is not a string, number or
// JSON structure, so JSON inside a log line works, and it never fails on
// truncated or unbalanced input. Matches are in order of Start.
func scanJSON(text string) []Match {
	var (
		ms         []Match
		stack      []jsonCtx // context each open container passes down
		pending    jsonCtx   // context from the key just seen
		hasPending bool
	)
	// current is the innermost of the pending key's rule and the inherited one.
	current := func() jsonCtx {
		if hasPending {
			return pending
		}
		if len(stack) > 0 {
			return stack[len(stack)-1]
		}
		return jsonCtx{}
	}
	flag := func(ctx jsonCtx, start, end int) {
		if ctx.typ != "" && end > start {
			ms = append(ms, Match{Type: ctx.typ, Start: start, End: end, Score: ctx.score, Detector: jsonDetector, Field: ctx.field})
		}
	}

	for i := 0; i < len(text); {
		switch c := text[i]; {
		case c == '"':
			start := i + 1
			end, closed := stringEnd(text, start)
			if closed {
				if colon := skipSpace(text, end+1); colon < len(text) && text[colon] == ':' {
					pending, hasPending = keyCtx(text[start:end])
					i = colon + 1
					continue
				}
			}
			if closed {
				flag(current(), start, end)
				hasPending = false
				i = end + 1
				continue
			}
			// An unterminated string ends at a raw newline or at the end of
			// text, where valid JSON cannot continue: forget the open
			// containers so the cut does not taint what follows. A CRLF
			// line break is not part of the value.
			if end < len(text) && end > start && text[end-1] == '\r' {
				flag(current(), start, end-1)
			} else {
				flag(current(), start, end)
			}
			stack = stack[:0]
			hasPending = false
			i = end + 1
		case c == '-' || c >= '0' && c <= '9':
			end := numberEnd(text, i)
			if end > i+1 || c != '-' {
				flag(current(), i, end)
				hasPending = false
			}
			i = end
		case c == '{' || c == '[':
			if len(stack) > 0 && (i == 0 || text[i-1] == '\n') {
				// An opener in column 0 inside an open container starts a new
				// NDJSON record: pretty printers indent nested openers.
				stack = stack[:0]
				hasPending = false
			}
			stack = append(stack, current())
			hasPending = false
			i++
		case c == '}' || c == ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			hasPending = false
			i++
		case c == ',':
			hasPending = false
			i++
		default:
			i++
		}
	}
	return ms
}

// keyCtx classifies a key. The bool is false when the key is not in the
// keyword table, so the inherited context stays in force; a skip key returns
// the zero context and true, which stops inheritance.
func keyCtx(key string) (jsonCtx, bool) {
	r, found := lookup(key)
	if !found {
		return jsonCtx{}, false
	}
	if r.skip {
		return jsonCtx{}, true
	}
	return jsonCtx{typ: r.typ, score: r.score, field: key}, true
}

// stringEnd finds where a string whose content begins at start ends. It
// stops at the next unescaped quote (closed is true) or, for an unterminated
// string, at the newline that ends it or the end of text.
func stringEnd(text string, start int) (end int, closed bool) {
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '"':
			return i, true
		case '\n':
			return i, false
		case '\\':
			if i+1 < len(text) && text[i+1] != '\n' {
				i++
			}
		}
	}
	return len(text), false
}

// numberEnd returns the end of the number starting at i, matching
// -?[0-9][0-9.eE+-]*.
func numberEnd(text string, i int) int {
	if text[i] == '-' {
		i++
	}
	if i >= len(text) || text[i] < '0' || text[i] > '9' {
		return i
	}
	for i++; i < len(text); i++ {
		c := text[i]
		if c < '0' || c > '9' {
			switch c {
			case '.', 'e', 'E', '+', '-':
			default:
				return i
			}
		}
	}
	return i
}

// skipSpace returns the index of the first byte at or after i that is not
// JSON whitespace.
func skipSpace(text string, i int) int {
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
		i++
	}
	return i
}
