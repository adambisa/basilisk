package detect

import "strings"

// tableDetector tags matches from the table scanner.
const tableDetector = "fieldname/table"

// tableDelims are the cell delimiters tried for a header line.
const tableDelims = ",\t;|"

// span is a half-open byte range within a line.
type span struct{ start, end int }

// column is one header cell and what its values are flagged as.
type column struct {
	name      string
	typ       EntityType
	score     float64
	sensitive bool
}

// table is the header of the table being read.
type table struct {
	delim byte
	outer bool // pipe table whose lines have an outer leading and trailing "|" (markdown, not psql)
	cols  []column
}

// scanTables finds values in columns whose header names sensitive data, in
// CSV, TSV, psql and markdown tables. It makes one pass over the lines and
// never fails on odd input. Matches are in order of Start.
func scanTables(text string) []Match {
	var (
		ms  []Match
		cur *table
	)
	// Excel's "CSV UTF-8" export starts with a byte order mark. Spans stay
	// offsets into the original text.
	off := 0
	if strings.HasPrefix(text, "\xef\xbb\xbf") {
		off = 3
	}
	for off < len(text) {
		end := strings.IndexByte(text[off:], '\n')
		next := len(text)
		if end < 0 {
			end = len(text)
		} else {
			end += off
			next = end + 1
		}
		line := strings.TrimSuffix(text[off:end], "\r")

		if cur != nil {
			if isSeparator(line) {
				off = next
				continue
			}
			if cells := splitCells(line, cur.delim, cur.outer); len(cells) == len(cur.cols) {
				ms = appendRow(ms, cur, line, off, cells)
				off = next
				continue
			}
		}
		cur = parseHeader(line) // also ends the table when line is no header
		off = next
	}
	return ms
}

// appendRow flags the sensitive cells of one row. base is the offset of line
// in the text.
func appendRow(ms []Match, t *table, line string, base int, cells []span) []Match {
	for i, c := range cells {
		col := t.cols[i]
		if !col.sensitive {
			continue
		}
		s := valueSpan(line, c)
		if v := line[s.start:s.end]; v == "" || v == "NULL" || v == "null" {
			continue
		}
		ms = append(ms, Match{Type: col.typ, Start: base + s.start, End: base + s.end, Score: col.score, Detector: tableDetector, Field: col.name})
	}
	return ms
}

// parseHeader returns the table that line starts, or nil if it is no header.
// Of the delimiters that qualify, the one giving the most cells wins.
func parseHeader(line string) *table {
	var best *table
	for i := 0; i < len(tableDelims); i++ {
		d := tableDelims[i]
		outer := d == '|' && hasOuterPipes(line)
		cells := splitCells(line, d, outer)
		if len(cells) < 2 || (best != nil && len(cells) <= len(best.cols)) {
			continue
		}
		if cols, ok := headerColumns(line, cells); ok {
			best = &table{delim: d, outer: outer, cols: cols}
		}
	}
	return best
}

// headerColumns checks that every cell is identifier-like and at least one is
// sensitive.
func headerColumns(line string, cells []span) ([]column, bool) {
	cols := make([]column, len(cells))
	anySensitive := false
	for i, c := range cells {
		s := valueSpan(line, c)
		name := line[s.start:s.end]
		if !isIdentifier(name) {
			return nil, false
		}
		typ, score, ok := Classify(name)
		cols[i] = column{name: name, typ: typ, score: score, sensitive: ok}
		anySensitive = anySensitive || ok
	}
	return cols, anySensitive
}

// isIdentifier reports whether s matches ^[A-Za-z][A-Za-z0-9 _.-]{0,63}$.
func isIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 64 || !isLetter(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isLetter(c) && (c < '0' || c > '9') && !strings.ContainsRune(" _.-", rune(c)) {
			return false
		}
	}
	return true
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// isSeparator reports whether line is a rule such as psql's "---+---" or
// markdown's "|:--|--:|".
func isSeparator(line string) bool {
	return strings.TrimLeft(line, "-+|: ") == "" && strings.TrimSpace(line) != ""
}

// splitCells splits line into cell spans. For "|" it splits plainly and, when
// outer is set, drops the empty cells an outer pipe produces; for the other
// delimiters it honours CSV double quotes.
func splitCells(line string, delim byte, outer bool) []span {
	if delim == '|' {
		return splitPipes(line, outer)
	}
	var cells []span
	start, quoted, atStart := 0, false, true
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted:
			if c == '"' {
				if i+1 < len(line) && line[i+1] == '"' {
					i++
				} else {
					quoted = false
				}
			}
		case c == delim:
			cells = append(cells, span{start, i})
			start, atStart = i+1, true
		case c == '"' && atStart:
			quoted, atStart = true, false
		case c != ' ' && c != '\t':
			atStart = false
		}
	}
	return append(cells, span{start, len(line)})
}

// hasOuterPipes reports whether line starts and ends with "|", as markdown
// table lines do. psql lines don't: its empty last value is a real cell.
func hasOuterPipes(line string) bool {
	t := strings.TrimSpace(line)
	return len(t) >= 2 && t[0] == '|' && t[len(t)-1] == '|'
}

// splitPipes splits a psql or markdown row on "|". With outer set, a leading
// and a trailing pipe are ignored when the line has them.
func splitPipes(line string, outer bool) []span {
	var cells []span
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '|' {
			cells = append(cells, span{start, i})
			start = i + 1
		}
	}
	cells = append(cells, span{start, len(line)})
	if !outer {
		return cells
	}
	if strings.HasPrefix(strings.TrimLeft(line, " \t"), "|") {
		cells = cells[1:]
	}
	if len(cells) > 0 && strings.HasSuffix(strings.TrimRight(line, " \t"), "|") {
		cells = cells[:len(cells)-1]
	}
	return cells
}

// valueSpan trims spaces and tabs from a cell and strips surrounding double
// quotes, so the span covers only the value.
func valueSpan(line string, c span) span {
	s, e := c.start, c.end
	for s < e && (line[s] == ' ' || line[s] == '\t') {
		s++
	}
	for e > s && (line[e-1] == ' ' || line[e-1] == '\t') {
		e--
	}
	if s < e && line[s] == '"' {
		s++
		if e > s && line[e-1] == '"' {
			e--
		}
	}
	return span{s, e}
}
