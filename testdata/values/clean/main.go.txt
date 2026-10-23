package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/adambisa/basilisk/internal/detect"
)

// runScan reports the PII found in stdin or in each file given, one line per
// match. It never prints a matched value. It returns 2 if any file could not
// be read, otherwise 1 if anything was found, otherwise 0.
func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var found, failed bool
	scan := func(name string, text string) {
		cur := newLineCursor(text)
		for _, m := range (detect.All{}).Find(text) {
			found = true
			l1, c1 := cur.at(m.Start)
			l2, c2 := cur.at(m.End)
			fmt.Fprintf(stdout, "%s:%d:%d-%d:%d  %s  %.2f  %s  %s\n",
				name, l1, c1, l2, c2, m.Type, m.Score, m.Detector, matchLabel(m))
		}
	}

	if len(args) == 0 {
		data, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "basilisk scan: -: %v\n", err)
			return 2
		}
		scan("-", string(data))
	}
	for _, path := range args {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "basilisk scan: %s: %v\n", path, err)
			failed = true
			continue
		}
		scan(path, string(data))
	}

	switch {
	case failed:
		return 2
	case found:
		return 1
	}
	return 0
}

// matchLabel names what triggered a match: rule=<rule> for a value match, which
// has no field, otherwise field=<field>.
func matchLabel(m detect.Match) string {
	if m.Field == "" && m.Rule != "" {
		return "rule=" + m.Rule
	}
	return "field=" + printableField(m.Field)
}

// printableField makes a field name safe to print. The name is text from the
// scanned input, so one with control bytes, invalid UTF-8 or other
// non-printable runes (ANSI escapes, bidi overrides) is Go-quoted; any other
// name is returned as it is.
func printableField(field string) string {
	if utf8.ValidString(field) && !strings.ContainsFunc(field, func(r rune) bool { return !strconv.IsPrint(r) }) {
		return field
	}
	return strconv.Quote(field)
}

// lineCursor converts byte offsets to 1-based line and column positions. Its
// state moves forward with the offsets asked for, so converting the matches
// of one text, which come sorted, reads the text once instead of once per
// match.
type lineCursor struct {
	text      string
	off       int // offset the line state is valid for
	line      int // 1-based line containing off
	lineStart int // offset of the first byte of that line
}

func newLineCursor(text string) *lineCursor {
	return &lineCursor{text: text, line: 1}
}

// at returns the 1-based line and the 1-based column, counted in bytes, of
// offset. An offset before the previous one restarts from the top of text.
func (c *lineCursor) at(offset int) (line, col int) {
	if offset < c.off {
		c.off, c.line, c.lineStart = 0, 1, 0
	}
	for ; c.off < offset; c.off++ {
		if c.text[c.off] == '\n' {
			c.line++
			c.lineStart = c.off + 1
		}
	}
	return c.line, offset - c.lineStart + 1
}

// position converts a byte offset in text to a 1-based line and a 1-based
// column counted in bytes.
func position(text string, offset int) (line, col int) {
	return newLineCursor(text).at(offset)
}
