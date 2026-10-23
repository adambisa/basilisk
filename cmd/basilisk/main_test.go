package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adambisa/basilisk/internal/detect"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no args", nil, 2, "", "Usage:"},
		{"version", []string{"version"}, 0, "dev", ""},
		{"help", []string{"--help"}, 0, "Usage:", ""},
		{"hook stub", []string{"hook", "PreToolUse"}, 1, "", "hook PreToolUse: not implemented"},
		{"hook without event", []string{"hook"}, 2, "", "missing event name"},
		{"unknown", []string{"nope"}, 2, "", `unknown command "nope"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, strings.NewReader(""), &stdout, &stderr); got != tt.wantCode {
				t.Errorf("exit code = %d, want %d", got, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "users.csv")
	if err := os.WriteFile(file, []byte("name,email\nJane,j@x.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := "testdata-missing.csv"

	tests := []struct {
		name       string
		args       []string
		stdin      string
		wantCode   int
		wantStdout string // exact
		wantPrefix string // used when set instead of wantStdout
		wantStderr string
	}{
		{
			name:     "stdin csv",
			stdin:    "name,email\nJane,j@x.com\n",
			wantCode: 1,
			wantStdout: "-:2:1-2:5  PERSON  0.70  fieldname/table  field=name\n" +
				"-:2:6-2:13  EMAIL  0.90  fieldname/table  field=email\n",
		},
		{
			name:     "match ending at eof without trailing newline",
			stdin:    "name,email\nJane,j@x.com",
			wantCode: 1,
			wantStdout: "-:2:1-2:5  PERSON  0.70  fieldname/table  field=name\n" +
				"-:2:6-2:13  EMAIL  0.90  fieldname/table  field=email\n",
		},
		{
			name:       "columns count bytes",
			stdin:      `{"name": "Zoë"}`,
			wantCode:   1,
			wantPrefix: "-:1:11-1:15  PERSON",
		},
		{
			name:       "card in prose",
			stdin:      "my card is 4111 1111 1111 1111\n",
			wantCode:   1,
			wantStdout: "-:1:12-1:31  CARD  0.95  value/card  rule=card/visa\n",
		},
		{
			name:     "nothing found",
			stdin:    "id,plan\n1,pro\n",
			wantCode: 0,
		},
		{
			name:       "missing file",
			args:       []string{missing},
			wantCode:   2,
			wantStderr: missing,
		},
		{
			name:       "file path prefix",
			args:       []string{file},
			wantCode:   1,
			wantPrefix: file + ":2:1-2:5  PERSON",
		},
		{
			name:       "unreadable file does not stop the rest",
			args:       []string{missing, file},
			wantCode:   2,
			wantPrefix: file + ":2:1-2:5  PERSON",
			wantStderr: missing,
		},
		{
			name:       "directory is unreadable",
			args:       []string{dir},
			wantCode:   2,
			wantStderr: "basilisk scan: " + dir,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(append([]string{"scan"}, tt.args...), strings.NewReader(tt.stdin), &stdout, &stderr)
			if got != tt.wantCode {
				t.Errorf("exit code = %d, want %d", got, tt.wantCode)
			}
			switch {
			case tt.wantPrefix != "":
				if !strings.HasPrefix(stdout.String(), tt.wantPrefix) {
					t.Errorf("stdout = %q, want prefix %q", stdout.String(), tt.wantPrefix)
				}
			default:
				if stdout.String() != tt.wantStdout {
					t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
				}
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
			for _, secret := range []string{"Jane", "j@x.com", "Zoë", "4111"} {
				if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
					t.Errorf("output leaks the value %q: stdout=%q stderr=%q", secret, stdout.String(), stderr.String())
				}
			}
		})
	}
}

func TestPosition(t *testing.T) {
	text := "ab\nc\xc3\xa9d\n"
	tests := []struct {
		offset            int
		wantLine, wantCol int
	}{
		{0, 1, 1},
		{2, 1, 3}, // the newline itself
		{3, 2, 1}, // first byte of line 2
		{6, 2, 4}, // after a two-byte rune: columns count bytes
		{len(text), 3, 1},
	}
	for _, tt := range tests {
		line, col := position(text, tt.offset)
		if line != tt.wantLine || col != tt.wantCol {
			t.Errorf("position(%d) = %d:%d, want %d:%d", tt.offset, line, col, tt.wantLine, tt.wantCol)
		}
	}
}

// rescanPosition is the straightforward conversion the cursor replaces.
func rescanPosition(text string, offset int) (line, col int) {
	before := text[:offset]
	line = strings.Count(before, "\n") + 1
	col = offset - strings.LastIndexByte(before, '\n')
	return line, col
}

func TestLineCursor(t *testing.T) {
	text := "a,b\nc\xc3\xa9d,e\n\n\nlast line no newline"
	var offsets []int
	for i := 0; i <= len(text); i++ {
		offsets = append(offsets, i)
	}
	// ascending, as scan uses it: every offset in order
	c := newLineCursor(text)
	for _, off := range offsets {
		l, col := c.at(off)
		wl, wcol := rescanPosition(text, off)
		if l != wl || col != wcol {
			t.Fatalf("ascending at(%d) = %d:%d, want %d:%d", off, l, col, wl, wcol)
		}
	}
	// strided and repeated offsets, then a jump backwards
	c = newLineCursor(text)
	for _, off := range []int{0, 0, 3, 3, 4, 9, 9, 10, 11, 12, len(text), len(text), 5, 0, 7} {
		l, col := c.at(off)
		wl, wcol := rescanPosition(text, off)
		if l != wl || col != wcol {
			t.Fatalf("at(%d) = %d:%d, want %d:%d", off, l, col, wl, wcol)
		}
	}
}

func TestScanEscapesField(t *testing.T) {
	// Field is text from the scanned input. A header cell must be
	// identifier-like, so control bytes reach it through a JSON key.
	tests := []struct {
		name, stdin, wantField string
	}{
		{"ansi sequence before the name", "{\"\x1b[31m_name\": \"Jane\"}", `field="\x1b[31m_name"`},
		{"escape byte at end", "{\"name\x1b\": \"Jane\"}", `field="name\x1b"`},
		{"bidi override", "{\"name\u202e\": \"Jane\"}", `field="name\u202e"`},
		{"invalid utf-8", "{\"name\xff\": \"Jane\"}", `field="name\xff"`},
		{"plain stays unquoted", "{\"name\": \"Jane\"}", "field=name\n"},
		{"printable unicode stays unquoted", "{\"name\u00e9\": \"Jane\"}", "field=name\u00e9\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			run([]string{"scan"}, strings.NewReader(tt.stdin), &stdout, &stderr)
			out := stdout.String()
			if out == "" {
				t.Fatalf("no output for %q", tt.stdin)
			}
			for _, r := range strings.TrimSuffix(out, "\n") {
				if r < ' ' || r == 0x7f || r == 0x202e || r == 0xfffd {
					t.Errorf("stdout has raw control or non-printable %q: %q", r, out)
				}
			}
			if strings.Count(out, "\n") != 1 {
				t.Errorf("stdout is not a single line: %q", out)
			}
			if tt.wantField != "" && !strings.Contains(out, tt.wantField) {
				t.Errorf("stdout = %q, want it to contain %q", out, tt.wantField)
			}
		})
	}
}

func TestMatchLabel(t *testing.T) {
	tests := []struct {
		name string
		m    detect.Match
		want string
	}{
		{"field", detect.Match{Field: "name"}, "field=name"},
		{"rule", detect.Match{Rule: "card/visa"}, "rule=card/visa"},
		{"field wins", detect.Match{Field: "card", Rule: "card/visa"}, "field=card"},
		{"neither", detect.Match{}, "field="},
		{"field is escaped", detect.Match{Field: "a\x1bb"}, `field="a\x1bb"`},
	}
	for _, tt := range tests {
		if got := matchLabel(tt.m); got != tt.want {
			t.Errorf("%s: matchLabel = %q, want %q", tt.name, got, tt.want)
		}
	}
}
