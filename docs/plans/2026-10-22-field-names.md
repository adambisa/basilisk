# Field-Name Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flag PII values in JSON and table output (CSV, TSV, `psql`, markdown) by their field name, and expose it as `basilisk scan`.

**Architecture:** `internal/detect` gets the shared `Match`/`Detector` types, a field-name classifier, two tolerant single-pass scanners (JSON, tables) and a `FieldNames` detector that merges their results. `cmd/basilisk` gets a `scan` subcommand that prints match positions, never values.

**Tech Stack:** Go 1.27, standard library only.

**Spec:** [docs/specs/2026-10-22-field-names.md](../specs/2026-10-22-field-names.md)

## Global Constraints

- Module `github.com/adambisa/basilisk`, Go 1.27, no third-party dependencies.
- Spans are byte offsets into the original text: `Start` inclusive, `End` exclusive.
- Booleans, `null` and empty values are never flagged.
- A sensitive field name alone is enough to flag its value.
- `basilisk scan` never prints a matched value. Exit codes: 1 found, 0 nothing found, 2 usage or read error.
- All fixture values are synthetic.

## Review Focus

1. **CRLF line endings** (CSV exported on Windows): rows parse, and spans never include `\r`. Test in Task 3.
2. **Multibyte UTF-8 values** (`Zoë Ångström`): spans cover whole runes, and CLI columns count bytes. Tests in Tasks 2 and 5.
3. **Key-like text inside a string value** (`"note": "use \"email\": here"`): it isn't treated as a key. Test in Task 2.
4. **An unterminated non-sensitive string** must not swallow the lines after it. A raw newline ends a JSON string. Test in Task 2.
5. **Huge single-line input** (minified JSON, 200k array elements): the scan stays linear. Test in Task 2.

---

### Task 1: Types and field-name classifier

**Files:**
- Create: `internal/detect/detect.go`
- Create: `internal/detect/keys.go`
- Test: `internal/detect/keys_test.go`

**Interfaces:**
- Produces:
  - `type EntityType string`, with constants `SSN ITIN EIN PASSPORT DRIVER_LICENSE MEDICARE CARD BANK_ACCOUNT ROUTING_NUMBER SECRET EMAIL PHONE DOB IP_ADDRESS PERSON USERNAME ADDRESS`. Go names are `Type` plus the CamelCase name, with acronyms kept upper case (`TypeSSN`, `TypeDOB`, `TypeIPAddress`, `TypeDriverLicense`, `TypeBankAccount`); the string values are the upper-case names.
  - `type Match struct { Type EntityType; Start, End int; Score float64; Detector, Field string }`
  - `type Detector interface { Find(text string) []Match }`
  - `func Classify(key string) (EntityType, float64, bool)`
  - `func splitWords(key string) []string` (unexported, used by tests)

- [ ] **Step 1: Write the failing tests**

```go
func TestSplitWords(t *testing.T) {
	cases := map[string][]string{
		"customerEmail":  {"customer", "email"},
		"SSNNumber":      {"ssn", "number"},
		"address2":       {"address", "2"},
		"HOME-PHONE":     {"home", "phone"},
		"billing_address": {"billing", "address"},
		"userID":         {"user", "id"},
		"XMLHttpRequest": {"xml", "http", "request"},
		"e-mail":         {"e", "mail"},
		"":               nil,
	}
	// assert reflect.DeepEqual(splitWords(in), want) for each
}

func TestClassify(t *testing.T) {
	cases := []struct {
		key   string
		typ   EntityType
		score float64
		ok    bool
	}{
		{"customerEmail", TypeEmail, 0.9, true},
		{"emailAddress", TypeEmail, 0.9, true},
		{"e-mail", TypeEmail, 0.9, true},
		{"SSNNumber", TypeSSN, 0.95, true},       // filler fallback
		{"account_number", TypeBankAccount, 0.9, true},
		{"address_line_2", TypeAddress, 0.7, true},
		{"addresses", TypeAddress, 0.7, true},
		{"city", TypeAddress, 0.5, true},
		{"HOME-PHONE", TypePhone, 0.9, true},
		{"firstName", TypePerson, 0.7, true},
		{"display_name", TypePerson, 0.7, true},
		{"userName", TypeUsername, 0.6, true},
		{"password", TypeSecret, 0.9, true},
		{"email_verified", "", 0, false},
		{"file_name", "", 0, false},
		{"filename", "", 0, false},
		{"mac_address", "", 0, false},
		{"state", "", 0, false},
		{"password_hash", "", 0, false},
		{"", "", 0, false},
	}
	// assert all three return values for each
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/detect/ -run 'TestSplitWords|TestClassify'`
Expected: FAIL, because the package doesn't compile (`undefined: splitWords`).

- [ ] **Step 3: Implement `detect.go` and `keys.go`**

- `detect.go`: the types and constants above, with doc comments. Nothing else.
- `keys.go`: the keyword table from the spec, copied exactly, including the *skip* rows. Store it as `map[string]rule`, keyed by the space-joined word sequence, where `rule{typ EntityType; score float64; skip bool}`.
- `splitWords`: break on any non-alphanumeric byte, on a lower→upper change, before the last upper-case letter of a run when a lower-case letter follows (`SSNNumber` → `SSN|Number`), and on letter↔digit changes. Lowercase every word.
- `Classify`, in order:
  1. Split the key.
  2. Drop trailing all-digit words.
  3. Reduce plurals: a final `sses` becomes `ss`; otherwise drop a final `s` when the word is longer than three letters and doesn't end in `ss`.
  4. Try suffixes from longest to shortest. The first table hit decides: return its type, or `false` if it's a skip row.
  5. If nothing matched, drop trailing filler words (`number num no nr`) and repeat step 4 once.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/detect/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/detect/detect.go internal/detect/keys.go internal/detect/keys_test.go
git commit -m "Add field-name classifier"
```

---

### Task 2: JSON scanner

**Files:**
- Create: `internal/detect/jsonfields.go`
- Test: `internal/detect/jsonfields_test.go`

**Interfaces:**
- Consumes: `Classify`, `Match`, the `Type*` constants (Task 1)
- Produces: `func scanJSON(text string) []Match`, with `Detector: "fieldname/json"`, sorted by `Start`
- Produces, test helper in `jsonfields_test.go` and reused by Tasks 3 and 4: `func got(text string, ms []Match) []string`, which returns `"TYPE:value"` for each match

- [ ] **Step 1: Write the failing tests**

Table test `TestScanJSON`. Each case is an input and the expected `got(...)` result:

| Input | Expected |
| :- | :- |
| `{"email": "a@x.com", "id": 7}` | `EMAIL:a@x.com` |
| `{"email_verified": true, "phone": null, "name": ""}` | none |
| `{"ssn": 123456789}` | `SSN:123456789` |
| `{"emails": ["a@x.com", "b@y.com"]}` | `EMAIL:a@x.com`, `EMAIL:b@y.com` |
| `{"address": {"line1": "1 Main St", "city": "Springfield", "file_name": "x.txt"}}` | `ADDRESS:1 Main St`, `ADDRESS:Springfield` |
| `2026-10-22 INFO user={"name":"Jane Roe","plan":"pro"}` | `PERSON:Jane Roe` |
| `{"name":"Jane Roe"}` + `\n` + `{"name":"Bob Poe"}` (NDJSON) | `PERSON:Jane Roe`, `PERSON:Bob Poe` |
| `{"name": "Jane Ro` (truncated) | `PERSON:Jane Ro` |
| `{"name": "Jane \"JR\" Roe"}` | `PERSON:Jane \"JR\" Roe` (raw bytes) |
| `{"name": "Zoë Ångström"}` | `PERSON:Zoë Ångström` |
| `{"note": "use \"email\": here", "id": 1}` | none |
| `{"note": "abc` + `\n` + `"email": "a@x.com"}` | `EMAIL:a@x.com` |
| `{"user": {"name": "Jane"}}]]}` (stray closers) | `PERSON:Jane` |

Also check:
- `{"address": {"line1": "1 Main St"}}` has `Score == 0.7` and `Field == "address"`, so inherited matches carry the parent's score and key.
- `TestScanJSONLarge`: `{"emails": [` + 200,000 × `"a@x.com",` + `]}` returns 200,000 matches.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/detect/ -run TestScanJSON`
Expected: FAIL (`undefined: scanJSON`)

- [ ] **Step 3: Implement `scanJSON(text string) []Match`**

One forward pass over the bytes, with no backtracking:
- **Strings:**
  - A string runs from `"` to the next unescaped `"`. A raw `\n` also ends a string; that string is then unterminated.
  - Once a string ends, skip whitespace. If the next byte is `:`, the string is a key: classify it and remember the rule as the pending value context. Otherwise the string is a value.
- **Value context:** the innermost of (a) the pending key's rule and (b) the inherited rule on top of the container stack.
  - A key that maps to *skip* gives an explicit "no type" context, which stops inheritance.
  - A key that doesn't match leaves the inherited rule in force.
- **Values in a sensitive context:**
  - A non-empty string is flagged between its quotes.
  - A number (`-?[0-9][0-9.eE+-]*`) is flagged as its own span.
  - `true`, `false` and `null` are skipped.
  - An unterminated string is flagged to the end of its line, excluding the `\n`.
- **Containers:** `{` and `[` push the current value context. `}` and `]` pop it, or are ignored when the stack is empty. The pending key is cleared after each value, and after `,`.
- **Other bytes** outside strings are ignored. That is what makes JSON inside log lines work.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/detect/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/detect/jsonfields.go internal/detect/jsonfields_test.go
git commit -m "Add tolerant JSON field scanner"
```

---

### Task 3: Table scanner

**Files:**
- Create: `internal/detect/tablefields.go`
- Test: `internal/detect/tablefields_test.go`

**Interfaces:**
- Consumes: `Classify`, `Match` (Task 1); the `got` helper (Task 2)
- Produces: `func scanTables(text string) []Match`, with `Detector: "fieldname/table"`, sorted by `Start`

- [ ] **Step 1: Write the failing tests**

Table test `TestScanTables`:

| Input | Expected |
| :- | :- |
| `id,name,email\n1,Jane Roe,jane@x.com\n` | `PERSON:Jane Roe`, `EMAIL:jane@x.com` |
| `id,name\n1,"Roe, Jane"\n` | `PERSON:Roe, Jane` |
| `id\tname\n1\tJane Roe\n` | `PERSON:Jane Roe` |
| `id;email\n1;j@x.com\n` | `EMAIL:j@x.com` |
| `psql` output (below) | `PERSON:Jane Roe`, `EMAIL:jane@x.com` |
| `\| name \| email \|\n\|---\|---\|\n\| Jane \| j@x.com \|\n` | `PERSON:Jane`, `EMAIL:j@x.com` |
| `id,plan\n1,pro\n` | none |
| `name,email\nNULL,\n` | none |
| `name,email\n` (header only) | none |
| `name,email\nJane,j@x.com\nfoo\nBob,b@x.com\n` | `PERSON:Jane`, `EMAIL:j@x.com` |
| `name,email\r\nJane,j@x.com\r\n` | `PERSON:Jane`, `EMAIL:j@x.com` |

The `psql` case:

```
 id |   name   |   email
----+----------+------------
  1 | Jane Roe | jane@x.com
(1 row)
```

Also check that the `Field` of the first CSV case's matches is `"name"` and `"email"`, the trimmed header text.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/detect/ -run TestScanTables`
Expected: FAIL (`undefined: scanTables`)

- [ ] **Step 3: Implement `scanTables(text string) []Match`**

- **Lines:** iterate line by line, keeping byte offsets. Strip a trailing `\r` from each line before parsing.
- **Header detection:** use the spec's rule exactly: at least 2 cells, every trimmed cell matches `^[A-Za-z][A-Za-z0-9 _.-]{0,63}$`, and at least one cell classifies as sensitive. Try `,`, `\t`, `;` and `|`; the delimiter giving the most cells wins.
- **Cell splitting:**
  - For `,`, `;` and tab, write a small in-line splitter that honours `"…"` quoting with `""` escapes and records each cell's byte span. Don't use `encoding/csv`, because it doesn't expose spans.
  - For `|`, split plainly, trim, and drop the empty first and last cells that an outer `|` produces.
- **Rows:**
  - Skip separator lines, made only of `-+|:` and spaces.
  - A row with the header's cell count gets its sensitive cells flagged: the trimmed span, without quotes, skipping empty cells and `NULL`/`null`.
  - Any other line ends the table, and is then checked as a new header.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/detect/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/detect/tablefields.go internal/detect/tablefields_test.go
git commit -m "Add table header field scanner"
```

---

### Task 4: `FieldNames` detector, golden fixtures, fuzz

**Files:**
- Create: `internal/detect/fieldnames.go`
- Test: `internal/detect/fieldnames_test.go`
- Create: `testdata/fieldnames/{object.json,pretty.json,records.ndjson,truncated.json,app.log,users.csv,users.tsv,psql.txt,table.md}`, each with a matching `.golden`

**Interfaces:**
- Consumes: `scanJSON`, `scanTables` (Tasks 2–3)
- Produces: `type FieldNames struct{}` implementing `Detector`; `func mergeMatches(ms []Match) []Match`

- [ ] **Step 1: Write the failing tests**

- `TestMergeMatches`: given `[{Start:0,End:10,Score:0.7}, {Start:5,End:8,Score:0.9}, {Start:20,End:25,Score:0.5}]` in any order, it returns `[{5,8,0.9}, {20,25,0.5}]`. For an equal score, the earlier `Start` is kept.
- `TestFieldNamesGolden`: for every non-golden file in `../../testdata/fieldnames/`, run `FieldNames{}.Find` and render one line per match:

  ```
  <start>-<end> <TYPE> <score %.2f> <detector> field=<field> "<value>"
  ```

  Compare against `<file>.golden`. A package-level `var update = flag.Bool("update", false, "rewrite golden files")` rewrites them.
- `FuzzFieldNames`: seeded with every fixture's contents. For any input, `Find` doesn't panic, every match has `0 <= Start < End <= len(text)`, and matches are sorted and non-overlapping.

- [ ] **Step 2: Write the fixtures**

- One fixture per file name above. Use synthetic values only (`Jane Roe`, `jane@example.com`, `555-0100`, SSN `078-05-1120`).
- Each fixture mixes sensitive and non-sensitive fields, and includes at least one skip key (`file_name`, `mac_address`).
- `app.log` mixes plain log lines with embedded JSON.

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./internal/detect/ -run 'TestMergeMatches|TestFieldNamesGolden'`
Expected: FAIL (`undefined: FieldNames`)

- [ ] **Step 4: Implement `fieldnames.go`**

- `Find` returns `mergeMatches(append(scanJSON(text), scanTables(text)...))`.
- `mergeMatches` sorts by `Start`. When a match overlaps the last kept one, the higher score wins.

- [ ] **Step 5: Generate and review the golden files**

- Run: `go test ./internal/detect/ -run TestFieldNamesGolden -update`
- Then read every `.golden` file. Check each line against the spec by hand: the right values flagged, the skip keys absent, no `\r` and no quotes in values. Fix the code, not the golden file, if a line is wrong.

- [ ] **Step 6: Run all tests and a short fuzz**

Run: `go test ./... && go test ./internal/detect/ -run '^$' -fuzz FuzzFieldNames -fuzztime 30s`
Expected: PASS, with no new failing inputs in `testdata/fuzz/`.

- [ ] **Step 7: Commit**

```bash
git add internal/detect/fieldnames.go internal/detect/fieldnames_test.go testdata/fieldnames
git commit -m "Add FieldNames detector with golden fixtures and fuzz test"
```

---

### Task 5: `basilisk scan`

**Files:**
- Create: `cmd/basilisk/scan.go`
- Modify: `cmd/basilisk/main.go`. Change `run`'s signature, and point the `scan` case at `runScan`.
- Test: `cmd/basilisk/main_test.go`

**Interfaces:**
- Consumes: `detect.FieldNames` (Task 4)
- Produces:
  - `func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int`, replacing the old signature
  - `func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int`

- [ ] **Step 1: Write the failing tests**

- Update the existing `TestRun` cases for the new signature, and drop the `scan stub` case.
- Add `TestScan` cases:
  - stdin `name,email\nJane,j@x.com\n`, no args. Exit 1, and stdout is exactly:

    ```
    -:2:1-2:5  PERSON  0.70  fieldname/table  field=name
    -:2:6-2:13  EMAIL  0.90  fieldname/table  field=email
    ```

    stdout contains neither `Jane` nor `j@x.com`.
  - stdin `{"name": "Zoë"}`. Exit 1, and the line starts `-:1:11-1:15  PERSON`. The end column counts bytes: `Zoë` is 4 bytes.
  - stdin `id,plan\n1,pro\n`. Exit 0, empty stdout.
  - Arg `testdata-missing.csv`. Exit 2, and stderr contains `testdata-missing.csv`.
  - A file written to `t.TempDir()` as `users.csv`. Lines are prefixed with that path.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/basilisk/`
Expected: FAIL, because of a compile error from the new signature or `undefined: runScan`.

- [ ] **Step 3: Implement**

- `runScan` reads stdin when there are no args; otherwise it reads each file in order. An unreadable file prints `basilisk scan: <path>: <err>` to stderr and the command exits 2 after scanning the rest.
- Positions: convert byte offsets to 1-based `line:column`, with columns in bytes. The end position is the position of `End`, which is exclusive.
- Line format: `%s:%d:%d-%d:%d  %s  %.2f  %s  field=%s`.
- `main` passes `os.Stdin`.

- [ ] **Step 4: Run to verify it passes, then try it by hand**

Run: `go vet ./... && go test ./... && go build -o basilisk ./cmd/basilisk && ./basilisk scan testdata/fieldnames/users.csv; echo "exit=$?"; rm basilisk`
Expected: tests PASS, match lines with no values, `exit=1`.

- [ ] **Step 5: Commit**

```bash
git add cmd/basilisk
git commit -m "Add basilisk scan using the field-name detector"
```
