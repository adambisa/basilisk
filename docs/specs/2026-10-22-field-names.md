# Field-name detection

Oct 22, 2026 · status: draft for review

## Goal

Find PII in structured tool output by its **field name**, not its value. The first targets are JSON keys and table headers (CSV, TSV, `psql`, markdown). If a key or header says a field holds PII, its value is flagged, whatever the value looks like.

This is the first detector in `internal/detect` and the base for column-aware petrification in [design.md](../design.md).

## Decisions

* **A sensitive field name alone is enough** to flag its value. Field names give context that value patterns can't, and a false positive in petrify mode only costs a placeholder.
* **Booleans, `null` and empty values are never flagged.** `"email_verified": true` holds no PII.
* **Fragments must work.** Agents see `head -20 users.csv`, `jq` output, truncated records and JSON inside log lines. Both scanners are tolerant and never require a full, valid document.
* **Spans are byte offsets into the original text**, so petrify can later replace values in place.

## Interface

```go
package detect

type EntityType string // "PERSON", "EMAIL", "PHONE", ...

type Match struct {
	Type     EntityType
	Start    int     // byte offset of the value, inclusive
	End      int     // byte offset of the value, exclusive
	Score    float64 // 0..1
	Detector string  // "fieldname/json" or "fieldname/table"
	Field    string  // the key or header that triggered the match
}

type Detector interface {
	Find(text string) []Match
}
```

`FieldNames` implements `Detector`. It runs the JSON scanner and the table scanner and returns their matches sorted by `Start`. Overlapping spans are merged into one match covering their union, so no matched byte goes uncovered. Its Type, Score, Detector and Field come from the highest-scored match of the group, and on equal scores from the one with the earliest Start.

## Classifying a field name

`Classify(key string) (EntityType, float64, bool)` decides whether a field name is sensitive.

1. **Split into words.** Split on any non-alphanumeric character, on lower→upper case changes (`customerEmail` → `customer email`), on acronym ends (`SSNNumber` → `ssn number`) and on letter↔digit changes (`address2` → `address 2`). Lowercase every word.
2. **Drop trailing number words.** `address_line_2` → `address line`, `phone1` → `phone`.
3. **Reduce plurals.** A final `sses` becomes `ss` (`addresses` → `address`). Otherwise a final `s` is dropped when the word is longer than three letters and doesn't end in `ss` (`emails` → `email`, `address` stays).
4. **Longest suffix match against the keyword table.** The table maps word sequences to an entity type or to *skip*. The longest sequence that matches the end of the key wins, so `email address` beats `address`, and `file name` (skip) beats `name`.
   * `customer_email` matches `email`.
   * `email_verified` ends in `verified`, so nothing matches.
   * `filename` is one word, so it doesn't match `name`.
5. **Filler fallback.** If nothing matched, drop trailing filler words (`number`, `num`, `no`, `nr`) and try step 4 again. So `SSNNumber` (`ssn number`) matches `ssn`, while `account number` still matches its own entry first.

### Initial keyword table (`en-US`)

| Type | Score | Word sequences |
| :- | :- | :- |
| `SSN` | 0.95 | ssn, social security, social security number |
| `ITIN` | 0.95 | itin |
| `EIN` | 0.9 | ein, employer identification number |
| `PASSPORT` | 0.9 | passport, passport number, passport no |
| `DRIVER_LICENSE` | 0.9 | driver license, drivers license, driving license, dl number |
| `MEDICARE` | 0.9 | medicare number, mbi |
| `CARD` | 0.95 | card number, credit card, credit card number, cc number, cvv, cvc |
| `BANK_ACCOUNT` | 0.9 | account number, acct number, iban |
| `ROUTING_NUMBER` | 0.9 | routing number, aba |
| `SECRET` | 0.9 | password, passwd, pwd, secret, client secret, api key, apikey, access token, auth token, refresh token, token, private key, credential |
| `EMAIL` | 0.9 | email, e mail, email address |
| `PHONE` | 0.9 | phone, phone number, telephone, tel, mobile, cell phone, cellphone, fax |
| `DOB` | 0.9 | dob, birthdate, birth date, date of birth, birthday |
| `IP_ADDRESS` | 0.6 | ip, ip address, ipaddr |
| `PERSON` | 0.7 | name, firstname, lastname, fullname, surname, given name, family name, middle name, maiden name |
| `USERNAME` | 0.6 | username, user name, screen name |
| `ADDRESS` | 0.7 | address, street, street address, address line, zip, zipcode, zip code, postal code, postcode |
| `ADDRESS` | 0.5 | city |
| *skip* | | file name, host name, server name, domain name, table name, column name, field name, class name, type name, key name, bucket name, branch name, repo name, image name, package name, module name, function name, method name, event name, tag name, app name, project name, product name, service name, device name, queue name, topic name, index name, cluster name, region name, node name, param name, variable name, env name, dir name, folder name, path name, model name, brand name, category name, role name, plan name, template name, feature name, metric name, label name, company name, org name, organization name, business name, secret name, mac address, wallet address, memory address, web address, server address |

`display name`, `contact name` and `full name` deliberately stay `PERSON`, because they usually hold a real person's name. `state` and `county` are left out: `"state": "pending"` is far more common than a US state.

## JSON scanner

A single pass over the bytes, not `encoding/json`.

* **Keys:** a double-quoted string, followed by optional whitespace and `:`, is a key. Text outside strings that isn't JSON structure is ignored, so JSON embedded in a log line is found.
* **Values:**
  * Under a sensitive key, a string is flagged as the span between its quotes, escapes included as raw bytes. A number is flagged as its own span.
  * `true`, `false` and `null` are skipped. So are empty strings.
* **Nesting:** the scanner keeps a stack of open objects and arrays.
  * An object or array opened under a sensitive key passes its type down. Every string or number inside is flagged with that type (`"emails": ["a@x.com", "b@y.com"]`, `"address": {"line1": "…"}`).
  * An inner key with its own match uses its own type. An inner key that maps to *skip* turns the inheritance off for its value.
  * A closer with no matching opener is ignored.
* **Truncation:** a string under a sensitive key that never closes is flagged up to the end of its line (fail closed).
  * A string that ends unterminated (at a raw newline or at the end of input) clears the stack of open containers, so a cut does not make everything after it inherit the open sensitive context. A raw newline cannot occur inside valid JSON, so pretty-printed JSON is unaffected.
  * A `{` or `[` in column 0 (the first byte of a line) while containers are open starts a new NDJSON record: the stack and any pending key are cleared before it is pushed. Pretty printers indent nested openers.
  * A `\r` before the newline that ends an unterminated string is not part of the flagged span.
* **Not covered:** JSON escaped inside another JSON string (`"{\"email\":\"x\"}"`), single-quoted Python dicts, and YAML.

## Table scanner

Line by line. A leading UTF-8 BOM is skipped (Excel's "CSV UTF-8" export starts with one); spans stay offsets into the original text.

* **Header:** a line is a header candidate for delimiter `d` (`,`, tab, `;` or `|`) when:
  * it splits into at least two cells
  * every trimmed cell is identifier-like (`^[A-Za-z][A-Za-z0-9 _.-]{0,63}$`)
  * at least one cell classifies as sensitive

  If several delimiters qualify, the one giving the most cells wins. The header itself is never flagged.
* **Rows:** each following line is split with the same delimiter. CSV quoting rules apply for `,`, `;` and tab. For `|`, cells are split plainly, trimmed, and an outer leading and trailing `|` is ignored.
  * A row with the header's cell count has its sensitive cells flagged: the trimmed span, without surrounding quotes.
  * Empty cells and `NULL` / `null` are skipped.
* **Separators:** lines made only of `-`, `+`, `|`, `:` and spaces (`psql`'s `---+---`, markdown's `|---|`) are skipped without ending the table.
* **End of table:** a row with a different cell count ends the table, and so does a `psql` footer like `(3 rows)`. The next line can start a new table.
* **Not covered:** quoted CSV cells that span several lines, fragments without a header (`tail users.csv`), and `psql` expanded output (`\x`) and two-column key/value tables. Their first line is read as a header, so their values are missed.

## `basilisk scan`

* **Input:** reads stdin, or the files given as arguments.
* **Output:** one line per match, without printing the value. Positions are `line:column`, 1-based, with columns in bytes; stdin shows as `-`.
  Field names containing control or non-printable characters are printed Go-quoted.

  ```
  users.csv:3:14-3:31  EMAIL  0.90  fieldname/table  field=email
  ```

* **Exit codes:** 1 if anything was found, 0 if not, 2 on usage errors, like gitleaks. Scripts and the hooks can rely on this.

## Testing

* **Key splitting and classification:** table-driven tests for every rule above, plus the examples in this spec (`customerEmail`, `SSNNumber`, `address_line_2`, `email_verified`, `file_name`, `filename`, `addresses`).
* **Golden fixtures:** synthetic fixtures in `testdata/fieldnames/` (JSON, NDJSON, pretty-printed, truncated, log line with JSON, CSV, TSV, `psql`, markdown). Each has a `.golden` file listing the expected matches. `go test ./... -update` rewrites them. All values are made up.
* **Fuzz:** `FuzzFieldNames` checks for arbitrary input that `Find` never panics, every span is inside the text, and spans don't overlap.
* **CLI:** `basilisk scan` exit codes and output format, in the existing `cmd/basilisk` table test.

## Out of scope

* Free-text context phrases ("lives at …"), the next detector
* Value detectors (Luhn, SSN ranges, …)
* YAML, `key=value` logs, Python reprs, escaped JSON
* Remembering headers across reads
* Wiring into the hooks or petrify
