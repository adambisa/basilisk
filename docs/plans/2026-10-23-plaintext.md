# Plaintext Detectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect emails, phones, IP/MAC addresses, US identifiers, dates of birth, person names and street addresses in free text, all scored with one log-odds evidence model.

**Architecture:**
- **Evidence model:** a small type in `evidence.go`. It holds a prior plus weighted evidence, and the score is the logistic of the sum.
- **Finders:** each detector is one file with `func findX(text string) []Match`, registered in `valueFinders`, so `All` and `basilisk scan` pick it up.
- **Word lists:** names, surnames, street suffixes and top-level domains (TLDs) come from public-domain sources. A uv-run generator downloads them, and they are embedded under `internal/detect/data/`.

**Tech Stack:** Go 1.27 standard library (`net/netip`, `embed`, `math`, `time`). Python 3.11+ standard library for the generator, run with `uv run --script`.

**Spec:** [docs/specs/2026-10-23-plaintext.md](../specs/2026-10-23-plaintext.md). Every weight, prior and keyword list comes from the spec. Copy them verbatim as named constants.

## Global Constraints

- **Module:** `github.com/adambisa/basilisk`, Go 1.27, no third-party Go dependencies.
- **Spans:** byte offsets into the original text. Start is inclusive, End is exclusive.
- **Scoring:** `score = 1/(1+e^-L)`. A match is emitted only when score ≥ 0.30 (`minScore`).
- **Evidence string format:** `name±w` items, in the order they were added. The first item is `prior`. Weights are printed with one decimal and an explicit sign, for example `prior-2.5 first:t3+2.0 pair+1.5`.
- **Keyword evidence:** `keywordBefore`, which looks back 32 bytes. Phrase evidence for names and addresses looks back 48 bytes on the same line.
- **Rule ids:**
  - `email`
  - `phone/e164`, `phone/nanp`
  - `ip/v4`, `ip/v6`, `mac`
  - `ssn`, `itin`, `ein`, `aba`, `vin`, `mbi`
  - `dob`
  - `name`
  - `address`, `address/pobox`
- **Detector strings:** `value/email`, `value/phone`, `value/netaddr`, `value/usid`, `value/dob`, `value/name`, `value/address`.
- **Locale:** `en-US` only.
- **`basilisk scan`:** never prints a matched value.
- **Test data:** synthetic values only. Use example.com emails, 555-01xx phone numbers, documentation IP ranges, the SSN 078-05-1120, and published test vectors.
- **Commit trailer:** end every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Code identifiers in Go source, logs and stack traces.** Examples: `Field`, `Match`, `Rose.Bud`, `getMark()`. These must never become 0.9+ names. Test in Task 8, and the guard runs in Task 10.
2. **Version strings and timestamps.** `v1.2.3.4`, `build 415-555-2671`, `12:30:45` and ISO dates in logs must not become IPs, phones or dates of birth at 0.9 or above. Tests in Tasks 4, 5 and 7.
3. **Overlaps between detectors.** For example an address that contains a ZIP, a name inside an email local part, or a phone number inside an address line. The union merge must leave non-overlapping spans. Test in Task 10.
4. **Non-ASCII names.** `José García` and `Zoë Ångström` must produce correct spans and not panic. Test in Task 8.
5. **Generator robustness.** A missing or changed upstream format must make the generator fail loudly, never write an empty list. Test in Task 2.

---

### Task 1: Evidence model and new types

**Files:**
- Create `internal/detect/evidence.go` and `internal/detect/evidence_test.go`.
- Modify `internal/detect/detect.go`.

**Interfaces:**
- Produces:
  - `TypeMAC` and `TypeVIN`
  - the `Match.Evidence string` field
  - `newEvidence(prior float64) *evidence`
  - `(*evidence).add(name string, w float64)`
  - `(*evidence).score() float64`
  - `(*evidence).String() string`
  - `const minScore = 0.30`
  - `func (e *evidence) match(t EntityType, start, end int, detector, rule string) (Match, bool)`, which returns the match with `Score` and `Evidence` filled in, and false when the score is below `minScore`.

- [ ] **Step 1: Write failing tests**

`TestEvidenceScore` pins the logistic:

| L | Score |
| :- | :- |
| 3.0 | 0.9526 (±1e-4) |
| 2.2 | 0.9002 |
| 0 | 0.5 |
| −0.85 | 0.2994 |

`TestEvidenceString`: `newEvidence(-2.5)`, then `add("first:t3", 2.0)` and `add("pair", 1.5)`, gives `"prior-2.5 first:t3+2.0 pair+1.5"`.

`TestEvidenceMatch`:
- An evidence with prior −1.0 gives false, because 0.27 < 0.30.
- Prior −0.8 gives true, with `Score` ≈ 0.31 and `Evidence == "prior-0.8"`.

- [ ] **Step 2: Run the tests and confirm they fail** with `undefined: newEvidence`.
- [ ] **Step 3: Implement.** Use `math.Exp`. `String` formats with `%+.1f` and a leading `prior`.
- [ ] **Step 4: Run** `go vet ./... && go test ./...` and confirm they pass.
- [ ] **Step 5: Commit** `Add log-odds evidence model`.

---

### Task 2: Data generator and embedded lists

**Files:**
- Create:
  - `scripts/gen_lists.py`
  - `internal/detect/data/{tlds.txt,first_names.txt,surnames.txt,name_words.txt,street_suffixes.txt,SOURCES}`
  - `internal/detect/lists.go`, `internal/detect/lists_test.go`
- Modify: `.gitattributes`, `NOTICE`.

**Interfaces:**
- Produces:
  - `func tldKnown(label string) bool`, case-insensitive
  - `func firstNameTier(lower string) int`, which returns 0 when the name isn't listed
  - `func surnameTier(lower string) int`
  - `func isNameWord(lower string) bool`
  - `func isStreetSuffix(lower string) bool`, which takes the form without a trailing `.`

Every lookup loads its data once.

- [ ] **Step 1: Write the generator.**
  - PEP 723 header: `requires-python = ">=3.11"`, `dependencies = []`.
  - Download every source in the spec's Data section with `urllib.request`. Write the files exactly as the spec describes, and write `SOURCES` with each URL and the UTC date.
  - Validate before writing. Each list must have a minimum size: TLDs ≥ 1000, first names = 20000, surnames = 20000, suffixes ≥ 300 forms. Any failed download or validation exits non-zero and writes nothing.
  - Add `//go:generate uv run --script ../../scripts/gen_lists.py` to `lists.go`.
- [ ] **Step 2: Run** `go generate ./internal/detect/`, then run it again and confirm the second run leaves `git status` unchanged.
  - If any source is unreachable (403, a login wall), report NEEDS_CONTEXT with the URL and the error.
  - Never type a list from memory.
- [ ] **Step 3: Write failing tests** in `lists_test.go`:

| Call | Expected |
| :- | :- |
| `tldKnown("com")`, `tldKnown("COM")`, `tldKnown("io")` | true |
| `tldKnown("comm")` | false |
| `firstNameTier("jennifer")` | 3 |
| `surnameTier("smith")` | 3 |
| `firstNameTier("zzzz")` | 0 |
| `isNameWord("mark")` | true |
| `isNameWord("jennifer")` | false |
| `isStreetSuffix("st")`, `isStreetSuffix("avenue")`, `isStreetSuffix("blvd")` | true |
| `isStreetSuffix("apple")` | false |

Also add `TestListSizes`, which checks that the embedded line counts meet the same minimums as the generator.
- [ ] **Step 4: Implement** `lists.go`: `go:embed data/*.txt`, parsed into maps with `sync.Once`.
- [ ] **Step 5:** Add `internal/detect/data/* linguist-generated=true` to `.gitattributes` and the spec's attribution line to `NOTICE`.
- [ ] **Step 6: Run** `go vet ./... && go test ./...` and confirm they pass.
- [ ] **Step 7: Commit** `Add generated name, suffix and TLD lists`.

---

### Task 3: Email

**Files:** create `internal/detect/email.go` and `internal/detect/email_test.go`.

**Interfaces:**
- Consumes: `evidence` (Task 1), `tldKnown` (Task 2).
- Produces: `findEmails`, registered in `valueFinders`.

- [ ] **Step 1: Write failing tests** for `TestFindEmails`, given as input → Rule@Score:value or none:

| Input | Expected |
| :- | :- |
| `"mail jane.roe@example.com now"` | `email@0.95:jane.roe@example.com`, with Evidence `"prior+3.0"` |
| `"git@github.com:adambisa/basilisk.git"` | `email`, score `logistic(0.5)` ≈ 0.62, Evidence `"prior+3.0 role-2.5"` |
| `"a@b.comm"` | none (unknown TLD) |
| `"x@localhost"` | none |
| `".a@example.com"` | none |
| `"user@exa_mple.com"` | none |

Also check `Type == TypeEmail` and `Detector == "value/email"`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.** Find each `@`, then expand left over local-part characters and right over domain characters. Validate both, then check boundaries.
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit** `Add email detector`.

---

### Task 4: Phone

**Files:** create `internal/detect/phone.go` and `internal/detect/phone_test.go`.

**Interfaces:**
- Consumes: `evidence`, `keywordBefore`.
- Produces: `findPhones`, registered in `valueFinders`.

- [ ] **Step 1: Write failing tests** for `TestFindPhones`:

| Input | Expected |
| :- | :- |
| `"call (415) 555-0123"` | `phone/nanp`, L = 1.4 + 2.0, score ≈ 0.968 |
| `"415-555-0123"` | `phone/nanp`, ≈ 0.80 |
| `"4155550123"` | none: −1.5 gives 0.18 |
| `"phone 4155550123"` | `phone/nanp`, L = 0.5, ≈ 0.62 |
| `"+1 415 555 0123"` | `phone/nanp`, ≈ 0.80 |
| `"+420 777 123 456"` | `phone/e164`, ≈ 0.90 |
| `"+44 20 7946 0958"` | `phone/e164` |
| `"build 415-555-0123"` | L = 1.4 − 3.0 = −1.6, none |
| `"411-555-0123"` (exchange rule is N11 for the exchange only, so a 411 area code is still valid) | `phone/nanp` |
| `"415-211-0123"` (exchange 211 is N11) | none |
| `"1415555012345"` (inside a longer run) | none |

Also check `Type == TypePhone`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.** Scan maximal runs of digits and allowed separators (single space, `-`, `.`, `(`, `)`), with an optional leading `+`. Classify each run as E.164 or NANP, then apply the prior, keyword and version evidence.
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit** `Add phone detector`.

---

### Task 5: IP and MAC addresses

**Files:** create `internal/detect/netaddr.go` and `internal/detect/netaddr_test.go`.

**Interfaces:**
- Consumes: `evidence`, `keywordBefore`.
- Produces: `findNetAddrs`, registered in `valueFinders`.

- [ ] **Step 1: Write failing tests** for `TestFindNetAddrs`:

| Input | Expected |
| :- | :- |
| `"client 8.8.8.8"` | `ip/v4`, L = 1.4 + 1.0 |
| `"10.0.0.5"` | `ip/v4`, L = −0.5, ≈ 0.38 |
| `"192.0.2.10"` | `ip/v4`, ≈ 0.38 |
| `"version 1.2.3.4"` | none |
| `"1.2.3.4.5"` | none |
| `"256.1.1.1"` | none |
| `"2001:4860:4860::8888"` | `ip/v6`, ≈ 0.80 |
| `"2001:db8::1"` | `ip/v6`, ≈ 0.38 |
| `"12:30:45"` | none |
| `"::"` | none |
| `"mac 00:1A:2B:3C:4D:5E"` | `mac`, L = 0.8 + 1.5 |
| `"00-1A-2B-3C-4D-5E"` | `mac` |
| `"001a.2b3c.4d5e"` | `mac` |
| `"00:00:00:00:00:00"` | `mac`, L = −1.2, none |

Also check that IP results are `TypeIPAddress` and MAC results are `TypeMAC`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement** with `netip.ParseAddr`. Classify using `IsPrivate`, `IsLoopback`, `IsLinkLocalUnicast`, `IsUnspecified`, `IsMulticast`, plus explicit prefixes for CGNAT and the documentation ranges.
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit** `Add IP and MAC detector`.

---

### Task 6: US identifiers

**Files:** create `internal/detect/usids.go` and `internal/detect/usids_test.go`.

**Interfaces:**
- Consumes: `evidence`, `keywordBefore`, the ABA 3-7-1 checksum.
- Produces: `findUSIDs`, registered in `valueFinders`. Also `func vinCheckValid(vin string) bool` and `func abaValid(d string) bool`.

- [ ] **Step 1: Source the EIN prefixes.** Read the IRS page "How EINs are assigned and valid EIN prefixes" and copy its prefix list into `usids.go`, with the URL and date in a comment. If the page can't be read, skip the prefix check and say so in the report.
- [ ] **Step 2: Write failing tests**

`TestFindUSIDs`:

| Input | Expected |
| :- | :- |
| `"SSN 078-05-1120"` | `ssn@≈0.95`, Evidence `"prior-0.5 keyword+3.5"` |
| `"078-05-1120"` | `ssn`, ≈ 0.38 |
| `"078051120"` | none |
| `"ssn 078051120"` | `ssn`, L = 0.5 |
| `"SSN 666-12-3456"`, `"SSN 900-12-3456"`, `"SSN 123-00-4567"`, `"SSN 123-45-0000"` | none |
| `"ITIN 912-70-1234"` | `itin`, L = 3.0 |
| `"ITIN 912-40-1234"` | none |
| `"EIN 12-3456789"` | `ein`, L = 2.5 (if the 12 prefix is valid) |
| `"routing 011000015"` | `aba`, L = 1.5 |
| `"011000016"` | none (checksum) |
| `"VIN 1HGCM82633A004352"` | `vin`, check digit valid, L = 1.5 + 2.5 |
| `"1HGCM82633A004351"` (check digit wrong) | prior −1.0, none |
| `"medicare 1EG4-TE5-MK73"` with hyphens removed, `1EG4TE5MK73` | `mbi`, L = 3.5 |

`TestVINCheck`: `1HGCM82633A004352` is valid; changing one character makes it invalid.

Also check the types per the spec mapping.
- [ ] **Step 3: Run the tests and confirm they fail.**
- [ ] **Step 4: Implement.** Scan the candidate shapes and validate each. The VIN transliteration table and weights `8 7 6 5 4 3 2 10 0 9 8 7 6 5 4 3 2` follow 49 CFR 565. Position 9 holds the remainder mod 11, with 10 written as `X`.
- [ ] **Step 5: Run the tests and confirm they pass.**
- [ ] **Step 6: Commit** `Add US identifier detector`.

---

### Task 7: Date of birth

**Files:** create `internal/detect/dob.go` and `internal/detect/dob_test.go`.

**Interfaces:**
- Consumes: `evidence`, `keywordBefore`.
- Produces: `findDOBs`, registered in `valueFinders`. Also `var today = func() time.Time { return time.Now() }`, which tests override.

- [ ] **Step 1: Write failing tests.** Set `today` to 2026-10-23 in each test and restore it afterwards. `TestFindDOBs`:

| Input | Expected |
| :- | :- |
| `"born 1985-03-04"` | `dob`, L = 1.5, ≈ 0.82 |
| `"DOB: 03/04/1985"` | `dob` |
| `"d.o.b. 04.03.1985"` | `dob` |
| `"date of birth March 4, 1985"` | `dob` |
| `"born 4 Mar 1985"` | `dob` |
| `"2019-03-04"` | none |
| `"born 1985-02-30"` | none (not a real date) |
| `"born 2027-01-01"` | none (future) |
| `"born 1890-01-01"` | none (age over 120) |
| `"born 2024-02-29"` | `dob` (leap day) |
| `"born 2023-02-29"` | none |
| `"born 12:30:45"` | none |

Also check `Type == TypeDOB`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.** Use a candidate scanner per format, then `time.Date` and a round-trip comparison for validity.
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit** `Add date-of-birth detector`.

---

### Task 8: Names

**Files:** create `internal/detect/names.go` and `internal/detect/names_test.go`.

**Interfaces:**
- Consumes: `evidence`, `firstNameTier`, `surnameTier`, `isNameWord` (Task 2).
- Produces: `findNames`, registered in `valueFinders`.

- [ ] **Step 1: Write failing tests.** `TestFindNames` asserts each listed sum. Read the actual tiers from the embedded lists and write them into the expected L.

| Input | Expected |
| :- | :- |
| `"I spoke to Jane Roe yesterday"` | one `name` span `Jane Roe`. L = −2.5 + first(jane) + surname(roe) + 1.5 |
| `"Mark the date in the calendar"` | none |
| `"Dear Rose,"` | `name` `Rose`, score ≥ 0.30, Evidence includes `phrase+1.5` |
| `"Mr. Smith called"` | `name` `Smith`, with `title+2.5` |
| `"José García signed"` | one span covering both tokens with byte-correct offsets (Review Focus 4) |
| `"Zoë Ångström"` | no panic; span bytes valid |
| `"John J. Smith"` | one span covering all three |
| Go source line `func (m Match) Field() string { return m.Rule }` (Review Focus 1) | no match ≥ 0.9 |
| `"getMark()"`, `"Rose.Bud"`, `"user_Jane"` | none |
| `"MARK"` | the all-caps penalty applies |

Also check `Type == TypePerson` and `Detector == "value/name"`, and assert the exact `Evidence` for `Jane Roe`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
  - Tokenise each line into candidate tokens with byte offsets. Apply the non-name-token rules, then group up to three consecutive tokens, allowing a middle initial.
  - Compute the evidence per span in the spec's table order: prior, then list hits per token, pair, word penalty, title, phrase, sentence start, all caps.
  - Lowercase with `strings.ToLower` for lookups.
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit** `Add person-name detector`.

---

### Task 9: Addresses

**Files:** create `internal/detect/address.go` and `internal/detect/address_test.go`.

**Interfaces:**
- Consumes: `evidence`, `isStreetSuffix` (Task 2).
- Produces: `findAddresses`, registered in `valueFinders`. Also `usStates`, a map from USPS code or lowercased full name to the canonical code.

- [ ] **Step 1: Write failing tests** for `TestFindAddresses`:

| Input | Expected |
| :- | :- |
| `"12 Elm St"` | `address`, L = 0.5, ≈ 0.62, Evidence `"prior-1.0 street+1.5"` |
| `"12 Elm St, Springfield, IL 62704"` | one span over everything, L = 3.5 |
| `"lives at 12 Elm St"` | L = 2.0 |
| `"1600 Pennsylvania Avenue NW, Washington, DC 20500"` | one span, with state and ZIP |
| `"221B Baker Street"` | `address` |
| `"Apt 4B"`, on the same line after a street | the unit is included in the span |
| `"PO Box 123"` and `"P.O. Box 123"` | `address/pobox`, L = 0.5 |
| `"chapter 3 of the book"` | none |
| `"12 apples"` | none |
| `"version 2 Main"` | none, because no suffix follows |

Also check `Type == TypeAddress`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
  - Find house-number tokens. Look ahead up to 5 words for a street suffix, optionally followed by `.` and a directional.
  - Then extend greedily through unit, city, state and ZIP, in that order.
  - Write `usStates` in Go: the 50 states, DC, AS, GU, MP, PR and VI.
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit** `Add street-address detector`.

---

### Task 10: Guard, goldens, measurement, fuzz, README

**Files:**
- Create:
  - `testdata/values/clean/prose.txt`
  - `testdata/golden/{signature.txt,ticket.txt,shipping.txt}`, each with its `.golden`
- Modify:
  - `internal/detect/fieldnames_test.go`: add an overlap test
  - `cmd/basilisk/main_test.go`: add a CLI case
  - `README.md`

- [ ] **Step 1: Write the fixtures.**
  - `prose.txt` is technical prose with no people: written for this repo, a changelog, and code comments.
  - The golden fixtures use only synthetic values:
    - `signature.txt`: an email signature with a name, title, phone and email.
    - `ticket.txt`: a support ticket with a DOB, an SSN with its keyword, and an address.
    - `shipping.txt`: a shipping note with a full address line and a phone number.
- [ ] **Step 2: Write tests.**
  - `TestPlaintextOverlap` (Review Focus 3): `"Jane Roe <jane.roe@example.com>, 12 Elm St, Springfield, IL 62704, (415) 555-0123"` gives non-overlapping matches, with the name, email, address and phone each found.
  - Add a `TestScan` case: a prose line with an email prints `rule=email` and never the address itself.
  - Run the existing `TestNoPIIGuard` with the new `prose.txt` in the clean directory. It must pass, and the guard rule stands: if it fails, don't change fixtures, weights or lists. Report the file, rule, score and evidence, then report DONE_WITH_CONCERNS.
- [ ] **Step 3: Regenerate and read the goldens.** Run `go test ./internal/detect/ -run TestGolden -update`, then read every new and changed golden line against the spec, and explain every change to an existing golden line in the report.
- [ ] **Step 4: Measure.** In the report, list:
  - per rule, the number of matches at ≥ 0.9 and at ≥ 0.3 across all clean fixtures
  - the number of `name` matches at ≥ 0.3 in `prose.txt`

  The script or test you used goes in the report, not the repo.
- [ ] **Step 5: Run everything.**

```bash
go vet ./... && go test -count=1 ./... && go test ./internal/detect/ -run '^$' -fuzz FuzzAll -fuzztime 30s
```

Check that `gofmt -l .` prints nothing.
- [ ] **Step 6: Update the README.** Change the README status to: "`basilisk scan` finds PII and secrets in text: by field name in JSON and tables; by value for cards, IBANs, passport MRZ lines, crypto wallets and API keys; and in free text for emails, phone numbers, IP/MAC addresses, US identifiers, dates of birth, names and street addresses."
- [ ] **Step 7: Commit** `Add plaintext guard, goldens and measurements`.
