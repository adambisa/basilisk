# Plaintext detectors

Oct 23, 2026 · status: approved to build ("build it", Adam, 2026-10-23)

## Goal

Find PII in free text, such as prompts, messages, prose and logs, where there are no field names and few checksums. This covers emails, phone numbers, IP and MAC addresses, US identifiers, dates of birth, person names and street addresses.

Locale: `en-US` only. Czech (names, `+420`, rodné číslo) comes later as its own locale pack.

## Decisions

* **One scoring model: log-odds.** Every detector in this spec scores a candidate the same way:
  1. Start from a prior: the log-odds that a candidate of this shape is PII.
  2. Add a weight for each piece of evidence found. Counter-evidence has a negative weight.
  3. The score is the logistic of the sum: `score = 1 / (1 + e^-L)`.

  For reference: L = 3 gives 0.95, 2.2 gives 0.90, 1.1 gives 0.75, 0 gives 0.50, and −0.85 gives 0.30. A candidate is emitted only when its score is at least **0.30**.
* **Explainable.** Every match records its evidence, for example `prior-2.5 first:t3+2.0 pair+1.5`. Block mode will show this to the user later. `scan` doesn't print it yet.
* **Weights are hand-set** in this spec, as named constants in the code. A later step fits them on labelled synthetic text. The Tier 1 detectors keep their fixed scores.
* **Data comes only from public-domain or US-government sources.** A uv-run generator downloads it, and the generated lists are committed, so a build needs no network.
* **Spans are byte offsets** into the original text, as everywhere else. All new finders register in `valueFinders`, so `All` and `scan` pick them up.

## Interface

```go
// detect.go additions
const (
	TypeMAC EntityType = "MAC_ADDRESS"
	TypeVIN EntityType = "VIN"
)

type Match struct {
	// existing fields unchanged
	Evidence string // log-odds evidence, e.g. "prior-2.5 first:t3+2.0"; empty for Tier 1 and field-name matches
}

// evidence.go
type evidence struct{ /* sum and the list of (name, weight) */ }
func newEvidence(prior float64) *evidence
func (e *evidence) add(name string, w float64)
func (e *evidence) score() float64   // logistic of the sum
func (e *evidence) String() string   // "prior-2.5 name+w ..." in the order added, one decimal, sign always shown
const minScore = 0.30
```

## Shared helpers

* **Keyword evidence.** Weights below that mention a keyword use `keywordBefore` (whole word, case-insensitive, within 32 bytes before the candidate, same line). The one exception is phrase evidence for names and addresses, which looks back **48 bytes**.
* **Boundaries.** Every candidate must satisfy `atBoundary`, unless a detector below says otherwise.

## Email (`email.go`)

* **Candidate:** `local@domain`.
  * `local` is `[A-Za-z0-9._%+-]{1,64}` and doesn't start or end with `.`.
  * `domain` is two or more labels of `[A-Za-z0-9-]{1,63}` joined by `.`, and its last label is in the IANA top-level domain list.
* **Prior:** 3.0.
* **Counter-evidence:** a role local part (`git`, `noreply`, `no-reply`, `donotreply`, `do-not-reply`, `mailer-daemon`, `postmaster`) adds −2.5.
* **Rule:** `email`.

## Phone (`phone.go`)

* **`phone/e164`:** `+`, then a country code of 1–3 digits, then a national number. The total is 8–15 digits.
  * Single spaces, hyphens or dots are allowed between groups, and one `(…)` group.
  * Prior 2.2.
* **`phone/nanp`:** 10 digits laid out as `NXX NXX XXXX`, where N is 2–9, the exchange isn't `N11`, and there's an optional leading `1` or `+1`.
  * Formatted as `(NXX) NXX-XXXX`, `NXX-NXX-XXXX`, `NXX.NXX.XXXX` or `NXX NXX XXXX`: prior 1.4.
  * Bare 10 digits: prior −1.5.
  * A `+1` number is a NANP candidate, not an E.164 one.
* **Evidence:** keyword phone, tel, telephone, mobile, cell, call, text, fax, whatsapp, sms adds +2.0.
* **Counter-evidence:** a version context just before the candidate (`v`, `version`, `build`, `release`) adds −3.0.
* **Rejected:** candidates inside a longer digit run.

## IP and MAC (`netaddr.go`)

* **`ip/v4`:** dotted quad, parsed with `net/netip`. The candidate must not be followed by `.` plus a digit.
* **`ip/v6`:** a run of hex digits and colons with at least two colons that `netip.ParseAddr` accepts, optionally with an embedded IPv4.
* **IP priors:**
  * 1.4 for a global unicast address.
  * −0.5 for private, loopback, link-local, CGNAT `100.64.0.0/10`, unspecified, multicast and the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
* **IP evidence:** keyword ip, addr, address, client, remote, host, from, src, dst adds +1.0.
* **IP counter-evidence:** a version context adds −3.0.
* **`mac`:** six hex pairs joined by a single `:` or `-`, or Cisco's `xxxx.xxxx.xxxx`.
  * Prior 0.8.
  * All zeros or `ff:ff:ff:ff:ff:ff` adds −2.0.
  * Keyword mac, ether, hwaddr, bssid adds +1.5.

## US identifiers (`usids.go`)

| Rule | Candidate | Prior | Evidence |
| :- | :- | :- | :- |
| `ssn` | `AAA-GG-SSSS`: −0.5. `AAA GG SSSS`: −1.0. 9 bare digits: −3.0. Rejected if area is 000, 666 or 900–999, group is 00, or serial is 0000. | as left | ssn, social security, ss#, soc sec: +3.5 |
| `itin` | `9AA-GG-SSSS` with group in 50–65, 70–88, 90–92 or 94–99 | 0.0 | itin: +3.0 |
| `ein` | `PP-NNNNNNN`, where PP is a valid IRS campus prefix | −1.0 | ein, fein, tax id, employer id, tin: +3.5 |
| `aba` | 9 digits whose first two are 00–12, 21–32, 61–72 or 80, passing the 3-7-1 checksum | −2.5 | routing, aba, rtn, transit: +4.0 |
| `vin` | 17 characters from `[A-HJ-NPR-Z0-9]`, with at least 3 letters and 3 digits | 1.5 if the North American check digit (position 9) is valid, otherwise −1.0 | vin, vehicle, chassis: +2.5 |
| `mbi` | the Medicare MBI layout: C A AN N A AN N A A N N, where letters exclude S, L, O, I, B, Z and position 1 is 1–9 | 0.5 | mbi, medicare: +3.0 |

* **EIN prefixes:** the valid prefix list comes from the IRS page "How EINs are assigned and valid EIN prefixes", with the source recorded in a comment. If the page can't be read, the prefix check is skipped and the plan's report says so.
* **Type mapping:** `ssn` → `TypeSSN`, `itin` → `TypeITIN`, `ein` → `TypeEIN`, `aba` → `TypeRoutingNumber`, `vin` → `TypeVIN`, `mbi` → `TypeMedicare`.

## Date of birth (`dob.go`)

* **Candidate formats:**
  * `YYYY-MM-DD`
  * `MM/DD/YYYY`
  * `DD.MM.YYYY`
  * `Month D, YYYY` and `D Month YYYY`, with English month names or three-letter abbreviations
* **Validity:** the date must exist on the calendar, leap years included. The age must be 0–120 years, relative to a package variable `today` that tests set. Future dates are rejected.
* **Prior:** −3.0, because dates are everywhere.
* **Evidence:** keyword dob, d.o.b, born, birth, birthday, birthdate, date of birth adds +4.5.
* **Rule:** `dob`.

## Names (`names.go`)

* **Candidate:** one to three consecutive name tokens on one line, separated by single spaces.
  * A middle initial such as `J.` may sit between them.
  * A token is a capitalised word: an uppercase letter followed by lowercase letters, Latin-1 letters allowed, optionally joined by `-` or `'` (`Smith-Jones`, `O'Brien`).
* **Not a name token:** a token touching `.`, `_`, `/`, `(` or a digit with no space between, and camelCase words. That keeps code identifiers out.
* **Evidence:**

| Evidence | Weight |
| :- | :- |
| prior | −2.5 |
| first-name list hit (SSA), per token | tier 3 +2.0, tier 2 +1.4, tier 1 +0.8 |
| surname list hit (Census), per token | tier 3 +2.0, tier 2 +1.4, tier 1 +0.8 |
| a first name followed by a surname in the span | +1.5 |
| single-token span that is also a common English word | −1.2 |
| title just before: Mr, Mrs, Ms, Miss, Dr, Prof, Sir, Madam, Rev (optional `.`) | +2.5 |
| phrase within 48 bytes before: my name is, i am, i'm, this is, dear, hi, hello, thanks, regards, sincerely, signed, contact, patient, employee, customer, client | +1.5 |
| single-token span at a sentence start (text start, after `. ` `! ` `? `, or a line start) | −0.8 |
| an all-caps token | −0.7 |

* **Tiers:**
  * Tier 3 is a name in the top 1,000 of its list.
  * Tier 2 is a name in the top 5,000.
  * Tier 1 is any other listed name.
  * A token takes its best tier from each list. A token in both lists gets both weights only when the span has one token.
* **Rule and type:** `name`, `TypePerson`.

## Addresses (`address.go`)

* **Candidate:** a house number, 1–6 digits with an optional letter, then 1–5 words, then a USPS street suffix (with an optional `.` and a directional before or after). It extends greedily on the same line through each of these, in order, where present:
  1. a unit: `Apt`, `Apartment`, `Suite`, `Ste`, `Unit` or `#` plus an id
  2. `, ` and a city of 1–3 words
  3. `, ` or a space and a state: the USPS two-letter code or the full name
  4. a ZIP: 5 digits or ZIP+4
* **PO boxes:** `PO Box N` and `P.O. Box N` are candidates too.
* **Evidence:**

| Evidence | Weight |
| :- | :- |
| prior | −1.0 |
| number + street suffix | +1.5 |
| PO Box form (instead of number + suffix) | +1.5 |
| unit | +0.5 |
| state | +1.0 |
| ZIP | +1.5 |
| state and ZIP together | +0.5 |
| phrase within 48 bytes before: lives at, live at, living at, address, located at, ship to, deliver to, mail to, residing at, send to, home | +1.5 |

* **Rules and type:** `address` or `address/pobox`, `TypeAddress`.
* **States:** the list (50 states, DC and the 5 inhabited territories, codes and full names) is written in Go source.
* **Street suffixes:** generated from USPS Publication 28, Appendix C1.

## Data (`scripts/gen_lists.py`, `internal/detect/data/`)

* **The generator** is a uv script that needs only the standard library. It downloads each source, writes the files below one entry per line, sorted, and records each source URL and date in `internal/detect/data/SOURCES`.
* **Files:**
  * `tlds.txt`: lowercase IANA TLDs, from `https://data.iana.org/TLD/tlds-alpha-by-domain.txt`.
  * `first_names.txt` as `name<TAB>tier`: SSA national baby names (`https://www.ssa.gov/oact/babynames/names.zip`). Counts are summed over 1940 to the latest year and both sexes. The top 20,000 are kept and tiered by rank.
  * `surnames.txt` as `name<TAB>tier`: Census 2010 surnames (`https://www2.census.gov/topics/genealogy/2010surnames/names.zip`), top 20,000 by count, tiered by rank.
  * `name_words.txt`: lowercase entries of the public-domain `web2` word list (FreeBSD `share/dict/web2`), keeping only the words that are also in one of the two name lists. That keeps the file small.
  * `street_suffixes.txt`: every primary name, common abbreviation and USPS standard abbreviation from Pub 28 Appendix C1 (`https://pe.usps.com/text/pub28/28apc_002.htm`), lowercased.
* **Loading:** the files are embedded with `go:embed` and parsed once with `sync.Once`. Names are stored lowercase and looked up lowercase.
* **Attribution:** `.gitattributes` marks `internal/detect/data/*` as `linguist-generated`. `NOTICE` gets one line: "Name, surname, street-suffix and TLD lists from the US SSA, US Census Bureau, USPS and IANA (public domain); word list from FreeBSD web2 (public domain)."

## Testing

* **Per-detector table tests**, positive and negative, including every example weight sum below.
* **Worked examples that pin the weights:**

| Input | Arithmetic | Score | Result |
| :- | :- | :- | :- |
| `Jane Roe` | −2.5 + 2.0 + surname tier of Roe + 1.5 | — | emitted |
| `Mark the date` | sentence-start single token, common word | < 0.30 | not emitted |
| `Dear Rose,` | +1.5 phrase | at least 0.30 | emitted |
| `12 Elm St` | −1.0 + 1.5 = 0.5 | 0.62 | emitted |
| `12 Elm St, Springfield, IL 62704` | 0.5 + 1.0 + 1.5 + 0.5 = 3.5 | 0.97 | emitted |
| `SSN 078-05-1120` | −0.5 + 3.5 = 3.0 | 0.95 | emitted |
| `2019-03-04` | −3.0 | — | not emitted |
| `born 1985-03-04` (with `today` fixed) | −3.0 + 4.5 = 1.5 | 0.82 | emitted |

* **Evidence strings:** for at least one match per detector, the test asserts the exact `Evidence` string.
* **No-PII guard:** the existing guard must still pass, with nothing at or above 0.9. Add `testdata/values/clean/prose.txt`: technical prose with no people, such as a paragraph of the Go spec style written for this repo, a changelog, and code comments. It must also pass.
* **False-positive measurement:** the implementation report records the share of 0.9+ matches per detector across all clean fixtures, and the number of `name` matches at 0.3+ in `prose.txt`. These are reported, not asserted.
* **Golden fixtures** with prose, an email signature, a support ticket and a shipping note.
* **`FuzzAll`** keeps its invariants.

## Out of scope

* Czech and other locales.
* Driver's licences and US passport numbers outside MRZ.
* Fitting the weights.
* Showing evidence in `scan`.
* Hooks.
