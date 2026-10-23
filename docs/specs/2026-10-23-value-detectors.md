# Tier 1 value detectors

Oct 23, 2026 · status: draft for review

## Goal

Find PII and secrets by the **value itself**, with no field name or context required. A value counts when it has a known structure *and* passes a checksum or a vetted pattern. Prompts and free text rarely contain field names, so block mode depends on these detectors.

This is the second detector family in `internal/detect`, after [field names](2026-10-22-field-names.md). The design is in [design.md](../design.md) under "Detector catalogue, Tier 1".

## Decisions

* **Score by evidence.** A checksum-valid value scores high when its formatting or a nearby keyword backs it up, and lower when it stands bare. Detectors never drop a valid value for lack of evidence. The block or petrify threshold in `.basilisk.json` decides what happens to it, and that threshold belongs to block mode, not to this spec.
* **Secrets come from gitleaks.** Its rule set is vendored and pinned, converted to JSON by a generator, and embedded in the binary. The runtime stays standard-library only.
* **Field names and values combine.** A new `All` detector runs both families and merges overlapping matches with the existing union rule (`mergeMatches`). `basilisk scan` switches to `All`.
* **Spans are byte offsets into the original text**, the same as for field names.

## Interface

```go
// added to detect.go
const TypeCryptoWallet EntityType = "CRYPTO_WALLET"

type Match struct {
	// existing fields unchanged
	Rule string // the value rule that matched, e.g. "card/visa", "gitleaks/github-pat"; empty for field-name matches
}

type Values struct{} // Detector: runs every value detector, merged
type All struct{}    // Detector: FieldNames + Values, merged
```

* **Types:** IBAN values use the existing `TypeBankAccount`, MRZ lines `TypePassport`, cards `TypeCard` and secrets `TypeSecret`.
* **`Detector` strings:** `value/card`, `value/iban`, `value/mrz`, `value/crypto`, `value/secret`.
* **`basilisk scan` output:** a match prints `rule=<Rule>` in place of `field=<Field>` when `Field` is empty. The golden renderer does the same. Existing field-name goldens don't change.

## Shared rules

* **Two passes:** a cheap scan for candidates, then validation of each candidate.
* **Boundaries:** a candidate must not touch a letter or digit on either side (`[A-Za-z0-9]`). For grouped numbers, the groups must not continue past the candidate.
* **Keyword evidence:** a detector's keyword list is matched case-insensitively, as whole words, in the 32 bytes before the candidate on the same line.
* **Overlaps:** when two value rules overlap, the union rule keeps the higher score's metadata.

## Cards (`cards.go`)

* **Candidate:** 13 to 19 digits, written in one of two ways:
  * as one run of digits
  * in groups joined by a single separator, either a space or a hyphen, the same one throughout
* **Valid:** passes Luhn, and its prefix and length match an issuer:

| Rule | Prefix | Lengths |
| :- | :- | :- |
| `card/visa` | 4 | 13, 16, 19 |
| `card/mastercard` | 51–55, 2221–2720 | 16 |
| `card/amex` | 34, 37 | 15 |
| `card/discover` | 6011, 644–649, 65, 622126–622925 | 16–19 |
| `card/jcb` | 3528–3589 | 16–19 |
| `card/diners` | 300–305, 36, 38, 39 | 14–19 |
| `card/unionpay` | 62 (outside Discover's range) | 16–19 |

* **Score:**
  * **0.95** when the groups follow the card layout: 4-4-4-4 (or 4-4-4-4-3 for 19 digits), or 4-6-5 for Amex.
  * **0.95** when a keyword precedes it: card, credit, debit, visa, mastercard, amex, cc, pan, cvv.
  * **0.75** otherwise.
* **Test numbers:** published test numbers such as `4111 1111 1111 1111` are flagged like any other (fail closed).

## IBAN (`iban.go`)

* **Candidate:** two letters, two digits, then 11 to 30 alphanumerics.
  * Written either compact, or in groups of four joined by single spaces.
  * Letters of either case are accepted and uppercased before validation.
* **Valid:** the country code is in the length table, the length matches that country, and the ISO 7064 mod-97 check gives 1.
* **Length table:** the per-country lengths come from the SWIFT IBAN Registry. They are copied into `iban_countries.go`, with the registry release noted in a comment.
* **Score:** 0.95 when grouped, or when the keyword `iban` precedes it; 0.9 otherwise.

## Passport MRZ (`mrz.go`)

* **Candidate:** two consecutive lines of exactly 44 characters from `[A-Z0-9<]`, after trimming trailing `\r` and spaces. The first line starts with `P`.
* **Valid:** all four check digits on line 2 pass the ICAO 9303 7-3-1 weighted mod-10 check, with `<` counting as 0:
  * document number
  * date of birth
  * expiry date
  * the composite
* **Score:** 0.95. The span covers both lines, including the newline between them.
* **Not covered:** ID-card formats TD1 (3 × 30) and TD2 (2 × 36).

## Crypto wallets (`crypto.go`)

| Rule | Shape | Check | Score |
| :- | :- | :- | :- |
| `crypto/btc-base58` | starts with `1` or `3`, 25–34 base58 characters | base58 decodes to 25 bytes; the last 4 bytes equal the first 4 of double SHA-256 of the rest | 0.95 |
| `crypto/btc-bech32` | `bc1` + 11–71 bech32 characters, all lower or all upper case | bech32 (witness v0) or bech32m (v1+) checksum | 0.95 |
| `crypto/eth` | `0x` + 40 hex | mixed case: the EIP-55 checksum must pass | 0.95 |
| `crypto/eth` | `0x` + 40 hex, all lower or all upper | none possible | 0.8 with eth, ether, wallet or address before it; 0.6 otherwise |

* **Keccak-256:** EIP-55 needs Keccak-256, which Go's standard library doesn't provide (`crypto/sha3` is SHA-3, which pads differently). It lives in `keccak.go`, a small Keccak-f[1600] implementation tested against known digests.
* **Failed checksum:** a mixed-case address that fails EIP-55 is not flagged.

## Secrets (`secrets.go`)

* **Source:** gitleaks' `config/gitleaks.toml` (MIT), pinned to one release tag.
  * The vendored file and gitleaks' LICENSE live in `third_party/gitleaks/`.
  * `NOTICE` gets the line: "Secret rules from gitleaks (https://github.com/gitleaks/gitleaks), MIT License."
* **Generator:** `scripts/gen_secret_rules.py`, which needs only the standard library (`tomllib`, Python 3.11+).
  * It converts the TOML into `internal/detect/secret_rules.json`, keeping each rule's `id`, `regex`, `secretGroup`, `entropy`, `keywords` and allowlists (`regexes`, `stopwords`).
  * It also keeps the global allowlist.
  * It runs from a `//go:generate` line in `secrets.go`.
  * The JSON is committed, so building Basilisk never needs Python.
* **Rules without a regex** (gitleaks' path-only rules) are left out by the generator; Basilisk scans text, not paths.
* **Runtime:** for each rule, as gitleaks does it:
  1. If the rule has keywords, skip it unless one of them appears in the text (case-insensitive).
  2. Run the regex. The span is the capture group named by `secretGroup`, or the whole match.
  3. Drop the match when the rule sets an entropy minimum and the secret's Shannon entropy is below it, or when a rule or global allowlist regex or stopword matches.
* **Score:** 0.95 for provider rules. 0.7 for `generic-api-key`, which matches many strings that aren't keys.
* **Compilation:** every regex is compiled once, at first use. A rule whose regex fails to compile is skipped, and the generator's own test fails on it.

## Testing

* **Valid and invalid vectors** for every rule, table-driven:
  * published card test numbers, with one digit changed for the invalid case
  * the SWIFT registry's IBAN examples
  * the ICAO 9303 sample passport MRZ
  * known Bitcoin addresses (legacy, P2SH, bech32, bech32m)
  * the EIP-55 test addresses
  * synthetic tokens for a sample of gitleaks rules (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, generic)
* **Keccak-256:** digests for `""`, `"abc"` and a 200-byte input.
* **No-PII guard:** `testdata/values/clean/` holds:
  * Go source
  * logs with timestamps and durations
  * UUIDs and git SHAs
  * order and invoice numbers
  * a `go.sum` file
  * base64 image data

  The test asserts that `All` finds nothing at 0.9 or above in them.
* **Golden fixtures:** `testdata/fieldnames/` is renamed to `testdata/golden/`, and fixtures are added with prose, log lines and JSON that contain values. Value matches are rendered with `rule=`.
* **Fuzz:** `FuzzAll` with the same invariants as `FuzzFieldNames`: no panic, spans in bounds, sorted and non-overlapping.
* **CLI:** `basilisk scan` on a prose line that contains a card number prints `rule=card/visa` and never the number.

## Out of scope

* Tier 2 formats that need context: SSN, ITIN, ABA routing numbers, EIN, driver's licences, US passport numbers outside MRZ, Medicare, VIN, dates of birth.
* Email addresses, phone numbers and IP/MAC addresses. They are the next piece, right after this one.
* MRZ ID-card formats (TD1, TD2).
* The `.basilisk.json` threshold, and wiring the detectors into hooks.
