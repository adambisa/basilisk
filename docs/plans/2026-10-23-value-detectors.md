# Tier 1 Value Detectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect cards, IBANs, passport MRZ lines, crypto wallets and secrets by their value, merged with the field-name detector into one `All` detector that `basilisk scan` uses.

**Architecture:** Each value detector is one file in `internal/detect` exposing `func findX(text string) []Match`, and each task adds its function to the `valueFinders` list in `values.go`. `Values` runs that list. `All` runs `FieldNames` and `Values`, and both merge with the existing `mergeMatches` union rule. Gitleaks rules are vendored, converted to JSON by a stdlib-only Python script, and embedded.

**Tech Stack:** Go 1.27, standard library only. The Python 3.11+ generator, run with `uv`, is for maintainers only and is never shipped.

**Spec:** [docs/specs/2026-10-23-value-detectors.md](../specs/2026-10-23-value-detectors.md)

## Global Constraints

- **Module:** `github.com/adambisa/basilisk`, Go 1.27, no third-party Go dependencies.
- **Spans:** byte offsets into the original text, with `Start` inclusive and `End` exclusive.
- **Boundaries:** a candidate must not touch `[A-Za-z0-9]` on either side.
- **Keyword evidence:** a whole word, case-insensitive, within the 32 bytes before the candidate on the same line.
- **Scores:**
  - card: 0.95 with layout or keyword, else 0.75
  - IBAN: 0.95 grouped or keyword, else 0.9
  - MRZ: 0.95
  - BTC: 0.95
  - ETH: 0.95 with a valid EIP-55 checksum. All-lowercase or all-uppercase addresses get 0.8 with a keyword, else 0.6
  - secret: 0.95, except `generic-api-key` at 0.7
- **Rule ids:**
  - `card/<issuer>`
  - `iban`
  - `mrz/td3`
  - `crypto/btc-base58`, `crypto/btc-bech32`, `crypto/eth`
  - `gitleaks/<id>`
- **Detector strings:** `value/card`, `value/iban`, `value/mrz`, `value/crypto`, `value/secret`.
- **Output:** `basilisk scan` never prints a matched value. Value matches print `rule=<Rule>` in place of `field=<Field>`.
- **Test data:** all fixture values are synthetic or published test vectors.

## Review Focus

1. **Card-length runs inside longer numbers.** A 20+ digit run (timestamps, nanosecond IDs) must not yield a 16-digit card from its middle. Test in Task 2.
2. **A field-name match and a value match on the same span.** `{"card_number": "4111 1111 1111 1111"}` must give one merged match, not two. Test in Task 7.
3. **CRLF line endings around MRZ lines.** The lines still validate, and the span excludes the trailing `\r`. Test in Task 4.
4. **Multibyte text right next to a candidate** (`€4111…`, `číslo:DE89…`). Boundaries are byte-based, so a non-ASCII byte counts as a non-alphanumeric boundary. Test in Task 3.
5. **Lockfile hashes and base64 blobs** must not reach 0.9 as secrets or wallets. Test via the no-PII guard in Task 7.

---

### Task 1: Plumbing: `Rule`, `All`, keyword helper, `rule=` output

**Files:**
- Modify: `internal/detect/detect.go`. Add `TypeCryptoWallet` and the `Rule` field.
- Create: `internal/detect/values.go`
- Test: `internal/detect/values_test.go`
- Modify: `internal/detect/fieldnames_test.go`. The golden renderer and the fixture directory change.
- Move: `testdata/fieldnames/` → `testdata/golden/` with `git mv`.
- Modify: `cmd/basilisk/scan.go`, `cmd/basilisk/main_test.go`

**Interfaces:**
- Produces:
  - `const TypeCryptoWallet EntityType = "CRYPTO_WALLET"`
  - `Match.Rule string`
  - `type Values struct{}`, `type All struct{}`. Both implement `Detector`.
  - `var valueFinders []func(string) []Match`, which later tasks append to
  - `func keywordBefore(text string, start int, words []string) bool`
  - `func atBoundary(text string, start, end int) bool`, true when neither `text[start-1]` nor `text[end]` is `[A-Za-z0-9]`

- [ ] **Step 1: Write failing tests**

`TestKeywordBefore`, with `words = []string{"card", "cc"}`:

| Text | Candidate starts at | Expected |
| :- | :- | :- |
| `"card: 4111"` | `4111` | true |
| `"CC 4111"` | `4111` | true |
| `"discard 4111"` | `4111` | false: not a whole word |
| `"card\n4111"` | `4111` | false: different line |
| `"card" + 40 spaces + "4111"` | `4111` | false: more than 32 bytes back |

`TestAtBoundary`:

| Text | Span | Expected |
| :- | :- | :- |
| `"x4111y"` | `[1,5)` | false |
| `" 4111 "` | `[1,5)` | true |
| `"€4111"` | the span of `4111` | true |
| `"4111"` | `[0,4)` | true |

`TestAllEqualsFieldNamesWithoutValues`: on `"name,email\nJane,j@x.com\n"`, `All{}.Find` equals `FieldNames{}.Find`.

- [ ] **Step 2: Run, expect FAIL**

`go test ./internal/detect/` fails with `undefined: keywordBefore`.

- [ ] **Step 3: Implement**

- `Values.Find` calls every function in `valueFinders` and returns `mergeMatches` of the concatenation.
- `All.Find` returns `mergeMatches(append(FieldNames{}.Find(text), Values{}.Find(text)...))`.
- `git mv testdata/fieldnames testdata/golden`, then update the path in `fieldnames_test.go`.
- In the golden renderer and in `scan.go`, print `rule=%s` from `m.Rule` when `m.Field == ""` and `m.Rule != ""`. Otherwise print `field=` exactly as today, so existing goldens are unchanged.
- `scan.go` uses `detect.All{}`.

- [ ] **Step 4: Run, expect PASS**

`go vet ./... && go test ./...` passes, and `git status` shows no golden content changes, only the rename.

- [ ] **Step 5: Commit** `Add value-detector plumbing: Rule, All, keyword evidence`

---

### Task 2: Cards

**Files:** Create `internal/detect/cards.go`, `internal/detect/cards_test.go`.

**Interfaces:**
- Consumes: `atBoundary`, `keywordBefore`, `valueFinders` (Task 1).
- Produces: `func findCards(text string) []Match`, appended to `valueFinders` in an `init()` in `cards.go`. Also `func luhn(digits string) bool`.

- [ ] **Step 1: Write failing tests**

`TestLuhn`: true for `4111111111111111` and `79927398713`; false for `4111111111111112`.

`TestFindCards`, given as `input → Rule@Score:value`, or none:

| Input | Expected |
| :- | :- |
| `"card 4111 1111 1111 1111"` | `card/visa@0.95:4111 1111 1111 1111` |
| `"4111111111111111"` | `card/visa@0.75:4111111111111111` |
| `"pay 4111-1111-1111-1111 now"` | `card/visa@0.95` (layout) |
| `"5555555555554444"` | `card/mastercard@0.75` |
| `"2223003122003222"` | `card/mastercard@0.75` |
| `"378282246310005"` | `card/amex@0.75` |
| `"3782 822463 10005"` | `card/amex@0.95` (4-6-5) |
| `"6011111111111117"` | `card/discover@0.75` |
| `"3530111333300000"` | `card/jcb@0.75` |
| `"30569309025904"` | `card/diners@0.75` |
| `"6200000000000005"` | `card/unionpay@0.75` |
| `"4111111111111112"` (Luhn fails) | none |
| `"4111 1111-1111 1111"` (mixed separators) | none |
| `"order 12345678901234567890123"` (Review Focus 1) | none |
| `"x4111111111111111"` | none |

For each match, also assert that `Type == TypeCard` and `Detector == "value/card"`.

- [ ] **Step 2: Run, expect FAIL** with `undefined: findCards`.

- [ ] **Step 3: Implement** `cards.go`

- Scan for maximal runs of digits and single same-type separators.
- Reject a run unless it has 13–19 digits and passes `atBoundary`.
- Apply the issuer table from the spec verbatim. Ranges are compared numerically on the prefix digits.
- A run with more than 19 digits is rejected whole, never sliced.

- [ ] **Step 4: Run, expect PASS.** Then run `go vet ./... && go test ./...`.

- [ ] **Step 5: Commit** `Add card number detector`

---

### Task 3: IBAN

**Files:** Create `internal/detect/iban.go`, `internal/detect/iban_countries.go`, `internal/detect/iban_test.go`.

**Interfaces:**
- Consumes: Task 1 helpers.
- Produces:
  - `func findIBANs(text string) []Match`, registered in `init()`
  - `var ibanLengths map[string]int`, mapping a country code to its total length
  - `func ibanValid(compact string) bool`

- [ ] **Step 1: Source the country table**

- Download the current SWIFT IBAN Registry text release (swift.com, "IBAN Registry").
- Copy each country's code, total IBAN length and example IBAN into `iban_countries.go`, as `ibanLengths` plus a test-only `ibanExamples` slice.
- Record the registry release number and date in a comment at the top.
- If the download fails, stop and report `NEEDS_CONTEXT`. Do not type the table from memory.

- [ ] **Step 2: Write failing tests**

- `TestIBANRegistryExamples`: every entry in `ibanExamples` satisfies `ibanValid`, and its length equals `ibanLengths[code]`.
- `TestFindIBANs`:

| Input | Expected |
| :- | :- |
| `"IBAN DE89370400440532013000"` | `iban@0.95` (keyword) |
| `"DE89 3704 0044 0532 0130 00"` | `iban@0.95` (grouped) |
| `"DE89370400440532013000"` | `iban@0.9` |
| `"gb82west12345698765432"` (lowercase) | `iban@0.9` |
| `"CZ6508000000192000145399"` | `iban@0.9` |
| `"číslo:CZ6508000000192000145399"` (Review Focus 4) | `iban@0.9`, span starts at `C` |
| `"DE89370400440532013001"` (check digit wrong) | none |
| `"DE8937040044053201300"` (length wrong) | none |
| `"XX89370400440532013000"` (unknown country) | none |

Also assert `Type == TypeBankAccount` and `Detector == "value/iban"`.

- [ ] **Step 3: Run, expect FAIL.**

- [ ] **Step 4: Implement** the candidate scan and mod-97. Move the first four characters to the end, map `A`=10 … `Z`=35, and reduce mod 97 digit by digit, with no big integers.

- [ ] **Step 5: Run, expect PASS.** Then run the full suite.

- [ ] **Step 6: Commit** `Add IBAN detector`

---

### Task 4: Passport MRZ

**Files:** Create `internal/detect/mrz.go`, `internal/detect/mrz_test.go`.

**Interfaces:**
- Consumes: `valueFinders`.
- Produces:
  - `func findMRZ(text string) []Match`, registered in `init()`
  - `func mrzCheck(field string) int`, the 7-3-1 weighted sum mod 10, where `<` counts 0, `A`=10 … `Z`=35

- [ ] **Step 1: Write failing tests**

`TestMRZCheck`:

| Input | Expected |
| :- | :- |
| `"L898902C3"` | 6 |
| `"740812"` | 2 |
| `"120415"` | 9 |

`TestFindMRZ` uses the ICAO 9303 specimen:

```
P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
L898902C36UTO7408122F1204159ZE184226B<<<<<10
```

| Input | Expected |
| :- | :- |
| The specimen on its own | one match, `mrz/td3@0.95`, `Type == TypePassport`. The span runs from `P` to the final `0`, including the `\n` between the lines. |
| The specimen embedded after a prose line and before a trailing line | the same single match |
| The specimen with `\r\n` line endings (Review Focus 3) | one match, whose span ends at the final `0`, not the `\r` |
| Line 2 with its last digit `0` changed to `1` (composite check fails) | none |
| Line 1 not starting with `P` | none |
| A 44-character line of `<` only, twice | none |

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement**

- Walk the lines. For each pair of consecutive lines that both match the spec's candidate rule, validate line 2's check digits:
  - document number: positions 0–8, check at 9
  - DOB: 13–18, check at 19
  - expiry: 21–26, check at 27
  - composite: 0–9, 13–19 and 21–42, check at 43
- These are 0-based positions in line 2, per ICAO 9303 Part 4.

- [ ] **Step 4: Run, expect PASS.** Then run the full suite.

- [ ] **Step 5: Commit** `Add passport MRZ detector`

---

### Task 5: Keccak-256 and crypto wallets

**Files:** Create `internal/detect/keccak.go`, `internal/detect/keccak_test.go`, `internal/detect/crypto.go`, `internal/detect/crypto_test.go`.

**Interfaces:**
- Consumes: Task 1 helpers.
- Produces:
  - `func keccak256(data []byte) [32]byte`
  - `func findWallets(text string) []Match`, registered in `init()`

- [ ] **Step 1: Write failing tests**

`TestKeccak256` compares hex digests:

| Input | Expected digest |
| :- | :- |
| `""` | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |
| `"abc"` | `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45` |
| `"The quick brown fox jumps over the lazy dog"` | `4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15` |
| 300 × `"a"`, which exercises multiple blocks | computed once with an independent implementation: `uv run --with pycryptodome python -c "from Crypto.Hash import keccak; print(keccak.new(digest_bits=256, data=b'a'*300).hexdigest())"`. The command goes in a comment above the vector. |

`TestFindWallets`:

| Input | Expected |
| :- | :- |
| `"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"` | `crypto/btc-base58@0.95` |
| `"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"` | `crypto/btc-base58@0.95` |
| `"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"` | `crypto/btc-bech32@0.95` |
| `"bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"` | `crypto/btc-bech32@0.95` (bech32m) |
| `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`, `0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359`, `0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB`, `0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb` | each `crypto/eth@0.95` |
| `0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed` | `crypto/eth@0.6` |
| `"wallet 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"` | `crypto/eth@0.8` |
| `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD` (one case flipped, EIP-55 fails) | none |
| `"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"` (checksum fails) | none |
| `"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr"` (checksum fails) | none |
| A git SHA: 40 hex characters, no `0x` | none |

Also assert `Type == TypeCryptoWallet` and `Detector == "value/crypto"`.

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement**

- `keccak.go`: Keccak-f[1600], rate 136, the original Keccak padding (`0x01 … 0x80`, not SHA-3's `0x06`).
- `crypto.go`: base58 decode via `math/big` from the standard library, then the double SHA-256 check from `crypto/sha256`. Bech32 and bech32m use the BIP-173 and BIP-350 polymod constants (`1` and `0x2bc830a3`). EIP-55 follows the spec.

- [ ] **Step 4: Run, expect PASS.** Then run the full suite.

- [ ] **Step 5: Commit** `Add Keccak-256 and crypto wallet detector`

---

### Task 6: Secrets from gitleaks

**Files:**
- Create:
  - `third_party/gitleaks/gitleaks.toml` and `third_party/gitleaks/LICENSE`
  - `scripts/gen_secret_rules.py`
  - `internal/detect/secret_rules.json` (generated, committed)
  - `internal/detect/secrets.go`, `internal/detect/secrets_test.go`
- Modify: `NOTICE`

**Interfaces:**
- Consumes: `valueFinders`.
- Produces:
  - `type secretRules struct` (the parsed JSON, with compiled regexes)
  - `func scanSecrets(text string, rs *secretRules) []Match`
  - `func findSecrets(text string) []Match`, which calls `scanSecrets` with the embedded rules and is registered in `init()`

- [ ] **Step 1: Vendor gitleaks**

- Find the latest gitleaks v8 release tag with `gh api repos/gitleaks/gitleaks/releases/latest --jq .tag_name`.
- Download `config/gitleaks.toml` and `LICENSE` at that tag into `third_party/gitleaks/`.
- Write the tag into `third_party/gitleaks/VERSION`.
- Append the spec's attribution line to `NOTICE`.

- [ ] **Step 2: Write the generator**

`scripts/gen_secret_rules.py` is a uv script.
- Its PEP 723 header has `requires-python = ">=3.11"` and `dependencies = []`.
- It reads the TOML with `tomllib` and drops rules without `regex`.
- It writes `{"version": <tag>, "allowlist": {...}, "rules": [{id, regex, secretGroup, entropy, keywords, allowlists: [{regexes, stopwords}]}]}`, sorted by `id`, with `indent=1` for readable diffs.
- Add `//go:generate uv run --script ../../scripts/gen_secret_rules.py` to `secrets.go`.
- Run `go generate ./internal/detect/` and commit the JSON.

- [ ] **Step 3: Write failing tests**

- `TestSecretRulesCompile`: every rule's regex and every allowlist regex compiles with Go's `regexp`. Report every failing id, not just the first.
- `TestFindSecrets` uses synthetic tokens built from each rule's documented format. Build the tokens in the test, for example `"ghp_" + strings.Repeat("a1B2", 9)`, so no real-looking key is ever committed.

| Input | Expected |
| :- | :- |
| a GitHub PAT shape | `gitleaks/github-pat@0.95` |
| an AWS access key id `AKIA` + 16 uppercase alphanumerics | the rule id gitleaks uses for it, `@0.95` |
| a Slack bot token shape | the matching rule id `@0.95` |
| a Stripe secret key shape | the matching rule id `@0.95` |
| an Anthropic API key shape | the matching rule id `@0.95` |
| `api_key = "zX9qL2mN8vB4cR7tY1wE5uI3oP6aS0dF"` | `gitleaks/generic-api-key@0.7` |
| the same generic line with a low-entropy value `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | none (entropy) |

- **Exact rule ids:** read the rule ids from the vendored TOML and use them verbatim. If a listed provider has no rule in the pinned version, drop that row and say so in your report.
- **Spans and fields:** assert the span covers the `secretGroup` capture, not the surrounding `api_key = "`, and that `Type == TypeSecret`, `Detector == "value/secret"`.
- `TestSecretKeywordPrefilter`: real tokens usually contain their own keyword (`ghp_`), so the prefilter is tested with a synthetic `secretRules`. Its one rule has keywords `["foo"]` and regex `bar[0-9]+`. `scanSecrets("bar123", rs)` returns none, and `scanSecrets("foo bar123", rs)` returns one match.

- [ ] **Step 4: Run, expect FAIL.**

- [ ] **Step 5: Implement** `secrets.go`

- Embed the JSON with `//go:embed` and parse it once, lazily, with `sync.Once`.
- For each rule:
  - Apply the keyword prefilter: lowercase the text once, then `strings.Contains`.
  - Run `FindAllStringSubmatchIndex`.
  - Take the span of `secretGroup`, or the whole match.
  - If the rule sets an entropy minimum, require at least that Shannon entropy.
  - Apply the rule allowlists and the global allowlist (regexes against the secret, stopwords as case-insensitive substrings).
- Rules whose regex fails to compile are skipped at runtime; the test in Step 3 is what catches them.

- [ ] **Step 6: Run, expect PASS.** Then run the full suite.

- [ ] **Step 7: Commit** `Add secret detector with vendored gitleaks rules`

---

### Task 7: No-PII guard, golden fixtures, fuzz, CLI

**Files:**
- Create:
  - `testdata/values/clean/{main.go.txt,app.log,ids.txt,orders.csv,go.sum.txt,image.b64}`
  - `testdata/golden/{prose.txt,payment.log,wallets.json}`, each with its `.golden`
- Modify: `internal/detect/fieldnames_test.go`. Rename `FuzzFieldNames` → `FuzzAll`, and make the golden test use `All`.
- Modify: `cmd/basilisk/main_test.go`

**Interfaces:**
- Consumes: `All` (Task 1) and every finder (Tasks 2–6).

- [ ] **Step 1: Write the fixtures**

- **Clean fixtures:** realistic and synthetic.
  - `main.go.txt` is any small Go file, taken from this repo.
  - `app.log` has timestamps, durations and request ids.
  - `ids.txt` has UUIDs, 40-hex git SHAs and 64-hex SHA-256 digests.
  - `orders.csv` has order and invoice numbers of 8 to 20 digits.
  - `go.sum.txt` is a copy of a real `go.sum` from any public module.
  - `image.b64` holds 2 KB of base64 from random bytes, generated once.
- **Golden value fixtures:**
  - `prose.txt`: sentences with a card, an IBAN and a wallet.
  - `payment.log`: log lines, plus the MRZ specimen.
  - `wallets.json`: JSON with `"card_number": "4111 1111 1111 1111"` (Review Focus 2) and a wallet under a non-sensitive key.

- [ ] **Step 2: Write tests**

- `TestNoPIIGuard`: for every file in `testdata/values/clean/`, `All{}.Find` returns no match with `Score >= 0.9`. On failure, report the file, rule and score, never the value.
- `TestFieldAndValueMerge`: on `{"card_number": "4111 1111 1111 1111"}`, `All` returns exactly one match covering the number.
- In `TestScan`, stdin `"my card is 4111 1111 1111 1111\n"` gives exit 1. The single output line ends in `value/card  rule=card/visa`, and stdout does not contain `4111`.

- [ ] **Step 3: Generate the goldens, then read them**

- Run `go test ./internal/detect/ -run TestFieldNamesGolden -update`.
- Read every new golden line and check its rule, score and span against the spec.
- Existing goldens may change only where `All` now adds value matches. Explain every such change in your report.

- [ ] **Step 4: Run everything**

```bash
go vet ./... && go test ./... && go test ./internal/detect/ -run '^$' -fuzz FuzzAll -fuzztime 30s
```

All three must pass, and `gofmt -l .` must print nothing.

- [ ] **Step 5: Update the README status line**

The line becomes: "`basilisk scan` finds PII and secrets in text: by field name in JSON and tables, and by value for cards, IBANs, passport MRZ lines, crypto wallets and API keys."

- [ ] **Step 6: Commit** `Add no-PII guard, value goldens and FuzzAll`
