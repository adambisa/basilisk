# Basilisk: Block & Petrify Modes

Oct 22, 2026 · Adam Bisa

Basilisk is a downloadable plugin for Claude Code and Codex that stops PII and secrets from reaching the model. It has two modes: Block and Petrify. This doc maps each mode to what the hook APIs actually allow, based on the current Claude Code and Codex hook docs.

**Target market:** US English first. Detectors ship as locale packs. `en-US` is the first and only pack in v1, so other locales (UK, EU, SK/CZ) can be added later without touching the core.

**Design rule: fail closed.** If Basilisk times out, crashes or can't produce a valid replacement, the content is blocked, never passed through.

## Block mode

* **Prompts:** a `UserPromptSubmit` hook returns `decision: "block"` when it finds PII or a secret. The prompt never reaches the model. The user sees what was found and where; the reason isn't added to the model's context. Works in both Claude Code and Codex.
  * The hook is set to `onFailure: "block"`. Claude Code gives prompt hooks 30 seconds by default, and a timed-out hook otherwise lets the prompt through.
  * The blocked prompt text still lands on disk. By default it is in the block message, which is saved to the local transcript, and it may also be in prompt history. `suppressOriginalPrompt` removes it from the message. It never reaches the model, and the README says this.
* **Tools:** a `PreToolUse` hook denies reads of protected paths and commands that touch them. The reason goes to the agent so it can adapt.

## Petrify mode (Claude Code)

> **Superseded in part by the probe results below.** Redirecting Read to a petrified copy makes the file uneditable, so Layer 1 can't be the primary layer for Read. Output rewriting works for Read, and the Mirror works through Write but not through Edit. See "Probe results". This section gets rewritten once the new layering is agreed.

Petrify uses two layers. Rewriting inputs is the primary layer because it fails closed: the raw data never enters Claude Code, and if Basilisk fails, the tool reads a file that doesn't exist and errors. Rewriting outputs is the second layer, for tools that have no input to rewrite.

### Layer 1: rewrite inputs (`PreToolUse`)

* **Read:** the hook writes a petrified copy of the file to `.basilisk/petrified/<path>` and uses `updatedInput` to point `file_path` at it. The model only sees placeholders like `⟦IBAN_1⟧` or `⟦PERSON_2⟧`.
* **Writes (the Mirror):** Edit and Write are pointed at the same petrified copy. The model's `old_string` already matches the copy, since both contain placeholders. After the tool runs, Basilisk un-petrifies the copy and writes the result to the real file. If the real file changed since the copy was made, Basilisk refuses the write instead of guessing.
* **Bash:** read-only commands on an allowlist (`cat`, `head`, `tail`, `rg`, `grep`, `jq`, `wc`) are rewritten to pipe through `basilisk petrify`, with `pipefail` so the exit code survives. Other commands that touch protected paths are denied.
* **Costs:**
  * Claude Code checks the user's permission rules against the rewritten input, so a rule for the real path or command no longer matches. That means more prompts, not leaks.
  * Basilisk never pairs `updatedInput` with `"allow"`, because that skips the user's permission prompt.

### Layer 2: rewrite outputs (`PostToolUse`)

* **Coverage:** Grep, Glob, NotebookRead, WebFetch, MCP tools, and Bash commands outside the allowlist. `updatedToolOutput` replaces what the model sees after the tool runs, and it works for built-in tools, not only MCP.
* **File names:** Glob results and paths in Grep output are petrified too (`clients/⟦PERSON_3⟧.pdf`).
* **This layer fails open.** A replacement that doesn't match the tool's output schema is silently ignored, and the original goes to the model. Only the Bash shape is documented (`stdout`, `stderr`, `interrupted`, `isImage`).
  * Basilisk captures each tool's shape from real calls and pins it as a golden fixture. CI tests every fixture against new Claude Code releases.
  * In petrify mode, `PreToolUse` denies any tool without a pinned shape up front.
* **The raw output still exists inside Claude Code** before the hook replaces it. If the user has OpenTelemetry enabled, it records the original. Whether the transcript stores the original is an open question.

### Shared rules

* **Placeholders:** the format is one that doesn't appear in normal code (`⟦TYPE_N⟧`). The mapping is deterministic within a session: the same value always gets the same placeholder across every file and command, so the model can reason about joins.
* **Mirror limits:** files written by shell commands (`echo > file`, `sed -i`, scripts) bypass the Mirror, so placeholders can end up on disk. The README says so.
* **Prompts are the one gap.** Neither tool lets a hook rewrite a typed prompt. In petrify mode a prompt with PII is blocked, and Basilisk prints a petrified version to resend. One extra keystroke, but honest and predictable.

## Codex

Hooks are on by default in Codex. Events include `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart` and `Stop`. Plugins can bundle hooks in their manifest or a default `hooks/hooks.json`. Installing a plugin doesn't automatically trust its hooks; users approve them first.

* **Block mode: full support.** `UserPromptSubmit` blocks prompts. `PreToolUse` denies shell, `apply_patch` and MCP calls that touch protected data.
* **Petrify mode: limited.**
  * `PostToolUse` can't rewrite output; `updatedMCPToolOutput` is parsed but not supported. A block replaces the result with feedback, which hides the output but gives the model nothing to work with.
  * So only Layer 1 exists, and only for shell. Codex accepts a rewrite only when it's paired with `permissionDecision: "allow"`, and `"ask"` isn't supported. Every rewritten command is therefore auto-approved, bypassing Codex's own approvals.
  * v1 rewrites only the read-only allowlist. Everything else follows block-mode rules.
* **Mirror on Codex:** possible by rewriting `apply_patch` input, but that also auto-approves the patch. It ships off by default.
* The README states all of this plainly.

## What hooks can't see

* **`@file` mentions:** it isn't documented whether `UserPromptSubmit` receives the file's contents or only `@path`. Until that's confirmed, Basilisk blocks prompts that `@`-mention protected paths. Pasted text does arrive expanded, so it is scanned.
* **Images and screenshots:** not scanned in v1.
* **CLAUDE.md, rules and memory files:** the `InstructionsLoaded` hook can't block or modify them. A `SessionStart` hook runs `basilisk scan` on them and warns the user.
* **Subagents:** covered. Tool hooks fire inside subagents too.

## What you download

* **Claude Code:** a plugin installed from a marketplace (a GitHub repo acting as one). It bundles the hooks plus a `/basilisk` command to switch modes and show stats.
* **Codex:** a plugin built on the same core, with the limits above.
* **Binary delivery:** a plugin is a git repo, so the Go binary needs a path to the user. Options: commit per-OS binaries to the marketplace repo, or add a first-run shim that downloads from GitHub Releases and verifies a checksum.
* **npm:** `basilisk-core` as a standalone CLI (`basilisk scan`, `basilisk petrify`), which also makes the detectors testable and reusable. Published with per-platform optional dependencies, the pattern esbuild uses.
* **Config:** a `.basilisk.json` per project for mode, entity types, custom rules and protected paths.

## Tech stack

Basilisk is written in Go:

* fast to learn coming from TypeScript
* a single static binary per OS
* millisecond cold starts, which matters for hooks running on every tool call
* the same niche as gitleaks and trufflehog

```
basilisk/
├── cmd/basilisk/          # main: scan, petrify, mirror, hook <event>
├── internal/
│   ├── detect/            # one file per detector + _test.go
│   ├── vault/             # placeholder ↔ original mapping, per session
│   ├── hook/              # Claude Code & Codex hook payload adapters
│   └── config/            # .basilisk.json loading
├── plugins/
│   ├── claude-code/       # plugin manifest, hooks.json, /basilisk command
│   └── codex/
├── probes/                # experiments that check undocumented hook behaviour
├── testdata/
│   ├── shapes/            # pinned tool-output shapes per Claude Code version
│   └── ...                # synthetic fixtures for the accuracy table
└── .goreleaser.yaml       # binaries for macOS, Linux, Windows
```

* **Detectors:** one shared `Detector` interface (`Find(text) []Match`). A new entity type is one file plus its test.
* **Vault:** the vault is itself a store of PII. It lives in `${CLAUDE_PLUGIN_DATA}` with 0600 permissions and is deleted at `SessionEnd`, with a TTL as backup. Petrified copies in `.basilisk/petrified/` follow the same lifetime.
* **Phones:** `nyaruka/phonenumbers` (Go port of libphonenumber). Everything else stays in the standard library.
* **Tests:** table-driven tests for validators, fuzz tests (`go test -fuzz`) for parsers, golden tests for output shapes.
* **Releases:** GoReleaser + GitHub Actions; tagging a version builds all binaries.
* **NER (v2):** the shipped runtime stays pure Go. Models are trained offline in Python and only their weights ship (see ML roadmap).

## Detector catalogue

Detectors are grouped in three tiers by how confidently each entity can be detected. v1 covers the `en-US` locale pack plus global, language-independent detectors.

A checksum filters candidates but doesn't confirm them. Luhn and the ABA checksum each pass about 1 in 10 random numbers, so a checksum alone is never enough to block.

### Tier 1: checksum plus structure (high confidence)

* **Payment cards:** Luhn plus issuer prefix plus valid length for that issuer.
* **Passport MRZ lines:** built-in 7-3-1 check digits over a fixed line structure.
* **IBAN:** country code, per-country length and mod-97.
* **Crypto wallet addresses:** Bitcoin base58check and bech32 checksums. Ethereum only when mixed-case, since the EIP-55 checksum exists only in mixed-case addresses. All-lowercase Ethereum addresses drop to Tier 2.
* **Secrets/API keys:** gitleaks' rule set (MIT-licensed) for known prefixes, plus entropy scoring.

### Tier 2: format plus context (medium confidence)

These have a known shape but no checksum strong enough on its own. A match is flagged only when a nearby keyword appears ("SSN", "DL#", "driver's license", "passport no.", "DOB", "EIN", "routing", "acct").

* **SSN:** format plus invalid-range rejection (area 000, 666, 900–999; group 00; serial 0000). SSNs have been randomized since 2011, so most 9-digit numbers pass the range rules. A dashed `XXX-XX-XXXX` scores higher than bare digits, but still needs context to block.
* **ITIN:** 9xx prefix with valid middle-digit ranges, plus context.
* **ABA routing numbers:** 3-7-1 weighted checksum plus context.
* **Driver's licence numbers:** formats vary by state, so per-state patterns plus context keywords.
* **US passport numbers** (outside MRZ lines) and **EIN** (`XX-XXXXXXX`).
* **Bank account numbers:** near a routing number or "acct".
* **Medicare MBI:** fixed 11-character structure.
* **VIN:** 17 characters. The North American check digit makes this nearly Tier 1.
* **Dates of birth:** near "DOB", "born" or "date of birth".
* **Lowercase Ethereum addresses.**
* **Phone numbers, emails, IP and MAC addresses:** format-reliable on their own.

### Tier 3: names and addresses

1. **v1, patterns:** ZIP and ZIP+4, house number plus street suffix (`123 Main St`, `Apt 4B`), state abbreviations, PO boxes. Scored by how many signals co-occur.
2. **v1.5, gazetteers:** US Census surname lists, Social Security Administration first-name data, street suffix tables and GeoNames places, embedded in the binary.
3. **v2, model:** names and addresses in free text that the first two stages miss.

## Confidence scoring

Every match carries a score. A single threshold in `.basilisk.json` decides what gets blocked or petrified, so users trade recall against false positives. Precision and recall are reported per detector and per tier.

## PII coverage: what Basilisk can and can't promise

Detecting all PII is impossible for any tool:

* PII depends on context ("the only red-haired dentist in Bozeman" has no name or number).
* Harmless fields combine into identifiers (ZIP code + birth date + sex).
* Names collide with ordinary words (Mark, Bill, Rose, Hunter, Young).
* Data hides in encodings, screenshots and unusual formats.

On top of that, some inputs never pass through a hook (see "What hooks can't see"). The README states the goal plainly: Basilisk reduces exposure; it is not a compliance guarantee.

Coverage beyond detection:

1. **Protected paths:** block or fully petrify configured files and folders (`.env`, `exports/*.csv`, `clients/**`) instead of scanning them.
2. **Column-aware mode:** for CSV, JSON and SQL output, find sensitive columns by header (`name`, `address`, `email`, `ssn`, `dob`, `phone`) or by sampling values, then petrify the whole column.
3. **Quasi-identifier warnings:** flag when several harmless-looking fields appear together.
4. **Tiered detectors**, plus NER in v2 for the free-text long tail.
5. **Strict mode:** anything from protected sources is petrified unless explicitly allowed.

**Benchmark positioning:** English PII detection is crowded (Presidio and most GLiNER models are English-first), so Basilisk won't win on raw accuracy. The story is comparable accuracy, far faster, and built into the agent.

## ML roadmap

v1 has no models. Detection is validators, patterns and gazetteers only: fast, deterministic, nothing to download. Free-text names and addresses beyond those patterns are deferred to v2.

### v2: Basilisk's own model

1. **Training data:** start from public labeled English datasets (ai4privacy's PII-masking sets, NVIDIA Nemotron-PII). Add synthetic text from Faker's `en_US` locale in agent-specific formats: logs, CSVs, stack traces, configs, SQL output. Hold out a test set for benchmarking.
2. **Own CRF tagger:** a classic sequence tagger trained on hand-designed features: capitalization, name and street gazetteer membership, word shape, context words ("Mr.", "Dr.", "St", "Apt", "lives at"). Small, explainable, sub-millisecond.
3. **Later, optionally:** fine-tune a small multilingual encoder on the same corpus if more accuracy is needed.

### Python for training, Go for runtime

* **Python (offline, never shipped):** corpus generator, training (`sklearn-crfsuite`), evaluation and notebooks, managed with uv.
* **Go (shipped):** loads exported weights embedded in the binary and runs Viterbi decoding. Users never install Python.
* **Feature parity:** Python and Go must extract features identically. Shared golden fixtures (input text → expected features → expected tags) run in both test suites in CI.

```
basilisk/
├── cmd/, internal/      # Go runtime (shipped)
├── training/            # Python, managed with uv (never shipped)
│   ├── corpus/          # public datasets + synthetic en_US generator
│   ├── train.py         # CRF training → export weights
│   ├── eval/            # precision/recall, benchmarks
│   └── notebooks/       # analysis and charts for the README
└── testdata/golden/     # shared feature-parity fixtures
```

## Benchmarks and optional add-ons

* **Benchmark against:** Microsoft Presidio, GLiNER2-PII (Fastino, 0.3B params, 42 PII types) and nullpii (GLiNER + regex + reversible vault, the closest prior art).
* **Differentiators:**
  * native Claude Code and Codex hooks with block and petrify modes
  * fail-closed petrification of reads, with output rewriting as a second layer
  * the Mirror (code the agent writes stays correct)
  * column-aware petrification
  * a small local Go binary with no Python or model required
* **Jev (TypeSafe AI), optional and off by default:** a cloud pass on already-petrified text, for context questions ("does this still identify a person?") and Bash command risk scoring. The README states exactly what gets sent.

## Probe results (Claude Code 2.1.287, 2026-10-22)

Run with `probes/run.sh`: headless Haiku, synthetic canary, one fresh temp project per probe.

| Question | Result |
| :- | :- |
| `updatedToolOutput` on Read | Works. The model sees only the placeholder, and the transcript on disk stores only the replacement. |
| Read's output shape | `{type: "text", file: {filePath, content, numLines, startLine, totalLines}}` |
| Wrong shape, hook crash (exit 1), hook timeout | **All three leak.** The original output reaches the model unchanged. |
| `updatedInput` without `permissionDecision` | Applies (seen on Read and Write, in acceptEdits mode). |
| Read redirected to a petrified copy | The read works, but **the file can't be edited afterwards**: Edit fails with "File has not been read yet". |
| Edit pointed at the copy as well | Doesn't help. The Edit's `PreToolUse` hook never fires. |
| Edit after a petrified Read (output rewriting) | Works when `old_string` has no placeholder. |
| Edit whose `old_string` contains a placeholder | **Fails** with "String to replace not found". The hook never fires, so the Mirror can't swap the value back. |
| Write with placeholders (the Mirror) | Works. `PreToolUse` swaps them back, and the real file gets the real values. |
| Where real values still land on disk | Write's `toolUseResult` (`content`, `originalFile`) and the logged hook stdout in the transcript. Neither is model-visible, and the values are in the real file anyway. |
| Model behaviour after failed Edits | With Bash available, the model ran `od -c` on the file and read the real value as a character dump. |

What this means for the design:

1. **Claude Code validates before running hooks.** For Edit, "was it read?" and "does `old_string` exist?" are both checked before `PreToolUse`. Any design that makes the model's view of a file differ from the file breaks one of them.
2. **For Read, output rewriting is the only workable layer.** It fails open on wrong shape, crash or timeout, so Basilisk must be built so that none of those happen:
   * pinned output shapes, checked in CI
   * no panics
   * the default 600s timeout instead of a short one
   * a `PreToolUse` deny for tools whose shape isn't pinned
3. **The Mirror needs another route for Edit.** Write works. For an Edit whose `old_string` contains a placeholder, candidates are:
   * a `PostToolUseFailure` hook that tells the model to use Write or `basilisk edit` instead
   * a Basilisk-provided edit command

   Whether `PostToolUseFailure` fires for validation errors is untested.
4. **Bash is the bypass.** The model will read files through Bash when its other tools fail. Bash output must be petrified too, and since the vault knows the exact real values, Basilisk can match them in common encodings (raw, `od -c`, hex, base64), not just with detectors.

## Open questions

1. **`@file` mentions:** does `UserPromptSubmit` see the contents of `@`-mentioned files?
2. **`PostToolUseFailure`:** does it fire for Edit's validation errors, and can it add context the model sees?
3. **Output shapes for other tools:** Grep, Glob, NotebookRead and WebFetch.
4. **Permission modes:** does `updatedInput` without a decision also apply in default mode, or does it change what the permission prompt shows?
5. **Codex details:** the minimum version for each hook event, and whether Codex has built-in read tools besides shell that `PreToolUse` covers.
