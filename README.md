<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/icon/basilisk-dark.svg">
    <img src="assets/icon/basilisk.svg" alt="Basilisk" width="160">
  </picture>
</p>

# Basilisk

A plugin for Claude Code and Codex that stops PII and secrets from reaching the model.

- **Block mode** stops prompts and tool reads that contain PII or secrets, and says what was found and where.
- **Petrify mode** lets the agent keep working, but it only ever sees placeholders like `⟦IBAN_1⟧`. When the agent writes code, the Mirror swaps the real values back in.

Basilisk reduces exposure. It is not a compliance guarantee: no tool can detect all PII, and some inputs never pass through a hook. The design doc lists what it can and can't cover.

## Status

Early. `basilisk scan` finds PII and secrets in text: by field name in JSON and tables, and by value for cards, IBANs, passport MRZ lines, crypto wallets and API keys. It prints where, without printing the values. The hooks, block mode and petrify mode aren't built yet.

```bash
go run ./cmd/basilisk scan users.csv
psql -c 'select * from customers' | go run ./cmd/basilisk scan
```

- [docs/design.md](docs/design.md): the design, mapped to what the Claude Code and Codex hook APIs allow.
- [probes/](probes/): small experiments that check hook behaviour the docs don't cover.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). If you redistribute Basilisk or build on it, keep the NOTICE file with it.

If Basilisk helps you, a mention or a link back is appreciated.
