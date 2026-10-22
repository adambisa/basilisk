# Probes

Experiments that check hook behaviour the Claude Code docs don't cover. They answer the open questions in [docs/design.md](../docs/design.md).

Each probe runs headless Claude Code (Haiku) in a fresh temp project. The project holds a `secret.txt` with a synthetic canary value. The probe then reports whether the canary reached the model's reply and the transcript on disk, and whether an Edit landed on the real file or the petrified copy.

| Mode | Question |
| :- | :- |
| `log` | What does a Read's `tool_response` look like? |
| `post_replace` | Does `updatedToolOutput` hide the value from the model, and what does the transcript keep? |
| `post_bad`, `post_crash`, `post_timeout` | Does the original reach the model when the hook returns the wrong shape, crashes or times out? |
| `pre_redirect` | Does `updatedInput` apply without a `permissionDecision`, and does Edit work after a redirected Read? |
| `pre_redirect_edit` | Does Edit work when it's pointed at the petrified copy too? |

```bash
probes/run.sh            # all modes
probes/run.sh post_bad   # one mode
```

Needs a signed-in `claude` CLI (`claude auth login`), `jq` and `python3`. Each run is a real model call. Raw results land in `probes/.runs/`, which is gitignored.
