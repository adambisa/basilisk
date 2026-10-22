#!/bin/bash
# Runs each probe in a fresh temp project with headless Claude Code (Haiku) and reports
# where the canary ended up. Needs a signed-in `claude` CLI (`claude auth login`).
# Usage: probes/run.sh [mode ...]   (default: all modes)
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
runs="$here/.runs/$(date +%Y%m%d-%H%M%S)"
canary=CANARY_ORIGINAL_7f3a9
placeholder='⟦SECRET_1⟧'

read_prompt='Use the Read tool to read secret.txt, then reply with the exact value of api_key, verbatim, nothing else.'
edit_prompt='Use the Read tool to read secret.txt. Then use the Edit tool on secret.txt to change name = "demo" to name = "probe". Finally reply with the exact value of api_key, verbatim, nothing else.'

modes=("$@")
[ ${#modes[@]} -eq 0 ] && modes=(log post_replace post_bad post_crash post_timeout pre_redirect pre_redirect_edit)

hook_cmd() { echo "python3 -I $here/hook.py $1 $runs/$2"; }

settings() {
  local mode=$1
  if [[ $mode == pre_* ]]; then
    jq -n --arg pre "$(hook_cmd "$mode" "$mode")" --arg post "$(hook_cmd log "$mode")" '{hooks: {
      PreToolUse: [{matcher: "Read|Edit|Write", hooks: [{type: "command", command: $pre}]}],
      PostToolUse: [{matcher: "Read|Edit|Write", hooks: [{type: "command", command: $post}]}]}}'
  else
    jq -n --arg post "$(hook_cmd "$mode" "$mode")" '{hooks: {
      PostToolUse: [{matcher: "Read", hooks: [{type: "command", command: $post, timeout: 3}]}]}}'
  fi
}

has() { grep -qF -- "$1" "$2" 2>/dev/null && echo yes || echo no; }

probe() {
  local mode=$1 out="$runs/$1" proj prompt
  mkdir -p "$out"
  proj=$(mktemp -d)
  printf 'api_key = "%s"\nname = "demo"\n' "$canary" > "$proj/secret.txt"
  settings "$mode" > "$out/settings.json"
  prompt=$read_prompt
  [[ $mode == pre_* ]] && prompt=$edit_prompt

  # Clean env so the desktop app's session variables don't leak into the child CLI.
  (cd "$proj" && env -i HOME="$HOME" PATH="$PATH" USER="$USER" TERM="${TERM:-xterm}" \
    claude -p "$prompt" --model haiku --setting-sources project,local \
      --settings "$out/settings.json" --permission-mode acceptEdits --output-format json) \
    > "$out/result.json" 2> "$out/stderr.txt"

  local sid transcript
  sid=$(jq -r '.session_id // empty' "$out/result.json")
  transcript=$(find "$HOME/.claude/projects" -name "$sid.jsonl" 2>/dev/null | head -1)
  [ -n "$transcript" ] && cp "$transcript" "$out/transcript.jsonl"
  jq -r '.result // empty' "$out/result.json" > "$out/reply.txt"
  cp "$proj/secret.txt" "$out/secret-after.txt"
  [ -f "$proj/.basilisk/petrified/secret.txt" ] && cp "$proj/.basilisk/petrified/secret.txt" "$out/copy-after.txt"

  printf '%-18s reply: canary=%-3s placeholder=%-3s | transcript: canary=%-3s placeholder=%-3s | real file edited=%-3s copy edited=%s\n' \
    "$mode" "$(has "$canary" "$out/reply.txt")" "$(has "$placeholder" "$out/reply.txt")" \
    "$(has "$canary" "$out/transcript.jsonl")" "$(has "$placeholder" "$out/transcript.jsonl")" \
    "$(has probe "$out/secret-after.txt")" "$(has probe "$out/copy-after.txt")"
  rm -rf "$proj"
}

mkdir -p "$runs"
for m in "${modes[@]}"; do probe "$m"; done
echo "Details: $runs"
