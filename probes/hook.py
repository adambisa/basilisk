"""Test hook for the probes. Usage: hook.py <mode> <logdir>, hook payload on stdin.

Every payload is appended to <logdir>/<mode>.jsonl. Modes:
  log                 record only
  post_replace        PostToolUse: replace the canary in tool_response via updatedToolOutput
  post_bad            PostToolUse: return an updatedToolOutput of the wrong shape
  post_crash          PostToolUse: exit 1
  post_timeout        PostToolUse: sleep past the hook timeout
  pre_redirect        PreToolUse: point Read of secret.txt at a petrified copy
  pre_redirect_edit   as pre_redirect, and point Edit/Write of secret.txt at the copy too
"""

import json
import os
import sys
import time

CANARY, PLACEHOLDER = "CANARY_ORIGINAL_7f3a9", "⟦SECRET_1⟧"

mode, logdir = sys.argv[1], sys.argv[2]
data = json.load(sys.stdin)
os.makedirs(logdir, exist_ok=True)
with open(os.path.join(logdir, f"{mode}.jsonl"), "a") as f:
    f.write(json.dumps(data) + "\n")


def scrub(v):
    if isinstance(v, str):
        return v.replace(CANARY, PLACEHOLDER)
    if isinstance(v, list):
        return [scrub(x) for x in v]
    if isinstance(v, dict):
        return {k: scrub(x) for k, x in v.items()}
    return v


def respond(output):
    print(json.dumps({"hookSpecificOutput": output}, ensure_ascii=False))
    sys.exit(0)


event, tool, tool_input = data["hook_event_name"], data.get("tool_name"), data.get("tool_input", {})

if event == "PostToolUse":
    if mode == "post_replace":
        respond({"hookEventName": event, "updatedToolOutput": scrub(data["tool_response"])})
    if mode == "post_bad":
        respond({"hookEventName": event, "updatedToolOutput": "wrong shape"})
    if mode == "post_crash":
        sys.stderr.write("probe hook crashed on purpose\n")
        sys.exit(1)
    if mode == "post_timeout":
        time.sleep(10)
        sys.exit(0)

if event == "PreToolUse" and mode.startswith("pre_redirect"):
    real = os.path.join(data["cwd"], "secret.txt")
    copy = os.path.join(data["cwd"], ".basilisk", "petrified", "secret.txt")
    if tool_input.get("file_path") == real:
        if tool == "Read":
            os.makedirs(os.path.dirname(copy), exist_ok=True)
            with open(real) as r, open(copy, "w") as w:
                w.write(scrub(r.read()))
            respond({"hookEventName": event, "updatedInput": {**tool_input, "file_path": copy}})
        if mode == "pre_redirect_edit" and tool in ("Edit", "Write"):
            respond({"hookEventName": event, "updatedInput": {**tool_input, "file_path": copy}})

sys.exit(0)
