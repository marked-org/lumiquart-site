#!/usr/bin/env python3
"""Claude PreToolUse hook (Write, Edit, MultiEdit, Bash). Exit code 2 blocks the call; the reason goes to Claude.

- What Claude writes into the repository, and every shell command, is scanned by scripts/check_safety.py's rules
  (secrets, keys, private addresses, home folders, personal e-mails; allowlist `.safety-allow`).
- Before `git commit`: everything the commit could record (also `.claude/settings.local.json` if staged), and the
  commit message (no `Claude-Session:` line, no session link).
- Blocked commands: force push to main, `git tag` (creating), pushing tags, `--no-verify`, `[skip ci]` markers,
  any change of `core.hooksPath` other than `.githooks` (`git -c core.hooksPath=…`, `git config core.hooksPath …`).
Logic lives in scripts/check_safety.py; this file only routes the tool call.
"""

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import check_safety  # noqa: E402

SKIP_CI = re.compile(r"\[(skip ci|ci skip|no ci|skip actions|actions skip)\]", re.I)
SEGMENT_SPLIT = re.compile(r"\|\||&&|[;|&\n]")


def git_invocations(command):
    """Each `git …` invocation of a shell command: (global options, words after them), best effort."""
    result = []
    for segment in SEGMENT_SPLIT.split(command):
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
        while words and ("=" in words[0] and not words[0].startswith("-")):
            words = words[1:]  # VAR=value prefixes
        if words and words[0] == "git":
            # Drop global options such as `-C dir` or `-c key=value`.
            rest, options = words[1:], []
            while rest and rest[0].startswith("-"):
                take = 2 if rest[0] in ("-C", "-c") else 1
                options += rest[:take]
                rest = rest[take:]
            result.append((options, rest))
    return result


def git_words(command):
    return [rest for _, rest in git_invocations(command) if rest]


def hooks_path_changed(options, words):
    """True when the command points core.hooksPath anywhere but .githooks, or unsets it."""
    values = [options[i + 1] for i, o in enumerate(options[:-1]) if o == "-c"]
    values += [o[2:] for o in options if o.startswith("-c") and len(o) > 2]
    for value in values:
        key, _, target = value.partition("=")
        if key.lower() == "core.hookspath" and target.strip() != ".githooks":
            return True
    if words and words[0] == "config":
        args = [w for w in words[1:] if not w.startswith("--") or w in ("--unset", "--unset-all")]
        lowered = [a.lower() for a in args]
        if "core.hookspath" in lowered:
            position = lowered.index("core.hookspath")
            if "--unset" in args or "--unset-all" in args:
                return True
            value = args[position + 1] if position + 1 < len(args) else None
            return value is not None and value != ".githooks"
    return False


def current_branch(root):
    out = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root, capture_output=True, text=True)
    return out.stdout.strip()


def command_problems(command, root):
    problems = []
    if SKIP_CI.search(command):
        problems.append("a [skip ci] marker: every commit must be checked by CI")
    for options, words in git_invocations(command):
        if hooks_path_changed(options, words):
            problems.append("core.hooksPath: the git hooks stay on (.githooks)")
        if not words:
            continue
        verb, args = words[0], words[1:]
        if "--no-verify" in args or (verb == "commit" and "-n" in args):
            problems.append("--no-verify: the git hooks are the same checks as CI; fix the finding instead")
        if verb == "tag" and args and not set(args) & {"-l", "--list", "--contains", "--points-at"}:
            problems.append("git tag: tags are created by the Release workflow only (sessions cannot push tags)")
        if verb == "push":
            if set(args) & {"--tags", "--follow-tags", "--mirror"} or any("refs/tags" in a or re.fullmatch(r"\+?v\d+\.\d+\.\d+", a) for a in args):
                problems.append("pushing tags: the Release workflow creates them")
            force = any(a in ("-f", "--force") or a.startswith("--force-with-lease") or a.startswith("--force-if-includes")
                        or (a.startswith("+") and len(a) > 1) for a in args)
            refs = [a for a in args if not a.startswith("-")][1:]
            to_main = any(a.lstrip("+").split(":")[-1] in ("main", "refs/heads/main") for a in refs) or (
                not refs and current_branch(root) == "main")
            if force and to_main:
                problems.append("force push to main: never rewrite main")
            if "--delete" in args and to_main or any(a == ":main" for a in refs):
                problems.append("deleting main")
    return problems


def bash_findings(command, root, allow):
    findings = [(w, r, s) for w, r, s in check_safety.scan_text(command, "command", allow)]
    if re.search(r"\bgit\b[^|;&]*\bcommit\b", command):
        findings += check_safety.scan_working(root, allow)
        for match in check_safety.SESSION_LINK.finditer(command):
            findings.append(("commit message", "session link or Claude-Session line", match.group(0)))
        if re.search(r"(?m)Claude-Session:", command):
            findings.append(("commit message", "Claude-Session line", "Claude-Session:"))
    return findings


def write_findings(data, root, allow):
    path = Path(data.get("file_path") or data.get("notebook_path") or "")
    if not path.is_absolute():
        path = root / path
    try:
        relative = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return []  # outside the repository: never published from here
    if subprocess.run(["git", "check-ignore", "-q", relative], cwd=root).returncode == 0:
        return []  # ignored files are never committed
    texts = [data.get("content", ""), data.get("new_string", ""), data.get("new_source", "")]
    texts += [edit.get("new_string", "") for edit in data.get("edits", []) or []]
    findings = check_safety.scan_names([relative], allow)
    for text in texts:
        if text:
            findings += check_safety.scan_text(text, relative, allow)
    return findings


def evaluate(event, root=ROOT):
    """(blocking reasons) for one tool call."""
    tool, data = event.get("tool_name", ""), event.get("tool_input") or {}
    allow = check_safety.load_allowlist(root)
    reasons = []
    if tool == "Bash":
        command = data.get("command", "")
        reasons += command_problems(command, root)
        reasons += [f"{w}: {r} ({s})" for w, r, s in dict.fromkeys(bash_findings(command, root, allow))]
    elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        reasons += [f"{w}: {r} ({s})" for w, r, s in dict.fromkeys(write_findings(data, root, allow))]
    return reasons


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    reasons = evaluate(event)
    if not reasons:
        return 0
    print("Blocked by .claude/hooks/guard.py:", file=sys.stderr)
    for reason in reasons[:20]:
        print(f"  - {reason}", file=sys.stderr)
    print("Remove the secret or private detail (secrets go to GitHub secrets), or for a false positive add a "
          "commented regex to .safety-allow. Process rules: CLAUDE.md.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
