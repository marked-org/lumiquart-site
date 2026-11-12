#!/usr/bin/env python3
"""Enforces the CI budget and supply-chain rules on GitHub Actions workflows.

Fails on:
  - a job whose `runs-on` is not one of the two self-hosted label sets (RUNNERS);
  - a job without `timeout-minutes`;
  - a workflow without a top-level `permissions` block, or with `write-all`;
  - an action not pinned by a 40-character commit SHA (local `./` actions and `docker://…@sha256:` are fine);
  - the `pull_request_target` trigger;
  - an `upload-artifact` step without `retention-days` <= 3 and `continue-on-error: true`;
  - a secret (other than GITHUB_TOKEN) used outside the workflows named by --secrets-in, or used there outside a
    main-ref condition (job `if`, step `if`, or the `${{ }}` expression itself);
  - more than one Mac job in a workflow, unless the file says `# mac-jobs: N` (with the reason on the same line);
  - a checkout without `persist-credentials: false` (the token would stay in .git/config on a shared runner);
  - on a workflow triggered by `pull_request`, a self-hosted job without the fork guard
    (`github.event.pull_request.head.repo.full_name == github.repository` in its `if`, or only after guarded jobs);
  - an unpinned action inside a composite action (`.github/actions/*/action.yml`);
  - YAML features the reader does not follow (anchors, aliases, merge keys, tags, `?` keys): they fail closed;
  - the provisioning runner `[self-hosted, Linux, X64, provision]` outside the workflows named by --provision-in;
  - with --public (a public repository): any self-hosted runner. The organisation's runners never serve public
    repositories, and GitHub-hosted runners are not used either, so a public repo has no job at all.

Usage: scripts/check_workflows.py [--public] [--secrets-in release.yml,...] [workflow files]
Default files: .github/workflows/*.yml; default --secrets-in: project.json `workflow_secrets`, else release.yml.
Standard library only: a small YAML reader for the subset workflows use is included.
"""

import argparse
import glob
import json
import os
import re
import sys

RUNNERS = (
    ("self-hosted", "Linux", "X64", "linux-vps"),
    ("self-hosted", "macOS", "ARM64", "alfred-mac"),
)
# The dedicated provisioning runner of ops-apps: allowed only in the workflows named by --provision-in.
PROVISION_RUNNER = ("self-hosted", "Linux", "X64", "provision")
MAC_LABEL = "alfred-mac"
MAX_RETENTION_DAYS = 3
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
SECRET = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
MAIN = re.compile(r"github\.ref\s*==\s*'refs/heads/main'")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
FORK_GUARD = re.compile(r"github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository")
MAC_JOBS = re.compile(r"#\s*mac-jobs:\s*(\d+)\s*\S")


# --- Minimal YAML reader (block/flow mappings and sequences, scalars, block scalars, comments) ---------------------


class YamlError(ValueError):
    pass


def _strip_comment(line):
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"" and (i == 0 or line[i - 1] in " \t:[{,-"):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r", "e": "\x1b",
           " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029"}


def _unescape(body):
    """YAML double-quoted escapes, without touching other characters (non-ASCII text stays as it is)."""
    def replace(match):
        code = match.group(1)
        if code[0] in "xuU":
            return chr(int(code[1:], 16))
        if code in ESCAPES:
            return ESCAPES[code]
        raise YamlError(f"unknown escape \\{code}")
    return re.sub(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", replace, body)


def _scalar(text):
    text = text.strip()
    if not text:
        return None
    if text[0] == '"' and text.endswith('"') and len(text) >= 2:
        return _unescape(text[1:-1])
    if text[0] == "'" and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    if text[0] in "&*!" or text.startswith("<<"):
        raise YamlError(f"anchors, aliases, merge keys and tags are not allowed: {text[:40]}")
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if text in ("null", "~", "Null", "NULL"):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def _split_flow(text):
    """Splits the inside of a flow collection on top-level commas."""
    parts, depth, quote, start = [], 0, None, 0
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _key_split(text):
    """(key, rest) when text is `key: rest` (outside quotes and flow collections), else None."""
    quote, depth = None, 0
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"" and i == 0:
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0 and (i + 1 == len(text) or text[i + 1] in " \t"):
            key = text[:i].strip()
            if key[:1] in "'\"":
                key = key[1:-1]
            return key, text[i + 1:].strip()
    return None


def _flow(text):
    text = text.strip()
    if text.startswith("["):
        if not text.endswith("]"):
            raise YamlError(f"unclosed flow sequence: {text}")
        return [_flow(p) for p in _split_flow(text[1:-1])]
    if text.startswith("{"):
        if not text.endswith("}"):
            raise YamlError(f"unclosed flow mapping: {text}")
        result = {}
        for part in _split_flow(text[1:-1]):
            pair = _key_split(part)
            if pair is None:
                raise YamlError(f"bad flow mapping entry: {part}")
            result[pair[0]] = _flow(pair[1]) if pair[1] else None
        return result
    return _scalar(text)


class _Reader:
    def __init__(self, text):
        self.raw = text.splitlines()
        self.lines = []  # (indent, content, raw index)
        for index, line in enumerate(self.raw):
            if "\t" in line[: len(line) - len(line.lstrip())]:
                raise YamlError(f"tab indentation on line {index + 1}")
            content = _strip_comment(line)
            if content.strip() and content.strip() != "---":
                self.lines.append((len(content) - len(content.lstrip()), content.strip(), index))
        self.pos = 0

    def parse(self):
        if not self.lines:
            return None
        value = self.block(self.lines[0][0])
        if self.pos < len(self.lines):
            raise YamlError(f"unexpected content on line {self.lines[self.pos][2] + 1}")
        return value

    def block(self, indent):
        if self.lines[self.pos][1].startswith("- ") or self.lines[self.pos][1] == "-":
            return self.sequence(indent)
        return self.mapping(indent)

    def value_after(self, rest, indent, raw_index):
        """The value of `key: rest` or `- rest`, possibly continued on deeper lines."""
        if rest and rest[0] in "&*!":
            raise YamlError(f"anchors, aliases and tags are not allowed (line {raw_index + 1}): {rest[:40]}")
        if rest in ("|", "|-", "|+", ">", ">-", ">+"):
            return self.block_scalar(rest, indent, raw_index)
        if rest:
            text = rest
            # Plain or flow scalar continued on more indented lines.
            while self.pos < len(self.lines) and self.lines[self.pos][0] > indent and not (
                    rest[0] not in "[{" and _key_split(self.lines[self.pos][1])):
                text += " " + self.lines[self.pos][1]
                self.pos += 1
            return _flow(text)
        if self.pos < len(self.lines) and self.lines[self.pos][0] > indent:
            return self.block(self.lines[self.pos][0])
        # A sequence may sit at the same indent as its key.
        if self.pos < len(self.lines) and self.lines[self.pos][0] == indent and self.lines[self.pos][1].startswith("- "):
            return self.sequence(indent)
        return None

    def block_scalar(self, style, indent, raw_index):
        body, i = [], raw_index + 1
        block_indent = None
        while i < len(self.raw):
            line = self.raw[i]
            if line.strip():
                current = len(line) - len(line.lstrip())
                if current <= indent:
                    break
                block_indent = current if block_indent is None else block_indent
                body.append(line[block_indent:])
            else:
                body.append("")
            i += 1
        while body and body[-1] == "":
            body.pop()
        while self.pos < len(self.lines) and self.lines[self.pos][2] < i:
            self.pos += 1
        text = "\n".join(body) if style.startswith("|") else " ".join(x for x in body if x)
        return text if style.endswith("-") else text + "\n"

    def mapping(self, indent):
        result = {}
        while self.pos < len(self.lines):
            line_indent, content, raw_index = self.lines[self.pos]
            if line_indent < indent:
                break
            if line_indent > indent:
                raise YamlError(f"bad indentation on line {raw_index + 1}")
            if content.startswith("- "):
                break
            if content.startswith("? ") or content == "?":
                raise YamlError(f"complex keys are not allowed (line {raw_index + 1})")
            pair = _key_split(content)
            if pair is None:
                raise YamlError(f"expected 'key: value' on line {raw_index + 1}: {content}")
            if pair[0] == "<<" or (pair[0] and pair[0][0] in "&*!"):
                raise YamlError(f"merge keys, anchors and tags are not allowed (line {raw_index + 1})")
            self.pos += 1
            result[pair[0]] = self.value_after(pair[1], indent, raw_index)
        return result

    def sequence(self, indent):
        result = []
        while self.pos < len(self.lines):
            line_indent, content, raw_index = self.lines[self.pos]
            if line_indent != indent or not (content.startswith("- ") or content == "-"):
                break
            rest = content[1:].strip()
            self.pos += 1
            pair = _key_split(rest) if rest and rest[0] not in "[{'\"" else None
            if pair is not None:
                # `- key: value` starts a mapping whose keys sit at indent + 2.
                item_indent = indent + 2
                self.lines.insert(self.pos, (item_indent, rest, raw_index))
                result.append(self.mapping(item_indent))
            else:
                result.append(self.value_after(rest, indent, raw_index))
        return result


def load_yaml(text):
    return _Reader(text).parse()


# --- Rules ------------------------------------------------------------------------------------------------------


def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


def triggers(workflow):
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def secret_uses(text, gated):
    found = []
    for match in SECRET.finditer(text):
        if match.group(1) == "GITHUB_TOKEN":
            continue
        expressions = [e for e in EXPRESSION.finditer(text) if e.start() <= match.start() < e.end()]
        if not gated and not any(MAIN.search(e.group(1)) for e in expressions):
            found.append((match.group(0), False))
        else:
            found.append((match.group(0), True))
    return found


def check_secrets(name, jobs, allowed):
    errors = []
    for job_id, job in jobs.items():
        job_gated = bool(MAIN.search(str(job.get("if", ""))))
        places = [(f"job {job_id}", {k: v for k, v in job.items() if k not in ("steps", "if")}, job_gated)]
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            label = step.get("name") or step.get("uses") or f"step {index + 1}"
            gated = job_gated or bool(MAIN.search(str(step.get("if", ""))))
            places.append((f"job {job_id}, {label}", {k: v for k, v in step.items() if k != "if"}, gated))
        for where, node, gated in places:
            for text in strings(node):
                for secret, is_gated in secret_uses(text, gated):
                    if name not in allowed:
                        errors.append(f"{where}: {secret} outside the release workflow(s) ({', '.join(sorted(allowed))})")
                    elif not is_gated:
                        errors.append(f"{where}: {secret} without a main-ref condition "
                                      "(`if: github.ref == 'refs/heads/main'`)")
    return errors


def runner_labels(runs_on):
    if isinstance(runs_on, str):
        return (runs_on,)
    if isinstance(runs_on, list):
        return tuple(str(x) for x in runs_on)
    if isinstance(runs_on, dict):
        return tuple(str(x) for x in (runs_on.get("labels") or []))
    return ()


def check_workflow(path, text, allowed_secrets, public=False, provision_in=()):
    name = os.path.basename(path)
    errors = []
    try:
        workflow = load_yaml(text) or {}
    except YamlError as error:
        return [f"{path}: cannot read YAML ({error})"]
    if not isinstance(workflow, dict):
        return [f"{path}: not a workflow"]
    if "pull_request_target" in triggers(workflow):
        errors.append("pull_request_target is forbidden (fork code with secrets)")
    permissions = workflow.get("permissions")
    if permissions is None:
        errors.append("no top-level `permissions:` (use `contents: read`)")
    elif permissions == "write-all":
        errors.append("`permissions: write-all` is forbidden")
    jobs = workflow.get("jobs") or {}
    mac_jobs = []
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if "uses" in job:  # reusable workflow call: runner and timeout are checked in the called file
            if not str(job["uses"]).startswith("./"):
                errors.append(f"job {job_id}: only local reusable workflows are allowed")
            continue
        labels = runner_labels(job.get("runs-on"))
        if public and "self-hosted" in labels:
            errors.append(f"job {job_id}: a public repository must not use self-hosted runners")
        elif labels == PROVISION_RUNNER:
            if name not in provision_in:
                errors.append(f"job {job_id}: the provisioning runner is reserved for {', '.join(provision_in) or 'no workflow here'}")
        elif labels not in RUNNERS:
            errors.append(f"job {job_id}: runs-on {list(labels)} is not a self-hosted label set "
                          f"({' or '.join(str(list(r)) for r in RUNNERS)})")
        if MAC_LABEL in labels:
            mac_jobs.append(job_id)
        if "timeout-minutes" not in job:
            errors.append(f"job {job_id}: no timeout-minutes")
        if job.get("permissions") == "write-all":
            errors.append(f"job {job_id}: `permissions: write-all` is forbidden")
        errors += [f"job {job_id}, {e}" for e in check_steps(job.get("steps") or [])]
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            label = step.get("name") or uses or f"step {index + 1}"
            if uses:
                uses = str(uses)
                if re.match(r"^actions/upload-artifact@", uses):
                    days = (step.get("with") or {}).get("retention-days")
                    if not isinstance(days, int) or days > MAX_RETENTION_DAYS:
                        errors.append(f"job {job_id}, {label}: upload-artifact needs retention-days <= "
                                      f"{MAX_RETENTION_DAYS}")
                    if step.get("continue-on-error") is not True:
                        errors.append(f"job {job_id}, {label}: upload-artifact needs continue-on-error: true")
    if "pull_request" in triggers(workflow):
        errors += unguarded_jobs(jobs)
    errors += check_secrets(name, jobs, allowed_secrets)
    declared = MAC_JOBS.search(text)
    limit = int(declared.group(1)) if declared else 1
    if len(mac_jobs) > limit:
        errors.append(f"{len(mac_jobs)} Mac jobs ({', '.join(mac_jobs)}): one per workflow, or `# mac-jobs: N <reason>`")
    return [f"{path}: {e}" for e in errors]


def check_steps(steps):
    """Pinning and checkout rules shared by workflow jobs and composite actions."""
    errors = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or not step.get("uses"):
            continue
        uses = str(step["uses"])
        label = step.get("name") or uses or f"step {index + 1}"
        if not (uses.startswith("./") or (uses.startswith("docker://") and "@sha256:" in uses) or PINNED.match(uses)):
            errors.append(f"{label}: action `{uses}` is not pinned by a 40-character SHA")
        if uses.startswith("actions/checkout@") and (step.get("with") or {}).get("persist-credentials") is not False:
            errors.append(f"{label}: checkout needs `persist-credentials: false`")
    return errors


def unguarded_jobs(jobs):
    """Self-hosted jobs that fork pull requests could reach: neither guarded nor only after guarded jobs."""
    guarded = {}

    def is_guarded(job_id, seen=()):
        if job_id in guarded:
            return guarded[job_id]
        job = jobs.get(job_id) or {}
        result = bool(FORK_GUARD.search(str(job.get("if", ""))))
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        if not result and needs and job_id not in seen:
            result = all(is_guarded(n, seen + (job_id,)) for n in needs)
        guarded[job_id] = result
        return result

    errors = []
    for job_id, job in jobs.items():
        if isinstance(job, dict) and "self-hosted" in runner_labels(job.get("runs-on")) and not is_guarded(job_id):
            errors.append(f"job {job_id}: runs on a self-hosted runner for pull requests without the fork guard "
                          "(github.event.pull_request.head.repo.full_name == github.repository)")
    return errors


def check_composite(path, text):
    try:
        action = load_yaml(text) or {}
    except YamlError as error:
        return [f"{path}: cannot read YAML ({error})"]
    steps = ((action.get("runs") or {}).get("steps") or []) if isinstance(action, dict) else []
    return [f"{path}: {e}" for e in check_steps(steps)]


def default_secret_workflows():
    try:
        with open("project.json", encoding="utf-8") as handle:
            return set(json.load(handle).get("workflow_secrets", ["release.yml"]))
    except (OSError, ValueError):
        return {"release.yml"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--secrets-in", help="comma-separated workflow file names allowed to use secrets")
    parser.add_argument("--public", action="store_true", help="the repository is public")
    parser.add_argument("--provision-in", default="", help="workflow file allowed on the provisioning runner")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)
    allowed = set(filter(None, args.secrets_in.split(","))) if args.secrets_in else default_secret_workflows()
    paths = args.files or sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml"))
    errors = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            errors += check_workflow(path, handle.read(), allowed, args.public,
                                     tuple(filter(None, args.provision_in.split(","))))
    if not args.files:
        for path in sorted(glob.glob(".github/actions/*/action.yml") + glob.glob(".github/actions/*/action.yaml")):
            with open(path, encoding="utf-8") as handle:
                errors += check_composite(path, handle.read())
    for error in errors:
        print(f"::error::{error}")
    if errors:
        print(f"Workflow rules: {len(errors)} problem(s). See docs/CI.md.")
        return 1
    print(f"Workflow rules: OK ({len(paths)} workflow(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
