#!/usr/bin/env python3
"""Keeps secrets, keys and personal or infrastructure details out of the repository.

Modes:
  --staged   staged changes (git pre-commit hook): added lines, added file names, the commit identity
  --all      every tracked file, plus every commit message and identity (CI, `make check`)
  --tree     every tracked file only (a repository whose history is checked elsewhere)

Looks for: private keys (PEM, raw, base64), keystores, cloud and service tokens, JSON Web Tokens, App Store Connect
key files and IDs, credentials in URLs, hard-coded secrets, Google service-account JSON; home folders, private,
CGNAT/Tailscale and link-local addresses, Tailscale host names, personal e-mail addresses (only noreply and example
addresses are fine); files that must never be committed (.env, .p8, .p12, .pem, keystores, provisioning profiles…);
session links and `Claude-Session:` lines in commit messages; machine identities as commit e-mails.

A finding that is known to be safe is allowed by a regex in `.safety-allow` (one per line, each with a comment
saying why, never broad) or by `safety: allow -- <reason>` on the line itself; --all lists every inline marker.
Standard library only.
Sources: Lamap check-sensitive.sh, Encave check-public-safety.sh, Ondo leak_guard.py.
"""

import base64
import re
import subprocess
import sys
from pathlib import Path

# Inline exception: `safety: allow -- <reason of 10+ characters>` on the line. Counted and listed by --all.
ALLOW_MARKER = re.compile(r"safety: allow\s*(?:--|—|:)\s*(\S.{9,})")
# Lines any real secret or detail would not match: an allowlist rule matching one of them is far too broad.
GENERIC_SAMPLES = ["", "a", "x = 1", "the quick brown fox 123", "password = hunter2-example-0", "192." + "168.1.1"]
ALLOW_FILE = ".safety-allow"
MAX_FILE_BYTES = 2_000_000

TEMPLATE = re.compile(r"[$<>{}]|\\\(|%[(s]|^[*.…]+$")
PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|(?:your|my|the|some|a)?[_-]?(?:pass(?:word|wd)?|secret|token|(?:api[_-]?)?key|user(?:name)?|login|"
    r"value|changeme)s?[_-]?\d{0,2})$|example|placeholder|dummy|redacted|not[_-]?(?:a[_-]?)?(?:real|secret)")
SECRET_WORD = re.compile(r"(?i)pass(?:word|wd|phrase)|secret|token|api[_-]?key|private[_-]?key")


def placeholder(value):
    return bool(TEMPLATE.search(value) or PLACEHOLDER.search(value))


def mixed(value):
    return bool(re.search(r"[A-Za-z]", value) and re.search(r"\d", value))


def assigned_secret(match):
    quoted, bare = match.group("quoted"), match.group("bare")
    value = quoted or bare
    if placeholder(value) or SECRET_WORD.search(value) or "://" in value:
        return False
    if quoted:
        return len(value) >= 16 or (len(value) >= 8 and mixed(value))
    return len(value) >= 8 and mixed(value)


def base64_private_key(match):
    run = match.group(0)
    try:
        decoded = base64.b64decode(run[: len(run) // 4 * 4]).decode("utf-8", "replace")
    except ValueError:
        return False
    return "PRIVATE KEY-----" in decoded


def apple_id(match):
    value = match.group("value")
    return not placeholder(value) and bool(re.search(r"\d", value))


SECRET_NAME = (r"(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?key|client[_-]?secret|secret|"
               r"token|password|passwd|passphrase)s?(?![A-Za-z0-9_])")

SECRET_RULES = [
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:[A-Za-z0-9+/=\s]|\\[nr]){40,}")),
    ("private key", re.compile(
        r"\b(?:MIG[HT]AgEAMBMGByqGSM49AgEGCCqGSM49AwEHB|MII[A-Za-z0-9+/]{2}QIBADANBgkqhkiG9w0BAQEFAASC)[A-Za-z0-9+/]{40,}")),
    ("private key", re.compile(r"(?<![A-Za-z0-9+/])LS0tLS1CRUdJTi[A-Za-z0-9+/]{22,}={0,2}"), base64_private_key),
    ("keystore", re.compile(r"(?<![A-Za-z0-9+/])(?:/u3\+7QAAAA|MII[A-Za-z0-9+/]{2}[AQgw]IBAzCC)[A-Za-z0-9+/]{60,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}")),
    ("Anthropic / OpenAI key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("App Store Connect key file", re.compile(r"\bAuthKey_[A-Z0-9]{10}\.p8\b")),
    ("App Store Connect key ID, issuer ID or team ID", re.compile(
        r"(?i)(?:key[_-]?id|issuer[_-]?id|team[_-]?id(?:entifier)?|development[_-]?team)"
        r"(?:[\"'`]?[ \t]*(?:=>|:=|=|:|\()[ \t]*[\"'`]?|</key>\s*<string>)"
        r"(?P<value>(?-i:[A-Z0-9]{10})|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![\w-])"), apple_id),
    ("credentials in a URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:[^/\s:@'\"$]{6,}@[^\s'\"]+")),
    ("hard-coded secret", re.compile(
        rf"(?i)(?<![?&]){SECRET_NAME}[\"'`]?(?:\s*:\s*[A-Za-z_][\w.<>?\[\]]*\s*(?==))?\s*(?:=>|:=|\?=|=|:)[ \t]*"
        r"(?:(?P<quote>[\"'`])(?P<quoted>[^\"'`\s]{8,})(?P=quote)|(?P<bare>[^\s\"'`.$<>{}()\[\]\\,;#&?]{8,})(?=[\s,;)\]}]|$))"),
     assigned_secret),
]

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ALLOWED_EMAIL = re.compile(
    r"(?i)(?:@users\.noreply\.github\.com$|^noreply@[a-z0-9.-]+$|@example\.(?:com|org|net)$|@\d+x\.)")
OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
PERSONAL_RULES = [
    ("home folder", re.compile(
        r"(?:(?<![\w.~-])/Users/(?!runner\b|Shared\b|\$|<)[A-Za-z0-9._-]+/|(?<![\w.~-])/home/(?!runner\b|\$|<)[a-z_][a-z0-9_.-]*/"
        r"|(?<![\w.~-])/" + r"root/|[A-Z]:\\Users\\[A-Za-z0-9._-]+)")),  # split: this file must pass itself
    ("private network address", re.compile(
        rf"(?<![\d.])(?:10\.{OCTET}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.{OCTET}\.{OCTET}(?![\d]|\.\d)")),
    ("CGNAT / Tailscale address", re.compile(
        rf"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.{OCTET}\.{OCTET}(?![\d]|\.\d)")),
    ("link-local address", re.compile(rf"(?<![\d.])169\.254\.{OCTET}\.{OCTET}(?![\d]|\.\d)")),
    ("Tailscale host name", re.compile(r"[A-Za-z0-9-]\.ts\.net\b")),
]
SERVICE_ACCOUNT = re.compile(r'"type"\s*:\s*"service_account"')

FORBIDDEN_FILES = re.compile(
    r"(?i)(?:^|/)(?:secrets/|\.env(?:\.[^/]*)?$|[^/]+\.env$|\.envrc$|\.netrc$|_netrc$|local\.properties$|"
    r"(?:google-services\.json|GoogleService-Info\.plist)$|id_(?:rsa|dsa|ed25519|ecdsa)[^/]*$|"
    r"(?:keystore|signing)\.properties$|\.claude/settings\.local\.json$|[^/]*\.xcresult(?:/|$)|"
    r"[^/]*\.(?:p8|p12|pfx|pem|key|cer|crt|der|mobileprovision|provisionprofile|keystore|jks|pyc|sqlite)$|"
    r"__pycache__/)")
SESSION_LINK = re.compile(r"(?i)claude\.ai/(?:code/)?(?:session|chat)|chatgpt\.com/(?:c|share)/|^Claude-Session:", re.M)
MACHINE_EMAIL = re.compile(r"(?i)^(?:ubuntu|root|admin|debian|ec2-user)@|@(?:vps|ip|localhost)[-.]|\.(?:local|internal|lan)$")


class AllowlistError(ValueError):
    pass


def load_allowlist(root):
    """The regexes of .safety-allow. Each needs a comment line just above it (the reason) and must be narrow: a
    rule that matches an empty or generic line is refused."""
    path = Path(root) / ALLOW_FILE
    if not path.exists():
        return []
    rules, previous = [], ""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if text and not text.startswith("#"):
            if not previous.startswith("#"):
                raise AllowlistError(f"{ALLOW_FILE}:{number}: no comment line above the rule saying why")
            try:
                rule = re.compile(text)
            except re.error as error:
                raise AllowlistError(f"{ALLOW_FILE}:{number}: bad regex ({error})") from None
            if any(rule.search(sample) for sample in GENERIC_SAMPLES):
                raise AllowlistError(f"{ALLOW_FILE}:{number}: rule too broad (matches a generic line)")
            rules.append(rule)
        previous = text
    return rules


def inline_markers(root, names):
    """(file:line, reason) of every inline `safety: allow` marker in the tracked files."""
    found = []
    for name in names:
        path = Path(root) / name
        if path.is_file() and path.stat().st_size < MAX_FILE_BYTES and Path(name).name not in ("check_safety.py", "test_check_safety.py"):
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                match = ALLOW_MARKER.search(line)
                if match:
                    found.append((f"{name}:{number}", match.group(1).strip()))
    return found


def redact(text):
    text = text.strip().replace("\n", " ")
    return text[:6] + "…" if len(text) > 6 else "…"


def scan_text(text, where, allow):
    """Findings (where, rule, sample) in a block of text."""
    findings = []
    lines = text.splitlines()

    def allowed(found, line):
        return bool(ALLOW_MARKER.search(line)) or any(rule.search(found) or rule.search(line) for rule in allow)

    def line_of(position):
        number = text.count("\n", 0, position)
        return number + 1, lines[number] if number < len(lines) else ""

    for name, rule, *decide in SECRET_RULES:
        for match in rule.finditer(text):
            if decide and not decide[0](match):
                continue
            number, line = line_of(match.start())
            if not allowed(match.group(0), line):
                findings.append((f"{where}:{number}", name, redact(match.group(0))))
    for match in EMAIL.finditer(text):
        number, line = line_of(match.start())
        if not ALLOWED_EMAIL.search(match.group(0)) and not allowed(match.group(0), line):
            findings.append((f"{where}:{number}", "e-mail address", redact(match.group(0))))
    for name, rule in PERSONAL_RULES:
        for match in rule.finditer(text):
            number, line = line_of(match.start())
            if not allowed(match.group(0), line):
                findings.append((f"{where}:{number}", name, match.group(0)))
    if SERVICE_ACCOUNT.search(text) and '"private_key"' in text:
        number, line = line_of(SERVICE_ACCOUNT.search(text).start())
        if not allowed("service_account", line):
            findings.append((f"{where}:{number}", "Google service-account key", "service_account"))
    return findings


def scan_names(names, allow):
    return [(name, "file that must not be committed", name) for name in names
            if FORBIDDEN_FILES.search(name) and not name.endswith(".example")
            and not any(rule.search(name) for rule in allow)]


def scan_message(text, where, allow):
    findings = []
    for match in SESSION_LINK.finditer(text):
        line = text[text.rfind("\n", 0, match.start()) + 1:].split("\n", 1)[0]
        if not any(rule.search(line) for rule in allow):
            findings.append((where, "session link or Claude-Session line in a commit message", redact(line)))
    return findings + scan_text(text, where, allow)


def scan_identity(email, where, allow, strict=True):
    """Machine identities always fail; with strict (the identity of a new commit), only noreply addresses pass.
    History is not strict: GitHub's squash merges carry the merger's own address."""
    if not email or any(rule.search(email) for rule in allow):
        return []
    if MACHINE_EMAIL.search(email):
        return [(where, "machine identity as commit e-mail", redact(email))]
    if strict and not ALLOWED_EMAIL.search(email):
        return [(where, "commit e-mail is not a noreply address", redact(email))]
    return []


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, errors="replace").stdout


def added_lines_by_file(diff):
    files, current = {}, None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
            if current:
                files.setdefault(current, [])
        elif current and line.startswith("+") and not line.startswith("+++"):
            files[current].append(line[1:])
    return {name: "\n".join(lines) for name, lines in files.items()}


def scan_staged(root, allow):
    findings = scan_identity(git(root, "config", "user.email").strip(), "git config user.email", allow)
    for name, text in added_lines_by_file(git(root, "diff", "--cached", "--no-color", "--no-ext-diff")).items():
        findings += scan_text(text, name, allow)
    findings += scan_names(git(root, "diff", "--cached", "--name-only", "--diff-filter=AR").split(), allow)
    return findings


def scan_working(root, allow):
    """Everything a `git add -A && git commit` would record (the Claude hook, before a commit)."""
    findings = scan_identity(git(root, "config", "user.email").strip(), "git config user.email", allow)
    for diff in (git(root, "diff", "HEAD", "--no-color", "--no-ext-diff"),
                 git(root, "diff", "--cached", "--no-color", "--no-ext-diff")):
        for name, text in added_lines_by_file(diff).items():
            findings += scan_text(text, name, allow)
    changed = git(root, "diff", "HEAD", "--name-only", "--diff-filter=AR").split()
    changed += git(root, "diff", "--cached", "--name-only", "--diff-filter=AR").split()
    untracked = git(root, "ls-files", "--others", "--exclude-standard").split()
    findings += scan_names(changed + untracked, allow)
    for name in untracked:
        path = Path(root) / name
        if path.is_file() and path.stat().st_size < MAX_FILE_BYTES:
            findings += scan_text(path.read_text(encoding="utf-8", errors="replace"), name, allow)
    return findings


def scan_tree(root, allow):
    """Every tracked file (no history)."""
    names = git(root, "ls-files").splitlines()
    findings = scan_names(names, allow)
    for name in names:
        path = Path(root) / name
        if path.is_file() and path.stat().st_size < MAX_FILE_BYTES:
            data = path.read_bytes()
            if b"\0" not in data[:8000]:
                findings += scan_text(data.decode("utf-8", "replace"), name, allow)
    return findings


def scan_all(root, allow):
    findings = scan_tree(root, allow)
    for commit in git(root, "rev-list", "--all").split():
        meta = git(root, "show", "-s", "--format=%ae%n%ce%n%B", commit).split("\n", 2)
        where = f"commit {commit[:8]}"
        for email in meta[:2]:
            findings += scan_identity(email.strip(), where, allow, strict=False)
        if len(meta) > 2:
            # Messages: session links and secrets only (trailers carry e-mail addresses by design).
            findings += [f for f in scan_message(meta[2], f"{where} message", allow) if f[1] != "e-mail address"]
    return findings


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else "--all"
    if mode not in ("--staged", "--all", "--tree"):
        print(__doc__, file=sys.stderr)
        return 2
    root = git(".", "rev-parse", "--show-toplevel").strip()
    if not root:
        print("check_safety: not in a git repository", file=sys.stderr)
        return 2
    try:
        allow = load_allowlist(root)
    except AllowlistError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    scan = {"--staged": scan_staged, "--all": scan_all, "--tree": scan_tree}[mode]
    findings = list(dict.fromkeys(scan(root, allow)))
    if mode != "--staged":
        markers = inline_markers(root, git(root, "ls-files").splitlines())
        print(f"Inline 'safety: allow' markers: {len(markers)}; {ALLOW_FILE} rules: {len(allow)}.")
        for where, reason in markers:
            print(f"  {where}: {reason}")
    if findings:
        print("Safety check: possible secret or private detail:", file=sys.stderr)
        for where, rule, sample in findings[:40]:
            print(f"::error::{where}: {rule} ({sample})", file=sys.stderr)
        print(f"Remove it (secrets go to GitHub secrets), or for a false positive add a regex with a comment to "
              f"{ALLOW_FILE}.", file=sys.stderr)
        return 1
    print("Safety check: OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
