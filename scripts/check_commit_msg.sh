#!/usr/bin/env bash
# Keeps commit messages short and free of conversation/prompt text.
# Usage:
#   scripts/check_commit_msg.sh <message-file>      (commit-msg hook)
#   scripts/check_commit_msg.sh --range A..B        (CI)
#   scripts/check_commit_msg.sh --text-only <file>  (PR title/body: phrases only)
set -euo pipefail

MAX_SUBJECT=72
MAX_BODY_LINES=12
# Phrases that indicate a pasted prompt or chat transcript. Short words only
# match as whole words ("commercial" is not "merci"), with POSIX classes rather
# than \b, which BSD grep on macOS does not support.
L='(^|[^[:alnum:]_])'
R='([^[:alnum:]_]|$)'
BANNED="${L}(my|your|this|the user.s|mon|ton|le) prompt|the user (asked|wants|said|requested)|${L}as requested|${L}you asked|l.utilisateur|${L}je veux${R}|${L}tu peux${R}|${L}peux-tu|${L}stp${R}|s.il te pla|${L}merci${R}|${L}as an ai${R}|claude code session transcript|<pasted_content|system-reminder|^(user|assistant|human) ?:"

# Links to AI chat sessions expose private conversations, even as trailers.
SESSION_LINK='(claude\.ai/(code/)?(session|chat)|chatgpt\.com/(c|share)/|Claude-Session:)'

# Markers that make GitHub skip every push workflow, ci.yml included: a later push
# checks only its own range, so such a commit would never be checked.
SKIP_CI='\[(skip ci|ci skip|no ci|skip actions|actions skip)\]'

# Trailers left out of the line count: only those git finds in the last
# paragraph, and only the usual kinds.
TRAILER='^([A-Za-z-]+-by|Fixes|Closes|Refs|See-also|Change-Id|Bug): '

check_message() {
  local label="$1" msg="$2" errors=0
  if printf '%s\n' "$msg" | grep -qiE "$SESSION_LINK"; then
    echo "$label: contains a link to an AI chat session; remove it"; errors=1
  fi
  local nocomment subject clean trailers body_lines
  nocomment=$(printf '%s\n' "$msg" | grep -v '^#' || true)
  if printf '%s\n' "$nocomment" | grep -qiE "$SKIP_CI"; then
    echo "$label: contains a marker that skips CI ($(printf '%s\n' "$nocomment" | grep -oiE "$SKIP_CI" | head -1)); remove it"; errors=1
  fi
  subject=$(printf '%s\n' "$nocomment" | sed -n '1p')
  # The phrases are looked for in the whole message, trailers included.
  clean="$nocomment"
  trailers=$(printf '%s\n' "$nocomment" | git interpret-trailers --parse --no-divider 2>/dev/null | grep -ciE "$TRAILER" || true)
  body_lines=$(printf '%s\n' "$nocomment" | sed '1d' | grep -c '[^[:space:]]' || true)
  body_lines=$(( body_lines - trailers ))

  if [[ -z "$subject" ]]; then
    echo "$label: empty subject"; errors=1
  elif (( ${#subject} > MAX_SUBJECT )); then
    echo "$label: subject is ${#subject} chars (max $MAX_SUBJECT)"; errors=1
  fi
  if (( body_lines > MAX_BODY_LINES )); then
    echo "$label: body has $body_lines lines (max $MAX_BODY_LINES); summarize the change"; errors=1
  fi
  if printf '%s\n' "$clean" | grep -qiE "$BANNED"; then
    echo "$label: message looks like it contains prompt or chat text:"
    printf '%s\n' "$clean" | grep -inE "$BANNED" | head -3 | sed 's/^/    /'
    errors=1
  fi
  return $errors
}

if [[ "${1:-}" == "--text-only" ]]; then
  if grep -qiE "$SESSION_LINK" "$2"; then
    echo "Pull request text contains a link to an AI chat session; remove it"
    exit 1
  fi
  if grep -qiE "$BANNED" "$2"; then
    echo "Pull request text looks like it contains prompt or chat text:"
    grep -inE "$BANNED" "$2" | head -3 | sed 's/^/    /'
    exit 1
  fi
  exit 0
fi

if [[ "${1:-}" == "--range" ]]; then
  status=0
  # Assigned first so an unknown range fails instead of checking nothing.
  shas=$(git rev-list --no-merges "$2")
  for sha in $shas; do
    check_message "commit ${sha:0:8}" "$(git log -1 --format=%B "$sha")" || status=1
  done
  exit $status
fi

check_message "commit message" "$(cat "$1")"
