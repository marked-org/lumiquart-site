# Lumiquart website

Public, static website (GitHub Pages from `main`, root). The app lives in the private repository `marked-org/lumiquart`;
its session maintains this site.

- **Public repository**: no secrets, personal data, e-mail addresses, hostnames, private IPs or app code, in files,
  commit messages or screenshots. `make check` runs `scripts/check_safety.py` and `scripts/check_workflows.py`;
  the git hooks run them too (`make hooks`).
- **No workflows**: a public repo must not use the organisation's self-hosted runners, and GitHub-hosted runners are
  not used either. Actions are turned off for this repo; Pages deploys from the branch. ops-apps checks this repo
  with its own scripts every week.
- The Claude hook `.claude/hooks/guard.py` blocks secrets and private details in writes and commands; never turn
  the git hooks off.
- Pages in English; plain HTML and CSS, no build step, no third-party scripts, trackers or fonts.
- The privacy page must match what the app really does before each store submission.
- Commit subject ≤ 72 characters, body ≤ 12 lines, no `Claude-Session:` line, no chat links
  (`scripts/check_commit_msg.sh`).
