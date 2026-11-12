# Website checks. `make` lists the commands.
.DEFAULT_GOAL := help
.PHONY: help hooks check

help: ## This list
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  make %-8s %s\n", $$1, $$2}'

hooks: ## Turn on the git hooks (.githooks)
	git config core.hooksPath .githooks

check: ## No secret or private detail; no workflow on self-hosted runners (public repo)
	python3 scripts/check_safety.py --all
	python3 scripts/check_workflows.py --public
