#!/bin/sh
# Fails if any non-test Go file imports net or net/http, except the agent's
# Unix-socket code (internal/agent, added in Week 2). PRD section 12.
set -eu
hits=$(grep -rEl --include='*.go' --exclude='*_test.go' \
  '^[[:space:]]*(import[[:space:]]+)?"net(/http[a-z/]*)?"' . \
  | grep -v '^\./internal/agent/' || true)
if [ -n "$hits" ]; then
  echo "forbidden net import in:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "ok: no net imports outside internal/agent"
