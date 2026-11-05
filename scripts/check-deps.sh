#!/bin/sh
# Enforces the dependency cap (PRD section 7): only these direct requirements.
set -eu
allowed='filippo.io/age golang.org/x/term golang.org/x/sys'
direct=$(go list -m -f '{{if and (not .Indirect) (not .Main)}}{{.Path}}{{end}}' all)
for m in $direct; do
  case " $allowed " in
    *" $m "*) ;;
    *) echo "disallowed direct dependency: $m" >&2; exit 1 ;;
  esac
done
echo "ok: direct dependencies within cap"
