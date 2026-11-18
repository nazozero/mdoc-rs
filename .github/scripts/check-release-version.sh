#!/usr/bin/env bash
set -euo pipefail

version=$(cargo metadata --locked --no-deps --format-version 1 |
  jq -er '.packages[0].version')
if [[ "$GITHUB_REF_NAME" != "v$version" ]]; then
  printf 'Release tag %s must match Cargo package version (v%s).\n' "$GITHUB_REF_NAME" "$version" >&2
  exit 1
fi
