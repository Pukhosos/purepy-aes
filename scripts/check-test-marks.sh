#!/usr/bin/env bash

output="$(
    python -m pytest tests/unit --collect-only \
    -n 0 -m "not quick and not slow" 2>&1
)"
status=$?

case "$status" in
    0)
        printf '%s\n' "$output"
        exit 1
        ;;
    5)
        exit 0
        ;;
    *)
        printf '%s\n' "$output" >&2
        exit "$status"
        ;;
esac
