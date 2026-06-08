#!/bin/bash

# list_hosts.sh
# List all unique hosts from a .indexHAR.yaml file with request counts.
#
# USAGE:
#   list_hosts.sh <index_file>
#
# EXAMPLE:
#   list_hosts.sh build/har/capture.indexHAR.yaml

INDEX_FILE="$1"

if [[ -z "$INDEX_FILE" ]]; then
    echo "ERROR: Missing required argument: index_file" >&2
    exit 1
fi

if [[ ! -f "$INDEX_FILE" ]]; then
    echo "ERROR: Index file not found: $INDEX_FILE" >&2
    exit 1
fi

# Extract hosts from entry rows only and count them.
# The index format is: - [METHOD, URL, STATUS, OFFSET, LENGTH]
awk '/^[[:space:]]*-[[:space:]]*\[/ { print }' "$INDEX_FILE" \
    | grep -Eo 'https?://[^/"]+' \
    | sort | uniq -c | sort -rn
