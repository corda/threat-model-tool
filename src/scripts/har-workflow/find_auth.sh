#!/bin/bash

# find_auth.sh
# Search for authentication and identity-related requests in a .indexHAR.yaml file.
#
# USAGE:
#   find_auth.sh <index_file>
#
# EXAMPLE:
#   find_auth.sh build/har/capture.indexHAR.yaml

INDEX_FILE="$1"

if [[ -z "$INDEX_FILE" ]]; then
    echo "ERROR: Missing required argument: index_file" >&2
    exit 1
fi

if [[ ! -f "$INDEX_FILE" ]]; then
    echo "ERROR: Index file not found: $INDEX_FILE" >&2
    exit 1
fi

# Search auth-related URLs in entry rows only and preserve original line numbers.
awk '
BEGIN { IGNORECASE = 1 }
/^[[:space:]]*-[[:space:]]*\[/ {
    if ($0 ~ /(login|token|auth|kyc|oauth|oidc|authorize|complete)/) {
        print NR ":" $0
    }
}
' "$INDEX_FILE"
