#!/bin/bash

# show_entry.sh
# Extract a single HAR entry by byte-range seek using offset+length from .indexHAR.yaml
#
# USAGE:
#   show_entry.sh <har_file> <offset> <length> [--auth-only] [--headers-only]
#
# ARGUMENTS:
#   har_file      Path to the .har file
#   offset        Byte offset of the entry (from .indexHAR.yaml)
#   length        Byte length of the entry (from .indexHAR.yaml)
#
# OPTIONS:
#   --auth-only   Extract only auth/cookie/token headers and query params
#   --headers-only Extract only request headers (no body)
#   --pretty      Pretty-print JSON (default)
#   --compact     Compact JSON output
#
# EXAMPLES:
#   # Full entry (row 35 has offset 1109849, length 2282):
#   show_entry.sh capture.har 1109849 2282
#
#   # Auth-relevant headers only:
#   show_entry.sh capture.har 1109849 2282 --auth-only
#
#   # Request headers only:
#   show_entry.sh capture.har 1109849 2282 --headers-only

set -e

HAR_FILE="$1"
OFFSET="$2"
LENGTH="$3"
FILTER_MODE="full"
JQ_ARGS=()

if [[ -z "$HAR_FILE" || -z "$OFFSET" || -z "$LENGTH" ]]; then
    echo "ERROR: Missing required arguments" >&2
    echo "USAGE: $0 <har_file> <offset> <length> [--auth-only] [--headers-only]" >&2
    exit 1
fi

# Validate the file exists
if [[ ! -f "$HAR_FILE" ]]; then
    echo "ERROR: HAR file not found: $HAR_FILE" >&2
    exit 1
fi

# Parse optional flags
while [[ $# -gt 3 ]]; do
    case "$4" in
        --auth-only)
            FILTER_MODE="auth"
            shift
            ;;
        --headers-only)
            FILTER_MODE="headers"
            shift
            ;;
        --compact)
            JQ_ARGS=(-c)
            shift
            ;;
        --pretty)
            JQ_ARGS=()
            shift
            ;;
        *)
            echo "ERROR: Unknown option: $4" >&2
            exit 1
            ;;
    esac
done

# Byte-range read using tail+head (portable across macOS and Linux)
# tail -c is 1-based, so start position = offset + 1
START=$((OFFSET + 1))

case "$FILTER_MODE" in
    full)
        # Full entry with pretty JSON
        tail -c +"$START" "$HAR_FILE" | head -c "$LENGTH" | jq "${JQ_ARGS[@]}" .
        ;;
    auth)
        # Extract auth-relevant headers and cookies
        tail -c +"$START" "$HAR_FILE" | head -c "$LENGTH" | jq "${JQ_ARGS[@]}" \
            '{
                request: {
                    method: .request.method,
                    url: .request.url,
                    headers: [
                        .request.headers[]
                        | select(
                            .name | ascii_downcase
                            | test("auth|cookie|token|bearer|x-api-key|authorization|x-access|api-key")
                        )
                    ],
                    queryString: .request.queryString
                },
                response: {
                    status: .response.status,
                    statusText: .response.statusText,
                    headers: [
                        .response.headers[]
                        | select(
                            .name | ascii_downcase
                            | test("auth|cookie|token|bearer|set-cookie|x-api-key|www-authenticate")
                        )
                    ]
                }
            }'
        ;;
    headers)
        # Extract request headers only
        tail -c +"$START" "$HAR_FILE" | head -c "$LENGTH" | jq "${JQ_ARGS[@]}" \
            '{
                request: {
                    method: .request.method,
                    url: .request.url,
                    headers: .request.headers
                }
            }'
        ;;
esac
