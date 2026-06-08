#!/bin/bash

# auth_erf.sh
# Build a compact Authentication Evidence Record (ERF) for one HAR entry.
#
# USAGE:
#   auth_erf.sh <har_file> <offset> <length> [request_id] [--compact]
#
# EXAMPLES:
#   auth_erf.sh capture.har 1109849 2282 35
#   auth_erf.sh capture.har 1109849 2282 --compact

set -e

HAR_FILE="$1"
OFFSET="$2"
LENGTH="$3"
shift 3 || true

REQUEST_ID=""
JQ_ARGS=()

if [[ -z "$HAR_FILE" || -z "$OFFSET" || -z "$LENGTH" ]]; then
    echo "ERROR: Missing required arguments" >&2
    echo "USAGE: $0 <har_file> <offset> <length> [request_id] [--compact]" >&2
    exit 1
fi

if [[ ! -f "$HAR_FILE" ]]; then
    echo "ERROR: HAR file not found: $HAR_FILE" >&2
    exit 1
fi

if [[ $# -gt 0 && "$1" != --* ]]; then
    REQUEST_ID="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --compact)
            JQ_ARGS=(-c)
            shift
            ;;
        --pretty)
            JQ_ARGS=()
            shift
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Reuse show_entry.sh to keep byte-range extraction behavior consistent.
ENTRY_JSON="$($SCRIPT_DIR/show_entry.sh "$HAR_FILE" "$OFFSET" "$LENGTH" --compact)"

echo "$ENTRY_JSON" | jq "${JQ_ARGS[@]}" --arg request_id "$REQUEST_ID" '
def trim: gsub("^\\s+|\\s+$"; "");

def cookie_names_from_header($v):
  ($v // ""
    | split(";")
    | map(split("=")[0] | trim)
    | map(select(length > 0))
    | unique);

def req_headers:
  (.request.headers // []);

def res_headers:
  (.response.headers // []);

def auth_header_value:
  (req_headers | map(select((.name | ascii_downcase) == "authorization") | .value) | .[0] // "");

def cookie_header_values:
  (req_headers | map(select((.name | ascii_downcase) == "cookie") | .value));

def request_cookie_names:
  (cookie_header_values | map(cookie_names_from_header(.)) | add // [] | unique);

def response_set_cookie_names:
  (res_headers
    | map(select((.name | ascii_downcase) == "set-cookie") | (.value | split("=")[0] | trim))
    | unique);

def www_authenticate_values:
  (res_headers | map(select((.name | ascii_downcase) == "www-authenticate") | .value));

def query_auth_param_names:
  (.request.queryString // []
    | map(select((.name | ascii_downcase) | test("auth|token|key|session|sid|code")) | .name)
    | unique);

def bearer_token_from_header($h):
  if ($h | test("^[Bb]earer\\s+")) then ($h | sub("^[Bb]earer\\s+"; "")) else "" end;

def b64url_decode:
  gsub("-"; "+")
  | gsub("_"; "/") as $s
  | ($s + ("=" * ((4 - (($s | length) % 4)) % 4)))
  | @base64d;

def jwt_claims_from_bearer($token):
  ($token | split(".")) as $parts
  | if ($parts | length) == 3 then
      ($parts[1] | b64url_decode | fromjson?)
    else
      null
    end;

def realm_hints_from_www_auth($arr):
  ($arr
    | map((try capture("realm=\\\"(?<realm>[^\\\"]+)\\\"").realm catch null))
    | map(select(. != null))
    | unique);

. as $entry
| (auth_header_value) as $authHeader
| (bearer_token_from_header($authHeader)) as $bearer
| (jwt_claims_from_bearer($bearer)) as $jwt
| (www_authenticate_values) as $wwwAuth
| {
    requestId: (if ($request_id | length) == 0 then null else ($request_id | tonumber?) end),
    method: $entry.request.method,
    url: $entry.request.url,
    erf: {
      authHeaderScheme: (if ($authHeader | length) == 0 then null else ($authHeader | split(" ") | .[0]) end),
      cookieNames: request_cookie_names,
      setCookieNames: response_set_cookie_names,
      queryAuthParams: query_auth_param_names,
      token: (
        if ($bearer | length) == 0 then
          null
        else {
          kind: (if $jwt == null then "opaque-or-non-jwt-bearer" else "jwt-bearer" end),
          realmHints: realm_hints_from_www_auth($wwwAuth),
          issuer: (if $jwt == null then null else ($jwt.iss // null) end),
          audience: (if $jwt == null then null else ($jwt.aud // null) end),
          scope: (if $jwt == null then null else ($jwt.scope // $jwt.scp // null) end),
          claimKeys: (if $jwt == null then [] else ($jwt | keys_unsorted) end)
        }
        end
      ),
      authorizationHints: {
        jwtScope: (if $jwt == null then null else ($jwt.scope // $jwt.scp // null) end),
        jwtRoles: (if $jwt == null then null else ($jwt.roles // $jwt.role // null) end),
        audience: (if $jwt == null then null else ($jwt.aud // null) end)
      }
    }
  }
'