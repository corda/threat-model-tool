# HAR_2_TM_tool

HAR_2_TM_tool is a lightweight utility to transform HAR captures into artifacts that are useful for threat modeling:

- PlantUML sequence diagrams (default)
- Mermaid sequence diagrams (optional)
- `.indexHAR.yaml` byte-offset index files for LLM workflows on large HAR files
- starter YAML config files for iterative LLM and human refinement

## Why this exists

Large HAR files are hard to inspect manually and expensive for LLMs to process in full.
This tool creates:

- A compact interaction view (sequence diagram)
- A line-level index that points to request locations in the original HAR

## CLI Usage

Run from the threat-model-tool workspace:

```bash
npm run har2seq -- --har /path/to/capture.har
```

If `--out` is omitted for PlantUML, the tool now writes a default bundle of views:

- `build/har/<capture-name>.sequence.puml`
- `build/har/<capture-name>.sourceHostSummary.puml`
- `build/har/<capture-name>.HighLevelDFD.puml`

These are derived from the same config semantics but rendered at different abstraction levels.

If you want a single file instead, pass `--out` explicitly:

```bash
npm run har2seq -- --har /path/to/capture.har --out build/capture.puml
```

Generate PlantUML + index in one command:

```bash
npm run har2seq -- --har /path/to/capture.har --out build/capture.puml --index-out build/capture.indexHAR.yaml
```

Generate only the index file:

```bash
npm run har2seq -- --har /path/to/capture.har --only-index
```

This writes by default to `build/har/<capture-name>.indexHAR.yaml`.

Optional Mermaid output:

```bash
npm run har2seq -- --har /path/to/capture.har --format mermaid --out build/capture.mmd
```

Default PlantUML bundle meaning:

- `sequence`: full interaction sequence using the current participant semantics
- `sourceHostSummary`: one call per original source host while still respecting collapsed participants
- `HighLevelDFD`: one generic browser call per visible participant/bucket, with gray notes listing the hidden underlying hosts

Generate a starter config plus index:

```bash
npm run har:init-config -- --har /path/to/capture.har --index-out build/capture.indexHAR.yaml --out build/capture.config.yaml
```

If `--out` and `--index-out` are omitted, the defaults are:

- `build/har/<capture-name>.config.yaml`
- `build/har/<capture-name>.indexHAR.yaml`

For a simpler first-party vs third-party starting point:

```bash
npm run har:init-config -- --har /path/to/capture.har --first-party '*.example.com,*.example.it' --collapse-third-party
```

That starter config preserves first-party hosts and collapses everything else into `3rd Party`.
How that semantic model is rendered, for example full sequence vs source-host summary vs HighLevelDFD, is a tool option rather than config state.

Recommended practice: keep generated HAR-derived artifacts inside the `threat-model-tool` workspace, such as `build/har/`.

## Config file

You can provide `--config` as YAML or JSON.

Supported keys:

- `excludePaths`: path rules to skip noisy requests
- `messagePrefixes`: per-method label prefixes
- `browserParticipant`: label to use for the browser/client actor
- `trustBoundaries`: trust boundary catalog used to group participants into PlantUML `box` blocks
- `participants`: primary editing surface; each participant carries its own domains, trust boundary, properties, and optional `collapseTo` target

Diagram/view controls belong to the tool invocation instead. For example:

- default PlantUML bundle with no `--out`
- `--view HighLevelDFD`
- `--single-call-per-source-host`
- `--single-call-per-participant`
- `--include-source-host-in-label`
- `--generic-call-description "Browser interactions"`

Example:

```yaml
browserParticipant: Browser
excludePaths:
  - app.example.com/fonts
messagePrefixes:
  GET: "REQ: "
  POST: "AUTH: "
trustBoundaries:
  - ID: FIRST_PARTY
    title: First-Party Boundary
    color: "#D7F3E3"
  - ID: THIRD_PARTY
    title: Third-Party Boundary
    color: "#F5F5F5"
participants:
  - ID: APP_EXAMPLE_COM
    title: app.example.com
    domains:
      - app.example.com
      - landing.example.com
    trustBoundary: FIRST_PARTY
    inScope: true
    properties:
      authentication: session cookie
      authorization: customer-scoped
      dataSensitivity: personal data
      notes:
        - account data
        - payment context

  - ID: GOOGLE_EDGE_CDN
    title: Google Edge/CDN
    domains:
      - "*.googleapis.com"
      - "*.gstatic.com"
      - "*.doubleclick.net"
    trustBoundary: THIRD_PARTY
    collapseTo: THIRD_PARTY
    inScope: true
    properties:
      authentication: none
      authorization: public asset delivery
      dataSensitivity: low

  - ID: THIRD_PARTY
    title: 3rd Party
    domains: []
    trustBoundary: THIRD_PARTY
    inScope: true
    properties:
      authentication: unknown / vendor-specific
      authorization: vendor-managed
      dataSensitivity: mixed external processing
```

Notes:

- Each participant's `domains` list can contain exact hosts, wildcard domains, full host/path prefixes, full URLs, or regex rules.
- `collapseTo` is applied before drawing participants.
- Trust boundaries still work with collapsed participants; matching can use either the visible participant label or the original source host.
- Array values are rendered as comma-separated lists in participant notes.

For a config-centric workflow, see `docs/HAR_2_TM_tool_config_workflow.md`.

Why make `participants` the primary object model?

- It keeps host matching, trust boundary ownership, properties, and collapse targets together.
- It makes generated configs easier to refine by moving domains between visible participants and collapsed buckets.
- It is more LLM-friendly than splitting participant behavior across several top-level rule lists.

## .indexHAR format

The generated `.indexHAR.yaml` file is YAML, using a compact **columnar v2**
layout: per-entry field names appear once in `columns`, and each entry is a
single inline array row. This avoids repeating key names on every row and keeps
token cost low for LLM workflows.

```yaml
schemaVersion: indexHAR.v2
harFile: file.har
harBytes: 23550297
harSha256: 4f0c...e91a
totalRequests: 123
columns: [method, url, status, offset, length]
entries:
  - [GET, https://example.com/path, 200, 1841, 5120]
  - [POST, https://api.example.com/login, 200, 6961, 9210]
```

Each row is positional, matching `columns`:

| column   | meaning |
|----------|---------|
| `method` | HTTP method |
| `url`    | full request URL (`host`/`path` are derivable from it) |
| `status` | HTTP response status |
| `offset` | byte offset of the entry's JSON in the source `.har` |
| `length` | byte length of the entry's JSON |

`requestId` is **implicit** — it is the row index + 1. Entries are in
chronological order, so the Nth row is `requestId` N. `host`, `path`,
`startedDateTime` and `generatedAt` are intentionally omitted (derivable or
redundant), and `harFile` is stored as a basename since the index lives next to
the HAR.

`offset` / `length` are a **byte range into the source `.har`**. They let you
fetch a single request's full, untouched JSON (headers, cookies, timing, body
included) with an O(1) `seek` + bounded read — no sequential scan, no duplicated
sidecar file. `harBytes` / `harSha256` pin the exact HAR the offsets refer to;
if the HAR is re-captured the offsets are invalid and the index must be
regenerated (a hash/size mismatch is the signal).

`load_indexHAR_file()` expands the columnar rows back into rich entry objects
(`{ requestId, method, url, status, entryOffset, entryLength }`), so consumers
work with named fields and the loader tolerates column reordering.

## Fetching a full entry by offset

The index is the small, queryable layer (method / url / status per entry). When
you need the complete detail of one request, read its `offset` / `length` off
the row and seek directly into the immutable `.har` — no CLI, no sidecar.

**Prefer `tail`+`head`**: it is portable across macOS and Linux and seeks
instead of scanning. `tail -c +K` is **1-based**, so the start byte is
`offset + 1`:

```bash
# Row 35 had offset 1841091, length 8519 in the index.
# start = offset + 1 = 1841092, then read `length` bytes:
tail -c +1841092 file.har | head -c 8519 | jq .

# Project just the auth-relevant headers:
tail -c +1841092 file.har | head -c 8519 \
  | jq '[.request.headers[] | select(.name|ascii_downcase|test("auth|cookie|token"))]'
```

`dd` also seeks (real `lseek` on `skip` for a regular file), but on macOS only
the `bs=1` form is portable — one syscall per byte, so reserve it for small
slices:

```bash
dd if=file.har bs=1 skip=1841091 count=8519 2>/dev/null | jq .
```

GNU `dd` on Linux can use a big block with byte units
(`dd if=file.har bs=1M iflag=skip_bytes,count_bytes skip=1841091 count=8519`),
but that flag is absent on macOS — use `tail` for the portable fast path.

**Drift check:** the offsets are only valid for the capture pinned by
`harBytes` / `harSha256`. Before trusting offsets when in doubt, compare the
size (`stat -f%z file.har` on macOS, `stat -c%s` on Linux) to `harBytes`; a
mismatch means the offsets are stale and the index must be regenerated.

From TypeScript, `read_har_entry` does the seek + parse for you:

```ts
import { generate_indexHAR, read_har_entry } from '../src/utils/HAR_2_TM_tool.js';

const index = generate_indexHAR('/path/to/file.har');
const e = index.entries.find(x => x.requestId === 35)!;
const fullEntry = read_har_entry('/path/to/file.har', e.entryOffset, e.entryLength);
```

This stays fast regardless of HAR size: reading entry 1 and entry 5000 from a
200 MB capture cost the same, because each is a direct seek to that entry's
bytes rather than a scan from the start of the file. The original `.har` is the
single source of truth and is never modified or duplicated.

### Scaling to very large HARs

`generate_indexHAR` builds the byte ranges with a single-pass brace scanner
(`indexHarEntryByteRanges`) over the raw HAR buffer. It never parses the whole
file into one object graph — it records each entry's `[offset, length)` and
parses entry slices individually for the index metadata, so memory stays
proportional to the number of entries, not the file size.

## TypeScript API

Use the utility from code:

```ts
import {
  generate_puml_sequence,
  create_indexHAR_file,
  read_har_entry,
} from '../src/utils/HAR_2_TM_tool.js';

const puml = generate_puml_sequence('/path/to/file.har', '/path/to/config.yaml');
const indexPath = create_indexHAR_file('/path/to/file.har'); // writes <name>.indexHAR.yaml

// Read one full entry on demand using its byte range from the index.
const entry = read_har_entry('/path/to/file.har', 1841091, 8519);
```

