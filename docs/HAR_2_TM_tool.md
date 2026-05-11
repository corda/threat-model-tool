# HAR_2_TM_tool

HAR_2_TM_tool is a lightweight utility to transform HAR captures into artifacts that are useful for threat modeling:

- PlantUML sequence diagrams (default)
- Mermaid sequence diagrams (optional)
- `.indexHAR.yaml` line-reference files for LLM workflows on large HAR files
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

The generated `.indexHAR.yaml` file is YAML.

```yaml
schemaVersion: indexHAR.v1
harFile: /abs/path/to/file.har
generatedAt: '2026-05-11T12:00:00.000Z'
totalRequests: 123
entries:
  - requestId: 1
    method: GET
    url: https://example.com/path
    status: 200
    host: example.com
    path: /path
    startedDateTime: '...'
    lineRefs:
      methodLine: 42
      urlLine: 43
      statusLine: 57
      startedDateTimeLine: 40
```

## TypeScript API

Use the utility from code:

```ts
import {
  generate_puml_sequence,
  create_indexHAR_file,
} from '../src/utils/HAR_2_TM_tool.js';

const puml = generate_puml_sequence('/path/to/file.har', '/path/to/config.yaml');
const indexPath = create_indexHAR_file('/path/to/file.har');
```
