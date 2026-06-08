# HAR_2_TM_tool Config And Workflow

This document focuses on the YAML config model and the intended workflow for using HAR_2_TM_tool with large HAR captures and LLM-assisted analysis.

## Goal

The end goal is to create a compact, iteratively improvable summary of a HAR file that can be used for:

- trust-boundary mapping
- compact dataflow diagram generation
- identifying likely authentication and authorization controls
- capturing sensitivity and security-relevant properties per participant
- guiding later threat-model creation

## Recommended workflow

1. Generate a `.indexHAR.yaml` file from the HAR.
2. Build a small Authentication Evidence Record (ERF) set from auth-relevant rows early.
3. Use the `.indexHAR.yaml` plus ERFs and a compact sequence diagram as the primary context for an LLM.
4. Ask the LLM to propose or refine a YAML config:
  - participant groupings and collapse targets
   - trust boundaries
   - participant properties
5. Re-run the tool with the updated config.
6. Iterate until the diagram and properties capture the architecture well enough for threat modeling.
7. Use the resulting participant properties as structured input to your threat model.

If you want an interactive agent-led version of this loop, use the workspace custom agent `har-party-classifier`.
It is intended for:

- classifying first-party vs third-party domains from HAR artifacts
- refining `participants` and `collapseTo` iteratively
- inferring likely third-party roles
- proposing participant properties such as `authentication`, `authorization`, `dataSensitivity`, `owner`, and `notes`

When the HAR-derived architecture view is stable, hand off to `threat-modeling-agent` for formal threat model YAML creation.

### Bootstrap ERF commands

Use index-first discovery, then build compact ERFs for a handful of representative auth rows:

```bash
# 1) Find auth-relevant rows in the index
src/scripts/har-workflow/find_auth.sh build/har/capture.indexHAR.yaml

# 2) For selected rows, build compact ERFs using their offset/length
src/scripts/har-workflow/auth_erf.sh /absolute/path/to/capture.har <offset> <length> <requestId>
```

Capture ERFs for both first-party auth endpoints and key third-party vendors. ERFs should include cookie names and token hints (realm/claims when available) without exposing raw secrets.

All generated artifacts should live in the `threat-model-tool` workspace, for example under `build/har/`.

Example layout:

```text
threat-model-tool/
  build/
    har/
      capture.indexHAR.yaml
      capture.config.yaml
      capture.compact.puml
      capture.full.puml
```

## End-to-end commands

### 1. Create `.indexHAR.yaml` plus a starter config

```bash
cd /Users/david.cervigni/workspace/threat-model-tool

npm run har:init-config -- \
  --har /absolute/path/to/capture.har
```

Default outputs:

- `build/har/capture.indexHAR.yaml`
- `build/har/capture.config.yaml`

Explicit paths are still supported:

```bash
cd /Users/david.cervigni/workspace/threat-model-tool

npm run har:init-config -- \
  --har /absolute/path/to/capture.har \
  --index-out build/har/capture.indexHAR.yaml \
  --out build/har/capture.config.yaml
```

This creates:

- a lightweight `.indexHAR.yaml` file for LLM and human inspection
- a starter YAML config with participant entries, trust-boundary catalog entries, and participant property placeholders

Default behavior: third-party participants remain separate and are placed in the `THIRD_PARTY` trust boundary. They are not collapsed unless `--collapse-third-party` is explicitly passed.

For a coarse first-party vs third-party starter config, use:

```bash
cd /Users/david.cervigni/workspace/threat-model-tool

npm run har:init-config -- \
  --har /absolute/path/to/capture.har \
  --first-party '*.example.com,*.example.it' \
  --collapse-third-party
```

This preserves discovered first-party hosts and collapses everything else into `3rd Party`.
Which view you generate from that semantic model is decided by the tool invocation.

### 2. Ask an LLM to refine the config

Use these artifacts as input:

- the original HAR file
- `build/har/capture.indexHAR.yaml`
- `build/har/capture.config.yaml`

Ask the LLM to:

- refine trust boundaries
- refine `participants`, `domains`, and `collapseTo`
- set per-participant `properties`
- add likely authentication, authorization, and data-sensitivity properties

### 3. Generate a compact diagram for architecture review

```bash
cd /Users/david.cervigni/workspace/threat-model-tool

npm run har2seq -- \
  --har /absolute/path/to/capture.har \
  --config build/har/capture.config.yaml
```

Default PlantUML outputs:

- `build/har/capture.sequence.puml`
- `build/har/capture.sourceHostSummary.puml`
- `build/har/capture.HighLevelDFD.puml`

These use the same semantic config but render progressively more abstract views.

Explicit path example:

```bash
cd /Users/david.cervigni/workspace/threat-model-tool

npm run har2seq -- \
  --har /absolute/path/to/capture.har \
  --config build/har/capture.config.yaml \
  --out build/har/capture.compact.puml
```

The default bundle gives you these levels:

- `sequence`: detailed interactions
- `sourceHostSummary`: one call per source host under each visible participant
- `HighLevelDFD`: one generic call per visible participant with gray host inventory notes

If you want a single specific rendering instead of the default bundle, choose that at the tool level, for example with:

- `--view HighLevelDFD`
- `--single-call-per-source-host`
- `--single-call-per-participant`
- `--include-source-host-in-label`

### 4. Generate a full interaction diagram

Use a single explicit output path when you want one chosen view:

```bash
cd /Users/david.cervigni/workspace/threat-model-tool

npm run har2seq -- \
  --har /absolute/path/to/capture.har \
  --config build/har/capture.config.yaml \
  --out build/har/capture.full.puml
```

### 5. Translate the config into threat-model input

Use the refined YAML as input to your threat model:

- `trustBoundaries` become scope and trust-boundary context
- participant `properties` become asset/system properties or assumptions
- collapsed participants become higher-level external/internal assets
- the compact PlantUML view becomes architecture evidence for the threat model

### 6. Build or edit the threat model YAML

Create or update a threat model YAML in the normal `threat-model-tool` flow, then verify it:

```bash
cd /Users/david.cervigni/workspace/threat-model-tool

npm run verify -- /absolute/path/to/MyThreatModel.yaml
```

## YAML options

### `browserParticipant`
Optional label for the browser or client actor.

```yaml
browserParticipant: Browser
```

### `excludePaths`
Skip noisy paths.
These can be exact host/path prefixes, bare path prefixes, or full URLs.

```yaml
excludePaths:
  - "app.example.com/fonts"
  - "/favicon"
```

### `messagePrefixes`
Control request labels in diagrams.

```yaml
messagePrefixes:
  GET: "REQ "
  POST: "AUTH "
```

### `trustBoundaries`
Define the trust-boundary catalog. Participants reference these entries by ID.

```yaml
trustBoundaries:
  - ID: FIRST_PARTY
    title: "First-Party Boundary"
    color: "#D7F3E3"

  - ID: THIRD_PARTY
    title: "Third-Party Boundary"
    color: "#F5F5F5"
```

### `participants`
This is the primary editing surface.
Each participant keeps matching rules, trust-boundary ownership, properties, and optional collapse behavior together.

```yaml
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

Participant matching model:

- `domains` can contain exact hosts.
- `domains` can contain wildcard domains such as `*.example.com`.
- `domains` can contain full host/path prefixes such as `app.example.com/fonts`.
- `domains` can contain full URLs.
- `domains` can contain regex rules via `regex:<expr>` or `/expr/flags`.

Property model:

- `properties` is intentionally flexible.
- Supported values are strings, numbers, booleans, and arrays of strings.
- These properties are rendered as notes in the diagrams and can be reused later as structured threat-model input.

## Example config pattern

```yaml
browserParticipant: Browser

excludePaths:
  - "app.example.com/fonts"

messagePrefixes:
  GET: "REQ "
  POST: "AUTH "

trustBoundaries:
  - ID: FIRST_PARTY
    title: "First-Party Boundary"
    color: "#D7F3E3"

  - ID: THIRD_PARTY
    title: "Third-Party Boundary"
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
```

## LLM-oriented workflow

A practical prompt flow for an LLM can be:

1. Read `.indexHAR.yaml` and identify repeated host families.
2. Propose or refine `participants`, `domains`, and `collapseTo` targets.
3. Infer trust boundaries from domain ownership and request purpose.
4. Infer participant properties such as:
   - probable authentication mechanism
   - likely authorization model
   - likely data sensitivity
5. Emit an updated YAML config.
6. Re-run HAR_2_TM_tool and review the resulting diagram.

This keeps the HAR itself as the source of truth while using the config as a curated, human-editable interpretation layer.

## Why this helps

This workflow separates concerns cleanly:

- HAR: raw evidence
- `.indexHAR.yaml`: lightweight pointer layer into the HAR
- config YAML: curated interpretation layer
- PlantUML: visual architecture/dataflow output
- threat model YAML: structured security analysis artifact

That separation makes it practical to use an LLM iteratively without losing the original evidence trail.
