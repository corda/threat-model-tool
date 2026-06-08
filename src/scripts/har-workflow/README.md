# HAR Workflow Scripts

This folder contains scripts used for HAR-to-threat-model preprocessing and diagram generation.

## Scripts

### TypeScript / Node.js

- `init-har-config.ts`
  - Creates a HAR index file (`.indexHAR.yaml`) and a starter HAR config (`.config.yaml`).
  - Backed by npm script: `npm run har:init-config -- ...`

- `har2seq.ts`
  - Generates sequence and high-level sequence diagrams in PlantUML from HAR + config.
  - Backed by npm script: `npm run har2seq -- ...`

### Shell Utilities

- `list_hosts.sh`
  - Lists unique request hosts with counts from `.indexHAR.yaml`.
  - Scans entry rows only, then extracts URL hosts.

  **Usage:**
  ```bash
  src/scripts/har-workflow/list_hosts.sh build/har/capture.indexHAR.yaml
  ```

- `find_auth.sh`
  - Finds auth and identity-related request rows from `.indexHAR.yaml`.
  - Scans entry rows only and prints source line numbers plus full row content.

  **Usage:**
  ```bash
  src/scripts/har-workflow/find_auth.sh build/har/capture.indexHAR.yaml
  ```

- `auth_erf.sh`
  - Builds a compact Authentication Evidence Record (ERF) for one request row.
  - Uses `offset`/`length` and reports:
    - cookie names and set-cookie names
    - auth header scheme
    - token hints (kind, realm hints, issuer/audience/scope when JWT)
    - authorization hints (scope/roles/audience)
  - Does not output raw token secrets.

  **Usage:**
  ```bash
  src/scripts/har-workflow/auth_erf.sh capture.har 1109849 2282 35
  src/scripts/har-workflow/auth_erf.sh capture.har 1109849 2282 35 --compact
  ```

- `show_entry.sh`
  - Reads a single HAR entry by byte-range seek using `offset` and `length` from `.indexHAR.yaml`.
  - Supports multiple output modes: full entry, auth-only headers, headers-only.
  - **Portable**: uses `tail`+`head` (macOS and Linux).
  
  **Usage:**
  ```bash
  # Full entry (row 35 has offset 1109849, length 2282):
  src/scripts/har-workflow/show_entry.sh capture.har 1109849 2282
  
  # Auth-relevant headers and cookies only:
  src/scripts/har-workflow/show_entry.sh capture.har 1109849 2282 --auth-only
  
  # Request headers only:
  src/scripts/har-workflow/show_entry.sh capture.har 1109849 2282 --headers-only
  
  # Compact JSON:
  src/scripts/har-workflow/show_entry.sh capture.har 1109849 2282 --compact
  ```
  
  For full usage and options, see the script header comments: `src/scripts/har-workflow/show_entry.sh`

## Unified HAR Workflow (Scripts + Agent)

Use this as the default end-to-end flow from raw HAR to threat-model-ready architecture evidence.

### 1. Bootstrap artifacts with scripts

Generate the HAR index and starter config:

```bash
npm run har:init-config -- --har /absolute/path/to/capture.har
```

Generate baseline diagrams from the starter config:

```bash
npm run har2seq -- --har /absolute/path/to/capture.har --config build/har/capture.config.yaml
```

Default outputs are written under `build/har/`.

### 2. Refine classification with the agent

Use the `har-party-classifier` agent when you want interactive, evidence-driven refinement of:

- first-party vs third-party scope
- participant extraction and `collapseTo` rules
- inferred vendor roles
- participant properties (`authentication`, `authorization`, `dataSensitivity`, `owner`, `notes`)

Agent definition:

- `.github/agents/har-party-classifier.agent.md`

Primary workflow reference consumed by the agent:

- `docs/HAR_2_TM_tool_config_workflow.md`

### 3. Regenerate and iterate

After each meaningful config update, regenerate diagrams:

```bash
npm run har2seq -- --har /absolute/path/to/capture.har --config build/har/capture.config.yaml
```

Repeat until the output is compact and still preserves threat-relevant distinctions.

### 4. Handoff to threat modeling

When classification stabilizes, hand off to the `threat-modeling-agent` with:

- refined config
- `.indexHAR.yaml`
- generated sequence/DFD diagrams

The handoff should include unresolved classification uncertainties and security-relevant observations.

## Agent Classification Logic (What Gets Decided)

The `har-party-classifier` follows an interactive process that should also guide manual edits.

### Phase 1: First-party scope

Confirm first-party domain patterns and whether first-party hosts remain distinct or are partially collapsed.

### Phase 2: Third-party bucket identification

Infer functional buckets from host/path patterns, such as:

- analytics and telemetry
- consent/privacy
- chat/support
- CDN/asset delivery
- ads/retargeting
- A/B testing/feature flags

### Phase 3: Property inference

Propose best-effort participant properties:

- `owner`
- `role`
- `authentication`
- `authorization`
- `dataSensitivity`
- `notes`

Uncertain claims should be marked as tentative in `notes`.

### Phase 4: Explicit edit confirmation

Before applying changes, summarize:

- first-party patterns
- explicit participants vs collapsed groups
- new extracted vendors
- property updates

Then apply config edits and regenerate diagrams.

## Workflow Modes (from the agent)

- `Coarse bootstrap`: keep first-party hosts distinct and collapse the rest to `3rd Party`.
- `Interactive refinement`: iteratively extract high-value third parties and improve properties in small steps.

## Config Schema Quick Reference

The HAR config is a semantic model for classification, not just rendering options.
This is the minimum shape you should understand when refining it:

```yaml
browserParticipant: Browser

excludePaths:
  - "/favicon"

messagePrefixes:
  GET: "REQ "
  POST: "AUTH "

trustBoundaries:
  - ID: FIRST_PARTY
    title: First-Party Boundary
    color: "#D7F3E3"
  - ID: THIRD_PARTY
    title: Third-Party Boundary
    color: "#F5F5F5"

participants:
  - ID: LOGIN_TELEPASS_COM
    title: login.telepass.com
    domains:
      - login.telepass.com
    trustBoundary: FIRST_PARTY
    inScope: true
    properties:
      owner: first-party
      role: authentication
      authentication: OIDC session + cookies
      authorization: client-scoped auth flow
      dataSensitivity: high
      notes:
        - observed auth endpoints and callback flow

  - ID: ANALYTICS_VENDOR
    title: Analytics Vendor
    domains:
      - "*.example-analytics.com"
    trustBoundary: THIRD_PARTY
    collapseTo: THIRD_PARTY
    inScope: true
    properties:
      owner: third-party
      role: telemetry
      authentication: none observed
      authorization: vendor/key scoped ingestion
      dataSensitivity: medium
```

Field intent:

- `browserParticipant`: label used for the browser actor in diagrams.
- `excludePaths`: request path filters to remove noise before rendering.
- `messagePrefixes`: method-to-label mapping for readable edges.
- `trustBoundaries`: reusable ownership/control boundaries used by participants.
- `participants`: primary classification objects used for both diagrams and threat-model preparation.
- `participants[].domains`: host/domain matchers that map requests to a participant.
- `participants[].trustBoundary`: ownership boundary assignment (`FIRST_PARTY` or `THIRD_PARTY` typically).
- `participants[].collapseTo`: optional visual/logical collapsing target to reduce clutter.
- `participants[].inScope`: whether this participant is considered in current threat-model scope.
- `participants[].properties`: inferred security semantics used later for threat hypotheses.

Practical logic:

- Keep participants separate when controls or risk meaning differ.
- Collapse participants when grouping does not change attack paths or mitigations.
- Treat `properties` as evidence-backed inference and update them iteratively.

## Config Logic And Reasoning

The generated `.config.yaml` is intentionally a starting point, not a final architecture model.
Its purpose is to make large HAR captures manageable while preserving security-relevant semantics.

### 1. Why `.indexHAR.yaml` exists first

`init-har-config.ts` first creates `.indexHAR.yaml` so reasoning is based on a compact summary of:

- request method and URL
- host and path
- status code
- line references back to the original HAR

This allows configuration decisions to be evidence-driven without repeatedly parsing massive HAR files.

### 2. Participant modeling philosophy

`participants` are the primary abstraction layer. They should represent security-relevant trust and ownership boundaries, not every host one-to-one.

Use this rule of thumb:

- Keep separate participants when authentication, authorization, ownership, or sensitivity differs
- Collapse domains when they are operationally equivalent for threat modeling

Examples:

- Multiple CDN hosts can be one participant when they are all public asset delivery
- Login and portal hosts should usually stay separate when auth/session semantics differ

### 3. Trust boundary reasoning

`trustBoundaries` capture who controls a component and therefore who can enforce controls.

- `FIRST_PARTY`: infrastructure or services controlled by the modeled team/org
- `THIRD_PARTY`: external providers (consent, analytics, CDN, chat/widget vendors)

Boundary assignment should reflect operational ownership, not domain naming conventions.

### 4. `collapseTo` behavior and why it matters

`collapseTo` is used to reduce diagram noise while preserving threat-model meaning.

- Keep host-level detail when host differences affect attack paths
- Collapse when extra granularity does not change mitigations or threat ownership

`--collapse-third-party` is a coarse bootstrap option: useful early, then refine high-value third-party groups later.

### 5. How auth/authz fields should be inferred

Populate participant `properties.authentication` and `properties.authorization` from observed request evidence, such as:

- endpoint patterns (`/auth`, `/authorize`, `/token`, callback routes)
- cookies/session headers
- `Authorization` header usage
- parameterized tenant or SDK keys
- static asset-only behavior (typically no end-user auth)

Prefer concrete, observable statements over assumptions.

### 6. Data sensitivity scoring approach

Set `dataSensitivity` by what the participant can expose or influence:

- `high`: credentials, session identifiers, account/private-area operations
- `medium`: feature flags, telemetry identifiers, tenant config metadata
- `low`: public static assets (fonts, images, generic scripts)

### 7. Iteration loop (recommended)

1. Generate index + starter config.
2. Refine participants, boundaries, and properties from evidence.
3. Regenerate diagrams (`sequence`, `sourceHostSummary`, `HighLevelDFD`).
4. Re-check whether grouping still preserves threat-relevant distinctions.
5. Repeat until the model is compact but security-informative.

### 8. Output consumption for threat modeling

The refined config is meant to feed threat-model authoring:

- participants -> candidate assets/systems
- trust boundaries -> scope/ownership boundaries
- auth/authz/dataSensitivity properties -> threat and control hypotheses
- sequence/DFD outputs -> architecture evidence

## CLI Binaries

Published binary entrypoints map to these scripts:

- `threat-model-har-config`
- `threat-model-har2seq`

Both are configured in `package.json` under `bin`.

## Testing

HAR workflow behavior is covered by dedicated fixtures and tests.

Primary fixture:

- `tests/fixtures/har2seq-sample.har.json`

Supporting config fixtures:

- `tests/fixtures/har2seq-config.yaml`
- `tests/fixtures/har2seq-boundaries.yaml`
- `tests/fixtures/har2seq-collapse-properties.yaml`

Relevant test files:

- `tests/Har2Seq.test.ts`
- `tests/Har2SeqCli.test.ts`
- `tests/InitHarConfig.test.ts`

Run the focused HAR workflow tests with:

```bash
npx tsx --test tests/Har2SeqCli.test.ts tests/Har2Seq.test.ts tests/InitHarConfig.test.ts
```

What is covered:

- HAR indexing and `.indexHAR.yaml` generation
- starter config generation
- trust boundary and participant rendering
- collapse behavior and compact views
- default PlantUML bundle generation
- HighLevelDFD labeling behavior

Note:

- the HAR fixture used in tests is a JSON HAR sample (`*.har.json`), which is sufficient for parser and CLI coverage even though production inputs may be named `.har`.