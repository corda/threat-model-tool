# Structured Threat Modeling Tools

These tools enable a structured approach to threat modeling using YAML files, allowing for version control, automated report generation, and consistent security analysis across projects.

## Development Setup

### Option 1: Dev Container (Recommended)

The easiest way to get started is by using the provided Dev Container. It comes pre-configured with all necessary tools, including **uv**, **make**, and a Python environment.

**Prerequisites:** [Docker](https://www.docker.com/) and [VS Code](https://code.visualstudio.com/) with the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers).

1. Clone the repo and open it in VS Code.
2. When prompted, click **"Reopen in Container"** (or use the Command Palette: `Dev Containers: Reopen in Container`).
3. All tools (`uv`, `make`) and dependencies are pre-installed.

#### Quick Commands (via Makefile)
- `make init` - Setup editable installation in the current environment.
- `make test` - Run all tests using `pytest`.
- `make run-example` - Generate example threat model reports from `tests/exampleThreatModels`.
- `make build` - Build the project distribution packages.
- `make check-yaml` - Validate all YAML files in the default directory.
- `make upgrade-yaml-inplace TM_FILE=<path>` - Perform in-place schema upgrade (recursive).
- `make clean` - Cleanup generated artifacts (dist, build, public).

#### Debugging
- Run `make debug` in a terminal.
- Use the **"Python: Attach to Makefile Debugger"** configuration in VS Code to step through the execution.

The dev container includes:
- Python 3.12 with `uv` for fast package management.
- Everything needed for PlantUML rendering and PDF generation.

### Option 2: Local Development Setup (Manual)

If you prefer to work outside a container, Python 3.10+ is required. We recommend using `uv` for dependency management.

```bash
# Clone the repository
git clone https://github.com/corda/threat-model-tool.git
cd threat-model-tool

# Install packages in development mode
uv pip install -e ./tree-node
uv pip install -e .
```

### Option 3: Production Installation

For use in other projects, you can install directly from the repository:

```bash
pip install git+https://github.com/corda/threat-model-tool.git
```

## Project Structure

This repository contains two main packages:

### 1. `tree-node/` - Standalone Tree Structure Library
- **Purpose**: Reusable tree node implementation with hierarchical ID management
- **Independence**: Zero dependencies, can be used in any Python project
- **Features**: Parent-child relationships, tree traversal, ID validation
- **Documentation**: See [tree-node/README.md](tree-node/README.md)

### 3. `threat-model-tool-js/` - TypeScript/Node.js Implementation
- **Purpose**: A modern port of the threat modeling library to TypeScript.
- **Features**: Type-safe parsing, fast rendering, and shared logic with the Python version.
- **Documentation**: See [threat-model-tool-js/README.md](threat-model-tool-js/README.md).

## Building and Distribution

The project uses `uv` for building. You can build both the `tree-node` library and the main `r3threatmodeling` package using:

```bash
make build
```

This will generate `.whl` and `.tar.gz` files in the `dist/` directories of both packages.

## Report Generation

### Main Tool: `fullBuildSingleTM`

The primary way to generate reports for a single threat model is using `fullBuildSingleTM`.

```bash 
python -m r3threatmodeling.fullBuildSingleTM \
  --rootTMYaml path/to/MySystem.yaml \
  --outputDir build/generated_reports \
  --generatePDF \
  --template TM_templateFull
```

### Available Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--rootTMYaml` | file | required | Path to the root threat model YAML file |
| `--outputDir` | path | `build` | Output directory for generated reports |
| `--template` | string | `TM_template` | Template to use for report generation |
| `--mainTitle` | string | auto-generated | **Optional.** Custom title for the report. |
| `--generatePDF` | flag | false | Generate PDF output in addition to HTML/Markdown |
| `--pdfHeaderNote` | string | `Private and confidential` | Note to include in PDF header |
| `--versionsFilter` | string | - | Filter threats/assets by version (e.g., `5.0,5.1`) |
| `--ancestorData` | flag | true | Include security objectives inherited from parent threat models |
| `--baseFileName` | string | `{ThreatModelID}` | Custom base filename for output files |
| `--visibility` | choice | `full` | Report visibility level: `full` or `public` |

### Batch Generation

To generate reports for all threat models in a directory (as used in `make run-example`):

```bash
python -m r3threatmodeling.fullBuildDirectory \
  --TMDirectory threatModels/ \
  --outputDir build/
```

## Schema Upgrades

If you have threat models created with older versions of the schema, you can upgrade them using the normalization tool:

```bash
# Dry run to see changes
make upgrade-yaml-dryrun TM_FILE=path/to/model.yaml

# Apply changes in-place
make upgrade-yaml-inplace TM_FILE=path/to/model.yaml
```

## Introduction

This repository provides tools to manage structured threat models as YAML files and transform them into human-readable reports (HTML, Markdown, PDF).

### Example Threat Model YAML

```yaml
threats:
  - ID: VNode1.HoldingID.1
    assets:
      - ID: HoldingID
    CVSS:
      base: 9.8
      vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:H/MI:H/MA:H
    threatType: Spoofing (caused by HoldingID collision)
    description: |
      The entropy chosen ...
    public: false
    fullyMitigated: true
    countermeasures:
      - ID: Hashing
        description: |
          Use a full SHA-256 hash ...
        inPlace: no
      - ID: UniquenessCheck
        description: |
          Check uniqueness when onboarding a virtual Node
        inPlace: true 
        public: true
```

Source YAML files can be found in the [threatModels](threatModels/) folder of your project.

## Validation Rules

The tool enforces several validation rules to ensure consistency across threat models:

### Mandatory Rules
- **ID and Filename Consistency**: The root `ID` field must match the filename (excluding the `.yaml` extension).
- **Mandatory Scope**: Every threat model requires a non-empty `scope` section.
- **Security Objective Groups**: Each `securityObjective` must have a defined `group` attribute.
- **Threat Fields**: Threats must use `attack` and `impactDesc` instead of a generic `description`. They must also define `threatType` and `title`.
- **Countermeasure Attributes**: Non-reference countermeasures require `inPlace` (bool), `public` (bool), `title`, and `description`.
- **Asset Constraints**: Assets require a `type` and an explicit boolean `inScope` status.

### Consistency Checks (Warnings)
- **Mitigation Check**: `fullyMitigated` threats should have at least one `inPlace` countermeasure.
- **Public Safety**: `public` threats should be `fullyMitigated`.
- **Public Mitigation**: Public mitigated threats require at least one mitigation that is both `inPlace` and `public`.

## AI Assistance for Threat Modeling

This repository includes a specialized guide for LLM agents (like GitHub Copilot or ChatGPT) to help them understand the methodology and schema requirements of this project.

The [AI Threat Modeling Guide](docs/ai/threat-modeling-guide.md) can be provided to an AI agent to:
- Instruct it on the "Are we building it?" scope philosophy.
- Define the strict validation rules for YAML generation.
- Ensure consistent terminology and semantics across the threat model.

## YAML Schema Documentation

### Attackers (Roles)

The `attackers` section defines the roles involved in the system. They can be trusted (`inScope: false`) or untrusted (`inScope: true`).

```yaml
attackers:
  - ID: ANONYMOUS
    description: |
      Anonymous internet user
    inScope: true
```

### Threats

A threat represents something that can go wrong. We separate the **attack** (mechanism) from the **impact** (business consequence).

- `title`: Short name of the threat.
- `attack`: How the threat can be exploited.
- `impactDescription`: Business-level impact.

### Security Objectives

Security objectives (S.O.) represent high-level security goals (e.g., "Full Confidentiality"). Threats are linked to these objectives via the `impactedSecObj` or `impacts` field.

```yaml
securityObjectives:
  - ID: FULL_CIA
    title: Confidentiality, Integrity, and Availability
    description: |
      Ability to maintain fundamental confidentiality, integrity and availability.
```

By associating a threat with a security objective, the generated reports can highlight the security gaps where objectives are not fully met by countermeasures.

### Assets

An asset represents any part of the system in or out of scope. Explicitly defining assets helps avoid ambiguity and ensures consistent naming.

```yaml
    - ID: unique ID of the asset
      specifies: | 
        optional reference to a more general Asset ID
      type: process, dataFlow, credential...
      title: Short title
      description: Detailed description
      inScope: true/false
```

#### Asset Hierarchy
Using the `specifies` keyword, an asset can be a specific instance of a more general definition (e.g., a specific API endpoint specifying a general HTTP server). This allows for inheritance of threats and countermeasures.

### Versioning
You can specify which versions an asset, threat, or countermeasure applies to:

```yaml
    - ID: DF_BOOTSTRAP_TO_DB
      appliesToVersions: ">=5.0"
```

Use the `--versionsFilter` parameter (e.g., `"--versionsFilter" "5.0,5.1"`) to filter reports by version.

### Operational Hardening Guide

The tool can generate a Security Hardening Guideline by collecting all operational countermeasures (`operational: true`) and grouping them by operator (e.g., `operator: ADMIN`).

To make the guide readable, the title and description of an operational countermeasure should precisely answer "what the operator needs to do".

```yaml
    countermeasures:
      - ID: DATA_BACKUP
        title: Perform data backup 
        description: |
          The infrastructure operator performs regular backups...
        operational: true
        operator: INFRASTRUCTURE_OPERATOR
        inPlace: true
```

## Proposal Marker

You can mark parts of the threat model as proposals using `proposal: PROPOSAL_NAME`. The reports will highlight these sections with a special CSS class.



## Threat Mitigation Status

In the `threats:` section, `fullyMitigated: true` indicates that the current countermeasures (both technical and operational) are sufficient to address the threat. If a threat is only mitigated by operational steps that are not yet in place, this should be `false`.
 