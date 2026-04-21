# jira_utils

Simple TypeScript utilities for Jira CSV/threat-model synchronization.

## Goals

- Keep logic reusable and easy to test.
- Avoid hardcoded project-specific data.
- Provide pure helpers that can be reused by scripts/CLI layers.

## Modules

- `adf.ts`: Markdown sanitization and conversion to Jira ADF.
- `csv.ts`: CSV key/row normalization (including BOM-safe keys).
- `mapping.ts`: Parse `Threat ID -> issue key` from YAML text.
- `sync.ts`: Build a sync plan from CSV rows and mappings.

## Example

```ts
import { planCsvSyncUpdates } from './sync.js';

const result = planCsvSyncUpdates(rows, threatToTicketMap, {
  manualMap: { GENERIC_THREAT_DELTA: 'SEC-300' },
});
```
