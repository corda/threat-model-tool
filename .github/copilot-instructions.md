## Test Data Policy

**Never use files or data from the `threatModels/` directory** (in the `threat-modeling` workspace) in tests or test fixtures.
Always use generic, self-contained examples from `tests/exampleThreatModels/` or `tests/fixtures/` within the `threat-model-tool` workspace.

If a new test fixture is needed, create it under `tests/exampleThreatModels/` or `tests/fixtures/` with generic, non-project-specific data.