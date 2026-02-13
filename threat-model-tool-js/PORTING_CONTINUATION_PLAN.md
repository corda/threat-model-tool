# Porting Continuation Plan: Parity, Testing, and Documentation

This document outlines the strategy for the next phase of the TypeScript port, focusing on output parity with the Python implementation, handling the MkDocs dependency, and establishing a robust cross-project test suite.

## 1. Markdown-to-HTML Parity Challenge

### Context
The Python tool uses the `markdown` library with specific extensions (`toc`, `attr_list`, `fenced_code`). The output matches how MkDocs (Python-based) renders the site. To achieve parity in the TS tool, we must ensure the HTML generated from our Markdown is identical or functionally equivalent.

### Plan
- **Standardize MD Engine**: Use `markdown-it` as the core JS engine.
- **Extensions Implementation**:
  - `markdown-it-anchor`: For header anchors.
  - `markdown-it-toc-done-right`: For TOC generation.
  - `markdown-it-attrs`: To support `{.tocLink}` and other attribute markers used in Python.
- **Diff Testing**:
  1. Generate Markdown using both Python and TS tools.
  2. Use a standard renderer (like `pandoc`) to convert both to HTML.
  3. Compare the HTML structures using a structural diff tool (e.g., `html-differ`).
- **Handle Python-Specific Artifacts**: Python's `markdown` library sometimes handles nested lists and blockquotes differently. We may need custom `markdown-it` rules to match the Python behavior.

## 2. MkDocs & Static Site Generation

### Problem
MkDocs is a Python ecosystem. Currently, the threat modeling project relies on `mkdocs build` to turn MD files into the final security site.

### Strategy (The "VitePress Transition")
Instead of maintaining a Python MkDocs dependency, we will explore a transition to a TS-native static site generator.
- **Target**: **VitePress** or **Docusaurus**.
- **Actions**:
  - Create a `SiteConfigGenerator.ts` that outputs a `vitepress.config.ts` or similar based on the threat model's `Index.md`.
  - Port custom MkDocs plugins (like the one that injects diagrams) to VitePress/Docusaurus plugins.
  - Replicate the `mkdocs-material` theme styling using Tailwind or standard CSS modules.

## 3. Cross-Project Test Suite (Real Data Validation)

### Objective
Ensure the TS tool can handle the complexity of "live" threat models from the `threat-modeling` repository.

### Execution Plan
1. **Model Porting**:
   - Establish a sync process (or script) to copy `.yaml` files from `/workspaces/threat-modeling/threatModels/` to `/workspaces/threat-model-tool/tests/exampleThreatModels/`.
   - Focus on `CBUAE_PHASE2`, `C5`, and `Corda` models which use the most advanced features.
2. **Automated Run Comparison**:
   - Implement a CI script that runs both `r3threatmodeling` (Python) and `r3threatmodeling-ts` (TypeScript) on the same input.
   - Output both to a `test-results/` directory.
   - Fail the build if the number of threats, assets, or cross-references differs.
3. **Reference Output "Golden Files"**:
   - Store the Python-generated `FullFeature.md` as a "Golden Master".
   - Any change in the TS tool must justify deviations from this reference.

## 4. Template & Renderer Completion

### Missing Sections
- **ISO27001 Report**: Port `ISO27001Report1.py` logic. This involves complex mapping logic and custom tables.
- **Testing Guide**: Port `render_testing_guide` from `renderers.py`.
- **Compact Report**: Port `render_compact_report`.
- **Advanced Diagrams**: Support Security Objective trees and Legend generation in the PUML engine.

## 5. Timeline & Milestones

| Milestone | Description | Target Date |
|-----------|-------------|-------------|
| **M1: MD Parity** | `markdown-it` output matches Python rendering | TBD |
| **M2: Data Sync** | Real models from `threat-modeling` running in TS | TBD |
| **M3: Site Engine** | First prototype of TS-based site generator (VitePress) | TBD |
| **M4: Full Parity** | All annexes and specialized reports (ISO) completed | TBD |

---
*Created on 2026-02-13*
