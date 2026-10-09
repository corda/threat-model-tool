# Annexes from markdown files

Put markdown files in `<model>/assets/annexes/` and the report gets them as numbered annex sections, in the HTML, the PDF and the MkDocs site. Authors keep writing ordinary markdown files in a folder.

This is different from the older `assets/markdown_sections_1/pre_NN_*.md` and `post_NN_*.md` files, which are pasted before and after the whole report. Annexes are sections inside the report: numbered, in the table of contents, with their links and diagrams resolved.

## Layout

```
threatModels/MyModel/
  MyModel.yaml
  assets/
    annexes/
      10-response-plan/            -> "Annex 3: Response Plan"
        _index.md                  -> optional: the annex title (its # heading) and an intro
        00-overview.md             -> a section, titled by its first # heading
        01-roles.md
      20-playbooks/                -> "Annex 4: Playbooks"
        PB-01-first.md
        PB-01-first.puml           -> a diagram, linked from PB-01-first.md
        sub-area/                  -> a nested heading inside the annex
          notes.md
```

| Rule | Detail |
|---|---|
| One folder = one annex | Each top-level folder becomes "Annex N: Title". Files placed directly in `annexes/` are skipped with a warning. |
| Numbering | The full report already has Annex 1 and 2, so the first folder is "Annex 3". The MkDocs report numbers from "Annex 1". |
| Order | A leading number sorts numerically (`10-`, `20-`), the rest alphabetically. Files come before sub-folders. |
| Titles | An annex takes the `# heading` of its `_index.md`, else its folder name without the number prefix. A file takes its first `# heading`, else its file name. |
| Page breaks | One before each annex and each file. |
| Only the root model | Only the root model's `annexes/` folder is rendered. |

## What the tool does to your markdown

- **Headings.** A file's `# Title` becomes a section heading under its annex, and the other headings move down to match. Manual numbers such as `## 3. Purpose` are removed, because the report numbers headings itself. Only the annex and file titles appear in the table of contents.
- **Links between files.** `[plan](../10-response-plan/00-overview.md)` becomes a link to that section. A `#fragment` on the link is dropped. A link to a file that is not an annex file produces a warning and is left as plain text. External links, `#anchors` and absolute paths are untouched.
- **Diagrams.** A link to a `.puml` file next to your markdown is replaced by the rendered diagram:

  ```markdown
  [Swimlane diagram](PB-01-first.puml)
  ```

  On a line of its own it becomes a diagram in its own paragraph; inside a sentence it becomes an inline image. The `.puml` is copied to `img/annexes/` in the output, where the normal PlantUML step renders it to SVG. Images (`.png`, `.jpg`, `.gif`, `.svg`) next to your markdown are copied the same way.
- **Code blocks** are never changed.
- **Model IDs.** An identifier in backticks in the form `UPPER_CASE_NAME` becomes a link to that threat, countermeasure, asset, security objective or attacker in the report (`` `ONCHAIN_TX_ANOMALY_DETECTION` `` links to `#ONCHAIN_TX_ANOMALY_DETECTION`). One that the model does not define as an `ID:` produces a warning, which catches typos and references to items that were renamed or removed. Text that is already a link, and code blocks, are left alone.

## Switches

| Switch | Effect |
|---|---|
| `--noAnnexes` | Leave the annexes out of this build. Use it to build a PDF without them. |
| `--strictAnnexes` | Fail the build when an annex file has a broken link. Unknown model IDs stay warnings. |
| `--visibility=public` | Annexes are not included in public reports. They are treated as internal documents. |

`--noAnnexes` and `--strictAnnexes` work on `build-threat-model`, `build-threat-model-directory` and `build-mkdocs-site`. In code, the same switches are the report context values `process_annexes` and `strictAnnexes`.

## Writing tips

- Keep each file self-contained: a `# Title`, then `##` sections.
- Link to other files with normal relative links, so the files also read well on their own in an editor or on GitHub.
- Put page-sized documents (one playbook, one procedure) in separate files, and group related files in one folder.

## Implementation notes

- `src/utils/AnnexRenderer.ts` does the scanning, ordering and rewriting. `ReportGenerator.generate` calls it after the template is rendered, so every template and every build script gets annexes.
- `copyStaticAssets` skips `assets/annexes`, so the source files are not also published as raw files.
- Countermeasures carry an anchor named after their ID in the report (`<dt id='ID'>`), like threats, assets, objectives and attackers, so every model ID can be a link target.
- Annex headings carry explicit anchors (`<a id='annex-…'></a>`, or `{#annex-…}` for MkDocs templates), so links work in the HTML, the PDF and MkDocs.
- Tests: `tests/integration/Annexes.test.ts`, with the fixture model in `tests/fixtures/annexes/AnnexExample`.
