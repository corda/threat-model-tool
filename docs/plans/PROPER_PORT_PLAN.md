# Proper TypeScript Port - Implementation Plan

## Context
The initial TypeScript port was a simplified version that doesn't match the Python implementation's sophistication. This document outlines the proper approach to port the Python threat model tool to TypeScript while maintaining full feature parity and output compatibility.

## Python Architecture Analysis

### Core Classes (threatmodel_data.py ~1000 lines)
1. **BaseThreatModelObject** - Base class extending TreeNode
   - Properties: originDict, description, isReference, versionsFilter
   - Methods: filterOut*, update(), getThreatModel(), getFileAndLineErrorMessage()

2. **REFID** - Reference resolution system
   - Resolves cross-references between objects
   - replaceInParent() - replaces references with actual objects
   
3. **TMCVSS** - CVSS scoring (extends python-cvss library)
   - getSmartScore*() methods for calculating and displaying scores
   - Color coding based on severity

4. **SecurityObjective**
   - contributesTo relationships
   - treeImage property for diagram generation
   - linkedImpactMDText() for cross-references

5. **Threat**
   - Complex relationships: countermeasures, assets, impactedSecObjs, attackers
   - Properties: description (computed), operational, ticketLink
   - CVSS integration

6. **Countermeasure**
   - operational flag, inPlace status
   - statusColors() for visual styling
   - RAGStyle() for status indicators

7. **ThreatModel**
   - Hierarchical structure (parent/child threat models)
   - Multiple query methods: getThreatsByFullyMitigated(), getAllDown()
   - Asset directory management

### Template System (~2000 lines across multiple files)

#### template_utils.py (~392 lines)
- **HeadingNumberer** - Singleton for hierarchical heading numbers (1, 1.1, 1.1.1)
- **makeMarkdownLinkedHeader()** - Creates numbered headers with anchors
- **createObjectAnchorHash()** - Generates anchor IDs
- **renderNestedMarkdownList()** - Recursive list rendering
- **unmark()** - Strip markdown formatting
- **markdown_to_text()** - Convert MD to plain text

#### lib_py.py (~496 lines)
- **executive_summary()** - Table-based threat summary with color coding
- **render_tm_report_part()** - Main report sections
- **render_threats()** - Detailed threat rendering
- **render_security_objectives()** - Security objectives with diagrams
- **render_assets()** - Asset tables
- **render_assumptions()** - Assumptions lists

#### renderers.py (~315 lines)
- **render_full_report()** - Complete report
- **render_mkdocs_report()** - MkDocs-compatible format
- **render_compact_report()** - Minimal version
- **render_operational_hardening()** - Operational guide
- **render_keys_summary()** - Keys/credentials summary

#### PlantUML Generators (3 files, ~604 lines)
- **createThreatPlantUMLDiagrams.py** - Attack trees (GraphViz DOT format)
- **createSecObjTreePUMLDiagrams.py** - Security objective trees
- **createSecObjectivesPlantUML.py** - Security objectives diagram
- **TM_AttackTreePlantUMLDiagram.py** - Complete attack tree with relationships

## Key Features Missing from Initial Port

### 1. Output Format
- ❌ HTML-enhanced markdown (divs, tables, styled spans)
- ❌ Table of Contents with hierarchical numbering
- ❌ Executive summary tables
- ❌ Color-coded severity indicators
- ❌ Page break markers
- ❌ Proper anchor links

### 2. PlantUML Generation
- ❌ GraphViz DOT format (not basic PlantUML)
- ❌ Attack trees with mitigation relationships
- ❌ Security objective trees
- ❌ Legend generation
- ❌ Proper colors and styling
- ❌ URL links in diagrams

### 3. Data Model
- ❌ Nested threat model support (children)
- ❌ REFID resolution and replaceInParent()
- ❌ Version filtering
- ❌ Operational countermeasures
- ❌ Query methods (getThreatsByFullyMitigated, etc.)

### 4. Template System
- ❌ Heading numbering (HeadingNumberer singleton)
- ❌ TOC placeholder injection
- ❌ Pre/post markdown sections
- ❌ Context objects for rendering

## Implementation Phases

### Phase 1: Enhanced Data Model (Priority: HIGH)
**Goal**: Match Python class hierarchy and functionality

Files to create/update:
- `src/core/BaseThreatModelObject.ts` - Complete base class
- `src/core/REFID.ts` - Reference resolution
- `src/core/CVSS.ts` - Full CVSS implementation
- `src/core/ThreatModel.ts` - With children support
- `src/core/Threat.ts` - All properties and methods
- `src/core/SecurityObjective.ts` - With contributesTo
- `src/core/Countermeasure.ts` - With operational flags
- `src/core/Asset.ts` - With properties
- `src/core/Attacker.ts`
- `src/core/Assumption.ts`
- `src/core/Scope.ts`

**Testing**: 
- Load FullFeature.yaml
- Verify all objects parse correctly
- Test REFID resolution
- Test nested models (FullFeature -> SubComponent)

### Phase 2: Template Utilities (Priority: HIGH)
**Goal**: Replicate template_utils.py functionality

Files to create:
- `src/template/HeadingNumberer.ts` - Singleton for numbering
- `src/template/TemplateUtils.ts` - All utility functions
- `src/template/MarkdownUtils.ts` - MD manipulation

Functions to implement:
- `makeMarkdownLinkedHeader(level, title, ctx, skipTOC, tmObject)`
- `createObjectAnchorHash(tmObject)`
- `renderNestedMarkdownList(data, level)`
- `unmark(text)` - Strip markdown
- `valueOr(o, a, alt)` - Safe property access
- TOC generation and injection

**Testing**:
- Test heading numbering (1, 1.1, 1.1.1, etc.)
- Test anchor generation
- Test TOC placeholder replacement

### Phase 3: Core Renderers (Priority: HIGH)
**Goal**: Match lib_py.py output format

Files to create:
- `src/renderers/LibPy.ts` - Main rendering functions
- `src/renderers/ExecutiveSummary.ts`
- `src/renderers/ThreatsSummary.ts`
- `src/renderers/SecurityObjectives.ts`
- `src/renderers/Threats.ts`
- `src/renderers/Assets.ts`

Functions to implement:
- `executive_summary(tmo, header_level, ctx)`
- `threats_summary(tmo, header_level, ctx)`
- `render_security_objectives(tmo, header_level, ctx)`
- `render_threats(tmo, header_level, ctx)`
- `render_assets(tmo, header_level, ctx)`

**Output Requirements**:
- HTML tables with color coding
- Proper anchor links
- CVSS score cells with background colors
- Markdown-in-HTML support

**Testing**:
- Compare output sections to Python-generated MD
- Verify table structure
- Check color codes match

### Phase 4: PlantUML Generators (Priority: MEDIUM)
**Goal**: Generate GraphViz DOT format attack trees

Files to create:
- `src/puml/AttackTreeGenerator.ts` - DOT format attack trees
- `src/puml/SecObjTreeGenerator.ts` - Security objective trees
- `src/puml/ThreatTreeGenerator.ts` - Per-threat diagrams
- `src/puml/LegendGenerator.ts` - Legend diagrams

**Format**: GraphViz DOT (not basic PlantUML)
```
@startuml
digraph G {
  rankdir="RL";
  node [shape=plaintext];
  "ThreatID" [fillcolor="#F8CECC", style=filled, ...];
  ...
}
@enduml
```

**Testing**:
- Generate attack trees
- Compare to build/FullFeature/img/*.puml
- Verify DOT syntax
- Check colors and styles

### Phase 5: Main Report Generator (Priority: HIGH)
**Goal**: Orchestrate full report generation

Files to create:
- `src/ReportGenerator.ts` - Main generator
- `src/renderers/FullReport.ts`
- `src/renderers/MkDocsReport.ts`
- `src/renderers/CompactReport.ts`

Functions:
- `generate(tmo, template, ancestorData, outputDir, ctx)`
- `renderFullReport(tmo, ctx)`
- `injectTOC(markdown)` - Replace `__TOC_PLACEHOLDER__`
- `processHeadingNumbers(markdown)` - Add numbers to headings

**Testing**:
- Generate complete FullFeature.md
- Diff against Python output
- Verify all sections present
- Check formatting matches

### Phase 6: Integration & Testing (Priority: HIGH)
**Goal**: End-to-end testing with real examples

Test Suite:
1. **Unit Tests**
   - Test each class individually
   - Test REFID resolution
   - Test CVSS calculations
   - Test utility functions

2. **Integration Tests**
   - Load FullFeature.yaml
   - Generate complete report
   - Generate all PlantUML diagrams
   - Compare outputs

3. **Regression Tests**
   - Test with all example threat models
   - Verify backward compatibility
   - Check edge cases

**Success Criteria**:
- FullFeature.md matches Python output (structure and content)
- All PlantUML files generated correctly
- Nested threat models work
- TOC generated properly
- All sections present and formatted correctly

## Technical Decisions

### TypeScript vs Python Differences

1. **YAML Parsing**: Use `js-yaml` (no line number tracking)
2. **CVSS Library**: Implement TMCVSS or wrap existing JS library
3. **Markdown**: Use `marked` or similar for MD processing
4. **HTML**: Use template literals for HTML generation
5. **File System**: Use Node.js `fs` module

### Architecture Patterns

1. **Singleton**: HeadingNumberer class
2. **Builder**: Report generation with context
3. **Template Method**: Base renderer with overrides
4. **Strategy**: Different report formats

### Dependencies to Add
```json
{
  "cvss": "^2.0.0",  // CVSS v3 calculator
  "marked": "^9.0.0",  // Markdown parser
  "cheerio": "^1.0.0",  // HTML manipulation
  "js-yaml": "^4.1.0"  // Already installed
}
```

## File Structure (New)

```
threat-model-tool/
├── src/
│   ├── core/                    # Data models
│   │   ├── BaseThreatModelObject.ts
│   │   ├── ThreatModel.ts
│   │   ├── Threat.ts
│   │   ├── SecurityObjective.ts
│   │   ├── Countermeasure.ts
│   │   ├── Asset.ts
│   │   ├── Attacker.ts
│   │   ├── Assumption.ts
│   │   ├── Scope.ts
│   │   ├── REFID.ts
│   │   └── CVSS.ts
│   ├── template/                # Template utilities
│   │   ├── HeadingNumberer.ts
│   │   ├── TemplateUtils.ts
│   │   └── MarkdownUtils.ts
│   ├── renderers/               # Report renderers
│   │   ├── LibPy.ts             # Core rendering functions
│   │   ├── FullReport.ts
│   │   ├── MkDocsReport.ts
│   │   ├── CompactReport.ts
│   │   ├── ExecutiveSummary.ts
│   │   └── ...
│   ├── puml/                    # PlantUML generators
│   │   ├── AttackTreeGenerator.ts
│   │   ├── SecObjTreeGenerator.ts
│   │   └── LegendGenerator.ts
│   ├── ReportGenerator.ts       # Main orchestrator
│   ├── Parser.ts                # YAML parser
│   └── index.ts                 # Exports
├── tests/
│   ├── core/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── fixtures/                # Test data
└── output/                      # Generated reports
```

## Timeline Estimate

- **Phase 1** (Data Model): 4-6 hours
- **Phase 2** (Template Utils): 2-3 hours
- **Phase 3** (Renderers): 4-6 hours
- **Phase 4** (PlantUML): 3-4 hours
- **Phase 5** (Report Generator): 2-3 hours
- **Phase 6** (Testing): 3-4 hours

**Total**: 18-26 hours of focused development

## Next Steps

1. ✅ Create this plan document
2. ⏳ Begin Phase 1: Enhanced Data Model
3. ⏳ Implement CVSS class
4. ⏳ Implement REFID resolution
5. ⏳ Test with FullFeature.yaml

## Success Metrics

- [ ] FullFeature.md output matches Python version (>95% similarity)
- [ ] All PlantUML diagrams generate correctly
- [ ] Nested threat models (SubComponent) work
- [ ] TOC generation with correct numbering
- [ ] Executive summary tables with color coding
- [ ] All tests pass
- [ ] Zero TypeScript compilation errors
