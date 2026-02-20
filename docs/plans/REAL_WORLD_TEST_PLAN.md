# Real-World Test Plan: CordaSolanaToolkit

## Objective
Compare Python and TypeScript threat model generation outputs using a real-world confidential threat model.

## Prerequisites
- [x] `build/totest/` folder is gitignored (via `build/` in `.gitignore`)
- [ ] Verify the YAML file is valid
- [ ] Python environment ready
- [ ] TypeScript environment ready

## Test Steps

### Step 1: Verify YAML validity and structure
Check that the threat model YAML can be parsed without errors.

### Step 2: Run Python generation
```bash
cd /workspaces/threat-model-tool
python -m r3threatmodeling.fullBuildSingleTM build/totest/CordaSolanaToolkit/CordaSolanaToolkit.yaml build/totest/output_python
```

### Step 3: Run TypeScript generation
```bash
cd /workspaces/threat-model-tool/threat-model-tool
npx tsx src/scripts/build-threat-model.ts ./build/totest/CordaSolanaToolkit/CordaSolanaToolkit.yaml ./build/totest/output_ts
```

### Step 4: Compare outputs
```bash
diff build/totest/output_python/CordaSolanaToolkit.md build/totest/output_ts/CordaSolanaToolkit.md
```

### Step 5: Analyze differences
Document any differences found and categorize them as:
- Expected (timestamps, etc.)
- Bugs to fix
- Feature gaps

## Security Notes
- All output files are in `build/` which is gitignored
- Do NOT commit any files from `build/totest/`
- Do NOT print confidential content in logs

## Results
*(Executed 2026-02-13)*

| Metric | Python | TypeScript | Notes |
|--------|--------|------------|-------|
| Line count | 3165 | 3165 | ✅ Match |
| Content diff | 6 lines | - | ✅ Expected (see below) |

### Remaining differences (all expected):
1. **Timestamp** - Build time differs (line 10)
2. **Dataflow inScope** - Python bug: `inScope` property returns string 'Yes'/'No', boolean check always truthy. TS is correct.
3. **Trailing newline** - Minor formatting, no functional impact

### Bugs fixed during testing:
- Asset `propertiesHTML()` - Fixed `[object Object]` by JSON.stringify for object values
- Asset `propertiesHTML()` - Fixed array properties rendering (match Python's empty handling)
- Countermeasure REFID resolution - Added resolve() call before rendering
- Countermeasure REFID path - Use `getHierarchicalId()` for full path like Python
- Operator value - Fixed to read from dictData in constructor
- `secureByDefault()` - Fixed logic: `fullyMitigated && !hasOperationalCountermeasures()`  
- `statusColors()` - Added 3rd color state (yellow for insecure-by-default)
- Threat sorting - Added CVSS score descending sort
- Operational CM sorting - Final sort by ID like Python
- Key table href - Use full hierarchical ID

### Test Status: ✅ PASSED

---

## Enhanced FullFeature Test (2026-02-13)

The FullFeature example was enhanced to better catch these kinds of bugs in development.

### New Features Added to FullFeature:
1. **Second child TM (ApiGateway)** - Tests complex multi-TM hierarchy
2. **Dataflow with inScope: false** - Tests Python's inScope bug
3. **Key/credential assets** - Tests Keys Summary section
4. **Operational countermeasures with varied operators** - Tests sorting and operator display
5. **Multiple CVSS scores** - Tests score sorting (10.0, 9.8, 9.1, etc.)
6. **REFID countermeasures** - Tests same-TM countermeasure references
7. **Asset with array properties** - Tests Python's .items() handling
8. **3-state threat status** - Tests mitigated/operational/vulnerable colors

### Enhanced FullFeature Results:
| Metric | Python | TypeScript |
|--------|--------|------------|
| Lines | 1128 | 1122 |
| Diff lines | 21 | (Python has bugs) |

### Remaining Python Bugs (TS is correct):
1. **Dataflow inScope** - Always shows "in scope" even when false
2. **Keys Summary duplicates** - Duplicate key entries in table
3. **Empty table generation** - Extra empty tables created

### Tests Updated:
- **Python**: 11 tests pass (added 5 new tests)
- **TypeScript**: 18 tests pass
| Diff lines | - | 237 |

## Issues Found

### 1. ✅ Expected: Timestamp difference (line 10)
Just different build times - OK

### 2. 🐛 BUG: Executive/Threats Summary ordering
Python sorts threats by severity, TS uses different order.
- Python: Sorted by CVSS score descending
- TS: Uses `getThreatsByFullyMitigated` join order

### 3. 🐛 BUG: Properties rendering `[object Object]`
Asset properties rendering `[object Object]` instead of formatted HTML.
Location: `propertiesHTML()` method not serializing correctly.

### 4. 🐛 BUG: Operator value "UNDEFINED" 
TS shows "UNDEFINED" instead of actual operator string like "Corda Network Operator".

### 5. 🐛 BUG: REFID resolution for countermeasures
Referenced countermeasures (REFID to other threats' CMs) fail to resolve.
Shows `undefined No title` instead of the referenced CM.

### 6. 🐛 BUG: Threat status mismatch
Some threats show wrong status:
- Python: "Mitigated"
- TS: "Not Secure by Default (Operational mitigation)"

## Status: ISSUES FOUND - FIXING


##  Final Step: improve the full example to resemble more a real threat model and catch this kind of bugs better during development!


