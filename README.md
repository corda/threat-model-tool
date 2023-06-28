# Structured Threat Models *WORK IN PROGRESS*

## Development setup
Run from [github.com:corda/threat-model-tool](https://github.com/corda/threat-model-tool) checkout directory:
```bash
python setup.py develop
```

Run from the [github.com:corda/threat-modeling.git](https://github.com/corda/threat-modeling) checkout directory:
```bash
pip install -e ../threat-model-tool
```

## Crete a distribution 

```bash
python3 -m pip install --upgrade build
python3 -m build
pip install dist/r3threatmodeling-0.1.0-py3-none-any.whl
```


## Report generation command

execute it from console, example:

```bash 
python -m r3threatmodeling.report_generator --rootTMYaml ../Corda5ThreatModels/threatModels/C5.yaml --TMID C5  --browserSync --outputDir ../Corda5ThreatModels/build/generated_reports --template TM_templateFull
```

## Status
[GANTT report](threatModels/generated_reports/gantt.md)
## Introduction

This repository to hold the structured threat model yaml files and their transformations/reports.

Example Threat Model yaml section:

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
    fullyMitigated: true (TBC)
    countermeasures:
      - ID:
        description: |
          Use a full SHA-256 hash ...
        inPlace: no
        vulnManagementLink:
        public: false
      - ID:
        description: |
          Check uniqueness when onboarding a virtual Node
        inPlace: true 
        public: true


```

### Generate an human readable report of the threat model yaml files:

Please refer to .vscode/launch.json to see report generations commands

```bash
 $ ./TMReportTool.py --yamlFiles threatModels/CPIpackaging.yaml \
  --browserSync --watchFiles threatModels/CPIpackaging.yaml \
  pyConThreatMod/template/TM_template.mako  \
  pyConThreatMod/template/lib.mako threatModels/C5.yaml \
  --outputDir threatModels/generated_reports
```

Source yaml files in [threatModels](threatModels/) folder.


## YAML schema documentation (work in progress) 
### Assets

```yaml
    - ID: unique ID of the asset
      specifies: optional, reference to more general Asset ID (e.g. a specific REST endpoint specify general HTTP server)
      type: process, dataFlow, credential...
      title: |
        short title of the asset
      description: |
        description fo the asset
      inScope: true/false
```