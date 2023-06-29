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

An asset can represent any part of the system that is in or out of scope. Explicitly and clearly defining the assets allows to:
 - Avoid ambiguity when referring a part of the system, as any ``asste`` defined has a punctual description 
 - Using a consistent naming, as different teams and individual may call the same part of the system with different names
 - Clearly state what is in scope of analysis or not. As usual, what is not created/coded by the dev team, just used/imported, tends to be out of scope, at least of the specific TM part. Also a dataflow not crossing a ``trust boundary`` tend to be out of scope.
 - Define generic a specific definition of an asset, improving analysis scalability (more below)
 - Group assets by type (credential, DataFlow, private keys, processes)
 - Assist, track progress and completeness of analysis, for example applying a taxonomies of threat to a specific asset (STRIDE to a dataflow crossing a trust boundary)

**YAML example of an asset definition**

```yaml
    - ID: unique ID of the asset
      specifies: | 
	      optional, reference to more general Asset ID (e.g. a specific REST endpoint specify general HTTP server)
      type: process, dataFlow, credential...
      title: |
        short title of the asset
      description: |
        description fo the asset
      inScope: true/false
```

**More on asset hierarchy**

When Working on different level of abstraction an asset, for example and DataFlow, can be a specification of a more general definition.
A HTTP server may have several API endpoints, in this case some threat like DoS and mitigation like TLS may apply to the general asset and be inherited by the specification. It is not unusual to identify a general threat/countermeasure during a specific asset analysis. 
This abstraction of hierarchy and the use if the ``specifies`` keyword of asset would assist and streamline threat analysis.
``specifies`` creates a linked reference in the report as follow: 

![](docs/img/Pasted%20image%2020230629133136.png)


**Example analysis of an specified asset**

![](docs/img/Pasted%20image%2020230629134214.png)
