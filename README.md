# Structured Threat Models *WORK IN PROGRESS*

## Development setup
Run from [github.com:corda/threat-model-tool](https://github.com/corda/threat-model-tool) checkout directory:
```bash
pip3 install develop
```

Run from the [github.com:corda/threat-modeling.git](https://github.com/corda/threat-modeling) checkout directory:
```bash
pip3 install -e ../threat-model-tool
```

## Create a distribution 

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


## Refactor yaml schema from version 0.1 to 0,2


```bash 
pip install git+https://github.com/corda/threat-model-tool.git@v0.1.4
```
```bash python -m r3threatmodeling.report_generator --rootTMYaml ../Corda5ThreatModels/threatModels/
C5.yaml --TMID C5 C5.CPIPackaging --browserSync --outputDir ../Corda5ThreatModels/build/generated_reports --template TM_tem
plateFull --formatYAML
```
pip install pip install git+https://github.com/corda/threat-model-tool.git



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

### Attackers

Could have been also called `roles`. Other synonyms could be agents, participants etc... 
The `attackers` section contains al the roles involved in the system. They may contain trusted and untrusted parties. A trusted party is identified as `inScope: true`, for example in:

```yaml
attackers:

- ID: ANONYMOUS

description: |

Anonymous internet user

inScope: true
```

the anonymous internet used is likely an untrusted party that could attack the system and we want to defend against. `ANONYMOUS` could launch DoS attacks to the system.
An opposite example:
```yaml
- ID: SYS_ADMIN
- description: |

Installed of the system and maintainer of the infrastructure (network, cloud ...
inScope: false
```

`SYS_ADMIN` is likely a trusted agent we are not performing threat analysis against during a software product development (may not be the case when threat modeling a specific instance of a running system/installation).

Other software users like `ADMIN` may be trusted (`inScope: false`) or not (`inScope: true`) depending on the criticality of the system and the compliance requirements.  While most software system contain power user (root, admin etc) a critical system may want to be by design resilient to a malicious admin. This should  also be represented explicitly using `SecurityObjective` item.

Attacker (roles) will be associated with threats and countermeasures; with threats when defining who can execute the specific attack; with an 'operational' countermeasure as the `operator` attribute. This last `operator` attribute will allow to extract checklist, and hardening guidelines to specific roles from the countermeasures in our threat model.


### Threat
Is in general something that can go wrong.

`title`
`attack`
`impactDescription`

In out yaml definition theres no general `description` for a threat, as we need to separate the `attack` (how to exploit) from the `impact`. The Impact should be described with a language closer to the business and not to the system. For example *"XSS on login page sending this payload ..."*, *"buffer overflow on input data reading on line 45 of  file.c ... "* or *"SQL injection on DAO object with non parametrised query..."* describes an attack on how to exploit the threat, while *"Confidential information disclosure"* is a description of an impact.

TODO

### Security Objectives

Security objectives (s.o.) represent a high level, generic goal or security requirement. Should be applicable and relate to many threats. They are not mandatory and could be implicit, for example "full Confidentiality, Integrity and availability" is commonly an implicit security objective driving any Threat Modeling exercise.  Structuring a well defined set of `securityObjectives` may allow to strategically manage less obvious security features we want in our system; for example some `compliance` feature, or some advance, defence in depth like generic feature. 
As security objective relates to a threat impact, as it is a s.o. negation. For example a Denial of Service Threat impacts the Availability s.o. 
On the other hand is advisable not to go too granular in `securityObjectives` definition as their usefulness is in grouping common 


```yaml
scope:

securityObjectives:

- ID: FULL_CIA

title: Confidentiality Integrity and availability of a Corda Network

description: |

Ability to maintain fundamental confidentiality

integrity and availability of the Corda network or of a specific cluster

group: General security Objectives
```

By associating the s.o. with the impact of the `threat` we can extract the design and implementation gap from the current design to the one that achieve the specific s.o. in other words we can easily identify the missing countermeasures associated with the general or specific s.o.

```yaml
threats:
[...]
- ID: XXXX
impactDescription: Creates a potential attack vector for compromising the Cluster
impacts:
- REFID: FULL_CIA
```
In the previous yaml example you can see the `impacts` referencing security objectives. We can also see the `impact` (without s) that is a text description of the impact.

### Assets

An asset can represent any part of the system that is 'in' or 'out' of scope. Explicitly and clearly defining the assets allows to:
 - Avoid ambiguity when referring a part of the system, as any ``asste`` defined has a punctual description 
 - Using a consistent naming, as different teams and individual may call the same part of the system with different names
 - Clearly state what is in scope of analysis or not. As usual, what is not created/coded by the dev team, just used/imported, tends to be out of scope, at least of the specific TM part. Also a dataflow not crossing a ``trust boundary`` tend to be out of scope.
 - Define a generic asset and then one of its specification, at a lower level of abstraction, improving scalability (more below)
 - Group assets by type (credential, DataFlow, private keys, processes)
 - Assist analysis and track it progress and completeness, for example applying a taxonomies of threat to a specific asset (STRIDE to a dataflow crossing a trust boundary)

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

**Versioning feature**

It is possible to tell via YAML to what versions a specific asset, threat or countermeasure belongs, for example:
```yaml
    - ID: DF_BOOTSTRAP_TO_DB
      appliesToVersions: ">=5.0"
```
This information will be used in two ways:

1. The ``appliesToVersions`` information will be displayed in the report
2. By adding the parameters ``"--versionsFilter" "5.0,5.1"`` to the report generator, the report will not show the assets, threat and countermeasures that do not match the list of versions provided as parameter. See [https://pypi.org/project/semantic-version/]() for more info on the versions format

### Operation hardening guide

The template system also creates a Security Hardening Guideline. It collects all the operational countermeasures `operational: true` grouping it by operator `operator: ADMIN`.
An operational countermeasure is something an operator (same as threat model defined actors/attackers) needs to do to prevent a threat; it is not a enabled by default/coded feature (`operational: false`).

To make the *Operation hardening guide* readable the title and description of an operational countermeasure should precisely answer to the question "what the operator needs to do (and why, how ...)" instead of a desired state of things or other phrasing.

For example, this phrasing may be not optimal to generate the most useful Hardening guide
```yaml
 threats:
   - ID: ACCIDENTAL_DATA_LOSS
    title: Data from the main DataBase is lost ...
    [...]
    countermeasures:
      - ID: DATA_BACKUP
        title: Data backup allows to restore the production system...
        description: |
          To restore data after an incident Backups allows...
        operational: false
        operator: INFRASTRUCTURE_OPERATOR
        inPlace: true
        public: true

 ```

 We can rephrase it in as way `title:` and `description:` refers to a precise action: 


 ```yaml
 threats:
   - ID: ACCIDENTAL_DATA_LOSS
    title: Data from the main DataBase is lost ...
    [...]
    countermeasures:
      - ID: DATA_BACKUP
        title: Perform data backup 
        description: |
          The infrastructure operator performs regular backup in an separate network and those backup are secured with encryption....
        operational: false
        operator: INFRASTRUCTURE_OPERATOR
        inPlace: true
        public: true

 ```

 ## Mark threat model parts PROPOSAL

It is possible to add a yaml attribute `proposal: PROPOSAL_NAME` to the main yaml threat model file, to specific `assets` and `threats` sub-elements.
The HTML and MKDOCS version of the report will apply a special css class to the div elements involved tp highlight the proposal nature.
It also will indicate in the summary the fact that a specific threat/vulnerability is in a proposal state.
In free text sections like `scope.description` it is possible to add `<div class='proposal'>TEXT</div> as well.`