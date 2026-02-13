<div markdown="block" class='current'>


# 1 Comprehensive Reference Threat Model Threat Model  <div class='skipTOC'></div> <a id='comprehensive-reference-threat-model-threat-model'></a>


Version: 1.0

Last update: 2026-02-13 11:34:57

Authors: Jane Doe
John Smith



<div class="pagebreak"></div>


## 1.1 Table of contents  <div class='skipTOC'></div> <a id='table-of-contents'></a>

<div markdown="1">
  **[2 Executive Summary](#executive-summary){.tocLink}**
&nbsp;&nbsp;  **[2.1 Threats Summary](#threats-summary){.tocLink}**
  **[3 Comprehensive Reference Threat Model - scope of analysis](#comprehensive-reference-threat-model---scope-of-analysis){.tocLink}**
&nbsp;&nbsp;  **[3.1 Comprehensive Reference Threat Model Overview](#comprehensive-reference-threat-model-overview){.tocLink}**
&nbsp;&nbsp;  **[3.2 Comprehensive Reference Threat Model security objectives](#comprehensive-reference-threat-model-security-objectives){.tocLink}**
&nbsp;&nbsp;&nbsp;&nbsp;  ***[3.2.1 Data Confidentiality (OBJ_CONFIDENTIALITY)](#FullFeature.OBJ_CONFIDENTIALITY){.tocLink}***
&nbsp;&nbsp;&nbsp;&nbsp;  ***[3.2.2 Data Integrity (OBJ_INTEGRITY)](#FullFeature.OBJ_INTEGRITY){.tocLink}***
&nbsp;&nbsp;  **[3.3 Linked threat Models](#linked-threat-models){.tocLink}**
&nbsp;&nbsp;  **[3.4 Comprehensive Reference Threat Model Threat Actors](#comprehensive-reference-threat-model-threat-actors){.tocLink}**
&nbsp;&nbsp;  **[3.5 Assumptions](#assumptions){.tocLink}**
&nbsp;&nbsp;  **[3.6 Assets](#assets){.tocLink}**
&nbsp;&nbsp;&nbsp;&nbsp;  ***[3.6.1 Summary Table](#summary-table){.tocLink}***
&nbsp;&nbsp;&nbsp;&nbsp;  ***[3.6.2 Details](#details){.tocLink}***
  **[4 Comprehensive Reference Threat Model Attack tree](#comprehensive-reference-threat-model-attack-tree){.tocLink}**
  **[5 Comprehensive Reference Threat Model Threats](#comprehensive-reference-threat-model-threats){.tocLink}**
&nbsp;&nbsp;  **[5.1 SQL Injection (THREAT_SQL_INJECTION)](#FullFeature.THREAT_SQL_INJECTION){.tocLink}**
&nbsp;&nbsp;  **[5.2 Potential Data Leak (THREAT_DATA_LEAK)](#FullFeature.THREAT_DATA_LEAK){.tocLink}**
  **[6 Sub-Component Feature Test - scope of analysis](#sub-component-feature-test---scope-of-analysis){.tocLink}**
&nbsp;&nbsp;  **[6.1 Sub-Component Feature Test Overview](#sub-component-feature-test-overview){.tocLink}**
&nbsp;&nbsp;  **[6.2 Sub-Component Feature Test security objectives](#sub-component-feature-test-security-objectives){.tocLink}**
&nbsp;&nbsp;  **[6.3 Sub-Component Feature Test Threat Actors](#sub-component-feature-test-threat-actors){.tocLink}**
&nbsp;&nbsp;  **[6.4 Assets](#assets){.tocLink}**
&nbsp;&nbsp;&nbsp;&nbsp;  ***[6.4.1 Summary Table](#summary-table){.tocLink}***
&nbsp;&nbsp;&nbsp;&nbsp;  ***[6.4.2 Details](#details){.tocLink}***
  **[7 Sub-Component Feature Test Attack tree](#sub-component-feature-test-attack-tree){.tocLink}**
  **[8 Sub-Component Feature Test Threats](#sub-component-feature-test-threats){.tocLink}**
&nbsp;&nbsp;  **[8.1 Threat to Sub Component (SUB_THREAT)](#SubComponent.SUB_THREAT){.tocLink}**
  **[9 Annex 1: Operational Security Hardening Guide](#annex-1-operational-security-hardening-guide){.tocLink}**
  **[10 Annex 2: Keys classification](#annex-2-keys-classification-){.tocLink}**

</div>

<div class="pagebreak"></div>


# 2 Executive Summary <a id='executive-summary'></a>

> This section contains an executive summary of the threats and their mitigation status.

There are **2** unmitigated threats without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>Severity</th></tr>
<tr markdown="block"><td><a href="#FullFeature.THREAT_DATA_LEAK">FullFeature.<br/>THREAT_DATA_LEAK</a></td><td style="background-color: #f9a009; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>Medium</strong></span> </td></tr>
<tr markdown="block"><td><a href="#SubComponent.SUB_THREAT">SubComponent.<br/>SUB_THREAT</a></td><td style="background-color: #f9a009; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>Medium</strong></span> </td></tr>
</table>
</div>
<div class="pagebreak"></div>


## 2.1 Threats Summary <a id='threats-summary'></a>

There are a total of **3** identified threats of which **3** are not fully mitigated by default, and  **2** are unmitigated without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>
<tr markdown="block"><td><a href="#FullFeature.THREAT_SQL_INJECTION">FullFeature.<br/>THREAT_SQL_INJECTION</a></td><td style="background-color: #df3d03; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>High</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#FullFeature.THREAT_DATA_LEAK">FullFeature.<br/>THREAT_DATA_LEAK</a></td><td style="background-color: #f9a009; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>Medium</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#SubComponent.SUB_THREAT">SubComponent.<br/>SUB_THREAT</a></td><td style="background-color: #f9a009; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>Medium</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
</table></div>
# 3 Comprehensive Reference Threat Model - scope of analysis <a id='comprehensive-reference-threat-model---scope-of-analysis'></a>

## 3.1 Comprehensive Reference Threat Model Overview <a id='comprehensive-reference-threat-model-overview'></a>

Full scope description for the comprehensive model.




## 3.2 Comprehensive Reference Threat Model security objectives <a id='comprehensive-reference-threat-model-security-objectives'></a>

**General:**

- <a href="#FullFeature.OBJ_CONFIDENTIALITY">Data Confidentiality</a>

- <a href="#FullFeature.OBJ_INTEGRITY">Data Integrity</a>


**Diagram:**
<img src="img/secObjectives.svg"/>
**Details:**

### 3.2.1 Data Confidentiality (<code>OBJ_CONFIDENTIALITY</code>) <a id='FullFeature.OBJ_CONFIDENTIALITY'></a>


Protect data from unauthorized access.
**Priority:** High

**Attack tree:**

<img src="img/secObjectives/OBJ_CONFIDENTIALITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>

### 3.2.2 Data Integrity (<code>OBJ_INTEGRITY</code>) <a id='FullFeature.OBJ_INTEGRITY'></a>


Protect data from unauthorized modification.
**Priority:** High

**Contributes to:**

- <code><a href="#FullFeature.OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code> *(Data Confidentiality)*

**Attack tree:**

<img src="img/secObjectives/OBJ_INTEGRITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>

## 3.3 Linked threat Models <a id='linked-threat-models'></a>

- **Sub-Component Feature Test** (ID: SubComponent)
<div class="pagebreak"></div>

## 3.4 Comprehensive Reference Threat Model Threat Actors <a id='comprehensive-reference-threat-model-threat-actors'></a>

> Actors, agents, users and attackers may be used as synonymous.

<a id="ATT_EXTERNAL"></a>
**External Attacker (<code>ATT_EXTERNAL</code>)**
An attacker from the public internet.

## 3.5 Assumptions <a id='assumptions'></a>

- **Cloud network provides basic isolation.[...]**: Cloud network provides basic isolation.

## 3.6 Assets <a id='assets'></a>

### 3.6.1 Summary Table <a id='summary-table'></a>

<div markdown="1">
<table markdown="block">
<tr><th>Asset</th><th>Type</th><th>Description</th></tr>
<tr markdown="block"><td>User Data</td><td>data</td><td>Personal data stored in the database.</td></tr>
</table></div>

### 3.6.2 Details <a id='details'></a>

**User Data (<code>ASSET_USER_DATA</code>)**
Personal data stored in the database.
<ul><li style='margin: 0px 0;'><b>type:</b> &nbsp;PII</li><li style='margin: 0px 0;'><b>storage:</b> &nbsp;Encrypted DB</li><li style='margin: 0px 0;'><b>authentication:</b> &nbsp;OAuth2</li><li style='margin: 0px 0;'><b>authorization:</b> &nbsp;RBAC</li><li style='margin: 0px 0;'><b>TLS:</b> &nbsp;1.3</li></ul>

# 4 Comprehensive Reference Threat Model Attack tree <a id='comprehensive-reference-threat-model-attack-tree'></a>

<img src="img/FullFeature_ATTACKTREE.svg"/>


# 5 Comprehensive Reference Threat Model Threats <a id='comprehensive-reference-threat-model-threats'></a>

## 5.1 SQL Injection (<code>THREAT_SQL_INJECTION</code>) <a id='FullFeature.THREAT_SQL_INJECTION'></a>

**Attack:** 1. Find vulnerable input field.
2. Inject SQL payload.
<br/> **Impact:** High

**Severity:** <span style="background-color: #df3d03; color: white; padding: 2px 5px; border-radius: 3px;">**High**</span>

**Countermeasures:**

- **Use Prepared Statements** [<span style="color: green">In Place</span>]
  Ensure all DB queries use parameterized inputs.

<hr/>

## 5.2 Potential Data Leak (<code>THREAT_DATA_LEAK</code>) <a id='FullFeature.THREAT_DATA_LEAK'></a>

**Attack:** Data might leak through logs.<br/> **Impact:** undefined

**Severity:** <span style="background-color: #f9a009; color: white; padding: 2px 5px; border-radius: 3px;">**Medium**</span>

**Countermeasures:**

- **Log Masking** [<span style="color: orange">Planned</span>]
  Mask PII in logs.

<hr/>

# 6 Sub-Component Feature Test - scope of analysis <a id='sub-component-feature-test---scope-of-analysis'></a>

## 6.1 Sub-Component Feature Test Overview <a id='sub-component-feature-test-overview'></a>

Scope for the sub-component.




## 6.2 Sub-Component Feature Test security objectives <a id='sub-component-feature-test-security-objectives'></a>

**Diagram:**
<img src="img/secObjectives.svg"/>
**Details:**


## 6.3 Sub-Component Feature Test Threat Actors <a id='sub-component-feature-test-threat-actors'></a>

> Actors, agents, users and attackers may be used as synonymous.


## 6.4 Assets <a id='assets'></a>

### 6.4.1 Summary Table <a id='summary-table'></a>

<div markdown="1">
<table markdown="block">
<tr><th>Asset</th><th>Type</th><th>Description</th></tr>
<tr markdown="block"><td>Sub Asset</td><td>service</td><td></td></tr>
</table></div>

### 6.4.2 Details <a id='details'></a>

**Sub Asset (<code>SUB_ASSET</code>)**


# 7 Sub-Component Feature Test Attack tree <a id='sub-component-feature-test-attack-tree'></a>

<img src="img/SubComponent_ATTACKTREE.svg"/>


# 8 Sub-Component Feature Test Threats <a id='sub-component-feature-test-threats'></a>

## 8.1 Threat to Sub Component (<code>SUB_THREAT</code>) <a id='SubComponent.SUB_THREAT'></a>

**Attack:** <br/> **Impact:** Sub component becomes unavailable.

**Severity:** <span style="background-color: #f9a009; color: white; padding: 2px 5px; border-radius: 3px;">**Medium**</span>

**Countermeasures:**

- **Rate Limiting** [<span style="color: green">In Place</span>]
  Limit requests to the sub component.

<hr/>

<div class="pagebreak"></div>
# 9 Annex 1: Operational Security Hardening Guide <a id='annex-1-operational-security-hardening-guide'></a>

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <thead><tr><th>Seq</th><th>Countermeasure Details</th></tr></thead>
  <tbody markdown="block">
<tr markdown="block"><td>1</td><td markdown="block">**Title (ID):** Use Prepared Statements (`CM_PREPARED_STATEMENTS`) <br/>
**Mitigates:** <a href="#FullFeature.THREAT_SQL_INJECTION">SQL Injection</a> (`THREAT_SQL_INJECTION`) <br/>
**Description:**

<br/>Ensure all DB queries use parameterized inputs.
<br/></td></tr>
</tbody></table>
<div class="pagebreak"></div>
# 10 Annex 2: Keys classification  <a id='annex-2-keys-classification-'></a>


</div>