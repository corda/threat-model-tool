<div markdown="block" class='current'>



# Comprehensive Reference Threat Model Threat Model   <div class='skipTOC'></div> <a id='FullFeature'></a>


Version: 1.0

Last update: 2026-02-13 15:06:04

Authors: Jane Doe
John Smith


<div class="pagebreak"></div>



## Table of contents   <div class='skipTOC'></div> <a id='table-of-contents'></a>


<div markdown="1">

&nbsp;&nbsp;  **[1 Executive Summary](#executive-summary){.tocLink}**

&nbsp;&nbsp;&nbsp;&nbsp;  ***[1.1 Threats Summary](#threats-summary){.tocLink}***

&nbsp;&nbsp;  **[2 Comprehensive Reference Threat Model - scope of analysis](#comprehensive-reference-threat-model---scope-of-analysis){.tocLink}**

&nbsp;&nbsp;&nbsp;&nbsp;  ***[2.1 Comprehensive Reference Threat Model Overview](#comprehensive-reference-threat-model-overview){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[2.2 Comprehensive Reference Threat Model security objectives](#comprehensive-reference-threat-model-security-objectives){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [2.2.1 Data Confidentiality (<code>OBJ_CONFIDENTIALITY</code>)](#OBJ_CONFIDENTIALITY){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [2.2.2 Data Integrity (<code>OBJ_INTEGRITY</code>)](#OBJ_INTEGRITY){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;  ***[2.3 Linked threat Models](#linked-threat-models){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[2.4 Comprehensive Reference Threat Model Threat Actors](#comprehensive-reference-threat-model-threat-actors){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[2.5 Assumptions](#assumptions){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[2.6 Assets](#assets){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [2.6.1 Summary Table](#summary-table){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [2.6.2 Details](#details){.tocLink}

&nbsp;&nbsp;  **[3 Comprehensive Reference Threat Model Attack tree](#comprehensive-reference-threat-model-attack-tree){.tocLink}**

&nbsp;&nbsp;  **[4 Comprehensive Reference Threat Model Threats](#comprehensive-reference-threat-model-threats){.tocLink}**

&nbsp;&nbsp;&nbsp;&nbsp;  ***[4.1 SQL Injection (<code>THREAT_SQL_INJECTION</code>)](#THREAT_SQL_INJECTION){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[4.2 Potential Data Leak (<code>THREAT_DATA_LEAK</code>)](#THREAT_DATA_LEAK){.tocLink}***

&nbsp;&nbsp;  **[5 Sub-Component Feature Test Threat Model Section](#SubComponent){.tocLink}**

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.1 Sub-Component Feature Test - scope of analysis](#sub-component-feature-test---scope-of-analysis){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [5.1.1 Sub-Component Feature Test Overview](#sub-component-feature-test-overview){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [5.1.2 Assets](#assets){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [5.1.2.1 Summary Table](#summary-table){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [5.1.2.2 Details](#details){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.2 Sub-Component Feature Test Attack tree](#sub-component-feature-test-attack-tree){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.3 Sub-Component Feature Test Threats](#sub-component-feature-test-threats){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [5.3.1 Threat to Sub Component (<code>SUB_THREAT</code>)](#SubComponent.SUB_THREAT){.tocLink}

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.4 Annex 1 Operational Hardening](#annex-1-operational-hardening){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.5 Operational Security Hardening Guide](#operational-security-hardening-guide){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.6 Annex 2: Key Summary](#annex-2-key-summary){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.7 Keys classification](#keys-classification){.tocLink}***

&nbsp;&nbsp;&nbsp;&nbsp;  ***[5.8 ISO27001 Summary](#iso27001-summary){.tocLink}***



</div>
<div class="pagebreak"></div>



# 1 Executive Summary <a id='executive-summary'></a>


> This section contains an executive summary of the threats and their mitigation status.

There are **2** unmitigated threats without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>Severity</th></tr>
<tr markdown="block"><td><a href="#THREAT_DATA_LEAK">FullFeature.<br/>THREAT_DATA_LEAK</a><td style="background-color: gray; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>TODO CVSS</strong></span> </td></tr>
<tr markdown="block"><td><a href="#SubComponent.SUB_THREAT">SubComponent.<br/>SUB_THREAT</a><td style="background-color: gray; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>TODO CVSS</strong></span> </td></tr>
</table>
</div>
<div class="pagebreak"></div>



## 1.1 Threats Summary <a id='threats-summary'></a>


There are a total of **3** identified threats of which **3** are not fully mitigated by default, and  **2** are unmitigated without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>
<tr markdown="block"><td><a href="#THREAT_SQL_INJECTION">FullFeature.<br/>THREAT_SQL_INJECTION</a></td><td style="background-color: #cc0500; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>9.8 (Critical)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#THREAT_DATA_LEAK">FullFeature.<br/>THREAT_DATA_LEAK</a></td><td style="background-color: gray; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>TODO CVSS</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#SubComponent.SUB_THREAT">SubComponent.<br/>SUB_THREAT</a></td><td style="background-color: gray; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>TODO CVSS</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
</table></div>



# 2 Comprehensive Reference Threat Model - scope of analysis <a id='comprehensive-reference-threat-model---scope-of-analysis'></a>





## 2.1 Comprehensive Reference Threat Model Overview <a id='comprehensive-reference-threat-model-overview'></a>


Full scope description for the comprehensive model.




## 2.2 Comprehensive Reference Threat Model security objectives <a id='comprehensive-reference-threat-model-security-objectives'></a>


**General:**

- <a href="#OBJ_CONFIDENTIALITY">Data Confidentiality</a>

- <a href="#OBJ_INTEGRITY">Data Integrity</a>

**Diagram:**
<img src="img/secObjectives.svg"/>
**Details:**



### 2.2.1 Data Confidentiality (<code>OBJ_CONFIDENTIALITY</code>) <a id='OBJ_CONFIDENTIALITY'></a>


Protect data from unauthorized access.
**Priority:** High

**Attack tree:**

<img src="img/secObjectives/OBJ_CONFIDENTIALITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>



### 2.2.2 Data Integrity (<code>OBJ_INTEGRITY</code>) <a id='OBJ_INTEGRITY'></a>


Protect data from unauthorized modification.
**Priority:** High

**Contributes to:**

- <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code> *(Data Confidentiality)*

**Attack tree:**

<img src="img/secObjectives/OBJ_INTEGRITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>



## 2.3 Linked threat Models <a id='linked-threat-models'></a>


- **Sub-Component Feature Test** (ID: FullFeature.SubComponent)
<div class="pagebreak"></div>



## 2.4 Comprehensive Reference Threat Model Threat Actors <a id='comprehensive-reference-threat-model-threat-actors'></a>


> Actors, agents, users and attackers may be used as synonymous.

<a id="ATT_EXTERNAL"></a>
**External Attacker (<code>ATT_EXTERNAL</code>)**

<dl markdown="block">
<dt>Description:</dt><dd markdown="block">An attacker from the public internet.</dd>
<dt>In Scope as threat actor:</dt><dd>Yes</dd>
</dl>
<hr/>



## 2.5 Assumptions <a id='assumptions'></a>


<dl markdown="block"><dt>ASSUMPTION_NETWORK</dt><dd>Cloud network provides basic isolation. </dd></dl>



## 2.6 Assets <a id='assets'></a>





### 2.6.1 Summary Table <a id='summary-table'></a>


<table markdown="block">
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
<tr markdown="block"><td markdown="block">User Data<br/><code><strong markdown="block">ASSET_USER_DATA</strong></code></td><td>data</td><td>&#x2714;&#xFE0F;</td></tr>
</table>



### 2.6.2 Details <a id='details'></a>


<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.ASSET_USER_DATA"></a>
**User Data (data in scope - ID: <code>ASSET_USER_DATA</code>)**

<dl markdown="block">
Personal data stored in the database.
<dt>Applies To Versions</dt>
<dd markdown="block">&gt;=5.0</dd>
<dt markdown="block">Other properties</dt>
<dd markdown="block"><ul><li style='margin: 0px 0;'><b>type:</b> &nbsp;PII</li><li style='margin: 0px 0;'><b>storage:</b> &nbsp;Encrypted DB</li><li style='margin: 0px 0;'><b>authentication:</b> &nbsp;OAuth2</li><li style='margin: 0px 0;'><b>authorization:</b> &nbsp;RBAC</li><li style='margin: 0px 0;'><b>TLS:</b> &nbsp;1.3</li></ul></dd>
</dl>
</div>
<hr/>



# 3 Comprehensive Reference Threat Model Attack tree <a id='comprehensive-reference-threat-model-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/FullFeature_ATTACKTREE.svg">
                     <img src="img/FullFeature_ATTACKTREE.svg" alt="$Comprehensive Reference Threat Model attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



# 4 Comprehensive Reference Threat Model Threats <a id='comprehensive-reference-threat-model-threats'></a>



> **Note** This section contains the threat and mitigations identified during the analysis phase.
<div markdown="1" class='current'>
<a id="THREAT_SQL_INJECTION"></a>



## 4.1 SQL Injection (<code>THREAT_SQL_INJECTION</code>) <a id='THREAT_SQL_INJECTION'></a>


<div style="text-align: center;">
<img src="img/threatTree/THREAT_SQL_INJECTION.svg"/>
</div>
<dl markdown="block">
<dt>Applies To Versions</dt>
<dd markdown="block">&gt;=5.1</dd>
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#ASSET_USER_DATA">ASSET_USER_DATA</a></code> - User Data</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block">1. Find vulnerable input field.
2. Inject SQL payload.
</dd>
<dt>Impact</dt><dd markdown="block">High<br/> <code><a href="#OBJ_INTEGRITY">OBJ_INTEGRITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 9.8 (Critical) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code>
</dd>
Compliance:
- **GDPR**: 
- **ref**: Article 32
- **ISO27001**: 
- **ref**: A.12.6.1

</dl>



### 4.1.1 Counter-measures for THREAT_SQL_INJECTION   <div class='skipTOC'></div> <a id='counter-measures-for-threat_sql_injection'></a>


<dl markdown="block">
<strong> <code>CM_PREPARED_STATEMENTS</code> Use Prepared Statements</strong><br/>
<dt>Applies To Versions</dt><dd markdown="block">&gt;=5.1</dd>
<dd markdown="block">Ensure all DB queries use parameterized inputs.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by UNDEFINED)</dd>
</dl>
</div>
<div class="pagebreak"></div>
<div markdown="1" class='current'>
<a id="THREAT_DATA_LEAK"></a>



## 4.2 Potential Data Leak (<code>THREAT_DATA_LEAK</code>) <a id='THREAT_DATA_LEAK'></a>


<div style="text-align: center;">
<img src="img/threatTree/THREAT_DATA_LEAK.svg"/>
</div>
<dl markdown="block">
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block">Data might leak through logs.</dd>
<dt>Impact</dt><dd markdown="block"></dd>
</dl>



### 4.2.1 Counter-measures for THREAT_DATA_LEAK   <div class='skipTOC'></div> <a id='counter-measures-for-threat_data_leak'></a>


<dl markdown="block">
<strong> <code>CM_LOG_MASKING</code> Log Masking</strong><br/>
<dd markdown="block">Mask PII in logs.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> &#10060;</dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
**Release history**
- 1.0  2024-01-01: Initial version
- 1.1  2024-02-11: Added compliance and versioning features

</div>
<div markdown="block" class='current'>



# 5 Sub-Component Feature Test Threat Model Section <a id='SubComponent'></a>


Version: 1.0




## 5.1 Sub-Component Feature Test - scope of analysis <a id='sub-component-feature-test---scope-of-analysis'></a>





### 5.1.1 Sub-Component Feature Test Overview <a id='sub-component-feature-test-overview'></a>


Scope for the sub-component.




### 5.1.2 Assets <a id='assets'></a>





#### 5.1.2.1 Summary Table <a id='summary-table'></a>


<table markdown="block">
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
<tr markdown="block"><td markdown="block">Sub Asset<br/><code><strong markdown="block">SUB_ASSET</strong></code></td><td>service</td><td>&#x2714;&#xFE0F;</td></tr>
</table>



#### 5.1.2.2 Details <a id='details'></a>


<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.SubComponent.SUB_ASSET"></a>
**Sub Asset (service in scope - ID: <code>SUB_ASSET</code>)**

<dl markdown="block">

</dl>
</div>
<hr/>



## 5.2 Sub-Component Feature Test Attack tree <a id='sub-component-feature-test-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/SubComponent_ATTACKTREE.svg">
                     <img src="img/SubComponent_ATTACKTREE.svg" alt="$Sub-Component Feature Test attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



## 5.3 Sub-Component Feature Test Threats <a id='sub-component-feature-test-threats'></a>



> **Note** This section contains the threat and mitigations identified during the analysis phase.
<div markdown="1" class='current'>
<a id="SUB_THREAT"></a>



### 5.3.1 Threat to Sub Component (<code>SUB_THREAT</code>) <a id='SubComponent.SUB_THREAT'></a>


<div style="text-align: center;">
<img src="img/threatTree/SUB_THREAT.svg"/>
</div>
<dl markdown="block">
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#SubComponent.SUB_ASSET">SUB_ASSET</a></code> - Sub Asset</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block"></dd>
<dt>Impact</dt><dd markdown="block">Sub component becomes unavailable.<br/> <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code><br/> </dd>
</dl>



#### 5.3.1.1 Counter-measures for SUB_THREAT   <div class='skipTOC'></div> <a id='counter-measures-for-sub_threat'></a>


<dl markdown="block">
<strong> <code>SUB_CM</code> Rate Limiting</strong><br/>
<dd markdown="block">Limit requests to the sub component.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
</div>
<div class="pagebreak"></div>



## 5.4 Annex 1 Operational Hardening <a id='annex-1-operational-hardening'></a>





## 5.5 Operational Security Hardening Guide <a id='operational-security-hardening-guide'></a>


<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <thead><tr><th>Seq</th><th>Countermeasure Details</th></tr></thead>
  <tbody markdown="block">
<tr markdown="block"><td>1</td><td markdown="block">**Title (ID):** Use Prepared Statements (`CM_PREPARED_STATEMENTS`)<br/>
**Mitigates:** <a href="#THREAT_SQL_INJECTION">SQL Injection</a> (`THREAT_SQL_INJECTION`)<br/>
**Description:**

<br/>Ensure all DB queries use parameterized inputs.
<br/></td></tr>
</tbody></table>
<div class="pagebreak"></div>



## 5.6 Annex 2: Key Summary <a id='annex-2-key-summary'></a>





## 5.7 Keys classification <a id='keys-classification'></a>


<div class="pagebreak"></div>



## 5.8 ISO27001 Summary <a id='iso27001-summary'></a>



<table>
  <thead>
    <tr>
      <th>Control ID</th>
      <th>Description</th>
      <th>Threats</th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>
