---
title: "Abstract Example Threat Model 2 Threat Model"
---
<div markdown="block" class='current'>



# 1 Abstract Example Threat Model 2 Threat Model   <div class='skipTOC'></div> <a id='Example2'></a>


Version: 1.0

Authors: Example Author 2





## 1.1 Executive Summary <a id='executive-summary'></a>


> This section contains an executive summary of the threats and their mitigation status.

There are **2** unmitigated threats without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>Severity</th></tr>
<tr markdown="block"><td><a href="#DATA_EXPOSURE">Example2.<br/>DATA_EXPOSURE</a><td style="background-color: #df3d03; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span> </td></tr>
<tr markdown="block"><td><a href="#DATA_TAMPERING">Example2.<br/>DATA_TAMPERING</a><td style="background-color: #df3d03; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span> </td></tr>
</table>
</div>
<div class="pagebreak"></div>



### 1.1.1 Threats Summary <a id='threats-summary'></a>


There are a total of **2** identified threats of which **2** are not fully mitigated by default, and  **2** are unmitigated without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>
<tr markdown="block"><td><a href="#DATA_EXPOSURE">Example2.<br/>DATA_EXPOSURE</a></td><td style="background-color: #df3d03; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#DATA_TAMPERING">Example2.<br/>DATA_TAMPERING</a></td><td style="background-color: #df3d03; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
</table></div>



## 1.2 Abstract Example Threat Model 2 - scope of analysis <a id='abstract-example-threat-model-2---scope-of-analysis'></a>





### 1.2.1 Abstract Example Threat Model 2 Overview <a id='abstract-example-threat-model-2-overview'></a>


Minimal abstract threat model for testing report generation.




### 1.2.2 Abstract Example Threat Model 2 security objectives <a id='abstract-example-threat-model-2-security-objectives'></a>


**Data Security:**

- <a href="#SYSTEM_CONFIDENTIALITY">System Confidentiality</a>


**System Integrity:**

- <a href="#SYSTEM_INTEGRITY">System Integrity</a>

**Diagram:**
<img src="img/secObjectives.svg"/>
**Details:**



#### 1.2.2.1 System Confidentiality (<code>SYSTEM_CONFIDENTIALITY</code>) <a id='SYSTEM_CONFIDENTIALITY'></a>


Prevent unauthorized disclosure of data.

**Priority:** High

**Attack tree:**

<img src="img/secObjectives/SYSTEM_CONFIDENTIALITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>



#### 1.2.2.2 System Integrity (<code>SYSTEM_INTEGRITY</code>) <a id='SYSTEM_INTEGRITY'></a>


Prevent unauthorized modification of data or behavior.

**Priority:** High

**Attack tree:**

<img src="img/secObjectives/SYSTEM_INTEGRITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>
<div class="pagebreak"></div>



### 1.2.3 Abstract Example Threat Model 2 Threat Actors <a id='abstract-example-threat-model-2-threat-actors'></a>


> Actors, agents, users and attackers may be used as synonymous.

<a id="EXTERNAL_ATTACKER"></a>
<p><strong>Unauthenticated external user with network access.[...] (<code>EXTERNAL_ATTACKER</code>)</strong></p>
<dl markdown="block">
<dt>Description:</dt><dd markdown="block">Unauthenticated external user with network access.
</dd>
<dt>In Scope as threat actor:</dt><dd>Yes</dd>
</dl>
<hr/>
<hr/>



## 1.3 Abstract Example Threat Model 2 Analysis <a id='abstract-example-threat-model-2-analysis'></a>


This abstract model is intended for testing the renderer and report pipeline.

<hr/>



## 1.4 Abstract Example Threat Model 2 Attack tree <a id='abstract-example-threat-model-2-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/Example2_ATTACKTREE.svg">
                     <img src="img/Example2_ATTACKTREE.svg" alt="$Abstract Example Threat Model 2 attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



## 1.5 Abstract Example Threat Model 2 Threats <a id='abstract-example-threat-model-2-threats'></a>



> **Note** This section contains the threat and mitigations identified during the analysis phase.
<div markdown="1" class='current'>
<a id="DATA_EXPOSURE"></a>



### 1.5.1 Unauthorized Data Exposure (<code>DATA_EXPOSURE</code>) <a id='DATA_EXPOSURE'></a>


<div style="text-align: center;">
<img src="img/threatTree/DATA_EXPOSURE.svg"/>
</div>
<dl markdown="block">
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#EXTERNAL_ATTACKER">EXTERNAL_ATTACKER</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block">An attacker accesses sensitive data through a misconfigured access control.
</dd>
<dt>Impact</dt><dd markdown="block">Sensitive data is disclosed to unauthorized parties.
<br/> <code><a href="#SYSTEM_CONFIDENTIALITY">SYSTEM_CONFIDENTIALITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 7.5 (High) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code>
</dd>
</dl>



#### 1.5.1.1 Counter-measures for DATA_EXPOSURE   <div class='skipTOC'></div> <a id='counter-measures-for-data_exposure'></a>


<dl markdown="block">
<strong> <code>ACCESS_CONTROL_ENFORCEMENT</code> Enforce Access Control</strong><br/>
<dd markdown="block">Require authentication and authorization checks on all data access paths.
</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> &#10060;</dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
<div markdown="1" class='current'>
<a id="DATA_TAMPERING"></a>



### 1.5.2 Unauthorized Data Modification (<code>DATA_TAMPERING</code>) <a id='DATA_TAMPERING'></a>


<div style="text-align: center;">
<img src="img/threatTree/DATA_TAMPERING.svg"/>
</div>
<dl markdown="block">
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#EXTERNAL_ATTACKER">EXTERNAL_ATTACKER</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block">An attacker modifies stored data using an unprotected endpoint.
</dd>
<dt>Impact</dt><dd markdown="block">Data integrity is compromised and trusted records are altered.
<br/> <code><a href="#SYSTEM_INTEGRITY">SYSTEM_INTEGRITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 7.5 (High) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code>
</dd>
</dl>



#### 1.5.2.1 Counter-measures for DATA_TAMPERING   <div class='skipTOC'></div> <a id='counter-measures-for-data_tampering'></a>


<dl markdown="block">
<strong> <code>INPUT_VALIDATION</code> Validate and Authorize Updates</strong><br/>
<dd markdown="block">Validate inputs and enforce authorization on update operations.
</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
</div>



## 1.6 Requests For Information <a id='requests-for-information'></a>


__RFI_PLACEHOLDER__
<div class="pagebreak"></div>



## 1.7 Operational Security Hardening Guide <a id='operational-security-hardening-guide'></a>


<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <thead><tr><th>Seq</th><th>Countermeasure Details</th></tr></thead>
  <tbody markdown="block">
</tbody></table>
<div class="pagebreak"></div>



## 1.8 Testing guide   <div class='skipTOC'></div> <a id='testing-guide'></a>



This guide lists all testable attacks described in the threat model

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Seq</th><th>Attack to test</th><th>Pass/Fail/NA</th></tr>
</table>
<div class="pagebreak"></div>



## 1.9 Keys classification <a id='keys-classification'></a>

