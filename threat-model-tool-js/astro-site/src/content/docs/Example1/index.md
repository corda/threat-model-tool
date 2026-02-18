---
title: "Abstract Example Threat Model Threat Model"
---
<div markdown="block" class='current'>



# 1 Abstract Example Threat Model Threat Model   <div class='skipTOC'></div> <a id='Example1'></a>


Version: 1.0

Authors: Example Author





## 1.1 Executive Summary <a id='executive-summary'></a>


> This section contains an executive summary of the threats and their mitigation status.

There are **3** unmitigated threats without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>Severity</th></tr>
<tr markdown="block"><td><a href="#DATA_EXPOSURE">Example1.<br/>DATA_EXPOSURE</a><td style="background-color: #df3d03; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span> </td></tr>
<tr markdown="block"><td><a href="#DATA_TAMPERING">Example1.<br/>DATA_TAMPERING</a><td style="background-color: #df3d03; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span> </td></tr>
<tr markdown="block"><td><a href="#Example1Child.DIRECT_DB_ACCESS">Example1Child.<br/>DIRECT_DB_ACCESS</a><td style="background-color: #f9a009; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>6.0 (Medium)</strong></span> </td></tr>
</table>
</div>
<div class="pagebreak"></div>



### 1.1.1 Threats Summary <a id='threats-summary'></a>


There are a total of **3** identified threats of which **3** are not fully mitigated by default, and  **3** are unmitigated without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>
<tr markdown="block"><td><a href="#DATA_EXPOSURE">Example1.<br/>DATA_EXPOSURE</a></td><td style="background-color: #df3d03; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#DATA_TAMPERING">Example1.<br/>DATA_TAMPERING</a></td><td style="background-color: #df3d03; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#Example1Child.DIRECT_DB_ACCESS">Example1Child.<br/>DIRECT_DB_ACCESS</a></td><td style="background-color: #f9a009; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>6.0 (Medium)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
</table></div>



## 1.2 Abstract Example Threat Model - scope of analysis <a id='abstract-example-threat-model---scope-of-analysis'></a>





### 1.2.1 Abstract Example Threat Model Overview <a id='abstract-example-threat-model-overview'></a>


Minimal abstract threat model for testing report generation.




### 1.2.2 Abstract Example Threat Model security objectives <a id='abstract-example-threat-model-security-objectives'></a>


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



### 1.2.3 Linked threat Models <a id='linked-threat-models'></a>


- **Database Security (Child of Example 1)** (ID: Example1.Example1Child)
<div class="pagebreak"></div>



### 1.2.4 Abstract Example Threat Model Threat Actors <a id='abstract-example-threat-model-threat-actors'></a>


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



## 1.3 Abstract Example Threat Model Analysis <a id='abstract-example-threat-model-analysis'></a>


This abstract model is intended for testing the renderer and report pipeline.

<hr/>



## 1.4 Abstract Example Threat Model Attack tree <a id='abstract-example-threat-model-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/Example1_ATTACKTREE.svg">
                     <img src="img/Example1_ATTACKTREE.svg" alt="$Abstract Example Threat Model attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



## 1.5 Abstract Example Threat Model Threats <a id='abstract-example-threat-model-threats'></a>



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
<div markdown="block" class='current'>



## 1.6 Database Security (Child of Example 1) Threat Model Section <a id='Example1Child'></a>


Version: 1.0

Authors: Example Author





### 1.6.1 Database Security (Child of Example 1) - scope of analysis <a id='database-security-(child-of-example-1)---scope-of-analysis'></a>





#### 1.6.1.1 Database Security (Child of Example 1) Overview <a id='database-security-(child-of-example-1)-overview'></a>


Detailed threat model for the database component.




#### 1.6.1.2 Database Security (Child of Example 1) security objectives <a id='database-security-(child-of-example-1)-security-objectives'></a>


**Data Security:**

- <a href="#Example1Child.DB_INTEGRITY">Database Integrity</a>

**Details:**



##### Database Integrity (<code>DB_INTEGRITY</code>) <a id='Example1Child.DB_INTEGRITY'></a>


Ensure that the stored data is accurate and consistent.

**Priority:** High

**Contributes to:**

- <code><a href="#SYSTEM_INTEGRITY">SYSTEM_INTEGRITY</a></code> *(System Integrity)*

**Attack tree:**

<img src="img/secObjectives/DB_INTEGRITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>
<div class="pagebreak"></div>



#### 1.6.1.3 Database Security (Child of Example 1) Threat Actors <a id='database-security-(child-of-example-1)-threat-actors'></a>


> Actors, agents, users and attackers may be used as synonymous.

<a id="MALICIOUS_ADMIN"></a>
<p><strong>Malicious Administrator (<code>MALICIOUS_ADMIN</code>)</strong></p>
<dl markdown="block">
<dt>Description:</dt><dd markdown="block">An internal user with administrative access to the database server.
</dd>
<dt>In Scope as threat actor:</dt><dd>Yes</dd>
</dl>
<hr/>



#### 1.6.1.4 Assets <a id='assets'></a>





##### Summary Table <a id='summary-table'></a>


<table>
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
<tr><td>Database Storage<br/><code><strong>DB_STORAGE</strong></code></td><td>data</td><td>&#x2714;&#xFE0F;</td></tr>
</table>



##### Details <a id='details'></a>


<hr/>
<div markdown="1" class='current'>
<a id="Example1.Example1Child.DB_STORAGE"></a>
**Database Storage (data in scope - ID: <code>DB_STORAGE</code>)**

<dl markdown="block">
Underlying data storage files.

</dl>
</div>
<hr/>



### 1.6.2 Database Security (Child of Example 1) Analysis <a id='database-security-(child-of-example-1)-analysis'></a>


This model focuses on threats specific to the database layer, inheriting broader context from Example 1.

<hr/>



### 1.6.3 Database Security (Child of Example 1) Attack tree <a id='database-security-(child-of-example-1)-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/Example1Child_ATTACKTREE.svg">
                     <img src="img/Example1Child_ATTACKTREE.svg" alt="$Database Security (Child of Example 1) attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



### 1.6.4 Database Security (Child of Example 1) Threats <a id='database-security-(child-of-example-1)-threats'></a>



> **Note** This section contains the threat and mitigations identified during the analysis phase.
<div markdown="1" class='current'>
<a id="DIRECT_DB_ACCESS"></a>



#### 1.6.4.1 Direct Access to Database Files (<code>DIRECT_DB_ACCESS</code>) <a id='Example1Child.DIRECT_DB_ACCESS'></a>


<div style="text-align: center;">
<img src="img/threatTree/DIRECT_DB_ACCESS.svg"/>
</div>
<dl markdown="block">
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#Example1Child.MALICIOUS_ADMIN">MALICIOUS_ADMIN</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block">An attacker with local system access bypasses the application and accesses database files directly on disk.
</dd>
<dt>Impact</dt><dd markdown="block">Confidential data stored in the database is exposed, bypassing all application-level controls.
<br/> <code><a href="#Example1Child.DB_INTEGRITY">DB_INTEGRITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 6.0 (Medium) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N</code>
</dd>
</dl>



##### Counter-measures for DIRECT_DB_ACCESS   <div class='skipTOC'></div> <a id='counter-measures-for-direct_db_access'></a>


<dl markdown="block">
<strong> <code>DISK_ENCRYPTION</code> Encrypt Data at Rest</strong><br/>
<dd markdown="block">Use transparent data encryption (TDE) or full-disk encryption to protect data files.
</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> &#10060;</dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
</div>



## 1.7 Requests For Information <a id='requests-for-information'></a>


__RFI_PLACEHOLDER__
<div class="pagebreak"></div>



## 1.8 Operational Security Hardening Guide <a id='operational-security-hardening-guide'></a>


<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <thead><tr><th>Seq</th><th>Countermeasure Details</th></tr></thead>
  <tbody markdown="block">
</tbody></table>
<div class="pagebreak"></div>



## 1.9 Testing guide   <div class='skipTOC'></div> <a id='testing-guide'></a>



This guide lists all testable attacks described in the threat model

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Seq</th><th>Attack to test</th><th>Pass/Fail/NA</th></tr>
</table>
<div class="pagebreak"></div>



## 1.10 Keys classification <a id='keys-classification'></a>

