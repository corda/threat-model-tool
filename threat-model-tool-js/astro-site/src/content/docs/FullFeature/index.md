---
title: "Comprehensive Reference TM Threat Model"
---
<div markdown="block" class='current'>



# 1 Comprehensive Reference TM Threat Model   <div class='skipTOC'></div> <a id='FullFeature'></a>


Version: 1.0

Authors: Jane Doe
John Smith





## 1.1 Executive Summary <a id='executive-summary'></a>


> This section contains an executive summary of the threats and their mitigation status.

There are **2** unmitigated threats without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>Severity</th></tr>
<tr markdown="block"><td><a href="#THREAT_RCE">FullFeature.<br/>THREAT_RCE</a><td style="background-color: #cc0500; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>10.0 (Critical)</strong></span> </td></tr>
<tr markdown="block"><td><a href="#THREAT_DATA_LEAK">FullFeature.<br/>THREAT_DATA_LEAK</a><td style="background-color: #f9a009; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>6.5 (Medium)</strong></span> </td></tr>
</table>
</div>
<div class="pagebreak"></div>



### 1.1.1 Threats Summary <a id='threats-summary'></a>


There are a total of **9** identified threats of which **2** are not fully mitigated by default, and  **2** are unmitigated without proposed operational controls.<br/>
<div markdown="1">
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>
<tr markdown="block"><td><a href="#THREAT_RCE">FullFeature.<br/>THREAT_RCE</a></td><td style="background-color: #cc0500; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>10.0 (Critical)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#THREAT_DATA_LEAK">FullFeature.<br/>THREAT_DATA_LEAK</a></td><td style="background-color: #f9a009; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>6.5 (Medium)</strong></span></td><td style="background-color: #F8CECC;text-align: center ">Vulnerable</td></tr>
<tr markdown="block"><td><a href="#THREAT_KEY_COMPROMISE">FullFeature.<br/>THREAT_KEY_COMPROMISE</a></td><td style="background-color: #cc0500; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>10.0 (Critical)</strong></span></td><td style="background-color: #FFF2CC;text-align: center ">Not Secure by Default <br/>(Operational mitigation)</td></tr>
<tr markdown="block"><td><a href="#THREAT_SQL_INJECTION">FullFeature.<br/>THREAT_SQL_INJECTION</a></td><td style="background-color: #cc0500; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>9.8 (Critical)</strong></span></td><td style="background-color: #D5E8D4;text-align: center ">Mitigated</td></tr>
<tr markdown="block"><td><a href="#ApiGateway.GW_JWT_FORGERY">ApiGateway.<br/>GW_JWT_FORGERY</a></td><td style="background-color: #cc0500; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>9.1 (Critical)</strong></span></td><td style="background-color: #FFF2CC;text-align: center ">Not Secure by Default <br/>(Operational mitigation)</td></tr>
<tr markdown="block"><td><a href="#SubComponent.SUB_THREAT_KEY_LEAK">SubComponent.<br/>SUB_THREAT_KEY_LEAK</a></td><td style="background-color: #df3d03; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>8.1 (High)</strong></span></td><td style="background-color: #FFF2CC;text-align: center ">Not Secure by Default <br/>(Operational mitigation)</td></tr>
<tr markdown="block"><td><a href="#SubComponent.SUB_THREAT_DOS">SubComponent.<br/>SUB_THREAT_DOS</a></td><td style="background-color: #df3d03; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>7.5 (High)</strong></span></td><td style="background-color: #FFF2CC;text-align: center ">Not Secure by Default <br/>(Operational mitigation)</td></tr>
<tr markdown="block"><td><a href="#ApiGateway.GW_RATE_LIMIT_BYPASS">ApiGateway.<br/>GW_RATE_LIMIT_BYPASS</a></td><td style="background-color: #f9a009; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>5.9 (Medium)</strong></span></td><td style="background-color: #FFF2CC;text-align: center ">Not Secure by Default <br/>(Operational mitigation)</td></tr>
<tr markdown="block"><td><a href="#THREAT_INFO_DISCLOSURE">FullFeature.<br/>THREAT_INFO_DISCLOSURE</a></td><td style="background-color: #f9a009; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>5.3 (Medium)</strong></span></td><td style="background-color: #FFF2CC;text-align: center ">Not Secure by Default <br/>(Operational mitigation)</td></tr>
</table></div>



## 1.2 Comprehensive Reference TM - scope of analysis <a id='comprehensive-reference-tm---scope-of-analysis'></a>





### 1.2.1 Comprehensive Reference TM Overview <a id='comprehensive-reference-tm-overview'></a>


Full scope description for the comprehensive model.
This example tests all features including cross-references, operational countermeasures,
varied CVSS scores, and complex asset properties.




### 1.2.2 Comprehensive Reference TM security objectives <a id='comprehensive-reference-tm-security-objectives'></a>


**General:**

- <a href="#OBJ_CONFIDENTIALITY">Data Confidentiality</a>

- <a href="#OBJ_INTEGRITY">Data Integrity</a>

- <a href="#OBJ_AVAILABILITY">Service Availability</a>

**Diagram:**
<img src="img/secObjectives.svg"/>
**Details:**



#### 1.2.2.1 Data Confidentiality (<code>OBJ_CONFIDENTIALITY</code>) <a id='OBJ_CONFIDENTIALITY'></a>


Protect data from unauthorized access.
**Priority:** High

**Attack tree:**

<img src="img/secObjectives/OBJ_CONFIDENTIALITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>



#### 1.2.2.2 Data Integrity (<code>OBJ_INTEGRITY</code>) <a id='OBJ_INTEGRITY'></a>


Protect data from unauthorized modification.
**Priority:** High

**Contributes to:**

- <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code> *(Data Confidentiality)*

**Attack tree:**

<img src="img/secObjectives/OBJ_INTEGRITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>



#### 1.2.2.3 Service Availability (<code>OBJ_AVAILABILITY</code>) <a id='OBJ_AVAILABILITY'></a>


Ensure service remains available to authorized users.
**Priority:** High

**Attack tree:**

<img src="img/secObjectives/OBJ_AVAILABILITY.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>
<hr/>



### 1.2.3 Linked threat Models <a id='linked-threat-models'></a>


- **Sub-Component Feature Test** (ID: FullFeature.SubComponent)
- **API Gateway Security Model** (ID: FullFeature.ApiGateway)
<div class="pagebreak"></div>



### 1.2.4 Comprehensive Reference TM Threat Actors <a id='comprehensive-reference-tm-threat-actors'></a>


> Actors, agents, users and attackers may be used as synonymous.

<a id="ATT_EXTERNAL"></a>
<p><strong>External Attacker (<code>ATT_EXTERNAL</code>)</strong></p>
<dl markdown="block">
<dt>Description:</dt><dd markdown="block">An attacker from the public internet.</dd>
<dt>In Scope as threat actor:</dt><dd>Yes</dd>
</dl>
<hr/>
<a id="ATT_INSIDER"></a>
<p><strong>Malicious Insider (<code>ATT_INSIDER</code>)</strong></p>
<dl markdown="block">
<dt>Description:</dt><dd markdown="block">An employee with legitimate access abusing privileges.</dd>
<dt>In Scope as threat actor:</dt><dd>Yes</dd>
</dl>
<hr/>



### 1.2.5 Assumptions <a id='assumptions'></a>


<dl markdown="block"><dt>ASSUMPTION_NETWORK</dt><dd>Cloud network provides basic isolation. </dd></dl>
<dl markdown="block"><dt>ASSUMPTION_ENCRYPTION</dt><dd>Data at rest is encrypted using AES-256. </dd></dl>



### 1.2.6 Assets <a id='assets'></a>





#### 1.2.6.1 Summary Table <a id='summary-table'></a>


<table>
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
<tr><td>User Data<br/><code><strong>ASSET_USER_DATA</strong></code></td><td>data</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>API Service Key<br/><code><strong>API_KEY</strong></code></td><td>key</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>Database Credential<br/><code><strong>DB_CREDENTIAL</strong></code></td><td>credential</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>TLS Certificate<br/><code><strong>TLS_CERTIFICATE</strong></code></td><td>certificate</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>Complex Properties Asset<br/><code><strong>ASSET_COMPLEX_PROPS</strong></code></td><td>service</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>Internal Service Communication<br/><code><strong>DATAFLOW_INTERNAL</strong></code></td><td>dataflow</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>External API Communication<br/><code><strong>DATAFLOW_EXTERNAL_API</strong></code></td><td>dataflow</td><td>&#x274C;</td></tr>
</table>



#### 1.2.6.2 Details <a id='details'></a>


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
<div markdown="1" class='current'>
<a id="FullFeature.API_KEY"></a>
**API Service Key (key in scope - ID: <code>API_KEY</code>)**

<dl markdown="block">
Key used for authenticating API requests between services.
<dt markdown="block">Other properties</dt>
<dd markdown="block"><ul><li style='margin: 0px 0;'><b>type:</b> &nbsp;Ed25519</li><li style='margin: 0px 0;'><b>length:</b> &nbsp;256 bits</li><li style='margin: 0px 0;'><b>Key Usage:</b> &nbsp;Service-to-service authentication</li></ul></dd>
</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.DB_CREDENTIAL"></a>
**Database Credential (credential in scope - ID: <code>DB_CREDENTIAL</code>)**

<dl markdown="block">
Credentials for database access.
<dt markdown="block">Other properties</dt>
<dd markdown="block"><ul><li style='margin: 0px 0;'><b>rotation:</b> &nbsp;90 days</li><li style='margin: 0px 0;'><b>storage:</b> &nbsp;Vault</li></ul></dd>
</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.TLS_CERTIFICATE"></a>
**TLS Certificate (certificate in scope - ID: <code>TLS_CERTIFICATE</code>)**

<dl markdown="block">
Server TLS certificate for HTTPS.
<dt markdown="block">Other properties</dt>
<dd markdown="block"><ul><li style='margin: 0px 0;'><b>algorithm:</b> &nbsp;RSA-2048</li><li style='margin: 0px 0;'><b>issuer:</b> &nbsp;Internal CA</li><li style='margin: 0px 0;'><b>validity:</b> &nbsp;1 year</li></ul></dd>
</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.ASSET_COMPLEX_PROPS"></a>
**Complex Properties Asset (service in scope - ID: <code>ASSET_COMPLEX_PROPS</code>)**

<dl markdown="block">
Asset with array-style properties to test rendering edge cases.
<dt markdown="block">Other properties</dt>
<dd markdown="block"><ul></ul></dd>
</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.DATAFLOW_EXTERNAL_API"></a>
**External API Communication (dataflow not in scope - ID: <code>DATAFLOW_EXTERNAL_API</code>)**

<dl markdown="block">
Communication with third-party external API.
This is out of scope for this threat model.

</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.DATAFLOW_INTERNAL"></a>
**Internal Service Communication (dataflow in scope - ID: <code>DATAFLOW_INTERNAL</code>)**

<dl markdown="block">
Communication between internal microservices.
</dl>
</div>
<hr/>



## 1.3 Comprehensive Reference TM Attack tree <a id='comprehensive-reference-tm-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/FullFeature_ATTACKTREE.svg">
                     <img src="img/FullFeature_ATTACKTREE.svg" alt="$Comprehensive Reference TM attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



## 1.4 Comprehensive Reference TM Threats <a id='comprehensive-reference-tm-threats'></a>



> **Note** This section contains the threat and mitigations identified during the analysis phase.
<div markdown="1" class='current'>
<a id="THREAT_SQL_INJECTION"></a>



### 1.4.1 SQL Injection (<code>THREAT_SQL_INJECTION</code>) <a id='THREAT_SQL_INJECTION'></a>


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
<dt>Threat Status:</dt><dd markdown="block">Mitigated</dd>
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



#### 1.4.1.1 Counter-measures for THREAT_SQL_INJECTION   <div class='skipTOC'></div> <a id='counter-measures-for-threat_sql_injection'></a>


<dl markdown="block">
<strong> <code>CM_PREPARED_STATEMENTS</code> Use Prepared Statements</strong><br/>
<dt>Applies To Versions</dt><dd markdown="block">&gt;=5.1</dd>
<dd markdown="block">Ensure all DB queries use parameterized inputs.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
<div markdown="1" class='current'>
<a id="THREAT_DATA_LEAK"></a>



### 1.4.2 Potential Data Leak (<code>THREAT_DATA_LEAK</code>) <a id='THREAT_DATA_LEAK'></a>


<div style="text-align: center;">
<img src="img/threatTree/THREAT_DATA_LEAK.svg"/>
</div>
<dl markdown="block">
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#ASSET_USER_DATA">ASSET_USER_DATA</a></code> - User Data</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_INSIDER">ATT_INSIDER</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block">Data might leak through logs or error messages.</dd>
<dt>Impact</dt><dd markdown="block"><code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 6.5 (Medium) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code>
</dd>
</dl>



#### 1.4.2.1 Counter-measures for THREAT_DATA_LEAK   <div class='skipTOC'></div> <a id='counter-measures-for-threat_data_leak'></a>


<dl markdown="block">
<strong> <code>CM_LOG_MASKING</code> Log Masking</strong><br/>
<dd markdown="block">Mask PII in logs.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> &#10060;</dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
<hr/>
<div markdown="1" class='current'>
<a id="THREAT_KEY_COMPROMISE"></a>



### 1.4.3 API Key Compromise (<code>THREAT_KEY_COMPROMISE</code>) <a id='THREAT_KEY_COMPROMISE'></a>


<div style="text-align: center;">
<img src="img/threatTree/THREAT_KEY_COMPROMISE.svg"/>
</div>
<dl markdown="block">
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#API_KEY">API_KEY</a></code> - API Service Key</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Not Secure by Default <br/>(Operational mitigation)</dd>
<dt>Threat Description</dt><dd markdown="block">Attacker obtains API key through:
1. Source code repository exposure
2. Man-in-the-middle attack
3. Social engineering
</dd>
<dt>Impact</dt><dd markdown="block">Complete service impersonation<br/> <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code><br/> <code><a href="#OBJ_INTEGRITY">OBJ_INTEGRITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 10.0 (Critical) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N</code>
</dd>
</dl>



#### 1.4.3.1 Counter-measures for THREAT_KEY_COMPROMISE   <div class='skipTOC'></div> <a id='counter-measures-for-threat_key_compromise'></a>


<dl markdown="block">
<strong> <code>CM_KEY_ROTATION</code> Regular Key Rotation</strong><br/>
<dd markdown="block">Rotate API keys every 30 days or immediately upon suspected compromise.
Keys should be stored in a secure vault with audit logging.
</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by Security Operations Team)</dd>
<strong> <code>CM_KEY_VAULT</code> Secure Key Storage</strong><br/>
<dd markdown="block">Store keys in HashiCorp Vault with audit logging.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by Platform Team)</dd>
</dl>
</div>
<div class="pagebreak"></div>
<hr/>
<div markdown="1" class='current'>
<a id="THREAT_RCE"></a>



### 1.4.4 Remote Code Execution (<code>THREAT_RCE</code>) <a id='THREAT_RCE'></a>


<div style="text-align: center;">
<img src="img/threatTree/THREAT_RCE.svg"/>
</div>
<dl markdown="block">
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#ASSET_USER_DATA">ASSET_USER_DATA</a></code> - User Data</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Vulnerable</dd>
<dt>Threat Description</dt><dd markdown="block">Exploiting deserialization vulnerability to execute arbitrary code.
</dd>
<dt>Impact</dt><dd markdown="block">Full system compromise<br/> <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code><br/> <code><a href="#OBJ_INTEGRITY">OBJ_INTEGRITY</a></code><br/> <code><a href="#OBJ_AVAILABILITY">OBJ_AVAILABILITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 10.0 (Critical) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</code>
</dd>
</dl>



#### 1.4.4.1 Counter-measures for THREAT_RCE   <div class='skipTOC'></div> <a id='counter-measures-for-threat_rce'></a>


<dl markdown="block">
<strong> <code>CM_INPUT_VALIDATION</code> Strict Input Validation</strong><br/>
<dd markdown="block">Validate and sanitize all deserialized input.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> &#10060;</dd>
</dd>
</dl>
</div>
<div class="pagebreak"></div>
<hr/>
<div markdown="1" class='current'>
<a id="THREAT_INFO_DISCLOSURE"></a>



### 1.4.5 Minor Information Disclosure (<code>THREAT_INFO_DISCLOSURE</code>) <a id='THREAT_INFO_DISCLOSURE'></a>


<div style="text-align: center;">
<img src="img/threatTree/THREAT_INFO_DISCLOSURE.svg"/>
</div>
<dl markdown="block">
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Not Secure by Default <br/>(Operational mitigation)</dd>
<dt>Threat Description</dt><dd markdown="block">Version information exposed in HTTP headers.</dd>
<dt>Impact</dt><dd markdown="block">Low - only exposes version info<br/> <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 5.3 (Medium) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</code>
</dd>
</dl>



#### 1.4.5.1 Counter-measures for THREAT_INFO_DISCLOSURE   <div class='skipTOC'></div> <a id='counter-measures-for-threat_info_disclosure'></a>


<dl markdown="block">
<strong> <code>CM_HEADER_REMOVAL</code> Remove Version Headers</strong><br/>
<dd markdown="block">Configure server to not expose version information.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by DevOps Team)</dd>
</dl>
</div>
<div class="pagebreak"></div>
<div markdown="1">
**Release history**
- 1.0  2024-01-01: Initial version
- 1.1  2024-02-11: Added compliance and versioning features
- 1.2  2026-02-13: Enhanced with real-world patterns for comprehensive testing

</div>
</div>
<div markdown="block" class='current'>



## 1.5 Sub-Component Feature Test Threat Model Section <a id='SubComponent'></a>


Version: 1.1




### 1.5.1 Sub-Component Feature Test - scope of analysis <a id='sub-component-feature-test---scope-of-analysis'></a>





#### 1.5.1.1 Sub-Component Feature Test Overview <a id='sub-component-feature-test-overview'></a>


Scope for the sub-component service.
Tests cross-reference countermeasures and nested TM hierarchies.




#### 1.5.1.2 Assets <a id='assets'></a>





##### Summary Table <a id='summary-table'></a>


<table>
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
<tr><td>Sub Asset<br/><code><strong>SUB_ASSET</strong></code></td><td>service</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>Sub-Component Service Key<br/><code><strong>SUB_SERVICE_KEY</strong></code></td><td>key</td><td>&#x2714;&#xFE0F;</td></tr>
</table>



##### Details <a id='details'></a>


<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.SubComponent.SUB_ASSET"></a>
**Sub Asset (service in scope - ID: <code>SUB_ASSET</code>)**

<dl markdown="block">
Internal microservice handling data processing.
</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.SubComponent.SUB_SERVICE_KEY"></a>
**Sub-Component Service Key (key in scope - ID: <code>SUB_SERVICE_KEY</code>)**

<dl markdown="block">
Key for sub-component internal authentication.
<dt markdown="block">Other properties</dt>
<dd markdown="block"><ul><li style='margin: 0px 0;'><b>type:</b> &nbsp;HMAC-SHA256</li><li style='margin: 0px 0;'><b>length:</b> &nbsp;256 bits</li></ul></dd>
</dl>
</div>
<hr/>



### 1.5.2 Sub-Component Feature Test Attack tree <a id='sub-component-feature-test-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/SubComponent_ATTACKTREE.svg">
                     <img src="img/SubComponent_ATTACKTREE.svg" alt="$Sub-Component Feature Test attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



### 1.5.3 Sub-Component Feature Test Threats <a id='sub-component-feature-test-threats'></a>



> **Note** This section contains the threat and mitigations identified during the analysis phase.
<div markdown="1" class='current'>
<a id="SUB_THREAT_DOS"></a>



#### 1.5.3.1 Denial of Service on Sub Component (<code>SUB_THREAT_DOS</code>) <a id='SubComponent.SUB_THREAT_DOS'></a>


<div style="text-align: center;">
<img src="img/threatTree/SUB_THREAT_DOS.svg"/>
</div>
<dl markdown="block">
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#SubComponent.SUB_ASSET">SUB_ASSET</a></code> - Sub Asset</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Not Secure by Default <br/>(Operational mitigation)</dd>
<dt>Threat Description</dt><dd markdown="block">Overwhelming the sub-component with excessive requests,
causing service degradation or unavailability.
</dd>
<dt>Impact</dt><dd markdown="block">Sub component becomes unavailable affecting dependent services.<br/> <code><a href="#OBJ_AVAILABILITY">OBJ_AVAILABILITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 7.5 (High) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code>
</dd>
</dl>



##### Counter-measures for SUB_THREAT_DOS   <div class='skipTOC'></div> <a id='counter-measures-for-sub_threat_dos'></a>


<dl markdown="block">
<strong> <code>SUB_CM_RATE_LIMIT</code> Rate Limiting</strong><br/>
<dd markdown="block">Limit requests to the sub component to 1000 req/sec.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by Platform Team)</dd>
</dl>
</div>
<div class="pagebreak"></div>
<div markdown="1" class='current'>
<a id="SUB_THREAT_KEY_LEAK"></a>



#### 1.5.3.2 Sub-Component Key Exposure (<code>SUB_THREAT_KEY_LEAK</code>) <a id='SubComponent.SUB_THREAT_KEY_LEAK'></a>


<div style="text-align: center;">
<img src="img/threatTree/SUB_THREAT_KEY_LEAK.svg"/>
</div>
<dl markdown="block">
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#SubComponent.SUB_SERVICE_KEY">SUB_SERVICE_KEY</a></code> - Sub-Component Service Key</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_INSIDER">ATT_INSIDER</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Not Secure by Default <br/>(Operational mitigation)</dd>
<dt>Threat Description</dt><dd markdown="block">API key for sub-component exposed through misconfiguration.</dd>
<dt>Impact</dt><dd markdown="block">Unauthorized access to sub-component services.<br/> <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 8.1 (High) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N</code>
</dd>
</dl>



##### Counter-measures for SUB_THREAT_KEY_LEAK   <div class='skipTOC'></div> <a id='counter-measures-for-sub_threat_key_leak'></a>


<dl markdown="block">
<strong>Reference to <code>FullFeature.SubComponent.SUB_THREAT_DOS.SUB_CM_RATE_LIMIT</code> Rate Limiting</strong><br/>
<dd markdown="block">Limit requests to the sub component to 1000 req/sec.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by Platform Team)</dd>
<strong> <code>SUB_CM_KEY_AUDIT</code> Key Access Auditing</strong><br/>
<dd markdown="block">Log and monitor all key access attempts.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by Security Operations Team)</dd>
</dl>
</div>
<div class="pagebreak"></div>
</div>
<div markdown="block" class='current'>



## 1.6 API Gateway Security Model Threat Model Section <a id='ApiGateway'></a>


Version: 1.0




### 1.6.1 API Gateway Security Model - scope of analysis <a id='api-gateway-security-model---scope-of-analysis'></a>





#### 1.6.1.1 API Gateway Security Model Overview <a id='api-gateway-security-model-overview'></a>


Security analysis for the API Gateway component.
The gateway handles authentication, rate limiting, and routing.




#### 1.6.1.2 Assets <a id='assets'></a>





##### Summary Table <a id='summary-table'></a>


<table>
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
<tr><td>Gateway TLS Certificate<br/><code><strong>GW_TLS_CERT</strong></code></td><td>certificate</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>JWT Signing Secret<br/><code><strong>GW_JWT_SECRET</strong></code></td><td>secret</td><td>&#x2714;&#xFE0F;</td></tr>
<tr><td>Legacy API Passthrough<br/><code><strong>GW_LEGACY_API</strong></code></td><td>dataflow</td><td>&#x274C;</td></tr>
</table>



##### Details <a id='details'></a>


<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.ApiGateway.GW_TLS_CERT"></a>
**Gateway TLS Certificate (certificate in scope - ID: <code>GW_TLS_CERT</code>)**

<dl markdown="block">
TLS certificate for API Gateway HTTPS termination.
<dt markdown="block">Other properties</dt>
<dd markdown="block"><ul><li style='margin: 0px 0;'><b>algorithm:</b> &nbsp;ECDSA P-256</li><li style='margin: 0px 0;'><b>issuer:</b> &nbsp;Public CA</li><li style='margin: 0px 0;'><b>validity:</b> &nbsp;90 days</li></ul></dd>
</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.ApiGateway.GW_JWT_SECRET"></a>
**JWT Signing Secret (secret in scope - ID: <code>GW_JWT_SECRET</code>)**

<dl markdown="block">
Secret key used to sign and verify JWT tokens.
</dl>
</div>
<hr/>
<div markdown="1" class='current'>
<a id="FullFeature.ApiGateway.GW_LEGACY_API"></a>
**Legacy API Passthrough (dataflow not in scope - ID: <code>GW_LEGACY_API</code>)**

<dl markdown="block">
Traffic passthrough to legacy system without inspection.
Out of scope as legacy system has separate threat model.

</dl>
</div>
<hr/>



### 1.6.2 API Gateway Security Model Attack tree <a id='api-gateway-security-model-attack-tree'></a>


<object type="image/svg+xml" style="width:100%; height:auto;" data="img/ApiGateway_ATTACKTREE.svg">
                     <img src="img/ApiGateway_ATTACKTREE.svg" alt="$API Gateway Security Model attack tree" style="width:600; height:auto;" />
                     </object>
<img src="img/legend_AttackTree.svg" width="600"/>
<div class="pagebreak"></div>
<hr/>



### 1.6.3 API Gateway Security Model Threats <a id='api-gateway-security-model-threats'></a>



> **Note** This section contains the threat and mitigations identified during the analysis phase.
<div markdown="1" class='current'>
<a id="GW_JWT_FORGERY"></a>



#### 1.6.3.1 JWT Token Forgery (<code>GW_JWT_FORGERY</code>) <a id='ApiGateway.GW_JWT_FORGERY'></a>


<div style="text-align: center;">
<img src="img/threatTree/GW_JWT_FORGERY.svg"/>
</div>
<dl markdown="block">
<dt>Assets (IDs) involved in this threat:</dt>
<dd markdown="block"> - <code><a href="#ApiGateway.GW_JWT_SECRET">GW_JWT_SECRET</a></code> - JWT Signing Secret</dd>
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Not Secure by Default <br/>(Operational mitigation)</dd>
<dt>Threat Description</dt><dd markdown="block">Attacker forges JWT token by:
1. Exploiting weak algorithm (alg:none)
2. Brute-forcing weak secret
3. Key confusion attack (RS/HS)
</dd>
<dt>Impact</dt><dd markdown="block">Complete authentication bypass<br/> <code><a href="#OBJ_CONFIDENTIALITY">OBJ_CONFIDENTIALITY</a></code><br/> <code><a href="#OBJ_INTEGRITY">OBJ_INTEGRITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 9.1 (Critical) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</code>
</dd>
</dl>



##### Counter-measures for GW_JWT_FORGERY   <div class='skipTOC'></div> <a id='counter-measures-for-gw_jwt_forgery'></a>


<dl markdown="block">
<strong> <code>GW_CM_ALG_WHITELIST</code> Algorithm Whitelist</strong><br/>
<dd markdown="block">Only allow RS256 algorithm, reject 'none' and HS*.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
</dd>
<strong> <code>GW_CM_STRONG_SECRET</code> Strong JWT Secret</strong><br/>
<dd markdown="block">Use cryptographically strong random secret (256+ bits).</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by Security Operations Team)</dd>
</dl>
</div>
<div class="pagebreak"></div>
<div markdown="1" class='current'>
<a id="GW_RATE_LIMIT_BYPASS"></a>



#### 1.6.3.2 Rate Limit Bypass (<code>GW_RATE_LIMIT_BYPASS</code>) <a id='ApiGateway.GW_RATE_LIMIT_BYPASS'></a>


<div style="text-align: center;">
<img src="img/threatTree/GW_RATE_LIMIT_BYPASS.svg"/>
</div>
<dl markdown="block">
<dt>Threat actors:</dt>
<dd markdown="block"> - <code><a href="#ATT_EXTERNAL">ATT_EXTERNAL</a></code></dd>
<dt>Threat Status:</dt><dd markdown="block">Not Secure by Default <br/>(Operational mitigation)</dd>
<dt>Threat Description</dt><dd markdown="block">Bypassing rate limits through distributed requests or header manipulation.</dd>
<dt>Impact</dt><dd markdown="block">Service degradation through resource exhaustion<br/> <code><a href="#OBJ_AVAILABILITY">OBJ_AVAILABILITY</a></code><br/> </dd>
<dt>CVSS</dt>
<dd>
<strong>Base score:</strong> 5.9 (Medium) <br/>
<strong>Vector:</strong><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code>
</dd>
</dl>



##### Counter-measures for GW_RATE_LIMIT_BYPASS   <div class='skipTOC'></div> <a id='counter-measures-for-gw_rate_limit_bypass'></a>


<dl markdown="block">
<strong>Reference to <code>FullFeature.ApiGateway.GW_JWT_FORGERY.GW_CM_ALG_WHITELIST</code> Algorithm Whitelist</strong><br/>
<dd markdown="block">Only allow RS256 algorithm, reject 'none' and HS*.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
</dd>
<strong> <code>GW_CM_IP_FINGERPRINT</code> Client IP Fingerprinting</strong><br/>
<dd markdown="block">Use multiple headers and techniques to identify true client IP.</dd>
<dd markdown="block"><strong>Countermeasure in place?</strong> <span style="color:green;">&#10004;</span></dd>
 <strong>Is operational?</strong><span style="color:green;">&#10004;</span> (operated by DevOps Team)</dd>
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
<tr markdown="block"><td>1</td><td markdown="block">**Title (ID):** Remove Version Headers (`CM_HEADER_REMOVAL`)<br/>
**Mitigates:** <a href="#THREAT_INFO_DISCLOSURE">Minor Information Disclosure</a> (`THREAT_INFO_DISCLOSURE`)<br/>
**Description:**

<br/>Configure server to not expose version information.
<br/>**Operated by:** DevOps Team</td></tr>
<tr markdown="block"><td>2</td><td markdown="block">**Title (ID):** Regular Key Rotation (`CM_KEY_ROTATION`)<br/>
**Mitigates:** <a href="#THREAT_KEY_COMPROMISE">API Key Compromise</a> (`THREAT_KEY_COMPROMISE`)<br/>
**Description:**

<br/>Rotate API keys every 30 days or immediately upon suspected compromise.
Keys should be stored in a secure vault with audit logging.

<br/>**Operated by:** Security Operations Team</td></tr>
<tr markdown="block"><td>3</td><td markdown="block">**Title (ID):** Secure Key Storage (`CM_KEY_VAULT`)<br/>
**Mitigates:** <a href="#THREAT_KEY_COMPROMISE">API Key Compromise</a> (`THREAT_KEY_COMPROMISE`)<br/>
**Description:**

<br/>Store keys in HashiCorp Vault with audit logging.
<br/>**Operated by:** Platform Team</td></tr>
<tr markdown="block"><td>4</td><td markdown="block">**Title (ID):** Client IP Fingerprinting (`GW_CM_IP_FINGERPRINT`)<br/>
**Mitigates:** <a href="#ApiGateway.GW_RATE_LIMIT_BYPASS">Rate Limit Bypass</a> (`GW_RATE_LIMIT_BYPASS`)<br/>
**Description:**

<br/>Use multiple headers and techniques to identify true client IP.
<br/>**Operated by:** DevOps Team</td></tr>
<tr markdown="block"><td>5</td><td markdown="block">**Title (ID):** Strong JWT Secret (`GW_CM_STRONG_SECRET`)<br/>
**Mitigates:** <a href="#ApiGateway.GW_JWT_FORGERY">JWT Token Forgery</a> (`GW_JWT_FORGERY`)<br/>
**Description:**

<br/>Use cryptographically strong random secret (256+ bits).
<br/>**Operated by:** Security Operations Team</td></tr>
<tr markdown="block"><td>6</td><td markdown="block">**Title (ID):** Key Access Auditing (`SUB_CM_KEY_AUDIT`)<br/>
**Mitigates:** <a href="#SubComponent.SUB_THREAT_KEY_LEAK">Sub-Component Key Exposure</a> (`SUB_THREAT_KEY_LEAK`)<br/>
**Description:**

<br/>Log and monitor all key access attempts.
<br/>**Operated by:** Security Operations Team</td></tr>
<tr markdown="block"><td>7</td><td markdown="block">**Title (ID):** Rate Limiting (`SUB_CM_RATE_LIMIT`)<br/>
**Mitigates:** <a href="#SubComponent.SUB_THREAT_DOS">Denial of Service on Sub Component</a> (`SUB_THREAT_DOS`)<br/>
**Description:**

<br/>Limit requests to the sub component to 1000 req/sec.
<br/>**Operated by:** Platform Team</td></tr>
</tbody></table>
<div class="pagebreak"></div>



## 1.9 Testing guide   <div class='skipTOC'></div> <a id='testing-guide'></a>



This guide lists all testable attacks described in the threat model

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Seq</th><th>Attack to test</th><th>Pass/Fail/NA</th></tr>
</table>
<div class="pagebreak"></div>



## 1.10 Keys classification <a id='keys-classification'></a>





### 1.10.1 Application-specific keys <a id='application-specific-keys'></a>


Keys issued to processes to communicate in a secure manner, not linked to a specific business logic
<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>
  <tr><td><strong><a href="#FullFeature.API_KEY">API Service Key</a></strong></td><td><b>Ed25519</b><br/>Key used for authenticating API requests between services.</td><td><ul><li style='margin: 0px 0;'><b>type:</b> &nbsp;Ed25519</li><li style='margin: 0px 0;'><b>length:</b> &nbsp;256 bits</li><li style='margin: 0px 0;'><b>Key Usage:</b> &nbsp;Service-to-service authentication</li></ul></td></tr>
  <tr><td><strong><a href="#FullFeature.SubComponent.SUB_SERVICE_KEY">Sub-Component Service Key</a></strong></td><td><b>HMAC-SHA256</b><br/>Key for sub-component internal authentication.</td><td><ul><li style='margin: 0px 0;'><b>type:</b> &nbsp;HMAC-SHA256</li><li style='margin: 0px 0;'><b>length:</b> &nbsp;256 bits</li></ul></td></tr>
</table>



### 1.10.2 Infrastructure Keys and PKI assets <a id='infrastructure-keys-and-pki-assets'></a>


<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>
  <tr><td><strong><a href="#FullFeature.TLS_CERTIFICATE">TLS Certificate</a></strong></td><td><b>certificate</b><br/>Server TLS certificate for HTTPS.</td><td><ul><li style='margin: 0px 0;'><b>algorithm:</b> &nbsp;RSA-2048</li><li style='margin: 0px 0;'><b>issuer:</b> &nbsp;Internal CA</li><li style='margin: 0px 0;'><b>validity:</b> &nbsp;1 year</li></ul></td></tr>
  <tr><td><strong><a href="#FullFeature.ApiGateway.GW_TLS_CERT">Gateway TLS Certificate</a></strong></td><td><b>certificate</b><br/>TLS certificate for API Gateway HTTPS termination.</td><td><ul><li style='margin: 0px 0;'><b>algorithm:</b> &nbsp;ECDSA P-256</li><li style='margin: 0px 0;'><b>issuer:</b> &nbsp;Public CA</li><li style='margin: 0px 0;'><b>validity:</b> &nbsp;90 days</li></ul></td></tr>
</table>



### 1.10.3 Credentials <a id='credentials'></a>


<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>
  <tr><td><strong><a href="#FullFeature.DB_CREDENTIAL">Database Credential</a></strong></td><td><b>credential</b><br/>Credentials for database access.</td><td><ul><li style='margin: 0px 0;'><b>rotation:</b> &nbsp;90 days</li><li style='margin: 0px 0;'><b>storage:</b> &nbsp;Vault</li></ul></td></tr>
  <tr><td><strong><a href="#FullFeature.ApiGateway.GW_JWT_SECRET">JWT Signing Secret</a></strong></td><td><b>secret</b><br/>Secret key used to sign and verify JWT tokens.</td><td></td></tr>
</table>
<div class="pagebreak"></div>



## 1.11 ISO27001 Summary <a id='iso27001-summary'></a>



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
