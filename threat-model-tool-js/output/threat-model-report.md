# Abstract Example Threat Model 2

**ID:** Example2

**Version:** 1

**Authors:** Example Author 2


**Schema Version:** 2

---

## Scope

Minimal abstract threat model for testing report generation.


### Security Objectives

#### SYSTEM_CONFIDENTIALITY: System Confidentiality

Prevent unauthorized disclosure of data.


**Group:** Data Security

#### SYSTEM_INTEGRITY: System Integrity

Prevent unauthorized modification of data or behavior.


**Group:** System Integrity

---

## Analysis

This abstract model is intended for testing the renderer and report pipeline.


---

## Threats

### DATA_EXPOSURE: Unauthorized Data Exposure

**Type:** Information Disclosure

**CVSS Score:** 7.5 (High)

**Attack:**

An attacker accesses sensitive data through a misconfigured access control.


**Impact:**

Sensitive data is disclosed to unauthorized parties.


**Impacted Security Objectives:**
- SYSTEM_CONFIDENTIALITY

**Attackers:**
- EXTERNAL_ATTACKER

**Countermeasures:**

- **ACCESS_CONTROL_ENFORCEMENT:** Enforce Access Control (Not In Place)
  Require authentication and authorization checks on all data access paths.


**Fully Mitigated:** No

---

### DATA_TAMPERING: Unauthorized Data Modification

**Type:** Tampering

**CVSS Score:** 7.5 (High)

**Attack:**

An attacker modifies stored data using an unprotected endpoint.


**Impact:**

Data integrity is compromised and trusted records are altered.


**Impacted Security Objectives:**
- SYSTEM_INTEGRITY

**Attackers:**
- EXTERNAL_ATTACKER

**Countermeasures:**

- **INPUT_VALIDATION:** Validate and Authorize Updates (In Place)
  Validate inputs and enforce authorization on update operations.


**Fully Mitigated:** No

---

