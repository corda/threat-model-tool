The following preamble describes some elements of a language called Metaphor.  Please pay
extremely close attention to the details as they will affect the way you interpret
everything that follows after "BEGIN DESCRIPTION IN METAPHOR:"

Metaphor has the structure of a document tree with branches and leaves being prefixed
by the keywords "Role:", "Context:" or "Action:".  Each of these indicates the
start of a new block of information.

Blocks have an optional section name that will immediately follow them on the same line.
If this is missing then the section name is not defined.

After a keyword line there may be one or more lines of text that will describe the purpose
of that block.  A block may also include one or more optional child blocks inside them and
that further clarify their parent block.  These text blocks and any keywords lines nested
inside a parent block will be indented by 4 spaces more than its parent.

For example a "Context:" indented by 8 spaces is a child of the block above it that is
indented by 4 spaces.  One indented 12 spaces would be a child of the block above it that is
indented by 8 spaces.

Within the text of a block, you may be presented with code or document fragments inside a
block delimited by 3 backticks.  Please pay close attention to the indentation level of the
opening 3 backticks.  The identation of such code or document fragments is relative to this,
not relative to the block in which the code or document fragment occurs.
For example, consider:
    ```plaintext
    text line 1
      text line 2
    ```
        ```plaintext
         text line 3
        ```
In this example, "text line 1" is not indented from the opening 3 backticks and thus has no
indentation.  "text line 2" is indented by 2 spaces relative to the opening 3 backticks
 "text line 3" is indented by 1 space relative to its opening 3 backticks.

If "Role:" blocks exists then these contain details about the role you should fulfil.  This
section may also describe specific skills you have, knowledge you should apply, and the
approach you take to apply these.
"Context:" blocks provide context necessary to understand what you will be asked to do.

"Action:" blocks describes the task, or tasks, I would like you to do.

When you process the actions please carefully ensure you do all of them accurately and
complete all the elements requested.  Unless otherwise instructed, do not include any
placeholders in your responses.

BEGIN DESCRIPTION IN METAPHOR:
Role: AppSec
    You are an applicatino security expert in Secure software development lifecycle.
Context: threat modeling and its terminilogy
    Threat models reasoning answer 4 main questions:
    - What is being building? It defines the scope
    - What can go wrong? it defines the threats aka attacks etc.
    - What is being doing about it? defines the mitigations aka countermeaures aka controls
    - Are we doing a good job?
    Terminology:
    Focusing on the semantics
    One way to overcome "the terminology catastrophe" is to ignore it mostly while focusing on few 
    cardinal concepts, like answering the fundamental 4 questions we are striving for. 
    Wether we call something 'risk', 'bug', 'vulnerability', 'threat', 'attack' we consider all
     those terms (and subjectively associated meanings) in the realm of "Something that can go wrong".
      Wether we call something 'countermeasure', 'mitigation', 'control' we consider the fact that that 
      is in the realm on "something we do about something that can go wrong". In the next chapter we'll 
      balance the need to have formal definition with that of having effective communication structuring 
      our threat model data and facts using few high level concepts.
    Context: threat model tool
        This tool is used to:
            - Structure the data (roles/attackers, security objectives, asset in scope, threat, countermeasures/mitigations)
            - It uses templates to generate reports from the data.
            - It assists in exploiting SDL (secure development lifecycle) synergies (operational hardening guidelines, testing checklist, extract crypto key catalog)
            - It assist in the process of RFI (request for information ti engineering teams)
            - Export ticket list for tracking tools (e.g. Jira)
    Context: Threat Model high level data structure
        What are we building? defines -> assets and, actors aka roles aka attackers
        What can go wrong? -> defines threat, attack, impact
        What are we doing about it? defines -> mitigations aka controls aka countermeasures
        In the reporting tool we use those high level concepts to structure the data 
        and generate highly consistent reports. This consistency of few high level concept 
        is not used only to generate those reports but also to leverage synergies in different phases 
        of the secure development lifecycle; for example a specific 
        'Dynamic test/DAST' may be associated with a countermeasure or a threat.
        YAML high elvel structures
            - Scope assets
            - Attackers (and roles en general)
            - Security objective
            - Threat and their countermeasures
        The minimal data structure we want to define is a set of threat and their mitigation; this answers
        the question: what can go wrong? and what we do about it?
        the `ID:` of the threat should sound (recall) something that can go wrong; for example: 
        - ID: REQUEST_REPUDIATION 
        - ID: SQL_INJECTION1
        - ID: BACKEND_SERVICE_SPOOFING
        There is no 'description' for threat rather a semantic couple that represents the 'description'
        'attack:' and 'impactDesc:' fields. Attack describes hot to exploit and impactDesc describe the impact of the realization of the potential threat.
        'impactedSecObj' may replace impactDesc that is optional; both impactedSecObj and impactDesc may be present if
        impactDesc give useful information on top of impactedSecObj.
    Context: Threat model Tool
        This threat model tool assist in structuring the treat model stricture into yaml to then create reports and query threat model data.
    Context: Exmple yaml Files
        File: /Users/auser/workspace/personal/threat-models/threatModels/Kubernetes/Secrets/Secrets.yaml
        ```yaml
        ID: Secrets
        title: Secrets 
        version: 1.0
        authors: |
          David Cervigni
        parent: Kubernetes
        scope:
          description: |
            
            
            **NOTE:** this is an example if threat model created with by training an LLM
        
        
            This document extends the Kubernetes security model to focus on threats specific to the handling,
             storage, and access of Kubernetes secrets. It includes detailed threats and mitigations to
              ensure the confidentiality, integrity, and secure management of secrets.
             
          securityObjectives:
            - ID: SECRET_CONFIDENTIALITY
              title: Secrets Confidentiality
              description: |
                Ensure Kubernetes secrets are protected from unauthorized access both in transit and at rest.
              group: Data Security
        
            - ID: SECRET_INTEGRITY
              title: Secrets Integrity
              description: |
                Prevent unauthorized modification of Kubernetes secrets to maintain their integrity.
              group: System Integrity
        
            - ID: ACCESS_CONTROL
              title: Access Control for Secrets
              description: |
                Restrict access to secrets based on the principle of least privilege.
              group: Access Management
        
            - ID: AUDITABILITY
              title: Secrets Auditability
              description: |
                Ensure all access to and modifications of secrets are auditable and logged for accountability.
              group: Monitoring and Audit
        
          assumptions:
            - ID: CLUSTER_EXPOSURE
              description: |
                The Kubernetes cluster may be exposed to external networks, increasing the risk of unauthorized access.
            - ID: NODE_COMPROMISE
              description: |
                Individual cluster nodes or workloads may be compromised by attackers, potentially exposing stored secrets.
        
          attackers:
            - ID: MALICIOUS_USER
              description: |
                Authorized users who attempt to misuse their access to secrets for malicious purposes.
              inScope: true
            - ID: EXTERNAL_ATTACKER
              description: |
                Unauthorized external entities attempting to access secrets through exposed APIs or workloads.
              inScope: true
            - ID: COMPROMISED_WORKLOAD
              description: |
                A compromised container or workload attempting to read or modify secrets it has access to.
              inScope: true
        
        analysis: |
          While encryption of secrets at rest provides a layer of defense, it is not a
                complete solution since an attacker who gains access to etcd or the API server can often retrieve
                 secrets at runtime.
        threats:
          - ID: UNAUTHORIZED_SECRET_ACCESS
            title: Unauthorized Access to Secrets
            threatType: Information Disclosure
            impactDesc: |
              Exposure of sensitive information, such as credentials or API keys, stored as Kubernetes secrets.
            attack: |
              Attackers exploit overly permissive access controls or stolen credentials to access secrets.
            impactedSecObj:
              - REFID: SECRET_CONFIDENTIALITY
            attackers:
              - REFID: EXTERNAL_ATTACKER
              - REFID: MALICIOUS_USER
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: RBAC_FOR_SECRETS
                title: Enforce RBAC for Secrets
                description: |
                  Apply strict Role-Based Access Control (RBAC) policies to ensure only authorized entities can access specific secrets.
                inPlace: true
                public: true
          - ID: SECRET_INJECTION
            title: Secret Injection or Tampering
            threatType: Tampering
            impactDesc: |
              Modification of secrets to introduce malicious values, potentially compromising applications relying on them.
            attack: |
              A malicious user or workload tampers with secrets through improperly secured API access.
            impactedSecObj:
              - REFID: SECRET_INTEGRITY
            attackers:
              - REFID: MALICIOUS_USER
              - REFID: COMPROMISED_WORKLOAD
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: AUDIT_SECRET_ACCESS
                title: Audit Secret Access and Modifications
                description: |
                  Enable audit logs for all API interactions with secrets to detect and investigate unauthorized modifications.
                inPlace: true
                public: true
          - ID: NODE_STORAGE_EXPOSURE
            title: Secrets Exposure on Compromised Nodes
            threatType: Information Disclosure
            impactDesc: |
              Secrets stored on a compromised node are exposed, potentially leading to cluster-wide compromise.
            attack: |
              Attackers extract secrets directly from node storage or memory, bypassing API server protections.
            impactedSecObj:
              - REFID: SECRET_CONFIDENTIALITY
            attackers:
              - REFID: EXTERNAL_ATTACKER
              - REFID: COMPROMISED_WORKLOAD
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: ENCRYPT_SECRETS_AT_REST
                title: Encrypt Secrets at Rest
                description: |
                  Use Kubernetes encryption providers to ensure secrets stored on disk are encrypted with strong encryption standards. Note that encryption at rest does not mitigate runtime access vulnerabilities; additional runtime protections are needed.
                inPlace: true
                public: true
          - ID: SECRETS_IN_TRANSIT
            title: Secrets Intercepted in Transit
            threatType: Information Disclosure
            impactDesc: |
              Secrets transmitted over the network are intercepted, leading to potential exposure of sensitive data.
            attack: |
              Attackers intercept API server or etcd communication to extract secrets during transmission.
            impactedSecObj:
              - REFID: SECRET_CONFIDENTIALITY
            attackers:
              - REFID: EXTERNAL_ATTACKER
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: ENCRYPT_SECRETS_IN_TRANSIT
                title: Encrypt Secrets in Transit
                description: |
                  Enforce TLS encryption for all communications involving secrets, including API server and etcd interactions.
                inPlace: true
                public: true
          - ID: EXCESSIVE_SECRET_ACCESS
            title: Excessive Permissions for Secrets
            threatType: Elevation of Privilege
            impactDesc: |
              Unauthorized access or misuse of secrets due to overly broad permissions granted to workloads or users.
            attack: |
              Attackers leverage misconfigured RBAC policies or service account bindings to access secrets beyond their intended scope.
            impactedSecObj:
              - REFID: ACCESS_CONTROL
            attackers:
              - REFID: MALICIOUS_USER
              - REFID: COMPROMISED_WORKLOAD
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: LEAST_PRIVILEGE_ACCESS
                title: Enforce Least Privilege Access
                description: |
                  Audit and enforce least privilege access to secrets, ensuring users and workloads have access only to what they require.
                inPlace: false
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/Kubernetes/Kubernetes.yaml
        ```yaml
        ID: Kubernetes
        title: Kubernetes
        version: 1.0
        
        children:
          - ID: Secrets
        
        authors: |
          David Cervigni
        scope:
          description: |
            **NOTE:** this is an example of threat model created by training an LLM
        
            This document outlines potential threats to Kubernetes, including its core components, workloads, and supporting infrastructure. It addresses threats to the API server, worker nodes, and the control plane, providing mitigations to secure the cluster.
          securityObjectives:
            - ID: API_SERVER_SECURITY
              title: API Server Security
              description: |
                Ensure the Kubernetes API server is secure, preventing unauthorized access and ensuring proper authentication and authorization.
              group: Access Control
        
            - ID: NODE_ISOLATION
              title: Node Isolation
              description: |
                Maintain isolation between workloads running on the same or different nodes, ensuring one compromised workload cannot affect others.
              group: Workload Isolation
        
            - ID: DATA_CONFIDENTIALITY
              title: Data Confidentiality
              description: |
                Ensure that sensitive data, such as secrets and configuration files, is protected in transit and at rest.
              group: Data Security
        
            - ID: RUNTIME_SECURITY
              title: Runtime Security
              description: |
                Protect the runtime environment to prevent unauthorized actions or access by compromised containers.
              group: Runtime Protection
        
            - ID: SUPPLY_CHAIN_SECURITY
              title: Supply Chain Security
              description: |
                Ensure that the Kubernetes environment and its components are free from malicious or compromised images, configurations, or code.
              group: Supply Chain Protection
        
          assumptions:
            - ID: PUBLIC_CLUSTER_ACCESS
              description: |
                Kubernetes clusters may be exposed to public networks, increasing the risk of external attacks.
            - ID: COMPROMISED_WORKLOAD
              description: |
                A single workload may become compromised due to application-level vulnerabilities or malicious actors.
        
          attackers:
            - ID: EXTERNAL_ACTORS
              description: |
                Unauthenticated or unauthorized users attempting to exploit exposed APIs or services.
              inScope: true
            - ID: MALICIOUS_WORKLOAD
              description: |
                A compromised container or workload attempting to exploit cluster resources or affect other workloads.
              inScope: true
            - ID: SUPPLY_CHAIN_ATTACKERS
              description: |
                Attackers introducing vulnerabilities or malicious code into container images, Helm charts, or infrastructure configurations.
              inScope: true
        
        analysis:
        
        threats:
          - ID: UNAUTHORIZED_API_ACCESS
            title: Unauthorized API Access
            threatType: Elevation of Privilege
            impactDesc: |
              Unauthorized users gain access to the Kubernetes API server, enabling them to perform privileged operations on the cluster.
            attack: |
              Attackers exploit weak authentication mechanisms, API server misconfigurations, or exposed endpoints to access the Kubernetes API server.
            impactedSecObj:
              - REFID: API_SERVER_SECURITY
            attackers:
              - REFID: EXTERNAL_ACTORS
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: RBAC_ENFORCEMENT
                title: Enforce RBAC Policies
                description: |
                  Use Role-Based Access Control (RBAC) to limit access to Kubernetes resources based on user roles.
                inPlace: true
                public: true
          - ID: NODE_ESCALATION
            title: Node-Level Escalation
            threatType: Elevation of Privilege
            impactDesc: |
              A compromised workload escapes its container and gains access to the underlying node, potentially affecting other workloads.
            attack: |
              Attackers exploit container runtime vulnerabilities or misconfigured pod security policies to escape container boundaries.
            impactedSecObj:
              - REFID: NODE_ISOLATION
            attackers:
              - REFID: MALICIOUS_WORKLOAD
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: POD_SECURITY_POLICIES
                title: Apply Pod Security Policies
                description: |
                  Use Pod Security Policies (PSPs) or Pod Security Admission (PSA) to restrict workload capabilities and enforce best practices.
                inPlace: true
                public: true
          - ID: DATA_LEAKAGE
            title: Sensitive Data Leakage
            threatType: Information Disclosure
            impactDesc: |
              Exposure of sensitive information such as Kubernetes secrets, configuration files, or environment variables.
            attack: |
              Attackers gain access to improperly secured secrets or intercept data in transit due to missing encryption.
            impactedSecObj:
              - REFID: DATA_CONFIDENTIALITY
            attackers:
              - REFID: MALICIOUS_WORKLOAD
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: ENCRYPT_SECRETS
                title: Encrypt Secrets and Data
                description: |
                  Enable encryption at rest for Kubernetes secrets and enforce HTTPS for communication between cluster components.
                inPlace: true
                public: true
          - ID: RUNTIME_COMPROMISE
            title: Compromise of Runtime Environment
            threatType: Tampering
            impactDesc: |
              Attackers modify or tamper with running containers to execute unauthorized actions or escalate privileges.
            attack: |
              Attackers exploit misconfigured containers, runtime vulnerabilities, or privileged container permissions.
            impactedSecObj:
              - REFID: RUNTIME_SECURITY
            attackers:
              - REFID: MALICIOUS_WORKLOAD
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: RUNTIME_MONITORING
                title: Monitor Runtime Behavior
                description: |
                  Use runtime security tools to detect and block unauthorized actions within running containers.
                inPlace: false
                public: true
          - ID: SUPPLY_CHAIN_COMPROMISE
            title: Supply Chain Attack
            threatType: Spoofing
            impactDesc: |
              Malicious or vulnerable images, Helm charts, or configurations are introduced into the Kubernetes environment.
            attack: |
              Attackers inject vulnerabilities or malicious code into container images, third-party Helm charts, or infrastructure-as-code templates.
            impactedSecObj:
              - REFID: SUPPLY_CHAIN_SECURITY
            attackers:
              - REFID: SUPPLY_CHAIN_ATTACKERS
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: IMAGE_SCANNING
                title: Scan Container Images
                description: |
                  Use automated tools to scan container images for vulnerabilities or malicious code before deployment.
                inPlace: true
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/IntelSGX/IntelSGX.yaml
        ```yaml
        ID: IntelSGX
        title: Intel SGX
        authors: |
          David Cervigni
        version: 1.0
        scope:
          description: |
            **NOTE:** this is an example of threat model created by training an LLM
        
            This document outlines potential threats to Intel SGX (Software Guard Extensions), focusing on threats to enclave integrity, confidentiality, and availability. It includes countermeasures to mitigate these threats.
          securityObjectives:
            - ID: ENCLAVE_CONFIDENTIALITY
              title: Enclave Confidentiality
              description: |
                Ensure the confidentiality of data and code within SGX enclaves, protecting them from unauthorized access.
              group: Data Security
        
            - ID: ENCLAVE_INTEGRITY
              title: Enclave Integrity
              description: |
                Ensure the integrity of the data and execution within SGX enclaves, preventing unauthorized modifications.
              group: System Integrity
        
            - ID: PLATFORM_TRUST
              title: Platform Trust
              description: |
                Maintain trust in the hardware root of trust and the integrity of SGX attestation mechanisms.
              group: Trust Assurance
        
          assumptions:
            - ID: PRIVILEGED_ATTACKER
              description: |
                Attackers may have elevated privileges (e.g., OS-level or hypervisor control).
            - ID: SIDE_CHANNEL_RISK
              description: |
                Side-channel attacks are a known class of threats, exploiting physical or timing-based information.
        
          attackers:
            - ID: MALICIOUS_OS
              description: |
                A malicious or compromised operating system attempting to subvert the SGX enclaves.
              inScope: true
            - ID: HARDWARE_ATTACKERS
              description: |
                Attackers targeting the hardware or firmware to bypass SGX protections.
              inScope: true
            - ID: SIDE_CHANNEL_ACTORS
              description: |
                Attackers exploiting side channels to infer sensitive information from SGX enclaves.
              inScope: true
        
        analysis:
        
        threats:
          - ID: ENCLAVE_SIDE_CHANNEL
            title: Side-Channel Attacks
            threatType: Information Disclosure
            impactDesc: |
              Leakage of sensitive information through side-channel analysis, such as cache timing or power consumption.
            attack: |
              Attackers monitor cache timing, memory access patterns, or power consumption during enclave execution to infer sensitive information, such as cryptographic keys.
            impactedSecObj:
              - REFID: ENCLAVE_CONFIDENTIALITY
            attackers:
              - REFID: SIDE_CHANNEL_ACTORS
            CVSS:
              vector: 'CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: CONSTANT_TIME_EXECUTION
                title: Constant-Time Execution
                description: |
                  Ensure that critical enclave operations, especially cryptographic routines, execute in constant time to minimize timing variations.
                inPlace: false
                public: true
          - ID: MALICIOUS_OS_MANIPULATION
            title: Privileged OS Attacks
            threatType: Elevation of Privilege
            impactDesc: |
              Exploitation of OS-level control to manipulate enclave memory or execution, potentially leading to enclave compromise.
            attack: |
              A malicious or compromised OS can attempt to inspect, modify, or inject data into enclave memory through controlled interrupts or debugging tools.
            impactedSecObj:
              - REFID: ENCLAVE_INTEGRITY
            attackers:
              - REFID: MALICIOUS_OS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: MEMORY_ENCRYPTION
                title: Encrypted Memory and Integrity Checks
                description: |
                  Leverage SGX's memory encryption engine to ensure data confidentiality and integrity, even under malicious OS control.
                inPlace: true
                public: true
          - ID: HARDWARE_EXPLOIT
            title: Hardware Vulnerabilities
            threatType: Spoofing
            impactDesc: |
              Exploitation of vulnerabilities in the SGX hardware or firmware to bypass protections, leading to unauthorized access to enclave data.
            attack: |
              Attackers exploit flaws in the SGX implementation (e.g., speculative execution vulnerabilities) to extract sensitive data from enclaves.
            impactedSecObj:
              - REFID: PLATFORM_TRUST
              - REFID: ENCLAVE_CONFIDENTIALITY
            attackers:
              - REFID: HARDWARE_ATTACKERS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: MICROCODE_UPDATES
                title: Microcode Updates
                description: |
                  Ensure systems are patched with the latest microcode updates from Intel to mitigate hardware vulnerabilities.
                inPlace: true
                public: true
          - ID: ATTESTATION_SPOOFING
            title: Fake Attestation Responses
            threatType: Spoofing
            impactDesc: |
              Undermining the trust in SGX attestation by presenting fake attestation responses, potentially leading to trust in compromised enclaves.
            attack: |
              Attackers intercept and manipulate attestation requests or responses to make compromised enclaves appear legitimate.
            impactedSecObj:
              - REFID: PLATFORM_TRUST
            attackers:
              - REFID: MALICIOUS_OS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: REMOTE_ATTESTATION_VALIDATION
                title: Validate Remote Attestation Responses
                description: |
                  Ensure attestation responses are validated against trusted Intel attestation servers.
                inPlace: true
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/ARM_TrustedPlatform/Trusted_Firmware/Trusted_Firmware.yaml
        ```yaml
        ID: Trusted_Firmware
        title: Trusted Firmware
        version: 1.0
        authors: |
          David Cervigni
        parent: ARM_Trusted_Platform
        
        scope:
          description: |
            This document extends the ARM Trusted Platform threat model to focus specifically on threats to Trusted Firmware-A (TF-A). It addresses issues such as firmware integrity, secure storage, and runtime attacks, leveraging details from the Trusted Firmware-A documentation.
          securityObjectives:
            - ID: FIRMWARE_INTEGRITY
              title: Firmware Integrity
              description: |
                Ensure that firmware is not tampered with during development, deployment, or runtime.
              group: System Integrity
        
            - ID: RUNTIME_RESILIENCE
              title: Runtime Resilience
              description: |
                Protect the Trusted Firmware during execution, ensuring it cannot be subverted by runtime attacks.
              group: Runtime Security
        
            - ID: SECURE_STORAGE
              title: Secure Storage
              description: |
                Protect sensitive data stored by the Trusted Firmware, ensuring confidentiality and integrity.
              group: Data Security
        
            - ID: FIRMWARE_UPDATES
              title: Secure Firmware Updates
              description: |
                Ensure that firmware updates are authenticated and authorized to prevent malicious firmware from being executed.
              group: Update Security
        
          assumptions:
            - ID: PLATFORM_INTEGRITY_RISK
              description: |
                The platform may be exposed to physical or logical attacks targeting the integrity of firmware components.
            - ID: PRIVILEGED_ATTACKERS
              description: |
                Privileged attackers (e.g., with kernel-level control) may attempt to compromise firmware operations.
        
          attackers:
            - ID: MALICIOUS_FIRMWARE
              description: |
                Attackers inserting or modifying firmware to execute malicious actions.
              inScope: true
            - ID: RUNTIME_EXPLOITERS
              description: |
                Attackers exploiting runtime vulnerabilities in Trusted Firmware.
              inScope: true
            - ID: SUPPLY_CHAIN_ATTACKERS
              description: |
                Attackers compromising firmware integrity during the development or distribution phases.
              inScope: true
        
        analysis:
        
        threats:
          - ID: MALICIOUS_FIRMWARE_UPDATE
            title: Unauthorized Firmware Updates
            threatType: Spoofing
            impactDesc: |
              Execution of unauthorized or malicious firmware due to unverified updates, potentially compromising system integrity.
            attack: |
              Attackers distribute unauthorized firmware updates by bypassing signature validation or exploiting insecure update mechanisms.
            impactedSecObj:
              - REFID: FIRMWARE_UPDATES
            attackers:
              - REFID: SUPPLY_CHAIN_ATTACKERS
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: UPDATE_SIGNING
                title: Enforce Update Signing
                description: |
                  Require all firmware updates to be signed with a trusted cryptographic key before installation.
                inPlace: true
                public: true
          - ID: RUNTIME_MEMORY_ATTACK
            title: Runtime Memory Manipulation
            threatType: Tampering
            impactDesc: |
              Exploitation of vulnerabilities in Trusted Firmware's runtime memory, allowing attackers to inject malicious code or extract sensitive data.
            attack: |
              Attackers use buffer overflows, heap spraying, or other techniques to manipulate memory used by Trusted Firmware.
            impactedSecObj:
              - REFID: RUNTIME_RESILIENCE
            attackers:
              - REFID: RUNTIME_EXPLOITERS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: MEMORY_PROTECTION_UNITS
                title: Use Memory Protection Units (MPUs)
                description: |
                  Leverage MPUs to enforce strict memory access policies, preventing unauthorized access or modification of firmware memory.
                inPlace: true
                public: true
          - ID: SUPPLY_CHAIN_INJECTION
            title: Supply Chain Injection
            threatType: Spoofing
            impactDesc: |
              Introduction of malicious firmware into the supply chain, compromising the integrity of devices using the firmware.
            attack: |
              Attackers inject malicious code into firmware during development, testing, or distribution, exploiting weak supply chain controls.
            impactedSecObj:
              - REFID: FIRMWARE_INTEGRITY
            attackers:
              - REFID: SUPPLY_CHAIN_ATTACKERS
            CVSS:
              vector: 'CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: SUPPLY_CHAIN_AUDITS
                title: Conduct Supply Chain Audits
                description: |
                  Regularly audit firmware development and distribution processes to detect and mitigate supply chain risks.
                inPlace: false
                public: true
          - ID: SECURE_STORAGE_COMPROMISE
            title: Secure Storage Breach
            threatType: Information Disclosure
            impactDesc: |
              Breach of confidential data stored by Trusted Firmware, such as encryption keys or sensitive configuration settings.
            attack: |
              Attackers exploit vulnerabilities in secure storage implementations or gain unauthorized access to storage areas.
            impactedSecObj:
              - REFID: SECURE_STORAGE
            attackers:
              - REFID: MALICIOUS_FIRMWARE
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: ENCRYPT_STORAGE
                title: Encrypt Sensitive Storage
                description: |
                  Use strong encryption algorithms to protect data stored by Trusted Firmware, ensuring confidentiality even if storage is compromised.
                inPlace: true
                public: true
        
          - ID: BOOTLOADER_ATTACK
            title: Bootloader Exploitation
            threatType: Elevation of Privilege
            impactDesc: |
              Exploitation of vulnerabilities in the bootloader to gain unauthorized control over the system or bypass secure boot mechanisms.
            attack: |
              Attackers manipulate the bootloader or inject malicious code during the boot process, compromising the root of trust.
            impactedSecObj:
              - REFID: FIRMWARE_INTEGRITY
              - REFID: SECURE_BOOT
            attackers:
              - REFID: SUPPLY_CHAIN_ATTACKERS
            countermeasures:
              - ID: SECURE_BOOT_VERIFICATION
                title: Verify Bootloader Integrity
                description: |
                  Use cryptographic signatures to ensure the bootloader has not been tampered with before execution.
                inPlace: true
                public: true
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H'
            fullyMitigated: false
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/ARM_TrustedPlatform/ARM_TrustedPlatform.yaml
        ```yaml
        ID: ARM_TrustedPlatform
        title: ARM Trusted Platform
        
        version: 1.0
        
        children:
          - ID: Trusted_Firmware
        
        authors: |
          David Cervigni
        scope:
          description: |
            **NOTE:** this is an example is a threat model created by training an LLM
        
            This document outlines potential threats to the ARM Trusted Platform, focusing on threats to trusted execution environments (TEEs), secure boot mechanisms, and the integrity of platform firmware. Countermeasures are included to mitigate these threats.
          securityObjectives:
            - ID: TEE_CONFIDENTIALITY
              title: Trusted Execution Environment Confidentiality
              description: |
                Ensure that data and code within ARM TEEs remain confidential and inaccessible to unauthorized entities.
              group: Data Security
        
            - ID: TEE_INTEGRITY
              title: Trusted Execution Environment Integrity
              description: |
                Ensure the integrity of data, execution, and communication within ARM TEEs.
              group: System Integrity
        
            - ID: SECURE_BOOT
              title: Secure Boot Integrity
              description: |
                Ensure the integrity and authenticity of firmware and boot loaders to prevent unauthorized code execution.
              group: Boot Integrity
        
            - ID: PLATFORM_TRUST
              title: Platform Trust
              description: |
                Maintain trust in the ARM hardware root of trust and secure firmware updates.
              group: Trust Assurance
        
          assumptions:
            - ID: PRIVILEGED_ATTACKER
              description: |
                Attackers may have privileged access (e.g., kernel-level or hypervisor control) and may attempt to subvert trusted components.
            - ID: SIDE_CHANNEL_RISK
              description: |
                Side-channel attacks exploiting timing, power, or electromagnetic leakage are considered potential threats.
        
          attackers:
            - ID: MALICIOUS_KERNEL
              description: |
                A malicious or compromised kernel attempting to interfere with ARM TEE operations.
              inScope: true
            - ID: HARDWARE_ATTACKERS
              description: |
                Attackers targeting the ARM hardware, secure elements, or firmware to bypass protections.
              inScope: true
            - ID: SIDE_CHANNEL_ACTORS
              description: |
                Attackers leveraging side-channel analysis to infer sensitive information.
              inScope: true
        
        analysis:
        
        threats:
          - ID: SIDE_CHANNEL_ATTACK
            title: Side-Channel Attacks on TEE
            threatType: Information Disclosure
            impactDesc: |
              Leakage of sensitive information, such as cryptographic keys or private data, through side-channel analysis.
            attack: |
              Attackers exploit physical or timing-based side channels, such as cache behavior, power consumption, or electromagnetic signals, to infer data processed within the TEE.
            impactedSecObj:
              - REFID: TEE_CONFIDENTIALITY
            attackers:
              - REFID: SIDE_CHANNEL_ACTORS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: CONSTANT_TIME_ALGORITHMS
                title: Use Constant-Time Algorithms
                description: |
                  Implement constant-time cryptographic and critical operations to eliminate timing-based side-channel vulnerabilities.
                inPlace: false
                public: true
          - ID: MALICIOUS_KERNEL_ACCESS
            title: Kernel-Level Attacks on TEE
            threatType: Elevation of Privilege
            impactDesc: |
              Exploitation of kernel-level privileges to interfere with or compromise the ARM TEE.
            attack: |
              A compromised or malicious kernel attempts to read, write, or manipulate memory assigned to the TEE, breaking its isolation guarantees.
            impactedSecObj:
              - REFID: TEE_INTEGRITY
            attackers:
              - REFID: MALICIOUS_KERNEL
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: MEMORY_ISOLATION
                title: Enforce Strong Memory Isolation
                description: |
                  Utilize ARM's memory management unit (MMU) and hardware-based isolation mechanisms to prevent unauthorized kernel access to TEE memory.
                inPlace: true
                public: true
          - ID: FIRMWARE_EXPLOIT
            title: Exploitation of Insecure Firmware
            threatType: Spoofing
            impactDesc: |
              Execution of unauthorized or malicious code by exploiting vulnerabilities in platform firmware.
            attack: |
              Attackers inject malicious firmware or exploit bugs in existing firmware to gain control over secure operations, potentially bypassing the TEE or secure boot.
            impactedSecObj:
              - REFID: SECURE_BOOT
            attackers:
              - REFID: HARDWARE_ATTACKERS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: FIRMWARE_VERIFICATION
                title: Verify Firmware Signatures
                description: |
                  Enforce cryptographic signature validation during firmware updates and secure boot processes.
                inPlace: true
                public: true
                
          - ID: ROGUE_DEVICE_ACCESS
            title: Rogue Peripheral Attacks
            threatType: Tampering
            impactDesc: |
              Compromise of TEE operations through unauthorized access or manipulation by malicious peripherals.
            attack: |
              Malicious devices connected to the platform exploit DMA (Direct Memory Access) or other interfaces to manipulate or extract data from the TEE.
            impactedSecObj:
              - REFID: TEE_INTEGRITY
              - REFID: TEE_CONFIDENTIALITY
            attackers:
              - REFID: HARDWARE_ATTACKERS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: DMA_PROTECTION
                title: Restrict DMA Access
                description: |
                  Implement IOMMU (Input-Output Memory Management Unit) to limit peripheral access to memory regions used by the TEE.
                inPlace: false
                public: true
          - ID: SECURE_BOOT_SPOOFING
            title: Spoofing Secure Boot
            threatType: Spoofing
            impactDesc: |
              Undermining trust in the secure boot process by executing malicious code under the guise of legitimate firmware.
            attack: |
              Attackers intercept or modify the boot process to execute unverified firmware or boot loaders, compromising the root of trust.
            impactedSecObj:
              - REFID: SECURE_BOOT
              - REFID: PLATFORM_TRUST
            attackers:
              - REFID: HARDWARE_ATTACKERS
            CVSS:
              vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: ROOT_OF_TRUST
                title: Use Hardware Root of Trust
                description: |
                  Ensure the secure boot process is anchored to an immutable hardware root of trust to verify all stages of the boot chain.
                inPlace: true
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/Bitcoin/ARK/ARK.yaml
        ```yaml
        ID: ARK
        title: ARK L2
        version: 1.1
        authors: |
          Example by David Cervigni
        parent: Bitcoin
        
        scope:
          description: |
            Threat model for ARK Layer 2 scaling solution for Bitcoin. ARK aims to provide efficient off-chain scaling and enhanced privacy while preserving decentralization and security.
          diagram: ARK_L2_Architecture.png
          assets:
            - ID: BITCOIN_LAYER1
              type: system
              title: Bitcoin Layer 1
              description: |
                The base layer of Bitcoin blockchain used for anchoring Layer 2 transactions.
              inScope: true
        
            - ID: ARK_TRANSACTIONS
              type: dataflow
              title: ARK Off-chain Transactions
              description: |
                Transactions processed off-chain within the ARK network before final settlement on Bitcoin L1.
              inScope: true
        
            - ID: ARK_HUB
              type: system
              title: ARK Hub
              description: |
                Centralized or semi-centralized hubs that facilitate batching and processing of ARK transactions.
              inScope: true
        
            - ID: USER_WALLETS
              type: system
              title: User Wallets
              description: |
                Wallets used by end-users to interact with the ARK network and execute transactions.
              inScope: true
        
          # attackers:
          #   - ID: MALICIOUS_HUB
          #     title: Malicious Hub Operator
          #     description: |
          #       A rogue hub operator attempting to steal funds or delay transactions.
          #     inScope: true
          attackers:
            - ID: MALICIOUS_HUB
              title: Malicious Hub Operator
              description: |
                A rogue hub operator attempting to steal funds or delay transactions.
              inScope: true
        
            - ID: NETWORK_ATTACKER
              title: Network Attacker
              description: |
                An adversary attempting to exploit ARK's communication network.
              inScope: true
        
            - ID: INTERNAL_THREAT
              title: Internal Threat
              description: |
                Insider threats from within the ARK network operations team.
              inScope: true
        
          assumptions:
            - ID: OFF_CHAIN_RISK
              description: |
                Off-chain transactions are inherently vulnerable to counterparty risks and require trust assumptions.
            - ID: HUB_OPERATORS
              description: |
                ARK hubs may be operated by third parties with varying trust levels.
            - ID: BITCOIN_FINALITY
              description: |
                ARK transactions are only final once confirmed on Bitcoin L1.
        
        
        
        analysis:
        
        threats:
          - ID: ARK_DOUBLE_SPENDING
            title: Double Spending in Off-chain Transactions
            impactDesc: |
              A malicious user may attempt to spend funds multiple times by exploiting delays in settlement finality.
            impactedSecObj:
              - REFID: DOUBLE_SPENDING_PREVENTION
            assets:
              - REFID: ARK_TRANSACTIONS
            # attackers:
            #   - REFID: MALICIOUS_HUB
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Integrity, Financial Fraud
            attack: |
              The attacker attempts to make multiple payments before the finalization of off-chain transactions.
            countermeasures:
              - ID: TIMELOCKS
                title: Timelocks on Transactions
                description: |
                  Implement timelocks to prevent double-spending attempts.
                operational: true
                inPlace: true
                public: true
        
            fullyMitigated: false
          - ID: HUB_COLLUSION
            title: Hub Collusion Attack
            impactDesc: |
              Colluding hub operators could manipulate transaction processing or withhold transactions.
            impactedSecObj:
              - REFID: AVAILABILITY
            assets:
              - REFID: ARK_HUB
            attackers:
              - REFID: MALICIOUS_HUB
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:H
            threatType: Availability, Collusion
            attack: |
              Multiple hubs conspire to delay or censor transactions to gain an unfair advantage.
            countermeasures:
              - ID: HUB_DECENTRALIZATION
                title: Distributed Hub Network
                description: |
                  Encourage a decentralized set of hubs to reduce collusion risks.
                operational: true
                inPlace: false
                public: true
        
            fullyMitigated: false
          - ID: PRIVACY_LEAK
            title: User Privacy Leakage
            impactDesc: |
              User transaction data could be leaked due to weak privacy mechanisms.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
            assets:
              - REFID: USER_WALLETS
            attackers:
              - REFID: NETWORK_ATTACKER
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N
            threatType: Privacy Violation
            attack: |
              An attacker monitors transaction flow to de-anonymize users.
            countermeasures:
              - ID: COINJOIN_INTEGRATION
                title: CoinJoin Integration
                description: |
                  Use privacy-enhancing techniques like CoinJoin to obfuscate transactions.
                operational: false
                inPlace: false
                public: true
        
            fullyMitigated: false
          - ID: FUND_LOCKUP
            title: Funds Locked Due to Hub Unresponsiveness
            impactDesc: |
              If a hub becomes unresponsive, user funds may become locked and inaccessible.
            impactedSecObj:
              - REFID: AVAILABILITY
            assets:
              - REFID: ARK_TRANSACTIONS
            attackers:
              - REFID: MALICIOUS_HUB
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H
            threatType: Availability, Financial Loss
            attack: |
              The hub operator ceases operations or withholds processing transactions, leading to user funds being locked.
            countermeasures:
              - ID: REFUND_TRANSACTION
                title: Refund Transactions After 4 Weeks
                description: |
                  Implement automatic refund transactions to return locked funds to the original owners after a pre-defined timeout period (e.g., 4 weeks).
                operational: true
                inPlace: false
                public: true
        
            fullyMitigated: false
          - ID: DOS_ATTACK
            title: Denial of Service Attack on Hubs
            impactDesc: |
              A flood of transactions could overwhelm ARK hubs and degrade service.
            impactedSecObj:
              - REFID: AVAILABILITY
            assets:
              - REFID: ARK_HUB
            attackers:
              - REFID: NETWORK_ATTACKER
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
            threatType: Denial of Service
            attack: |
              An attacker sends a large volume of requests to overload the network.
            countermeasures:
              - ID: RATE_LIMITING
                title: Rate Limiting on Hubs
                description: |
                  Implement rate limiting and anomaly detection to mitigate attacks.
                operational: true
                inPlace: false
                public: true
            fullyMitigated: false
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/Bitcoin/LightningNetwork/LightningNetwork.yaml
        ```yaml
        ID: LightningNetwork
        parent: Bitcoin
        title: Lightning Network
        version: 1.1
        authors: |
          David Cervigni
        scope:
          description: |
            This document extends the Bitcoin threat model to focus on the Lightning Network, addressing threats to payment channels, routing nodes, and channel state integrity. The Lightning Network improves Bitcoin's scalability by facilitating off-chain transactions, but introduces specific security challenges. Transaction examples are derived from the Lightning Network whitepaper, incorporating the role of watchtowers to mitigate specific threats.
          securityObjectives:
            - ID: CHANNEL_CONFIDENTIALITY
              title: Channel Confidentiality
              description: |
                Ensure that the details of payment channels and transactions remain confidential and are not exposed to unauthorized entities.
              group: Data Security
        
            - ID: CHANNEL_INTEGRITY
              title: Channel Integrity
              description: |
                Protect the integrity of payment channel states to prevent tampering or unauthorized modifications.
              group: System Integrity
        
            - ID: ROUTING_NODE_RESILIENCE
              title: Routing Node Resilience
              description: |
                Ensure routing nodes are protected against denial-of-service attacks and can handle high transaction volumes securely.
              group: Network Resilience
        
            - ID: TIMELY_CLOSURE
              title: Timely Channel Closure
              description: |
                Ensure channels can be closed promptly and securely in the event of disputes or failures.
              group: Operational Security
        
            - ID: WATCHTOWER_RELIABILITY
              title: Watchtower Reliability
              description: |
                Ensure watchtowers function correctly to detect and penalize malicious channel state broadcasts.
              group: Dispute Resolution
        
          assumptions:
            - ID: PUBLIC_NETWORK
              description: |
                The Lightning Network operates over a public and decentralized network, exposing nodes to potential adversaries.
            - ID: PARTIAL_TRUST
              description: |
                Routing nodes may not be fully trusted by participants but are required for facilitating payments.
            - ID: WATCHTOWER_AVAILABILITY
              description: |
                Watchtowers must remain available to detect and respond to malicious behavior promptly.
        
          attackers:
            - ID: MALICIOUS_ROUTING_NODE
              title: Malicious Routing Node
              description: |
                Routing nodes attempting to disrupt payments, intercept funds, or exploit network vulnerabilities.
              inScope: true
            - ID: CHANNEL_PARTNER
              title: Malicious Channel Partner
              description: |
                A malicious channel partner attempting to cheat by broadcasting outdated or invalid channel states.
              inScope: true
            - ID: NETWORK_ADVERSARY
              title: Network Adversary
              description: |
                An external attacker attempting to disrupt the network or compromise node communications.
              inScope: true
        
        analysis:
        
        threats:
          - ID: CHANNEL_STATE_TAMPERING
            title: Tampering with Channel States
            threatType: Tampering
            impactDesc: |
              Attackers tamper with channel states, leading to disputes or financial loss for participants.
            attack: |
              A malicious channel partner broadcasts an outdated channel state to reclaim funds already spent. For example, Alice and Bob open a channel with 1 BTC each. Alice pays Bob 0.5 BTC off-chain, but later broadcasts the original channel state to reclaim her initial 1 BTC.
            impactedSecObj:
              - REFID: CHANNEL_INTEGRITY
            attackers:
              - REFID: CHANNEL_PARTNER
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L'
            fullyMitigated: false
            countermeasures:
              - ID: PENALTY_MECHANISM
                title: Enforce Penalty Mechanisms
                description: |
                  Use penalty transactions to ensure that any attempt to broadcast an outdated state results in a financial penalty for the attacker. Watchtowers monitor the blockchain for outdated states and broadcast penalty transactions on behalf of the victim.
                inPlace: true
                public: true
        
          - ID: ROUTING_NODE_DOS
            title: Denial of Service on Routing Nodes
            threatType: Denial of Service
            impactDesc: |
              Attackers overwhelm routing nodes, disrupting payment processing and reducing network availability.
            attack: |
              A network adversary floods routing nodes with fake or excessive requests, causing them to exhaust resources. For instance, an attacker could repeatedly attempt to route payments through a specific node, forcing it to handle an unsustainable load.
            impactedSecObj:
              - REFID: ROUTING_NODE_RESILIENCE
            attackers:
              - REFID: NETWORK_ADVERSARY
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: RATE_LIMITING
                title: Implement Rate Limiting
                description: |
                  Use rate limiting and request validation to mitigate denial-of-service attacks on routing nodes. Monitor traffic patterns and reject requests from nodes exhibiting suspicious behavior.
                inPlace: true
                public: true
        
          - ID: CHANNEL_CLOSURE_DELAY
            title: Delayed Channel Closure
            threatType: Elevation of Privilege
            impactDesc: |
              A malicious channel partner delays the closure of a channel, locking funds and causing financial loss.
            attack: |
              The attacker refuses to cooperate during the channel closure process or uses the dispute mechanism maliciously. For example, Bob delays closing a channel with Alice, preventing her from accessing her locked funds during a time-sensitive event.
            impactedSecObj:
              - REFID: TIMELY_CLOSURE
            attackers:
              - REFID: CHANNEL_PARTNER
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: FORCE_CLOSURE
                title: Support Force Closures
                description: |
                  Allow participants to unilaterally close a channel after a timeout to recover locked funds. Watchtowers can assist by ensuring the closure process is secure and detecting malicious delays.
                inPlace: true
                public: true
        
          - ID: PRIVACY_LEAK
            title: Privacy Leak in Payment Routing
            threatType: Information Disclosure
            impactDesc: |
              Sensitive transaction details are exposed to unauthorized entities, compromising user privacy.
            attack: |
              Malicious routing nodes or external adversaries analyze payment routes to infer transaction amounts and participants. For example, a routing node could monitor the flow of payments to deduce Alice is paying Charlie 0.2 BTC via Bob.
            impactedSecObj:
              - REFID: CHANNEL_CONFIDENTIALITY
            attackers:
              - REFID: MALICIOUS_ROUTING_NODE
              - REFID: NETWORK_ADVERSARY
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: ROUTE_ENCRYPTION
                title: Encrypt Payment Routes
                description: |
                  Use onion routing to encrypt payment routes and protect transaction details from unauthorized disclosure. Ensure each hop only knows the adjacent nodes, preventing end-to-end correlation.
                inPlace: true
                public: true
        
          - ID: WATCHTOWER_FAILURE
            title: Watchtower Unavailability
            threatType: Denial of Service
            impactDesc: |
              Unavailable watchtowers fail to detect and penalize malicious behavior, weakening channel security.
            attack: |
              A network adversary targets watchtowers with a DoS attack, preventing them from monitoring channel state broadcasts. For example, an attacker floods a watchtower with traffic to render it non-functional during a critical dispute.
            impactedSecObj:
              - REFID: WATCHTOWER_RELIABILITY
            attackers:
              - REFID: NETWORK_ADVERSARY
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H'
            fullyMitigated: false
            countermeasures:
              - ID: DISTRIBUTED_WATCHTOWERS
                title: Use Distributed Watchtowers
                description: |
                  Encourage the use of multiple, geographically distributed watchtowers to ensure redundancy and availability during disputes.
                inPlace: false
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/Bitcoin/Mixing/Mixing.yaml
        ```yaml
        ID: Mixing
        parent: Bitcoin_Threat_Model
        title: Mixing
        version: 1.0
        authors: |
          David Cervigni
        scope:
          description: |
            This document provides a threat model for various Bitcoin mixing techniques aimed at enhancing privacy by obfuscating transaction trails. Mixing techniques such as CoinJoin, Tumbler services, and Chaumian mixing introduce potential security risks that need to be addressed.
          securityObjectives:
            - ID: TRANSACTION_PRIVACY
              title: Transaction Privacy
              description: |
                Ensure Bitcoin transactions remain unlinkable and anonymous to third parties.
              group: Privacy Enhancement
        
            - ID: MIXING_INTEGRITY
              title: Mixing Integrity
              description: |
                Ensure that the Bitcoin mixing process is free from tampering and fraudulent activity.
              group: System Integrity
        
            - ID: PARTICIPANT_ANONYMITY
              title: Participant Anonymity
              description: |
                Protect the identity of participants engaging in mixing services.
              group: Identity Protection
        
          assumptions:
            - ID: TRUSTED_MIXING_SERVICE
              description: |
                Users assume that mixing services are not colluding with adversaries or law enforcement.
            - ID: NETWORK_OBSERVATION
              description: |
                Adversaries may monitor the Bitcoin network to track transaction patterns despite mixing attempts.
        
          attackers:
            - ID: MALICIOUS_MIXER
              title: Malicious Mixing Service
              description: |
                A mixing service that colludes with attackers to deanonymize users.
              inScope: true
            - ID: NETWORK_OBSERVER
              title: Network Observer
              description: |
                Entities monitoring the Bitcoin network to analyze transaction patterns and break anonymity.
              inScope: true
            - ID: PARTICIPANT_COLLUSION
              title: Participant Collusion
              description: |
                Collaborating participants within a mixing process attempting to deanonymize others.
              inScope: true
        
        analysis:
        
        threats:
          - ID: PRIVACY_LEAK
            title: Privacy Leakage
            threatType: Information Disclosure
            impactDesc: |
              Users' Bitcoin addresses and transaction history may be linked due to weaknesses in the mixing process.
            attack: |
              A network observer analyzes mixing transaction patterns and timings to correlate addresses, revealing user identities.
            impactedSecObj:
              - REFID: TRANSACTION_PRIVACY
            attackers:
              - REFID: NETWORK_OBSERVER
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: COIN_JOIN
                title: Use CoinJoin Techniques
                description: |
                  Utilize CoinJoin-based mixing that combines multiple users' transactions to break address linkability.
                inPlace: true
                public: true
          - ID: MIXER_EXIT_SCAM
            title: Mixer Exit Scam
            threatType: Fraud
            impactDesc: |
              A mixing service may abscond with users' Bitcoin instead of returning mixed outputs.
            attack: |
              A malicious mixer operator collects deposits and disappears without processing the mixing, resulting in financial loss for users.
            impactedSecObj:
              - REFID: MIXING_INTEGRITY
            attackers:
              - REFID: MALICIOUS_MIXER
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: TRUSTED_SERVICES
                title: Use Trusted and Audited Mixing Services
                description: |
                  Prefer decentralized, open-source mixers with a proven track record of transparency.
                inPlace: false
                public: true
          - ID: PARTICIPANT_LINKAGE
            title: Participant Linkage Attack
            threatType: Information Disclosure
            impactDesc: |
              Participants within a mixing process collude to track inputs and outputs, reducing anonymity.
            attack: |
              Malicious participants join mixing transactions with the intent of analyzing inputs and outputs to deanonymize other users.
            impactedSecObj:
              - REFID: PARTICIPANT_ANONYMITY
            attackers:
              - REFID: PARTICIPANT_COLLUSION
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: RANDOMIZED_INPUTS
                title: Randomize Input and Output Patterns
                description: |
                  Use randomized transaction structures and delays to reduce linkability between participants.
                inPlace: true
                public: true
          - ID: NETWORK_LEVEL_ANALYSIS
            title: Network-Level Transaction Analysis
            threatType: Information Disclosure
            impactDesc: |
              Adversaries analyze network traffic to uncover the relationships between mixed transactions.
            attack: |
              An attacker monitors Bitcoin network traffic and uses timing analysis to correlate mixed transactions.
            impactedSecObj:
              - REFID: TRANSACTION_PRIVACY
            attackers:
              - REFID: NETWORK_OBSERVER
            CVSS:
              vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
            fullyMitigated: false
            countermeasures:
              - ID: TOR_VPN_USAGE
                title: Use Privacy-Enhancing Technologies
                description: |
                  Users should leverage Tor or VPN services to obfuscate their network traffic and enhance anonymity.
                inPlace: false
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/Bitcoin/Bitcoin.yaml
        ```yaml
        ID: Bitcoin
        title: Bitcoin
        version: 1.0
        authors: |
          David Cervigni
        children:
          - ID: LightningNetwork
          - ID: Mixing
          - ID: ARK
        scope:
          description: |
            Note: This is an example of threat model created by training an LLM
        
            This document outlines potential threats to the Bitcoin network based on its design and operations as outlined in the Bitcoin whitepaper. It includes security measures to mitigate these threats.
          securityObjectives:
            - ID: NETWORK_RESILIENCE
              title: Resilience of the Bitcoin Network
              description: |
                Ensure Bitcoin's blockchain remains secure and available even under attacks.
              group: Network Security
        
            - ID: TRANSACTION_INTEGRITY
              title: Transaction Integrity
              description: |
                Maintain the integrity of transactions recorded on the blockchain.
              group: Data Integrity
        
            - ID: MINING_SECURITY
              title: Mining Security
              description: |
                Ensure miners operate fairly and follow the network's protocol.
              group: Operational Security
            - ID: AVAILABILITY
              title: Network Availability
              description: |
                Ensure the Bitcoin network remains available and responsive to users.
              group: Operational Security
        
            - ID: CONFIDENTIALITY
              title: Transaction Confidentiality
              description: |
                Protect the privacy of Bitcoin transactions and user identities.
              group: Privacy Protection
            - ID: DOUBLE_SPENDING_PREVENTION
              title: Double Spending Prevention
              description: |
                Prevent the double-spending of Bitcoin.
              contributesTo: TRANSACTION_INTEGRITY
              group: Data Integrity
        
          assumptions:
            - ID: ADVANCED_ATTACKER
              description: |
                Attackers have significant computational power, potentially exceeding honest participants.
            - ID: PUBLIC_NETWORK
              description: |
                Bitcoin operates on a public and open network.
        
          attackers:
            - ID: NETWORK_PARTICIPANT
              title: Network Participants
              description: |
                Participants in the Bitcoin network who may attempt to exploit vulnerabilities or disrupt network operations.
              inScope: true
        
            - ID: SYBIL_ACTORS
              title: Sybil Actors
              description: |
                Attackers attempting to dominate the network with numerous fake identities.
              inScope: true
            - ID: MALICIOUS_MINERS
              title: Malicious Miners
              description: |
                Miners attempting to rewrite or fork the blockchain for selfish purposes.
              inScope: true
            - ID: NETWORK_ATTACKER
              title: Network Attacker
              description: |
                Attackers attempting to disrupt the network's confidentiality availability or integrity.
              inScope: true
              attackers:
            - ID: ECONOMIC_ACTORS
              description: |
                Actors whose economic interests could lead to disruptions in the network. This includes individuals or entities that may manipulate the mining rewards and transaction fees based on economic conditions or market demand.
              inScope: true
        
            - ID: OTHER_ONCHAIN_ACTORS
              description: |
                Actors involved in on-chain activities that could influence the security and availability of the network, including users transacting in Bitcoin and service providers.
              inScope: true
        
            - ID: ROGUE_MINING_POOL
              description: |
                A collective of miners acting maliciously to alter block history or engage in fraudulent activities such as double spending.
              inScope: true
        
            - ID: GOVERNMENT_ACTORS
              description: |
                Regulatory bodies or governments that may implement laws affecting Bitcoin's use and operation, with the potential to disrupt network stability through regulatory changes.
              inScope: true
        
        analysis:
        
        threats:
          - ID: 51_PERCENT_ATTACK
            title: Control of Majority Hashing Power
            threatType: Elevation of Privilege
            impactDesc: |
              Allows an attacker to rewrite transaction history, double-spend, or block transactions.
            attack: |
              An attacker accumulates more than 50% of the total mining power and uses this control to create a longer blockchain fork, thereby rewriting transaction history or blocking new transactions.
            impactedSecObj:
              - REFID: TRANSACTION_INTEGRITY
              - REFID: NETWORK_RESILIENCE
            attackers:
              - REFID: MALICIOUS_MINERS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H
            fullyMitigated: false
            countermeasures:
              - ID: DIVERSE_HASHPOWER
                title: Encourage diverse miner participation
                description: |
                  Promote geographic and organizational decentralization of miners to reduce the likelihood of any single entity achieving majority hash power.
                inPlace: false
                public: true
        
          - ID: DOUBLE_SPENDING
            title: Double Spending
            threatType: Tampering
            impactDesc: |
              Compromise of transaction validity by spending the same Bitcoin multiple times.
            attack: |
              The attacker broadcasts two conflicting transactions to the network, one to make a purchase and another to send the same funds back to their own wallet, exploiting timing and confirmation delays.
            impactedSecObj:
              - REFID: TRANSACTION_INTEGRITY
            attackers:
              - REFID: SYBIL_ACTORS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
            fullyMitigated: false
            countermeasures:
              - ID: LONGER_CONFIRMATION
                title: Increase block confirmations
                description: |
                  Encourage waiting for multiple block confirmations to ensure transaction permanence.
                inPlace: true
                public: true
        
          - ID: NETWORK_PARTITION
            title: Network Partitioning (Eclipse Attack)
            threatType: Denial of Service
            impactDesc: |
              Isolate nodes from the main network, manipulating their view of the blockchain.
            attack: |
              By controlling a node’s peers, the attacker isolates the target node from the rest of the network, feeding it incorrect blockchain data or preventing it from receiving updates.
            impactedSecObj:
              - REFID: NETWORK_RESILIENCE
            attackers:
              - REFID: SYBIL_ACTORS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
            fullyMitigated: false
            countermeasures:
              - ID: PEER_DIVERSITY
                title: Peer Diversity
                description: |
                  Nodes should maintain diverse peer connections to prevent isolation.
                inPlace: false
                public: false
        
          - ID: MINING_REORG
            title: Blockchain Reorganizations
            threatType: Information Disclosure
            impactDesc: |
              Reverse transactions by introducing a longer fork.
            attack: |
              Malicious miners use their hashing power to create an alternate chain that invalidates recent blocks, causing a reorganization of the blockchain.
            impactedSecObj:
              - REFID: TRANSACTION_INTEGRITY
            attackers:
              - REFID: MALICIOUS_MINERS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N
            fullyMitigated: false
            countermeasures:
              - ID: TIMESTAMP_MONITORING
                title: Monitor blockchain timestamps
                description: |
                  Use timestamps and multiple confirmations to minimize reorganization threats.
                inPlace: true
                public: true
        
          - ID: HASH_POWER_DECREASE
            title: Loss of Hash Power Due to Incentives
            threatType: Economic Threat
            impactDesc: |
              A significant decrease in hash power can lead to a drop in Bitcoin's price, reducing miner incentives, and potentially causing a negative feedback loop of further decreases in hash power before the next difficulty adjustment occurs. This creates a risk to the stability and security of the network, potentially making it more susceptible to attacks.
            attack: |
              If the prevailing market conditions lead to low Bitcoin prices, miners may exit the market as profitability decreases. This reduction in mining activity could create a downward spiral where the network becomes less secure due to lower hash power, leading to longer confirmation times and increased vulnerability to attacks.
            impactedSecObj:
              - REFID: AVAILABILITY
              - REFID: NETWORK_RESILIENCE
            attackers:
              - REFID: ECONOMIC_ACTORS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
            fullyMitigated: false
            countermeasures:
              - ID: MINER_SUBSIDY
                title: Maintain Miner Subsidies to Support Hash Power
                description: |
                  Implement strategies to support miners during low price periods, 
                  such as temporarily lowering the mining difficulty adjustment period or providing
                   incentives for miners to remain active in the ecosystem.
                inPlace: false
                public: true
        
              - ID: DIVERSIFIED_REVENUE_MODELS
                title: Encourage Diversified Revenue Streams for Miners
                description: |
                  Promote diversified revenue opportunities for miners, such as participating in 
                  transaction fee markets or providing ancillary services to the network to maintain 
                  viability even during low block reward phases.
                inPlace: false
                public: true
        
          # - ID: UNCOLLABORATIVE_COUNTERPARTY_CONDITIONAL_PAYMENT
          #   title: Uncollaborative Counterparty in Conditional Payment
          #   threatType: Elevation of Privilege
          #   impactDesc: |
          #     A counterparty may fail to cooperate in a conditional transaction, 
          #     leading to potential loss of funds or delayed transaction finalization.
          #      This could happen if the counterparty refuses to fulfill their part of the agreement,
          #       such as not providing necessary signatures or data.
          #   attack: |
          #     An adversary could exploit the lack of collaboration
          #      by either ignoring transaction conditions or attempting to
          #       manipulate the terms to their advantage. 
          #   impactedSecObj:
          #     - REFID: AVAILABILITY
          #   attackers:
          #     - REFID: NETWORK_PARTICIPANT
          #   CVSS:
          #     vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
          #   fullyMitigated: true
          #   countermeasures:
          #     - ID: CHECKLOCKTIMEVERIFY
          #       title: Implement CheckLockTimeVerify (CLTV)
          #       description: |
          #         Utilize CheckLockTimeVerify (CLTV) techniques to impose time-based conditions on 
          #         the transaction that prevent uncollaborative behavior. Implementing CLTV ensures that funds can only be
          #          spent after a particular time or block height, thus providing a potential exit strategy if the counterparty
          #           becomes uncollaborative.
          #       inPlace: true
          #       public: true  
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/LLM_adoption/LLM_adoption.yaml
        ```yaml
        ID: LLM_ADOPTION_THREAT_MODEL
        title: LLM Adoption
        version: "1.0"
        authors: |
          David Cervigni Using GenAI
        scope:
          description: |
            **NOTE:** This threat model addresses potential risks associated with the adoption 
            of large language models (LLMs) in enterprise environments. It is based on the OWASP Top 10 for LLM Applications 2025 and defines the assets, security objectives, assumptions, and attackers relevant to LLM deployment.
          securityObjectives:
            - ID: DATA_PROTECTION
              title: Data Protection
              description: |
                Protect sensitive data throughout the LLM lifecycle, including training data, model weights, and user inputs/outputs, ensuring proper classification, handling, and storage.
              treeImage: true
              group: Data Security
        
            - ID: MODEL_INTEGRITY
              title: Model Integrity
              description: |
                Maintain the integrity and reliability of the LLM system by preventing model poisoning, ensuring supply chain security, and validating model outputs against expected behaviors.
              treeImage: true
              group: System Security
        
            - ID: ACCESS_CONTROL
              title: Access Control
              description: |
                Implement robust authentication, authorization, and audit mechanisms to control access to LLM resources and ensure proper user permissions and accountability.
              treeImage: true
              group: Identity & Access Management
        
            - ID: COMPLIANCE
              title: Compliance & Governance
              description: |
                Ensure LLM operations adhere to regulatory requirements, industry standards, and organizational policies while maintaining transparency and auditability.
              treeImage: true
              group: Governance
        
            - ID: RESILIENCE
              title: System Resilience
              description: |
                Maintain system availability and performance under normal and adverse conditions, including protection against resource exhaustion and service degradation.
              treeImage: true
              group: Operational Security
        
          assumptions:
            - ID: TRUSTED_ENVIRONMENT
              description: |
                The underlying infrastructure is assumed to have baseline security controls, though LLM-specific risks remain.
            - ID: STATIC_MODEL_CONFIGURATION
              description: |
                The deployed LLM is configured with fixed parameters that may not dynamically adjust to emerging threats.
            - ID: DATA_PROCESSING_ISOLATION
              description: |
                Azure OpenAI Service processes data in isolation - prompts and completions are NOT:
                - Available to other customers
                - Available to OpenAI
                - Used to improve OpenAI models
                - Used to train/retrain Azure OpenAI foundation models
                - Used to improve Microsoft/3rd party services without permission
                
            - ID: GEOGRAPHIC_PROCESSING
              description: |
                Data is processed within customer-specified geography unless using Global deployment type. 
                Data at rest is always stored in customer-designated geography.
                
            - ID: MODEL_STATELESSNESS
              description: |
                The models are stateless - no prompts or generations are stored in the model itself.
        
          attackers:
            - ID: MALICIOUS_USER
              description: |
                Authorized users with malicious intent seeking to exploit the LLM application for unauthorized actions.
              inScope: true
            - ID: EXTERNAL_ATTACKER
              description: |
                Unauthenticated external entities attempting to exploit vulnerabilities in the LLM deployment.
              inScope: true
        analysis: |
          This threat model evaluates the key risks involved in adopting large language models by mapping potential threat vectors—derived from the OWASP Top 10 for LLM Applications 2025—against specific countermeasures. It is intended to support secure integration within the software development lifecycle, ensuring continuous monitoring and effective mitigation of risks.
        threats:
          - ID: LLM01_PROMPT_INJECTION
            title: Prompt Injection
            threatType: Injection
            impactDesc: |
              Malicious input may alter the model's behavior, leading to unauthorized actions, disclosure of sensitive information, or harmful outputs.
            attack: |
              Attackers craft inputs—either directly or indirectly—to inject malicious commands into the prompt, bypassing safety constraints and altering the intended response.
            impactedSecObj:
              - REFID: MODEL_INTEGRITY
              - REFID: ACCESS_CONTROL
              - REFID: DATA_PROTECTION
            attackers:
              - REFID: MALICIOUS_USER
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: CONSTRAINED_PROMPT
                title: Constrain Model Prompts
                description: |
                  Define and enforce strict system prompts that limit the scope of user inputs, preventing unauthorized modifications.
                inPlace: true
                public: true
              - ID: INPUT_OUTPUT_FILTERING
                title: Input and Output Filtering
                description: |
                  Apply robust filtering and validation for all data entering and exiting the model to detect and block injection attempts.
                inPlace: true
                public: true
              - ID: ADVERSARIAL_TESTING
                title: Regular Adversarial Testing
                description: |
                  Conduct periodic red team exercises and adversarial simulations to identify and remediate prompt injection vulnerabilities.
                inPlace: false
                public: false
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            fullyMitigated: false
          - ID: LLM02_SENSITIVE_INFO_DISCLOSURE
            title: Sensitive Information Disclosure
            threatType: Information Disclosure
            impactDesc: |
              The unintended exposure of confidential data, proprietary algorithms, or internal configurations via LLM outputs.
            attack: |
              Exploiting inadequate data sanitization or prompt injection flaws, an attacker can force the LLM to reveal sensitive information.
            impactedSecObj:
              - REFID: DATA_PROTECTION
              - REFID: COMPLIANCE
            attackers:
              - REFID: EXTERNAL_ATTACKER
              - REFID: MALICIOUS_USER
            countermeasures:
              - ID: DATA_SANITIZATION
                title: Data Sanitization
                description: |
                  Implement comprehensive scrubbing and masking techniques on both training inputs and model outputs to prevent leakage of sensitive data.
                inPlace: true
                public: true
              - ID: ACCESS_CONTROL
                title: Strict Access Control
                description: |
                  Enforce role-based access controls and data classification policies to restrict access to sensitive information.
                inPlace: true
                public: true
              - ID: OUTPUT_VALIDATION
                title: Output Validation and Review
                description: |
                  Regularly review and validate outputs with automated tools and human oversight to detect and mitigate unintended disclosures.
                inPlace: false
                public: false
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            fullyMitigated: false
          - ID: LLM03_SUPPLY_CHAIN
            title: Supply Chain Risks
            threatType: Supply Chain Attack
            impactDesc: |
              Vulnerabilities in third-party models, datasets, or fine-tuning processes may compromise the integrity of the LLM.
            attack: |
              Attackers tamper with third-party components or training data during procurement or integration, introducing malicious modifications that undermine model security.
            impactedSecObj:
              - REFID: MODEL_INTEGRITY
              - REFID: COMPLIANCE
            attackers:
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: SUPPLIER_AUDIT
                title: Third-Party Supplier Audit
                description: |
                  Regularly audit and verify the security posture of suppliers, including models, datasets, and fine-tuning tools, to ensure compliance with security standards.
                inPlace: true
                public: true
              - ID: SBOM_INTEGRATION
                title: Software Bill of Materials (SBOM)
                description: |
                  Implement SBOM practices to document and monitor all third-party components, ensuring timely updates and vulnerability management.
                inPlace: false
                public: false
              - ID: INTEGRITY_CHECKS
                title: Model and Data Integrity Checks
                description: |
                  Perform cryptographic integrity validations and provenance checks on models and datasets before deployment.
                inPlace: true
                public: true
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            fullyMitigated: false
          - ID: LLM04_DATA_MODEL_POISONING
            title: Data and Model Poisoning
            threatType: Integrity Attack
            impactDesc: |
              Malicious alteration of training data or fine-tuning processes can introduce biases, backdoors, or degrade model performance.
            attack: |
              Attackers inject adversarial or manipulated data into the training pipeline to compromise model outputs, causing systemic errors or hidden vulnerabilities.
            impactedSecObj:
              - REFID: MODEL_INTEGRITY
              - REFID: DATA_PROTECTION
              - REFID: COMPLIANCE
            attackers:
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: TRAINING_DATA_VALIDATION
                title: Rigorous Training Data Validation
                description: |
                  Validate and verify the provenance and integrity of all training and fine-tuning datasets using version control and anomaly detection.
                inPlace: true
                public: true
              - ID: RED_TEAMING
                title: Regular Red Teaming Exercises
                description: |
                  Conduct red team exercises to simulate poisoning attacks and identify vulnerabilities in the training pipeline.
                inPlace: false
                public: false
              - ID: PIPELINE_MONITORING
                title: Continuous Pipeline Monitoring
                description: |
                  Implement real-time monitoring and logging of training pipelines to quickly detect anomalies indicative of data poisoning.
                inPlace: true
                public: true
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            fullyMitigated: false
          - ID: LLM05_IMPROPER_OUTPUT_HANDLING
            title: Improper Output Handling
            threatType: Information Disclosure/Manipulation
            impactDesc: |
              Improperly formatted or unfiltered outputs can disclose sensitive data or be manipulated to mislead end users.
            attack: |
              Exploiting weak output controls, an attacker may trigger the model to emit outputs that reveal confidential information or misrepresent data.
            impactedSecObj:
              - REFID: DATA_PROTECTION
              - REFID: COMPLIANCE
              - REFID: ACCESS_CONTROL
            attackers:
              - REFID: MALICIOUS_USER
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: OUTPUT_FORMAT_ENFORCEMENT
                title: Enforce Standardized Output Formats
                description: |
                  Define and enforce deterministic output formats with strict validation rules to ensure consistency and prevent data leaks.
                inPlace: true
                public: true
              - ID: HUMAN_REVIEW
                title: Human-in-the-Loop Review
                description: |
                  Integrate manual review processes for high-risk outputs to provide an additional layer of verification.
                inPlace: false
                public: false
              - ID: AUTOMATED_MONITORING
                title: Automated Output Monitoring
                description: |
                  Deploy automated monitoring solutions to continuously analyze model outputs and detect deviations from expected patterns.
                inPlace: true
                public: true
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            fullyMitigated: false
          - ID: LLM06_EXCESSIVE_AGENCY
            title: Excessive Agency
            threatType: Over-Automation/Control
            impactDesc: |
              Granting excessive autonomy to LLM-driven agents can lead to unauthorized actions or unintended system modifications.
            attack: |
              An attacker exploits overly permissive agent configurations or permissions to drive the LLM into executing tasks without proper oversight.
            impactedSecObj:
              - REFID: ACCESS_CONTROL
              - REFID: COMPLIANCE
              - REFID: MODEL_INTEGRITY
            attackers:
              - REFID: MALICIOUS_USER
            countermeasures:
              - ID: LEAST_PRIVILEGE_AGENCY
                title: Enforce Least Privilege for Autonomous Agents
                description: |
                  Restrict agent permissions strictly to only those functions necessary for operation, and monitor for deviations.
                inPlace: true
                public: true
              - ID: HUMAN_IN_THE_LOOP
                title: Human-in-the-Loop Controls
                description: |
                  Integrate manual approval for high-risk agent actions to ensure human oversight over autonomous decisions.
                inPlace: false
                public: false
              - ID: PERMISSION_AUDITS
                title: Regular Permission Audits
                description: |
                  Conduct periodic audits of agent permissions and operational logs to verify adherence to security policies.
                inPlace: true
                public: false
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            fullyMitigated: false
          - ID: LLM07_SYSTEM_PROMPT_LEAKAGE
            title: System Prompt Leakage
            threatType: Information Disclosure
            impactDesc: |
              Leakage of internal system prompts or configuration details can enable attackers to reverse-engineer or subvert LLM behavior.
            attack: |
              An attacker gains access to internal system prompt data through vulnerabilities in prompt management or inadequate access controls.
            impactedSecObj:
              - REFID: DATA_PROTECTION
              - REFID: ACCESS_CONTROL
              - REFID: MODEL_INTEGRITY
            attackers:
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: PROMPT_ISOLATION
                title: Secure Prompt Isolation
                description: |
                  Isolate system prompts from user-facing interfaces and restrict access using strong authentication and access controls.
                inPlace: true
                public: true
              - ID: ACCESS_LOGGING
                title: Detailed Prompt Access Logging
                description: |
                  Maintain comprehensive logs of all accesses to system prompt data to detect and investigate potential breaches.
                inPlace: true
                public: false
              - ID: REGULAR_AUDITS
                title: Regular Security Audits for Prompts
                description: |
                  Conduct periodic audits of prompt storage and management systems to ensure no leakage of sensitive information.
                inPlace: false
                public: false
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            fullyMitigated: false
          - ID: LLM08_VECTOR_EMBEDDING_WEAKNESS
            title: Vector and Embedding Weaknesses
            threatType: Information Disclosure
            impactDesc: |
              Vulnerabilities in the storage and retrieval of vector embeddings can lead to the unintended disclosure of sensitive context or data.
            attack: |
              An attacker exploits insecure embedding databases or indexing methods to extract sensitive information from vector representations.
            impactedSecObj:
              - REFID: DATA_PROTECTION
              - REFID: ACCESS_CONTROL
              - REFID: MODEL_INTEGRITY
            attackers:
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: ENCRYPT_EMBEDDINGS
                title: Encrypt Embedding Storage
                description: |
                  Apply strong encryption to embedding databases and enforce robust authentication controls.
                inPlace: true
                public: true
              - ID: SECURE_INDEXING
                title: Implement Secure Indexing
                description: |
                  Use secure indexing and query mechanisms to restrict unauthorized access to embeddings.
                inPlace: true
                public: false
              - ID: EMBEDDING_ACCESS_CONTROL
                title: Enforce Embedding Access Controls
                description: |
                  Implement role-based access control for embedding data to limit exposure to only authorized users.
                inPlace: true
                public: true
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            fullyMitigated: false
          - ID: LLM09_MISINFORMATION
            title: Misinformation
            threatType: Manipulation
            impactDesc: |
              Generation of biased or false outputs can mislead users and adversely affect decision-making processes.
            attack: |
              Attackers manipulate training data or craft adversarial prompts to induce the LLM to produce misleading or harmful outputs.
            impactedSecObj:
              - REFID: MODEL_INTEGRITY
              - REFID: COMPLIANCE
              - REFID: DATA_PROTECTION
            attackers:
              - REFID: MALICIOUS_USER
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: OUTPUT_CROSS_VALIDATION
                title: Validate Outputs Against Trusted Sources
                description: |
                  Implement mechanisms to cross-check LLM outputs with trusted datasets and human review for critical decisions.
                inPlace: false
                public: true
              - ID: ADVERSARIAL_TRAINING
                title: Adversarial Training
                description: |
                  Regularly update and train the model with adversarial examples to improve resistance against manipulative inputs.
                inPlace: true
                public: true
              - ID: TRANSPARENCY_LOGS
                title: Maintain Transparency Logs
                description: |
                  Keep detailed logs of output generation processes to enable post-incident analysis and continuous improvement.
                inPlace: false
                public: false
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            fullyMitigated: false
        
          - ID: LLM10_UNBOUNDED_CONSUMPTION
            title: Unbounded Consumption
            threatType: Resource Exhaustion/DoS
            impactDesc: |
              Excessive or uncontrolled resource consumption may lead to service degradation, denial of service, and unanticipated cost escalations.
            attack: |
              An attacker triggers repeated or resource-intensive operations against the LLM system, exhausting computational resources and degrading performance.
            impactedSecObj:
              - REFID: RESILIENCE
              - REFID: COMPLIANCE
              - REFID: ACCESS_CONTROL
            attackers:
              - REFID: EXTERNAL_ATTACKER
            countermeasures:
              - ID: RATE_LIMITING
                title: Rate Limiting
                description: |
                  Implement rate limiting controls on requests to the LLM application to prevent abuse and resource exhaustion.
                inPlace: true
                public: true
              - ID: RESOURCE_MONITORING
                title: Continuous Resource Monitoring
                description: |
                  Deploy monitoring systems to track resource usage and trigger alerts when predefined thresholds are exceeded.
                inPlace: true
                public: true
              - ID: COST_MANAGEMENT
                title: Cost Management Practices
                description: |
                  Establish policies and automated alerts to manage and control operational costs associated with resource consumption.
                inPlace: false
                public: false
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
            fullyMitigated: false
        
          - ID: LLM14_DATA_RESIDENCY_VIOLATION
            title: Data Residency Violation
            threatType: Compliance Violation
            impactDesc: |
              Processing or storing data outside designated geographic boundaries could violate data residency requirements and regulations.
            attack: |
              System configuration or deployment type choices lead to data being processed or stored outside permitted geographic boundaries.
            impactedSecObj:
              - REFID: COMPLIANCE
              - REFID: DATA_PROTECTION
              - REFID: PRIVACY_PROTECTION
            attackers:
              - REFID: MALICIOUS_USER
            countermeasures:
              - ID: DEPLOYMENT_TYPE_CONTROL
                title: Deployment Type Control
                description: |
                  Carefully control use of Global and DataZone deployment types based on data residency requirements.
                inPlace: true
                public: true
              - ID: GEOGRAPHY_MONITORING
                title: Geographic Processing Monitoring
                description: |
                  Monitor and audit data processing locations to ensure compliance with residency requirements.
                inPlace: true
                public: true
              - ID: STORAGE_LOCATION_CONTROL
                title: Storage Location Control
                description: |
                  Ensure data at rest is stored only in approved geographic locations regardless of deployment type.
                inPlace: true
                public: true
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"
            fullyMitigated: false
        
          - ID: LLM15_ABUSE_MONITORING_BYPASS
            title: Abuse Monitoring System Bypass
            threatType: Detection Evasion
            impactDesc: |
              Bypassing abuse monitoring systems could allow generation of harmful content or violation of service terms.
            attack: |
              Attackers attempt to circumvent content filtering and abuse monitoring systems to generate prohibited content.
            impactedSecObj:
              - REFID: COMPLIANCE
              - REFID: MODEL_INTEGRITY
            attackers:
              - REFID: MALICIOUS_USER
            countermeasures:
              - ID: CONTENT_FILTERING
                title: Real-time Content Filtering
                description: |
                  Implement synchronous content filtering during prompt processing and content generation.
                inPlace: true
                public: true
              - ID: AI_REVIEW
                title: AI-based Review System
                description: |
                  Deploy AI systems to review prompts and completions for potential abuse patterns.
                inPlace: true
                public: true
              - ID: HUMAN_REVIEW
                title: Human Review Process
                description: |
                  Maintain authorized human reviewer access for flagged content with proper security controls.
                inPlace: true
                public: true
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
            fullyMitigated: false
        
          - ID: LLM16_FEATURE_DATA_EXPOSURE
            title: Feature Data Exposure
            threatType: Data Exposure
            impactDesc: |
              Improper handling of data stored for specific features (Assistants API, Batch processing, etc.) could lead to unauthorized access.
            attack: |
              Attackers target stored data used by specific Azure OpenAI features to gain unauthorized access.
            impactedSecObj:
              - REFID: DATA_PROTECTION
              - REFID: PRIVACY_PROTECTION
            attackers:
              - REFID: EXTERNAL_ATTACKER
              - REFID: MALICIOUS_USER
            countermeasures:
              - ID: DOUBLE_ENCRYPTION
                title: Double Encryption Implementation
                description: |
                  Implement double encryption at rest using AES-256 and optional customer managed keys.
                inPlace: true
                public: true
              - ID: FEATURE_ISOLATION
                title: Feature Data Isolation
                description: |
                  Ensure data for different features remains isolated and stored within appropriate geographic boundaries.
                inPlace: true
                public: true
              - ID: CUSTOMER_DELETION_CONTROL
                title: Customer Deletion Control
                description: |
                  Provide customers with ability to delete stored feature data at any time.
                inPlace: true
                public: true
            CVSS:
              vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N"
            fullyMitigated: false
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/OAuth2/Flows/Flows_ImplicitGrant/Flows_ImplicitGrant.yaml
        ```yaml
        #based on: https://datatracker.ietf.org/doc/html/rfc6819
        
        ID: Flows_ImplicitGrant
        title: Implicit Grant flow
        parent: Flows
        scope:
          description: |
            In the implicit grant type flow, the access token is directly
            returned to the client as a fragment part of the redirect URI. It is
            assumed that the token is not sent to the redirect URI target, as
            HTTP user agents do not send the fragment part of URIs to HTTP
            servers. Thus, an attacker cannot eavesdrop the access token on this
            communication path, and the token cannot leak through HTTP referrer
            headers.
        
          diagram:
        
        analysis:
        
         
        threats:
        
          - ID: 4_4_2_1_TOKEN_LEAK1_NETWORK
            title: Access Token Leak in Transport/Endpoints
            impactDesc: |
              The attacker would be able to assume the same rights granted
              by the token.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              This token might be eavesdropped by an attacker. The token is sent
              from the server to the client via a URI fragment of the redirect URI.
              If the communication is not secured or the endpoint is not secured,
              the token could be leaked by parsing the returned URI.
            countermeasures:
              - REFID: 5_1_1_CONFIDENTIAL_REQUESTS
        
            fullyMitigated: false
          - ID: 4_4_2_2_TOKEN_LEAK2_BROWSER_HISTORY
            title: Access Token Leak in Browser History
            impactDesc: |
              The attacker would be able to assume the same rights granted
              by the token. 
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker could obtain the token from the browser’s history. Note
              that this means the attacker needs access to the particular device.
            countermeasures:
              - REFID: 5_1_5_3_SHORT_EXPIRY_CODE
              - ID: NON_CACHEABLE_RESPONSES
                title: Make responses non-cacheable.
                description: |
                  Make responses non-cacheable.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
            fullyMitigated: false
        
          - ID: 4_4_2_2_TOKEN_LEAK2_BROWSER_HISTORY
            title: Malicious Client Obtains Authorization
            impactDesc: |
              The attacker would be able to assume the same rights granted
              by the token. 
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              A malicious client could attempt to obtain a token by fraud.
            countermeasures:
              - REFID: 5_2_3_5_VALIDATE_REDIRECT_URI
              - REFID: 5_2_4_3_VALIDATION_OF_CLIENT_BY_END_USER
              - REFID: 5_2_4_1_REPEAT_VALIDATE_CLIENT
              - REFID: REQUIRE_USER_MANUAL_STEP
              - REFID: 5_1_5_1_LIMITED_SCOPE_TOKEN
        
        
            fullyMitigated: false
          - ID: 4_4_2_4_MANIPULATION_SCRIPTS
            title: Manipulation of Scripts
            impactDesc: |
              The attacker could obtain user credential information and
              assume the full identity of the user.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              A hostile party could act as the client web server and replace or
              modify the actual implementation of the client (script). This could
              be achieved using DNS or ARP spoofing. This applies to clients
              implemented within the web browser in a scripting language.
        
            countermeasures:
              - REFID: 5_1_2_AUTH_SERVER_AUTHENTICATION
              - REFID: 5_1_1_CONFIDENTIAL_REQUESTS
              - ID: ONE_TIME_PER_USE_SECRET
                title: One-time, per-use secrets (e.g., "client_secret")
                description: |
                  Introduce one-time, per-use secrets (e.g., "client_secret") values
                  that can only be used by scripts in a small time window once
                  loaded from a server. The intention would be to reduce the
                  effectiveness of copying client-side scripts for re-use in an
                  attacker’s modified code.
                operational: true
                operator: CLIENT_OPERATOR
                inPlace: false
                public: true
            fullyMitigated: false
        
          - ID: 4_4_2_5_CSRF_IMPLICIT
            title: CSRF Attack against redirect-uri
            impactDesc: |
              The user accesses resources on behalf of the attacker. The
              effective impact depends on the type of resource accessed. For
              example, the user may upload private items to an attacker’s
              resources. Or, when using OAuth in 3rd-party login scenarios, the
              user may associate his client account with the attacker’s identity at
              the external Identity Provider. In this way, the attacker could
              easily access the victim’s data at the client by logging in from
              another device with his credentials at the external Identity
              Provider.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              CSRF attacks (see Section 4.4.1.8) also work against the redirect URI
              used in the implicit grant flow. An attacker could acquire an access
              token to their own protected resources. He could then construct a
              redirect URI and embed their access token in that URI. If he can
              trick the user into following the redirect URI and the client does
              not have protection against this attack, the user may have the
              attacker’s access token authorized within their client.
            fullyMitigated: false
            countermeasures:
        
              - ID: STATE_PARAM_VALIDATION
                title: Link the authorization request with the redirect URI (state param)
                description: |
                  The "state" parameter should be used to link the authorization
                  request with the redirect URI used to deliver the access token.
                  This will ensure that the client is not tricked into completing
                  any redirect callback unless it is linked to an authorization
                  request initiated by the client. The "state" parameter should not
                  be guessable, and the client should be capable of keeping the
                  "state" parameter secret.
                operational: true
                operator: CLIENT_OPERATOR
                inPlace: false
                public: true
              - REFID: USER_EDUCATION
        
          - ID: 4_4_2_6_TOKEN_SUBSTITUTION
            title: Token Substitution (OAuth Login)
            impactDesc: |
              The attacker gains access to an application and user-specific
               data within the application.
        
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker could attempt to log into an application or web site
              using a victim’s identity. Applications relying on identity data
              provided by an OAuth protected service API to login users are
              vulnerable to this threat. This pattern can be found in so-called
              "social login" scenarios.
              As a prerequisite, a resource server offers an API to obtain personal
              information about a user that could be interpreted as having obtained
              a user identity. In this sense, the client is treating the resource
              server API as an "identity" API. A client utilizes OAuth to obtain
              an access token for the identity API. It then queries the identity
              API for an identifier and uses it to look up its internal user
              account data (login). The client assumes that, because it was able
              to obtain information about the user, the user has been
              authenticated.
              To succeed, the attacker needs to gather a valid access token of the
              respective victim from the same Identity Provider used by the target
              client application. The attacker tricks the victim into logging into
              a malicious app (which may appear to be legitimate to the Identity
              Provider) using the same Identity Provider as the target application.
              This results in the Identity Provider’s authorization server issuing
              an access token for the respective identity API. The malicious app
              then sends this access token to the attacker, which in turn triggers
              a login process within the target application. The attacker now
              manipulates the authorization response and substitutes their access
              token (bound to their identity) for the victim’s access token. This
              token is accepted by the identity API, since the audience, with
              respect to the resource server, is correct. But since the identifier
              returned by the identity API is determined by the identity in the
              access token, the attacker is logged into the target application
              under the victim’s identity.
            fullyMitigated: false
            countermeasures:
              - REFID: SECURE_USER_LOGIN_PROTOCOL
        
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/OAuth2/Flows/Flows_AuthCode/Flows_AuthCode.yaml
        ```yaml
        #based on: https://datatracker.ietf.org/doc/html/rfc6819
        
        ID: Flows_AuthCode
        title: Authorization "code" flow
        parent: Flows
        scope:
          description: "Authorization \"code\" flow The authorization code is obtained by
            using an authorization server as an intermediary between the client and resource
            owner.  Instead of requesting authorization directly from the resource owner,
            the client directs the resource owner to an authorization server (via its user-agent
            as defined in [RFC2616]), which in turn directs the resource owner back to the
            client with the authorization code.\nBefore directing the resource owner back
            to the client with the authorization code, the authorization server authenticates
            the resource owner and obtains authorization.  Because the resource owner only
            authenticates with the authorization server, the resource owner's credentials
            are never shared with the client.\nThe authorization code provides a few important
            security benefits, such as the ability to authenticate the client, as well as
            the transmission of the access token directly to the client without passing it
            through the resource owner's user-agent and potentially exposing it to others,
            including the resource owner.\n**Implicit**\nThe implicit grant is a simplified
            authorization code flow optimized for clients implemented in a browser using a
            scripting language such as JavaScript.  In the implicit flow, instead of issuing
            the client an authorization code, the client is issued an access token directly
            (as the result of the resource owner authorization).  The grant type is implicit,
            as no intermediate credentials (such as an authorization code) are issued (and
            later used to obtain an access token).\nWhen issuing an access token during the
            implicit grant flow, the authorization server does not authenticate the client.\
            \  In some cases, the client identity can be verified via the redirection URI
            used to deliver the access token to the client.  The access token may be exposed
            to the resource owner or other applications with access to the resource owner's
            user-agent.\nImplicit grants improve the responsiveness and efficiency of some
            clients (such as a client implemented as an in-browser application), since it
            reduces the number of round trips required to obtain an access token.  However,
            this convenience should be weighed against the security implications of using
            implicit grants, such as those described in Sections 10.3 and 10.16, especially
            when the authorization code grant type is available."
          diagram:
        
          assets:
            - ID: DF_AUTH_CODE_AS
              type: dataflow
              title: Auth code is returned to the User Agent from the AUTH_SERVER
              description: |
                AUTH_SERVER response 30x (redirect)
                Assuming the resource owner grants access, the authorization
                server redirects the user-agent back to the client using the
                redirection URI provided earlier (in the request or during
                client registration).  The redirection URI includes an
                authorization code and any local state provided by the client
                earlier.
              inScope: true
        
            - ID: DF_AUTH_CODE_CLI
              type: dataflow
              title: Auth code redirected to the CLIENT
              description: |
                USER_AGENT request (redirected from DF_AUTH_CODE_AS 30x response)
                Assuming the resource owner grants access, the authorization
                server redirects the user-agent back to the client using the
                redirection URI provided earlier (in the request or during
                client registration).  The redirection URI includes an
                authorization code and any local state provided by the client
                earlier.
              inScope: true
        
        
        
            # - ID: AUTH_SERVER_AUTH_ENDPOINT
            #   type: endpoint
            #   title: Authorization endpoint for resource owner
            #   description: |
            #     Authorization server's endpoint for DF_AUTH_REDIRECT
            #   inScope: true
        
        
          assumptions:
            - ID: USER_AGENT_PROTECTION1
              description: |
                It is not the task of the authorization server to protect
                 the end-user’s device from malicious software. This is the
                 responsibility of the platform running on the particular device,
                 probably in cooperation with other components of the respective
                 ecosystem (e.g., an application management infrastructure). The sole
                 responsibility of the authorization server is to control access to
                 the end-user’s resources maintained in resource servers and to
                 prevent unauthorized access to them via the OAuth protocol. Based on
                 this assumption, the following countermeasures are available to cope
                 with the threat. (REF: 4.4.1.4)
          attackers:
            # - ID: ANONYMOUS
            #   description: |
            #     Anonymous internet user
            #   inScope: true
        
            # - ID: CLIENT
            #   description: |
            #     Client app
            #   inScope: true
        analysis:
        
         
        threats:
        
          - ID: 4_4_1_1_AUTH_CODE_DISCLOSURE
            title: Eavesdropping or Leaking Authorization codes
            impactDesc: |
              Auth codes can be used to 
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker could try to eavesdrop transmission of the authorization
              "code" between the authorization server and client. Furthermore,
              authorization "codes" are passed via the browser, which may
              unintentionally leak those codes to untrusted web sites and attackers
              in different ways:
              <br/>o Referrer headers: Browsers frequently pass a "referer" header when
              a web page embeds content, or when a user travels from one web
              page to another web page. These referrer headers may be sent even
              when the origin site does not trust the destination site. The
              referrer header is commonly logged for traffic analysis purposes.
              <br/>o Request logs: Web server request logs commonly include query
              parameters on requests.
              <br/>o Open redirectors: Web sites sometimes need to send users to
              another destination via a redirector. Open redirectors pose a
              particular risk to web-based delegation protocols because the
              redirector can leak verification codes to untrusted destination
              sites.
              <br/>o Browser history: Web browsers commonly record visited URLs in the
              browser history. Another user of the same web browser may be able
              to view URLs that were visited by previous users.
              Note: A description of similar attacks on the SAML protocol can be
              found at [OASIS.sstc-saml-bindings-1.1], Section 4.1.1.9.1;
              [Sec-Analysis]; and [OASIS.sstc-sec-analysis-response-01].
        
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_1_1_CONFIDENTIAL_REQUESTS
              - ID: 5_2_4_4_CLIENT_TO_CODE_BINDING
                title: Binding of Authorization "code" to "client_id"
                description: |
                  The authorization server should bind every authorization "code" to
                  the id of the respective client that initiated the end-user
                  authorization process. This measure is a countermeasure against:
                  <br/>o Replay of authorization "codes" with different client credentials,
                  since an attacker cannot use another "client_id" to exchange an
                  authorization "code" into a token
                  <br/>o Online guessing of authorization "codes"
                  Note: This binding should be protected from unauthorized
                  modifications (e.g., using protected memory and/or a secure
                  database).
                  Also:
                  The authorization server will require the client to authenticate
                  wherever possible, so the binding of the authorization "code" to a
                  certain client can be validated in a reliable way (see
                  Section 5.2.4.4).
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: true
                public: true
        
              - ID: 5_1_5_3_SHORT_EXPIRY_CODE
                title: Use Short Expiration Time
                description: |
                  A short expiration time for tokens is a means of protection against
                  the following threats:
                  <br/>o replay
                  <br/>o token leak (a short expiration time will reduce impact)
                  <br/>o online guessing (a short expiration time will reduce the
                  likelihood of success)
                  Note: Short token duration requires more precise clock
                  synchronization between the authorization server and resource server.
                  Furthermore, shorter duration may require more token refreshes
                  (access token) or repeated end-user authorization processes
                  (authorization "code" and refresh token).
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
              - ID: 5_1_5_4_ONE_TIME_USE_TOKEN
                title: Limit Number of Usages or One-Time Usage
                description: |
                  The authorization server may restrict the number of requests or
                  operations that can be performed with a certain token. This
                  mechanism can be used to mitigate the following threats:
                  <br/>o replay of tokens
                  <br/>o guessing
                  For example, if an authorization server observes more than one
                  attempt to redeem an authorization "code", the authorization server
                  may want to revoke all access tokens granted based on the
                  authorization "code" as well as reject the current request.
                  As with the authorization "code", access tokens may also have a
                  limited number of operations. This either forces client applications
                  to re-authenticate and use a refresh token to obtain a fresh access
                  token, or forces the client to re-authorize the access token by
                  involving the user.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
              - ID: 5_2_1_1_TOKEN_ABUSE_DETECTION
                title: Automatic Revocation of Derived Tokens If Abuse Is Detected
                description: |
                  If an authorization server observes multiple attempts to redeem an
                  authorization grant (e.g., such as an authorization "code"), the
                  authorization server may want to revoke all tokens granted based on
                  the authorization grant
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
              - ID: USER_AGENT_PAGE_RELOAD
                title: Reload the target page
                description: |
                  The client server may reload the target page of the redirect URI
                  in order to automatically clean up the browser cache.
                operational: true
                operator: CLIENT_OPERATOR
                inPlace: false
                public: true
        
        
        
          - ID: 4_4_1_2_AUTH_CODE_DISCLOSURE_DB
            title: Obtaining Authorization codes from AuthorizationServer Database
            impactDesc: |
              Disclosure of all authorization "codes", most likely along
               with the respective "redirect_uri" and "client_id" values.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTH_SERVER
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              This threat is applicable if the authorization server stores
               authorization "codes" as handles in a database. An attacker may
               obtain authorization "codes" from the authorization server’s database
               by gaining access to the database or launching a SQL injection
               attack.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_1_4_1_1_SYS_SEC
              - REFID: 5_1_4_1_2_SQL_SEC
              - REFID: 5_1_4_1_3_HASHED_TOKEN_DB
        
        
          - ID: 4_4_1_3_AUTH_CODE_BRUTE_FORCE
            title: Online Guessing of Authorization codes
            impactDesc: |
              Disclosure of a single access token and probably also an
               associated refresh token.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: AUTHORIZATION_GRANT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker may try to guess valid authorization "code" values and
               send the guessed code value using the grant type "code" in order to
               obtain a valid access token.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_1_4_2_2_HIGH_ENTROPY_SECRETS
              - ID: 5_1_5_9_SIGNED_TOKEN
                title: Sign Self-Contained Tokens
                description: |
                  Self-contained tokens should be signed in order to detect any attempt
                  to modify or produce faked tokens (e.g., Hash-based Message
                  Authentication Code or digital signatures).
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
              - REFID: 5_2_3_4_SPECIFIC_CLIENT_SECRETS
              - ID: 5_2_4_5_REDIRECT_CODE_BINDING
                title: Binding of Authorization "code" to "redirect_uri"
                description: |
                  The authorization server should be able to bind every authorization
                  "code" to the actual redirect URI used as the redirect target of the
                  client in the end-user authorization process. This binding should be
                  validated when the client attempts to exchange the respective
                  authorization "code" for an access token. This measure is a
                  countermeasure against authorization "code" leakage through
                  counterfeit web sites, since an attacker cannot use another redirect
                  URI to exchange an authorization "code" into a token.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
              - REFID: 5_1_5_3_SHORT_EXPIRY_CODE
        
        
          - ID: 4_4_1_4_CLIENT_SPOOFING1
            title: Malicious Client Obtains Authorization
            impactDesc: |
              Disclosure of a single access token and probably also an associated refresh token.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              # - REFID: USER_AGENT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              A malicious client could pretend to be a valid client and obtain an
              access authorization in this way. The malicious client could even
              utilize screen-scraping techniques in order to simulate a user’s
              consent in the authorization flow.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_2_3_4_SPECIFIC_CLIENT_SECRETS
              - REFID: 5_2_3_5_VALIDATE_REDIRECT_URI
              - ID: 5_2_4_3_VALIDATION_OF_CLIENT_BY_END_USER
                title: Validation of Client Properties by End User
                description: |
                  In the authorization process, the user is typically asked to approve
                  a client’s request for authorization. This is an important security
                  mechanism by itself because the end user can be involved in the
                  validation of client properties, such as whether the client name
                  known to the authorization server fits the name of the web site or
                  the application the end user is using. This measure is especially
                  helpful in situations where the authorization server is unable to
                  authenticate the client. It is a countermeasure against:
                  <br/>o A malicious application
                  <br/>o A client application masquerading as another client
                operational: true
                operator: RESOURCE_OWNER
                inPlace: false
                public: true
        
              - ID: 5_2_4_1_REPEAT_VALIDATE_CLIENT
                title: Automatic Processing of Repeated Authorizations Requires Client Validation
                description: |
                  Authorization servers should NOT automatically process repeat
                  authorizations where the client is not authenticated through a client
                  secret or some other authentication mechanism such as a signed
                  authentication assertion certificate (Section 5.2.3.7) or validation
                  of a pre-registered redirect URI (Section 5.2.3.5).
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
              - ID: REQUIRE_USER_MANUAL_STEP
                title: Automatic Processing of Repeated Authorizations Requires Client Validation
                description: |
                  If the authorization server automatically authenticates the end
                  user, it may nevertheless require some user input in order to
                  prevent screen scraping. Examples are CAPTCHAs (Completely
                  Automated Public Turing tests to tell Computers and Humans Apart)
                  or other multi-factor authentication techniques such as random
                  questions, token code generators, etc.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
              - ID: 5_1_5_1_LIMITED_SCOPE_TOKEN
                title: Limit Token Scope
                description: |
                  The authorization server may decide to reduce or limit the scope
                  associated with a token. The basis of this decision is out of scope;
                  examples are:
        
                  <br/>o a client-specific policy, e.g., issue only less powerful tokens to
                  public clients,
                  <br/>o a service-specific policy, e.g., it is a very sensitive service,
                  <br/>o a resource-owner-specific setting, or
                  <br/>o combinations of such policies and preferences.
        
                  The authorization server may allow different scopes dependent on the
                  grant type. For example, end-user authorization via direct
                  interaction with the end user (authorization "code") might be
                  considered more reliable than direct authorization via grant type
                  "username"/"password". This means will reduce the impact of the
                  following threats:
                  <br/>o token leakage
                  <br/>o token issuance to malicious software
                  <br/>o unintended issuance of powerful tokens with resource owner
                  credentials flow
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
          - ID: 4_4_1_5_CLIENT_SPOOFING2
            title: Authorization code Phishing
            impactDesc: |
              This affects web applications and may lead to a disclosure of
              authorization "codes" and, potentially, the corresponding access and
              refresh tokens.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              # - REFID: USER_AGENT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              A hostile party could impersonate the client site and get access to
              the authorization "code". This could be achieved using DNS or ARP
              spoofing. This applies to clients, which are web applications; thus,
              the redirect URI is not local to the host where the user’s browser is
              running.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_1_2_AUTH_SERVER_AUTHENTICATION
              - REFID: 5_2_4_4_CLIENT_TO_CODE_BINDING
        
        
        
          - ID: 4_4_1_6_CLIENT_SPOOFING3
            title: Authorization code Phishing
            impactDesc: |
              An attacker who intercepts the authorization "code" as it is
              sent by the browser to the callback endpoint can gain access to
              protected resources by submitting the authorization "code" to the
              client. The client will exchange the authorization "code" for an
              access token and use the access token to access protected resources
              for the benefit of the attacker, delivering protected resources to
              the attacker, or modifying protected resources as directed by the
              attacker. If OAuth is used by the client to delegate authentication
              to a social site (e.g., as in the implementation of a "Login" button
              on a third-party social network site), the attacker can use the
              intercepted authorization "code" to log into the client as the user.
              Note: Authenticating the client during authorization "code" exchange
              will not help to detect such an attack, as it is the legitimate
              client that obtains the tokens.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              # - REFID: USER_AGENT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              A hostile party could impersonate the client site and impersonate the
              user’s session on this client. This could be achieved using DNS or
              ARP spoofing. This applies to clients, which are web applications;
              thus, the redirect URI is not local to the host where the user’s
              browser is running.
        
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_1_2_AUTH_SERVER_AUTHENTICATION
        
        
        
          - ID: 4_4_1_7_CLIENT_SPOOFING4
            title: Authorization code Leakage through Counterfeit Client
        
            impactDesc: |
              The attacker gains access to the victim’s resources as associated with his account on the client site.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
              - REFID: NON_REPUDIATION
            assets:
              # - REFID: 
            attackers:
              - REFID: CLIENT_OPERATOR
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              The attacker leverages the authorization "code" grant type in an
              attempt to get another user (victim) to log in, authorize access to
              his/her resources, and subsequently obtain the authorization "code"
              and inject it into a client application using the attacker’s account.
              The goal is to associate an access authorization for resources of the
              victim with the user account of the attacker on a client site.
              The attacker abuses an existing client application and combines it
              with his own counterfeit client web site. The attacker depends on
              the victim expecting the client application to request access to a
              certain resource server. The victim, seeing only a normal request
              from an expected application, approves the request. The attacker
              then uses the victim’s authorization to gain access to the
              information unknowingly authorized by the victim.
              The attacker conducts the following flow:
        
              1. The attacker accesses the client web site (or application) and
              initiates data access to a particular resource server. The
              client web site in turn initiates an authorization request to the
              resource server’s authorization server. Instead of proceeding
              with the authorization process, the attacker modifies the
              authorization server end-user authorization URL as constructed by
              the client to include a redirect URI parameter referring to a web
              site under his control (attacker’s web site).
        
              2. The attacker tricks another user (the victim) into opening that
              modified end-user authorization URI and authorizing access (e.g.,
              via an email link or blog link). The way the attacker achieves
              this goal is out of scope.
        
              3. Having clicked the link, the victim is requested to authenticate
              and authorize the client site to have access.
        
              4. After completion of the authorization process, the authorization
              server redirects the user agent to the attacker’s web site
              instead of the original client web site.
        
              5. The attacker obtains the authorization "code" from his web site
              by means that are out of scope of this document.
        
              6. He then constructs a redirect URI to the target web site (or
              application) based on the original authorization request’s
              redirect URI and the newly obtained authorization "code", and
              directs his user agent to this URL. The authorization "code" is
              injected into the original client site (or application).
        
              7. The client site uses the authorization "code" to fetch a token
              from the authorization server and associates this token with the
              attacker’s user account on this site.
        
              8. The attacker may now access the victim’s resources using the
              client site.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_2_4_5_REDIRECT_CODE_BINDING
              - REFID: 5_2_3_4_SPECIFIC_CLIENT_SECRETS
              - REFID: 5_2_4_4_CLIENT_TO_CODE_BINDING
              - ID: IMPLICIT_GRANT_FLOW
                title: Implicit grant flow
                description: |
                  The client may consider using other flows that are not vulnerable
                  to this kind of attack, such as the implicit grant type (see
                  Section 4.4.2) or resource owner password credentials (see
                  Section 4.4.3).
                operational: false
                # operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
        
          - ID: 4_4_1_8_CSRF_ON_REDIRECT
            title: CSRF Attack against redirect-uri
            impactDesc: |
              The user accesses resources on behalf of the attacker. The
              effective impact depends on the type of resource accessed. For
              example, the user may upload private items to an attacker’s
              resources. Or, when using OAuth in 3rd-party login scenarios, the
              user may associate his client account with the attacker’s identity at
              the external Identity Provider. In this way, the attacker could
              easily access the victim’s data at the client by logging in from
              another device with his credentials at the external Identity
              Provider.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: NON_REPUDIATION
            assets:
              - REFID: DF_AUTH_REDIRECT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
            threatType: Spoofing, Repudiation, Information Disclosure
            attack: |
              Cross-site request forgery (CSRF) is a web-based attack whereby HTTP
              requests are transmitted from a user that the web site trusts or has
              authenticated (e.g., via HTTP redirects or HTML forms). CSRF attacks
              on OAuth approvals can allow an attacker to obtain authorization to
              OAuth protected resources without the consent of the user.
              This attack works against the redirect URI used in the authorization
              "code" flow. An attacker could authorize an authorization "code" to
              their own protected resources on an authorization server. He then
              aborts the redirect flow back to the client on his device and tricks
              the victim into executing the redirect back to the client. The
              client receives the redirect, fetches the token(s) from the
              authorization server, and associates the victim’s client session with
              the resources accessible using the token.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - ID: 5_3_5_ANTI_CSRF_STATE_PARAM
                title: Link the state Parameter to User Agent Session (anti CSRF)
                description: The "state" parameter is used to link client requests and prevent
                  CSRF attacks, for example, attacks against the redirect URI. An attacker
                  could inject their own authorization "code" or access token, which can result
                  in the client using an access token associated with the attacker’s protected
                  resources rather than the victim’s (e.g., save the victim’s bank account
                  information to a protected resource controlled by the attacker). The client
                  should utilize the "state" request parameter to send the authorization server
                  a value that binds the request to the user agent’s authenticated state (e.g.,
                  a hash of the session cookie used to authenticate the user agent) when making
                  an authorization request. Once authorization has been obtained from the
                  end user, the authorization server redirects the end-user’s user agent back
                  to the client with the required binding value contained in the "state" parameter.
                  The binding value enables the client to verify the validity of the request
                  by matching the binding value to the user agent’s authenticated state.
                operational: true
                operator: CLIENT_OPERATOR
                inPlace: false
                public: true
              - ID: USER_EDUCATION
                title: Users can be educated to not follow untrusted URLs
                description: |
                  Client developers and end users can be educated to not follow
                  untrusted URLs.    
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
        
          - ID: 4_4_1_9_CLICKJACKING
            title: Clickjacking Attack against Authorization
        
            impactDesc: |
              An attacker can steal a user’s authentication credentials and access their resources.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: NON_REPUDIATION
            assets:
              - REFID: DF_AUTH_REDIRECT
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
            threatType: Spoofing, Repudiation, Information Disclosure
            attack: |
              With clickjacking, a malicious site loads the target site in a
              transparent iFrame (see [iFrame]) overlaid on top of a set of dummy
              buttons that are carefully constructed to be placed directly under
              important buttons on the target site. When a user clicks a visible
              button, they are actually clicking a button (such as an "Authorize"
              button) on the hidden page.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - ID: 5_2_2_6_X_FRAME_OPTION
                title: Link the state Parameter to User Agent Session (anti CSRF)
                description: |
                  For newer browsers, avoidance of iFrames can be enforced on the
                    server side by using the X-FRAME-OPTIONS header (see
                    [X-Frame-Options]). This header can have two values, "DENY" and
                    "SAMEORIGIN", which will block any framing or any framing by sites
                    with a different origin, respectively. The value "ALLOW-FROM"
                    specifies a list of trusted origins that iFrames may originate from.
                     This is a countermeasure against the following threat:
        
                    o Clickjacking attacks
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
              - ID: FRAMEBUSTING
                title: JavaScript frame-busting
                description: |
                  For older browsers, JavaScript frame-busting (see [Framebusting])
                  techniques can be used but may not be effective in all browsers. 
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
          - ID: 4_4_1_10_RESOURCE_OWNER_SPOOFING1
            title: Resource Owner Impersonation
            # impact: |
            #   An attacker can steal a user’s authentication credentials and access their resources.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: NON_REPUDIATION
            assets:
              - REFID: DF_AUTH_REDIRECT
            attackers:
              - REFID: CLIENT_OPERATOR
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
            threatType: Spoofing, Repudiation, Information Disclosure
            attack: |
              When a client requests access to protected resources, the
              authorization flow normally involves the resource owner’s explicit
              response to the access request, either granting or denying access to
              the protected resources. A malicious client can exploit knowledge of
              the structure of this flow in order to gain authorization without the
              resource owner’s consent, by transmitting the necessary requests
              programmatically and simulating the flow against the authorization
              server. That way, the client may gain access to the victim’s
              resources without her approval. An authorization server will be
              vulnerable to this threat if it uses non-interactive authentication
              mechanisms or splits the authorization flow across multiple pages.
              The malicious client might embed a hidden HTML user agent, interpret
              the HTML forms sent by the authorization server, and automatically
              send the corresponding form HTTP POST requests. As a prerequisite,
              the attacker must be able to execute the authorization process in the
              context of an already-authenticated session of the resource owner
              with the authorization server. There are different ways to achieve
              this:
        
              o The malicious client could abuse an existing session in an
              external browser or cross-browser cookies on the particular
              device.
        
                o The malicious client could also request authorization for an
              initial scope acceptable to the user and then silently abuse the
              resulting session in his browser instance to "silently" request
              another scope.
        
              o Alternatively, the attacker might exploit an authorization
              server’s ability to authenticate the resource owner automatically
              and without user interactions, e.g., based on certificates.
              In all cases, such an attack is limited to clients running on the
              victim’s device, either within the user agent or as a native app.
              Please note: Such attacks cannot be prevented using CSRF
              countermeasures, since the attacker just "executes" the URLs as
              prepared by the authorization server including any nonce, etc.
        
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - ID: INTERACTIVE_APPROVAL
                title: Interactive (non automatic) user approval
                description: |
                  Authorization servers should decide, based on an analysis of the risk
                  associated with this threat, whether to detect and prevent this
                  threat.
                  In order to prevent such an attack, the authorization server may
                  force a user interaction based on non-predictable input values as
                  part of the user consent approval. The authorization server could
        
                  o combine password authentication and user consent in a single form,
        
                  o make use of CAPTCHAs, or
        
                  o use one-time secrets sent out of band to the resource owner (e.g.,
                  via text or instant message).
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
              - ID: NOTIFY_APPROVAL
                title: Notify User's approval
                description: |
                  In order to allow the resource owner to detect abuse,
                  the authorization server could notify the resource owner of any
                  approval by appropriate means, e.g., text or instant message, or
                  email.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
          - ID: 4_4_1_11_DOS_TOKEN_ENTROPY
            title: Resource Owner Impersonation
            # impact: |
            #   An attacker can steal a user’s authentication credentials and access their resources.
            impactedSecObj:
              - REFID: AVAILABILITY
            assets:
              - REFID: DF_AUTH_REDIRECT
            attackers:
              - REFID: CLIENT_OPERATOR
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
            threatType: Denial of Service
            attack: |
              If an authorization server includes a nontrivial amount of entropy in
               authorization "codes" or access tokens (limiting the number of
               possible codes/tokens) and automatically grants either without user
               intervention and has no limit on codes or access tokens per user, an
               attacker could exhaust the pool of authorization "codes" by
               repeatedly directing the user’s browser to request authorization
                "codes" or access tokens.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - ID: AUTH_SERVER_PER_USER_LIMIT
                title: Limit access tokens granted per user
                description: |
                  The authorization server should consider limiting the number of
                  access tokens granted per user.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
              - ID: AUTH_CODE_HIGH_ENTROPY
                title: High entropy codes
                description: |
                  The authorization server should include a nontrivial amount of
                  entropy in authorization "codes".
                operational: false
                # operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
          - ID: 4_4_1_12_DOS2
            title: DoS Using Manufactured Authorization "codes"
            impactDesc: |
              There are a few effects that the attacker can accomplish with
              this OAuth flow that they cannot easily achieve otherwise.
              1. Connection laundering: With the clients as the relay between the
              attacker and the authorization server, the authorization server
              learns little or no information about the identity of the
              attacker. Defenses such as rate-limiting on the offending
              attacker machines are less effective because it is difficult to
              identify the attacking machines. Although an attacker could also
              launder its connections through an anonymizing system such as
              Tor, the effectiveness of that approach depends on the capacity
              of the anonymizing system. On the other hand, a potentially
              large number of OAuth clients could be utilized for this attack.
              2. Asymmetric resource utilization: The attacker incurs the cost of
              an HTTP connection and causes an HTTPS connection to be made on
              the authorization server; the attacker can coordinate the timing
              of such HTTPS connections across multiple clients relatively
              easily. Although the attacker could achieve something similar,
              say, by including an iFrame pointing to the HTTPS URL of the
              authorization server in an HTTP web page and luring web users to
              visit that page, timing attacks using such a scheme may be more
              difficult, as it seems nontrivial to synchronize a large number
              of users to simultaneously visit a particular site under the
              attacker’s control.
            impactedSecObj:
              - REFID: AVAILABILITY
            assets:
              - REFID: AUTH_SERVER
            attackers:
              - REFID: CLIENT_OPERATOR
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H
            threatType: Denial of Service
            attack: |
              An attacker who owns a botnet can locate the redirect URIs of clients
               that listen on HTTP, access them with random authorization "codes",
               and cause a large number of HTTPS connections to be concentrated onto
               the authorization server. This can result in a denial-of-service
               (DoS) attack on the authorization server.
               This attack can still be effective even when CSRF defense/the "state"
               parameter (see Section 4.4.1.8) is deployed on the client side. With
               such a defense, the attacker might need to incur an additional HTTP
               request to obtain a valid CSRF code/"state" parameter. This
               apparently cuts down the effectiveness of the attack by a factor of
               2. However, if the HTTPS/HTTP cost ratio is higher than 2 (the cost
               factor is estimated to be around 3.5x at [SSL-Latency]), the attacker
               still achieves a magnification of resource utilization at the expense
               of the authorization server.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_3_5_ANTI_CSRF_STATE_PARAM
              - ID: CLIENT_LIMITS_PER_USER
                title: Client limits authenticated users codes
                description: |
                  If the client authenticates the user, either through a single-
                  sign-on protocol or through local authentication, the client
                  should suspend the access by a user account if the number of
                  invalid authorization "codes" submitted by this user exceeds a
                  certain threshold.
                operational: true
                operator: CLIENT_OPERATOR
                inPlace: false
                public: true
              - ID: AUTH_RATE_LIMIT
                title: Client limits authenticated users codes
                description: |
                  The authorization server should send an error response to the
                  client reporting an invalid authorization "code" and rate-limit or
                  disallow connections from clients whose number of invalid requests
                  exceeds a threshold.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
          - ID: 4_4_1_13_CODE_SUBSTITUTION
            title: DoS Using Manufactured Authorization "codes"
            impactDesc: |
              The attacker gains access to an application and user-specific
              data within the application.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
              - REFID: NON_REPUDIATION
            assets:
              # - REFID: 
            attackers:
              - REFID: CLIENT_OPERATOR
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N
            threatType: Denial of Service
            attack: |
              An attacker could attempt to log into an application or web site
               using a victim’s identity. Applications relying on identity data
               provided by an OAuth protected service API to login users are
               vulnerable to this threat. This pattern can be found in so-called
               "social login" scenarios.
               As a prerequisite, a resource server offers an API to obtain personal
               information about a user that could be interpreted as having obtained
               a user identity. In this sense, the client is treating the resource
               server API as an "identity" API. A client utilizes OAuth to obtain
               an access token for the identity API. It then queries the identity
               API for an identifier and uses it to look up its internal user
               account data (login). The client assumes that, because it was able
               to obtain information about the user, the user has been
               authenticated.
               If the client uses the grant type "code", the attacker needs to
               gather a valid authorization "code" of the respective victim from the
               same Identity Provider used by the target client application. The
               attacker tricks the victim into logging into a malicious app (which
               may appear to be legitimate to the Identity Provider) using the same
               Identity Provider as the target application. This results in the
               Identity Provider’s authorization server issuing an authorizatio
               "code" for the respective identity API. The malicious app then sends
               this code to the attacker, which in turn triggers a login process
               within the target application. The attacker now manipulates the
               authorization response and substitutes their code (bound to their
               identity) for the victim’s code. This code is then exchanged by the
               client for an access token, which in turn is accepted by the identity
               API, since the audience, with respect to the resource server, is
               correct. But since the identifier returned by the identity API is
               determined by the identity in the access token (issued based on the
               victim’s code), the attacker is logged into the target application
               under the victim’s identity.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - ID: IN_REQUEST_CLIENTID
                title: Clients indicate their ids in requests
                description: |
                  All clients must indicate their client ids with every request to
                  exchange an authorization "code" for an access token. The
                  authorization server must validate whether the particular
                  authorization "code" has been issued to the particular client. If
                  possible, the client shall be authenticated beforehand.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
              - ID: SECURE_USER_LOGIN_PROTOCOL
                title: Secure User Login Protocol
                description: |
                  Clients should use an appropriate protocol, such as OpenID (cf.
                  [OPENID]) or SAML (cf. [OASIS.sstc-saml-bindings-1.1]) to
                  implement user login. Both support audience restrictions on
                  clients.
                operational: true
                operator: CLIENT_OPERATOR
                inPlace: false
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/OAuth2/Flows/Flows.yaml
        ```yaml
        #based on: https://datatracker.ietf.org/doc/html/rfc6819
        
        ID: Flows
        title: Flows
        parent: OAuth2
        children:
          - ID: Flows_AuthCode
          - ID: Flows_ImplicitGrant
        
        scope:
          description: This section covers threats that are specific to certain flows utilized
            to obtain access tokens. Each flow is characterized by response types and/or grant
            types on the end-user authorization and token endpoint, respectively.
        
          diagram:
        
          assets:
            # - ID: AUTH_SERVER_TOKEN_ENDPOINT
            #   type: endpoint
            #   title: Authorization server token endpoint
            #   description: |
            #     Authorization server's endpoint for DF_AUTH_GRANT_AS and DF_ACCESS_TOKEN_CL
            #   inScope: true
        
        
            # - ID: AUTH_SERVER_AUTH_ENDPOINT
            #   type: endpoint
            #   title: Authorization endpoint for resource owner
            #   description: |
            #     Authorization server's endpoint for DF_AUTH_REDIRECT
            #   inScope: true
        
        
          assumptions:
            # - ID:
            #   description: |
            #     A Auth server may host several ...
        
          attackers:
            # - ID: ANONYMOUS
            #   description: |
            #     Anonymous internet user
            #   inScope: true
        
            # - ID: CLIENT
            #   description: |
            #     Client app
            #   inScope: true
        analysis:
        
         
        threats:
        
          # - ID: 4.3.5_CLIENT_SECRET_BRUTE_FORCE
          #   title: Obtaining Client Secret by Online Guessing
          #   impact: |
          #      Disclosure of a single "client_id"/secret pair.
          #   impacts:
          #     - REFID: CONFIDENTIALITY
          #     - REFID: INTEGRITY
          #   assets:
          #     - REFID: CLIENT_SECRETS
          #   attackers:
          #     - REFID: ANONYMOUS
          #   CVSS:
          #     vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L
          #   threatType: Spoofing, Elevation of privileges, Information Disclosure
          #   attack: |
          #     An attacker may try to guess valid "client_id"/secret pairs.
          #   pentestTestable: true
          #   public: true
          #   fullyMitigated: true
          #   countermeasures:
          #     - ID: 5.1.4.2.2_HIGH_ENTROPY_SECRETS
          #       title: Use High Entropy for Secrets
          #       description: |
          #         When creating secrets not intended for usage by human users (e.g.,
          #         client secrets or token handles), the authorization server should
          #         include a reasonable level of entropy in order to mitigate the risk
          #         of guessing attacks. The token value should be >=128 bits long and
          #         constructed from a cryptographically strong random or pseudo-random
          #         number sequence (see [RFC4086] for best current practice) generated
          #         by the authorization server.
          #       operational: false
          #       inPlace: false
          #       public: true
        
          #     - ID: 5.1.4.2.3_LOCK_ACCOUNTS
          #       title: Lock Accounts
          #       description: |
          #         Online attacks on passwords can be mitigated by locking the
          #         respective accounts after a certain number of failed attempts.
          #         Note: This measure can be abused to lock down legitimate service users.
          #       operational: false
          #       inPlace: false
          #       public: true       
        
          #     - ID: 5.2.3.7_STRONG_CLIENT_AUTHENTICATION
          #       title: Use strong client authentication
          #       description: |
          #         By using an alternative form of authentication such as client
          #         assertion [OAuth-ASSERTIONS], the need to distribute a
          #         "client_secret" is eliminated. This may require the use of a secure
          #         private key store or other supplemental authentication system as
          #         specified by the client assertion issuer in its authentication
          #         process. (e.g., client_assertion/client_token)
          #       operational: false
          #       inPlace: false
          #       public: true       
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/OAuth2/Client/Client.yaml
        ```yaml
        #based on: https://datatracker.ietf.org/doc/html/rfc6819
        
        ID: Client
        title: Client
        parent: OAuth2
        scope:
          description:
          diagram:
        analysis:
        
         
        threats:
          - ID: Client_Secrets_disclosure
            title: Client Secrets Disclosure and impersonation
            impactDesc: |
              - Client authentication of access to the authorization server can be
              bypassed.
              - Stolen refresh tokens or authorization "codes" can be replayed.
              - Client spoofing/impersonation
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              # - ID: 
            CVSS:
              vector: CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              Obtain Secret From Source Code or Binary:
              This applies for all client types.  For open source projects, secrets
              can be extracted directly from source code in their public
              repositories.  Secrets can be extracted from application binaries
              just as easily when the published source is not available to the
              attacker.  Even if an application takes significant measures to
              obfuscate secrets in their application distribution, one should
              consider that the secret can still be reverse-engineered by anyone
              with access to a complete functioning application bundle or binary.
            pentestTestable: true
            public: true
            fullyMitigated: false
            countermeasures:
              - ID: 5_2_3_1_CLIENT_CHECK1
                title: Checks on client's security policy
                description: |
                  Don't issue secrets to public clients or clients with
                  inappropriate security policy
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER
        
              - ID: 5_2_3_2_USER_CONSENT1
                title: Require User Consent for Public Clients without Secret
                description: |
                  Authorization servers should not allow automatic authorization for
                  public clients.  The authorization server may issue an individual
                  client id but should require that all authorizations are approved by
                  the end user.  For clients without secrets, this is a countermeasure
                  against the following threat:
                    -  Impersonation of public client applications.
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER
        
              - ID: 5_2_3_3_CLIENT_ID_TO_REDIRECT_URI
                title: Issue a "client_id" Only in Combination with "redirect_uri"
                description: |
                  The authorization server may issue a "client_id" and bind the
                    "client_id" to a certain pre-configured "redirect_uri".  Any
                    authorization request with another redirect URI is refused
                    automatically.  Alternatively, the authorization server should not
                    accept any dynamic redirect URI for such a "client_id" and instead
                    should always redirect to the well-known pre-configured redirect URI.
                    This is a countermeasure for clients without secrets against the
                    following threats:
        
                    -  Cross-site scripting attacks
        
                    -  Impersonation of public client applications
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER
        
              - ID: 5_2_3_4_SPECIFIC_CLIENT_SECRETS
                title: Issue Installation-Specific Client Secrets
                description: |
                  An authorization server may issue separate client identifiers and
                  corresponding secrets to the different installations of a particular
                  client (i.e., software package).  The effect of such an approach
                  would be to turn otherwise "public" clients back into "confidential"
                  clients.
        
                  For web applications, this could mean creating one "client_id" and
                  "client_secret" for each web site on which a software package is
                  installed.  So, the provider of that particular site could request a
                  client id and secret from the authorization server during the setup
                  of the web site.  This would also allow the validation of some of the
                  properties of that web site, such as redirect URI, web site URL, and
                  whatever else proves useful.  The web site provider has to ensure the
                  security of the client secret on the site.
        
                  For native applications, things are more complicated because every
                  copy of a particular application on any device is a different
                  installation.  Installation-specific secrets in this scenario will
                  require obtaining a "client_id" and "client_secret" either
        
                  1.  during the download process from the application market, or
        
                  2.  during installation on the device.
        
                  Either approach will require an automated mechanism for issuing
                  client ids and secrets, which is currently not defined by OAuth.
        
                  The first approach would allow the achievement of a certain level of
                  trust in the authenticity of the application, whereas the second
                  option only allows the authentication of the installation but not the
                  validation of properties of the client.  But this would at least help
                  to prevent several replay attacks.  Moreover, installation-specific
                  "client_ids" and secrets allow the selective revocation of all
                  refresh tokens of a specific installation at once.
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER_OPERATOR
        
              - ID: 5_2_3_5_VALIDATE_REDIRECT_URI
                title: Validate Pre-Registered "redirect_uri"
                description: |
                  An authorization server should require all clients to register their
                  "redirect_uri", and the "redirect_uri" should be the full URI as
                  defined in [RFC6749].  The way that this registration is performed is
                  out of scope of this document.  As per the core spec, every actual
                  redirect URI sent with the respective "client_id" to the end-user
                  authorization endpoint must match the registered redirect URI.  Where
                  it does not match, the authorization server should assume that the
                  inbound GET request has been sent by an attacker and refuse it.
                  Note: The authorization server should not redirect the user agent
                  back to the redirect URI of such an authorization request.
                  Validating the pre-registered "redirect_uri" is a countermeasure
                  against the following threats:
        
                  o  Authorization "code" leakage through counterfeit web site: allows
                      authorization servers to detect attack attempts after the first
                      redirect to an end-user authorization endpoint (Section 4.4.1.7).
        
                  o  Open redirector attack via a client redirection endpoint
                      (Section 4.1.5).
        
                  o  Open redirector phishing attack via an authorization server
                      redirection endpoint (Section 4.2.4).
        
                  The underlying assumption of this measure is that an attacker will
                  need to use another redirect URI in order to get access to the
                  authorization "code".  Deployments might consider the possibility of
                  an attacker using spoofing attacks to a victim's device to circumvent
                  this security measure.
        
                  Note: Pre-registering clients might not scale in some deployments
                  (manual process) or require dynamic client registration (not
                  specified yet).  With the lack of dynamic client registration, a
                  pre-registered "redirect_uri" only works for clients bound to certain
                  deployments at development/configuration time.  As soon as dynamic
                  resource server discovery is required, the pre-registered
                  "redirect_uri" may no longer be feasible.
                  5_Validate_redirect_uri
        
                  Note: An invalid redirect URI indicates an
                  invalid client, whereas a valid redirect URI does not necessarily
                  indicate a valid client. The level of confidence depends on the
                  client type. For web applications, the level of confidence is
                  high, since the redirect URI refers to the globally unique network
                  endpoint of this application, whose fully qualified domain name
                  (FQDN) is also validated using HTTPS server authentication by the
                  user agent. In contrast, for native clients, the redirect URI
                  typically refers to device local resources, e.g., a custom scheme.
                  So, a malicious client on a particular device can use the valid
                  redirect URI the legitimate client uses on all other devices.
        
        
                operational: true
                inPlace: false
                public: true
                operator: AUTHORIZATION_SERVER
        
        
        
          - ID: TOO_MUCH_GRANT
            title: User Unintentionally Grants Too Much Access Scope
            impactDesc: Disclosure of  RESOURCE_OWNER's RESOURCES
            impactedSecObj:
              - REFID: CONFIDENTIALITY
            assets:
              # - ID: 
            CVSS:
              vector: CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              When obtaining end-user authorization, the end user may not
              understand the scope of the access being granted and to whom, or they
              may end up providing a client with access to resources that should
              not be permitted.
            pentestTestable: true
            public: true
            fullyMitigated: false
            countermeasures:
              - ID: AUTH_SERVER_RE_CHECK_GRANTS
                title: AUTHORIZATION_SERVER policy discretional decision
                description: |
                  Narrow the scope, based on the client.  When obtaining end-user
                  authorization and where the client requests scope, the
                  authorization server may want to consider whether to honor that
                  scope based on the client identifier.  That decision is between
                  the client and authorization server and is outside the scope of
                  this spec.  The authorization server may also want to consider
                  what scope to grant based on the client type, e.g., providing
                  lower scope to public clients (Section 5.1.5.1).
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER
        
              - ID: USER_AUTH_AWARENESS
                title: Users educated to avoid phishing attacks
                description: |
                  Authorization servers should attempt to educate users about the
                  risks posed by phishing attacks and should provide mechanisms that
                  make it easy for users to confirm the authenticity of their sites.
                  Section 5.1.2).
                operator: AUTHORIZATION_SERVER
                operational: true
                inPlace: no
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/OAuth2/AuthorizationServer/AuthorizationServer.yaml
        ```yaml
        #based on: https://datatracker.ietf.org/doc/html/rfc6819
        
        ID: AuthorizationServer
        title: Authorization Server
        parent: OAuth2
        scope:
          description:
          diagram:
        
          assets:
            - ID: AUTH_SERVER_TOKEN_ENDPOINT
              type: endpoint
              title: Authorization server token endpoint
              description: |
                Authorization server's endpoint for DF_AUTH_GRANT_AS and DF_ACCESS_TOKEN_CL
              inScope: true
        
        
            - ID: AUTH_SERVER_AUTH_ENDPOINT
              type: endpoint
              title: Authorization endpoint for resource owner
              description: |
                Authorization server's endpoint for DF_AUTH_REDIRECT
              inScope: true
        
        
          assumptions:
            - ID:
              description: |
                A Auth server may host several ...
        
          attackers:
            - ID: ANONYMOUS
              description: |
                Anonymous internet user
              inScope: true
        
            - ID: CLIENT
              description: |
                Client app
              inScope: true
        
        analysis:
        
         
        threats:
          - ID: AuthServerPhishing1
            title: Password Phishing by Counterfeit Authorization Server
            impactDesc: Steal users' passwords
            impactedSecObj:
              - REFID: CONFIDENTIALITY
            assets:
              # - ID: 
            CVSS:
              vector: CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              A hostile party could take advantage of this
              by intercepting the client's requests and returning misleading or
              otherwise incorrect responses.  This could be achieved using DNS or
              Address Resolution Protocol (ARP) spoofing.  Wide deployment of OAuth
              and similar protocols may cause users to become inured to the
              practice of being redirected to web sites where they are asked to
              enter their passwords.  If users are not careful to verify the
              authenticity of these web sites before entering their credentials, it
              will be possible for attackers to exploit this practice to steal
              users' passwords.
            pentestTestable: true
            public: true
            fullyMitigated: false
            countermeasures:
              - ID: 5_1_2_AUTH_SERVER_AUTHENTICATION
                title: TLS for the authorization server
                description: |
                  Authorization servers should consider such attacks when developing
                  services based on OAuth and should require the use of transport-
                  layer security for any requests where the authenticity of the
                  authorization server or of request responses is an issue (see
                  Section 5.1.2).
        
                  HTTPS server authentication or similar means can be used to
                  authenticate the identity of a server. The goal is to reliably bind
                  the fully qualified domain name of the server to the public key
                  presented by the server during connection establishment (see
                  [RFC2818]).
                  The client should validate the binding of the server to its domain
                  name. If the server fails to prove that binding, the communication
                  is considered a man-in-the-middle attack. This security measure
                  depends on the certification authorities the client trusts for that
                  purpose. Clients should carefully select those trusted CAs and
                  protect the storage for trusted CA certificates from modifications.
                  This is a countermeasure against the following threats:
                  <br/>o Spoofing
                  <br/>o Proxying
                  <br/>o Phishing by counterfeit servers
        
        
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER
        
        
              - ID: USER_PHISHING_AWARENESS
                title: Users educated to avoid phishing attacks
                description: |
                  Authorization servers should attempt to educate users about the
                  risks posed by phishing attacks and should provide mechanisms that
                  make it easy for users to confirm the authenticity of their sites.
                  Section 5.1.2).
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER
        
        
          - ID: TOO_MUCH_GRANT
            title: User Unintentionally Grants Too Much Access Scope
            impactDesc: Disclosure of  RESOURCE_OWNER's RESOURCES
            impactedSecObj:
              - REFID: CONFIDENTIALITY
            assets:
              # - ID: 
            CVSS:
              vector: CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              When obtaining end-user authorization, the end user may not
              understand the scope of the access being granted and to whom, or they
              may end up providing a client with access to resources that should
              not be permitted.
            pentestTestable: true
            public: true
            fullyMitigated: false
            countermeasures:
              - ID: AUTH_SERVER_RE_CHECK_GRANTS
                title: AUTHORIZATION_SERVER policy discretional decision
                description: |
                  Narrow the scope, based on the client.  When obtaining end-user
                  authorization and where the client requests scope, the
                  authorization server may want to consider whether to honor that
                  scope based on the client identifier.  That decision is between
                  the client and authorization server and is outside the scope of
                  this spec.  The authorization server may also want to consider
                  what scope to grant based on the client type, e.g., providing
                  lower scope to public clients (Section 5.1.5.1).
                operational: true
                inPlace: no
                public: true
                operator: AUTHORIZATION_SERVER
        
              - ID: USER_AUTH_AWARENESS
                title: Users educated to avoid phishing attacks
                description: |
                  Authorization servers should attempt to educate users about the
                  risks posed by phishing attacks and should provide mechanisms that
                  make it easy for users to confirm the authenticity of their sites.
                  Section 5.1.2).
                operator: AUTHORIZATION_SERVER
                operational: true
                inPlace: no
                public: true
        
        
          - ID: OPEN_REDIRECTOR
            title: Authorization server open redirect
            impactDesc: Phishing attacks can be executed exploiting AUTH_SERVER open redirect
            assets:
              - REFID: DF_AUTH_REDIRECT
              - REFID: AUTH_SERVER
              - REFID: AUTH_SERVER_AUTH_ENDPOINT
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
            threatType: Spoofing, Information Disclosure
            attack: |
              An attacker could use the end-user authorization endpoint and the
              redirect URI parameter to abuse the authorization server as an open
              redirector. An open redirector is an endpoint using a parameter to
              automatically redirect a user agent to the location specified by the
              parameter value without any validation.
            pentestTestable: true
            public: true
            fullyMitigated: false
        
            countermeasures:
              - ID: PRE_REGISTERED_REDIRECT_URI
                title: Pre-registered redirect URI
                description: |
                  Require clients to register any full redirect URIs (Section 5.2.3.5).
                  Don’t redirect to a redirect URI if the client identifier or
                  redirect URI can’t be verified (Section 5.2.3.5).
                  Authorization servers should not automatically process repeat
                  authorizations to public clients unless the client is validated
                  using a pre-registered redirect URI (Section 5.2.3.5).
                operational: false
                inPlace: true
                public: true
        
        
        
          - ID: PUBLIC_CLIENT_SPOOFING1
            title: Malicious Client Obtains Existing Authorization by Fraud
            impactDesc: Disclosure of RESOURCE_OWNER's RESOURCES
            impactedSecObj:
              - REFID: CONFIDENTIALITY
            assets:
              - REFID: DF_AUTH_REDIRECT
              - REFID: AUTH_SERVER_AUTH_ENDPOINT
              - REFID: PUBLIC_CLIENT
            CVSS:
              vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              Authorization servers may wish to automatically process authorization
              requests from clients that have been previously authorized by the
              user. When the user is redirected to the authorization server's end-
              user authorization endpoint to grant access, the authorization server
              detects that the user has already granted access to that particular
              client. Instead of prompting the user for approval, the
              authorization server automatically redirects the user back to the
              client.
        
              A malicious client may exploit that feature and try to obtain such an
              authorization "code" instead of the legitimate client.
            pentestTestable: true
            public: true
            fullyMitigated: false
        
            countermeasures:
              - REFID: PRE_REGISTERED_REDIRECT_URI
        
        
              - ID: REDUCED_ACCESS_TOKEN_SCOPE
                title: Limiting the scope of access tokens obtained through automated approvals
                description: |
                  Authorization servers can mitigate the risks associated with
                  automatic processing by limiting the scope of access tokens
                  obtained through automated approvals (Section 5.1.5.1).
                operator: AUTHORIZATION_SERVER
                operational: true
                inPlace: false
                public: true
        
        
        
          - ID: 4_3_1_EAVESDROPPING_ACCESS_TOKENS1
            title: Eavesdropping Access Tokens
            impactDesc: |
              The attacker is able to access all resources with the
              permissions covered by the scope of the particular access token.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: DF_ACCESS_TOKEN_CL
              - REFID: DF_AUTH_GRANT_AS
              - REFID: AUTH_SERVER_TOKEN_ENDPOINT
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              Attackers may attempt to eavesdrop access tokens in transit from the
              authorization server to the client.
            pentestTestable: true
            public: true
            fullyMitigated: true
        
            countermeasures:
              - ID: CLIENT_AUTH_SERVER_TLS
                title: Secure transport layer to CLient to AUTH_SERVER by TLS
                description: |
                  As per the core OAuth spec, the authorization servers must ensure
                  that these transmissions are protected using transport-layer
                  mechanisms such as TLS (see Section 5.1.1).
                operator: AUTHORIZATION_SERVER
                operational: true
                inPlace: false
                public: true
        
              - REFID: REDUCED_ACCESS_TOKEN_SCOPE
        
        
          - ID: 4_3_2_AS_DB_TOKEN_DISCLOSURE
            title: Obtaining Access Tokens from Authorization Server Database
            impactDesc: |
              The attacker is able to access all resources for all tokens in Auth Server.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: ACCESS_TOKEN
              - REFID: AUTH_SERVER
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker may obtain access
              tokens from the authorization server’s database by gaining access to
              the database or launching a SQL injection attack. 
        
              This threat is applicable if the authorization server stores access
              tokens as handles in a database.
            pentestTestable: true
            public: true
            fullyMitigated: true
        
            countermeasures:
              - ID: 5_1_4_1_3_HASHED_TOKEN_DB
                title: Store access token hashes only (Section 5.1.4.1.3).
                description: |
                  Store access token hashes only (Section 5.1.4.1.3).
                operational: false
                inPlace: true
                public: true
        
              - ID: 5_1_4_1_1_SYS_SEC
                title: Enforce Standard System Security Means
                description: |
                  A server system may be locked down so that no attacker may get access
                  to sensitive configuration files and databases.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
              - ID: 5_1_4_1_2_SQL_SEC
                title: Enforce Standard SQL Injection Countermeasures
                description: |
                  If a client identifier or other authentication component is queried
                  or compared against a SQL database, it may become possible for an
                  injection attack to occur if parameters received are not validated
                  before submission to the database.
                  <br/>o Ensure that server code is using the minimum database privileges
                  possible to reduce the "surface" of possible attacks.
                  <br/>o Avoid dynamic SQL using concatenated input. If possible, use
                  static SQL.
                  <br/>o When using dynamic SQL, parameterize queries using bind arguments.
                  Bind arguments eliminate the possibility of SQL injections.
                  <br/>o Filter and sanitize the input. For example, if an identifier has
                  a known format, ensure that the supplied value matches the
                  identifier syntax rules.
                operational: false
                inPlace: false
                public: true
        
        
          - ID: 4_3_3_CLIENT_CREDENTIALS_DISCLOSURE
            title: Disclosure of Client Credentials during Transmission
            impactDesc: |
              Revelation of a client credential enabling phishing or impersonation of a client service.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: DF_AUTH_GRANT_AS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker could attempt to eavesdrop the transmission of client
              credentials between the client and server during the client
              authentication process or during OAuth token requests.
            pentestTestable: true
            public: true
            fullyMitigated: true
        
            countermeasures:
              - ID: 5_1_1_CONFIDENTIAL_REQUESTS
                title: Ensure Confidentiality of Requests (TLS)
                description: |
                  This is applicable to all requests sent from the client to the
                  authorization server or resource server. While OAuth provides a
                  mechanism for verifying the integrity of requests, it provides no
                  guarantee of request confidentiality. Unless further precautions are
                  taken, eavesdroppers will have full access to request content and may
                  be able to mount interception or replay attacks by using the contents
                  of requests, e.g., secrets or tokens.
                  Attacks can be mitigated by using transport-layer mechanisms such as
                  TLS [RFC5246]. A virtual private network (VPN), e.g., based on IPsec
                  VPNs [RFC4301], may be considered as well.
                  Note: This document assumes end-to-end TLS protected connections
                  between the respective protocol entities. Deployments deviating from
                  this assumption by offloading TLS in between (e.g., on the data
                  center edge) must refine this threat model in order to account for
                  the additional (mainly insider) threat this may cause.
                  This is a countermeasure against the following threats:
                  <br/>o Replay of access tokens obtained on the token’s endpoint or the
                  resource server’s endpoint
                  <br/>o Replay of refresh tokens obtained on the token’s endpoint
                  Replay of authorization "codes" obtained on the token’s endpoint
                  (redirect?)
                  <br/>o Replay of user passwords and client secrets
                operational: true
                operator: CLIENT_OPERATOR
                inPlace: true
                public: true
        
              - ID: CONFIDENTIAL_CREDENTIALS_REQUESTS
                title: Do not send plaintext credentials
                description: |
                  Use alternative authentication means that do not require the
                  sending of plaintext credentials over the wire (e.g., Hash-based
                  Message Authentication Code).
                operational: false
                inPlace: false
                public: true
        
        
          - ID: 4_3_4_CLIENT_CREDENTIALS_DISCLOSURE
            title: Obtaining Client Secret from Authorization Server Database
            impactDesc: |
              Disclosure of all "client_id"/secret combinations. This
              allows the attacker to act on behalf of legitimate clients.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: CLIENT_SECRETS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker may obtain valid "client_id"/secret combinations from the
              authorization server’s database by gaining access to the database or
              launching a SQL injection attack.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - REFID: 5_1_4_1_2_SQL_SEC
              - REFID: 5_1_4_1_1_SYS_SEC
              - ID: 5_1_4_1_CRED_PROTECTION
                title: Enforce Credential Storage Protection Best Practices
                description: |
                  Administrators should undertake industry best practices to protect
                  the storage of credentials (for example, see [OWASP]). Such
                  practices may include but are not limited to the following
                  sub-sections.
                operational: true
                operator: AUTHORIZATION_SERVER_OPERATOR
                inPlace: false
                public: true
        
          - ID: 4_3_5_CLIENT_SECRET_BRUTE_FORCE
            title: Obtaining Client Secret by Online Guessing
            impactDesc: |
              Disclosure of a single "client_id"/secret pair.
            impactedSecObj:
              - REFID: CONFIDENTIALITY
              - REFID: INTEGRITY
            assets:
              - REFID: CLIENT_SECRETS
            attackers:
              - REFID: ANONYMOUS
            CVSS:
              vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L
            threatType: Spoofing, Elevation of privileges, Information Disclosure
            attack: |
              An attacker may try to guess valid "client_id"/secret pairs.
            pentestTestable: true
            public: true
            fullyMitigated: true
            countermeasures:
              - ID: 5_1_4_2_2_HIGH_ENTROPY_SECRETS
                title: Use High Entropy for Secrets
                description: |
                  When creating secrets not intended for usage by human users (e.g.,
                  client secrets or token handles), the authorization server should
                  include a reasonable level of entropy in order to mitigate the risk
                  of guessing attacks. The token value should be >=128 bits long and
                  constructed from a cryptographically strong random or pseudo-random
                  number sequence (see [RFC4086] for best current practice) generated
                  by the authorization server.
                operational: false
                inPlace: false
                public: true
        
              - ID: 5_1_4_2_3_LOCK_ACCOUNTS
                title: Lock Accounts
                description: |
                  Online attacks on passwords can be mitigated by locking the
                  respective accounts after a certain number of failed attempts.
                  Note: This measure can be abused to lock down legitimate service users.
                operational: false
                inPlace: false
                public: true
        
              - ID: 5_2_3_7_STRONG_CLIENT_AUTHENTICATION
                title: Use strong client authentication
                description: |
                  By using an alternative form of authentication such as client
                  assertion [OAuth-ASSERTIONS], the need to distribute a
                  "client_secret" is eliminated. This may require the use of a secure
                  private key store or other supplemental authentication system as
                  specified by the client assertion issuer in its authentication
                  process. (e.g., client_assertion/client_token)
                operational: false
                inPlace: false
                public: true
        ```
        File: /Users/auser/workspace/personal/threat-models/threatModels/OAuth2/OAuth2.yaml
        ```yaml
        #based on: https://datatracker.ietf.org/doc/html/rfc6819
        
        ID: OAuth2
        title: OAuth 2.0
        version: rfc6819
        children:
          - ID: Client
          - ID: AuthorizationServer
          - ID: Flows
        authors: |
          Example by David Cervigni, based on: https://datatracker.ietf.org/doc/html/rfc6819
        
        # history: |
        #   - 2023.1 Draft  2023-07-xx: First release
        
        scope:
        
          description: |
            Functional objectives:
        
              - Allow final users (RESOURCE_OWNERS) to integrate services from third party apps **easily** (without credential creation like new accounts/username/password)
              - Allow users to login to new services without explicitly creating a new set of credentials (authorize a new third party service VS authenticate on a third party service)
              - Allows CLIENT (apps) to delegate/abstract/de-scope authentication
        
              TODO: describe the authz relationship with OPEN ID Connect , holistic real approach from CLIENT development point of view.
        
              Non-functional requirements:
              - Integrate third party services **securely**
        
              Reference: https://datatracker.ietf.org/doc/html/rfc6749
        
              >The OAuth 2.0 authorization framework enables a third-party
                application to obtain limited access to an HTTP service, either on
                behalf of a resource owner by orchestrating an approval interaction
                between the resource owner and the HTTP service, or by allowing the
                third-party application to obtain access on its own behalf.
        
        
        
              There are 3 type of Authorization Grant:
        
              - Authorization code
              - Implicit
              - Resource owner password credentials
              - Client credentials
        
        
              > [1.3](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3).  Authorization Grant
                An authorization grant is a credential representing the resource
                owner's authorization (to access its protected resources) used by the
                client to obtain an access token.  This specification defines four
                grant types -- authorization code, implicit, resource owner password
                credentials, and client credentials -- as well as an extensibility
                mechanism for defining additional types.
                >
              [1.3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.1).  Authorization Code
                The authorization code is obtained by using an authorization server
                as an intermediary between the client and resource owner.  Instead of
                requesting authorization directly from the resource owner, the client
                directs the resource owner to an authorization server (via its
                user-agent as defined in [[RFC2616](https://datatracker.ietf.org/doc/html/rfc2616)]), which in turn directs the  resource owner back to the client with the authorization code.
                Before directing the resource owner back to the client with the
                authorization code, the authorization server authenticates the
                resource owner and obtains authorization.  Because the resource owner
                only authenticates with the authorization server, the resource
                owner's credentials are never shared with the client.
                The authorization code provides a few important security benefits,
                such as the ability to authenticate the client, as well as the
                transmission of the access token directly to the client without
                passing it through the resource owner's user-agent and potentially
                exposing it to others, including the resource owner.
                  [1.3.2](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.2).  Implicit
                The implicit grant is a simplified authorization code flow optimized
                for clients implemented in a browser using a scripting language such
                as JavaScript.  In the implicit flow, instead of issuing the client
                an authorization code, the client is issued an access token directly
                (as the result of the resource owner authorization).  The grant type
                is implicit, as no intermediate credentials (such as an authorization
                code) are issued (and later used to obtain an access token).
                When issuing an access token during the implicit grant flow, the
                authorization server does not authenticate the client.  In some
                cases, the client identity can be verified via the redirection URI
                used to deliver the access token to the client.  The access token may
                be exposed to the resource owner or other applications with access to
                the resource owner's user-agent.
                Implicit grants improve the responsiveness and efficiency of some
                clients (such as a client implemented as an in-browser application),
                since it reduces the number of round trips required to obtain an
                access token.  However, this convenience should be weighed against
                the security implications of using implicit grants, such as those
                described in Sections [10.3](https://datatracker.ietf.org/doc/html/rfc6749#section-10.3) and [10.16](https://datatracker.ietf.org/doc/html/rfc6749#section-10.16), especially when the
                authorization code grant type is available.
        
              <img src="img/Pasted image 20230702114826.png"/>
        
        
          securityObjectives:
            - ID: FULL_CIA
              title: Confidentiality Integrity and availability of a Corda Network
              description: |
                Ability to maintain fundamental confidentiality
                integrity and availability of the system
              group: General security Objectives
        
            - ID: INTEGRITY
              title: Data integrity
              description: |
                Ability to maintain fundamental integrity of the system
              contributesTo:
                - REFID: FULL_CIA
              group: General security Objectives
            - ID: CONFIDENTIALITY
              title: Data confidentiality
              description: |
                Ability to maintain fundamental confidentiality of the system data
              contributesTo:
                - REFID: FULL_CIA
              group: General security Objectives
            - ID: AVAILABILITY
              title: System availability
              description: |
                Ability to maintain fundamental availability of the system
              contributesTo:
                - REFID: FULL_CIA
              group: General security Objectives
            - ID: COMPLIANCE
              title: Compliance
              description: |
                Ability to obtain and maintain maintain compliance with required regulations
              contributesTo:
                - REFID: AVAILABILITY
              group: Business specific
        
            - ID: NON_REPUDIATION
              title: Auditability and Non repudiation of resource access
              description: |
                Ability to have available evidence of the users and actor mains actions, including:
                  - Trackign of CLIENT access to RESOURCE_OWNER's assets and data 
              contributesTo:
                # - REFID: INTEGRITY
                - REFID: COMPLIANCE
              group: Business specific
        
            - ID: CLIENT_ACCESS_LIMITATION
              title: Limits CLIENT access to RESOURCE_OWNER's assets and data
              description: |
                Limits CLIENT access to RESOURCE_OWNER's assets and data . This includes:
        
                  - Revoke access to CLIENT over time
                  - Limit the set of resources accessed by CLIENT (authorization)
              contributesTo:
                - REFID: FULL_CIA
                - REFID: COMPLIANCE
              group: Business specific
        
            - ID: CLIENT_REVOKE_ACCESS
              title: Revoke CLIENT access to RESOURCE_OWNER's assets and data
              description: |
                Revoke access to CLIENT over time
              contributesTo:
                - REFID: CLIENT_ACCESS_LIMITATION
              group: Business specific
        
            - ID: CLIENT_LIMIT_ACCESS
              title: Limits CLIENT access to some RESOURCE_OWNER's assets and data
              description: |
                Limit the set of resources accessed by CLIENT (authorization)
              contributesTo:
                - REFID: CLIENT_ACCESS_LIMITATION
              group: Business specific
        
            - ID: NOT_SHARING_OWNER_CREDENTIAL
              title: Not sharing RESOURCE_OWNER credentials
              description: |
                Not sharing RESOURCE_OWNER credential with third parties
              contributesTo:
                - REFID: CLIENT_ACCESS_LIMITATION
              group: Advanced security features
        
            - ID: USER_AGENT_RESILIENCY
              title: Compromised USER_AGENT resiliency
              description: |
                Resiliency for RESOURCE_OWNER's USER_AGENT against attacks like XSS
              contributesTo:
                - REFID: CLIENT_ACCESS_LIMITATION
              group: Advanced security features
        
            - ID: CLIENT_RESILIENCY
              title: Compromised CLIENT resiliency
              description: |
                Resiliency for RESOURCE_OWNER's RESOURCES against compromised CLIENT
              contributesTo:
                - REFID: CLIENT_ACCESS_LIMITATION
              group: Advanced security features
        
        
        
          diagram:
        
          assets:
        
            - ID: CLIENT
              type: system
              title: Client
              description: |
                An application requesting access from the RESOURCE_OWNER (TODO: refine this description)
              inScope: true
        
            # - ID: AUTH_SERVER_TOKEN_ENDPOINT
            #   type: endpoint
            #   title: Authorization server token endpoint
            #   description: |
            #     Authorization server's endpoint for DF_AUTH_GRANT_AS and DF_ACCESS_TOKEN_CL
            #   inScope: true
        
        
            # - ID: AUTH_SERVER_AUTH_ENDPOINT
            #   type: endpoint
            #   title: Authorization endpoint for resource owner
            #   description: |
            #     Authorization server's endpoint for DF_AUTH_REDIRECT
            #   inScope: true
            - ID: CONFIDENTIAL_CLIENT
              title: Confidential Client
              description: |
                Clients capable of maintaining the confidentiality of their
                credentials (e.g., client implemented on a secure server with
                restricted access to the client credentials), or capable of secure
                client authentication using other means.
              specifies: CLIENT
              type: system
              inScope: true
        
            - ID: PUBLIC_CLIENT
              title: Confidential Client
              description: |
                Clients incapable of maintaining the confidentiality of their
                credentials (e.g., clients executing on the device used by the
                resource owner, such as an installed native application or a web
                browser-based application), and incapable of secure client
                authentication via any other means.
              specifies: CLIENT
              type: system
              inScope: true
        
            - ID: AUTHORIZATION_GRANT
              title: Authorization Grant
              description: |
                An authorization grant is a credential representing the resource
                owner's authorization (to access its protected resources) used by the
                client to obtain an access token.  This specification defines four
                grant types -- authorization code, implicit, resource owner password
                credentials, and client credentials -- as well as an extensibility
                mechanism for defining additional types.
              type: credential
              inScope: true
        
            - ID: ACCESS_TOKEN
              type: credential
              title: Access Token
              description: |
                Access tokens are credentials used to access protected resources.  An
                access token is a string representing an authorization issued to the
                client.  The string is usually opaque to the client.  Tokens
                represent specific scopes and durations of access, granted by the
                resource owner, and enforced by the resource server and authorization
                server.
        
                The token may denote an identifier used to retrieve the authorization
                information or may self-contain the authorization information in a
                verifiable manner (i.e., a token string consisting of some data and a
                signature).  Additional authentication credentials, which are beyond
                the scope of this specification, may be required in order for the
                client to use a token.
        
                The access token provides an abstraction layer, replacing different
                authorization constructs (e.g., username and password) with a single
                token understood by the resource server.  This abstraction enables
                issuing access tokens more restrictive than the authorization grant
                used to obtain them, as well as removing the resource server's need
                to understand a wide range of authentication methods.
        
                Access tokens can have different formats, structures, and methods of
                utilization (e.g., cryptographic properties) based on the resource
                server security requirements.  Access token attributes and the
                methods used to access protected resources are beyond the scope of
                this specification and are defined by companion specifications such
                as [RFC6750].
              inScope: true
        
            # - ID: CLIENT_CREDENTIALS
            #   type: system
            #   title: Client credentials
            #   description: |
            #   inScope: true
        
        
            - ID: CLIENT_SECRETS
              type: credential
              title: Client secret for authentication with AUTH_SERVER
              description: |
                Secrets held by CLIENT to authentication to the Authorization Server
              inScope: true
        
            - ID: AUTH_SERVER
              type: system
              title: Authorization server
              description: |
                The server issuing access tokens to the client after successfully
                authenticating the resource owner and obtaining authorization.
              inScope: true
        
            - ID: DF_AUTH_REDIRECT
              type: dataflow
              title: Auth User Agent Redirection
              description: User Agent Redirection for Client authorization request. this is
                part of DF_AUTH_REQUEST
              inScope: true
        
            - ID: DF_ACCESS_TOKEN_CL
              type: dataflow
              title: Auth server sending the access token to the client
              description: Auth server sending the access token to the client after resource
                owner approval
              inScope: true
        
            - ID: DF_AUTH_GRANT_AS
              type: dataflow
              title: Client requesting Authorization Server for the Access Token
              description: Client requesting Authorization Server for the Access Token after
                resource owner approval
              inScope: true
        
            - ID: CONFIDENTIAL_CLIENT
              type: system
              title: Public Client
              description: |
                Clients capable of maintaining the confidentiality of their
                credentials (e.g., client implemented on a secure server with
                restricted access to the client credentials), or capable of secure
                client authentication using other means.
                For example a web application. A web application is a confidential client running on a web
                server.  Resource owners access the client via an HTML user
                interface rendered in a user-agent on the device used by the
                resource owner.  The client credentials as well as any access
                token issued to the client are stored on the web server and are
                not exposed to or accessible by the resource owner.
              inScope: true
        
            - ID: PUBLIC_CLIENT
              type: system
              title: Public Client
              description: |
                Clients incapable of maintaining the confidentiality of their
                credentials (e.g., clients executing on the device used by the
                resource owner, such as an installed native application or a web
                browser-based application), and incapable of secure client
                authentication via any other means.
                For example a user-agent-based application or a native applications.
              inScope: true
        
            - ID: CLIENT_ID
              type: data
              title: Client Identifier
              description: |
                The authorization server issues the registered client a client
                identifier -- a unique string representing the registration
                information provided by the client.  The client identifier is not a
                secret; it is exposed to the resource owner and MUST NOT be used
                alone for client authentication.  The client identifier is unique to
                the authorization server.
        
                The client identifier string size is left undefined by this
                specification.  The client should avoid making assumptions about the
                identifier size.  The authorization server SHOULD document the size
                of any identifier it issues.
              inScope: true
        
        
          assumptions:
            - ID: ATT1
              description: |
                the attacker has full access to the network between the client and
                authorization servers and the client and the resource server,
                respectively.  The attacker may eavesdrop on any communications
            - ID: ATT2
              description: |
                an attacker has unlimited resources to mount an attack.
            - ID: ATT3
              description: |
                two of the three parties involved in the OAuth protocol may
                collude to mount an attack against the 3rd party.  For example,
                the client and authorization server may be under control of an
                attacker and collude to trick a user to gain access to resources.
        
            - ID: ARC1
              description: |
                The OAuth protocol leaves deployments with a certain degree of
                freedom regarding how to implement and apply the standard.  The core
                specification defines the core concepts of an authorization server
                and a resource server.  Both servers can be implemented in the same
                server entity, or they may also be different entities.  The latter is
                typically the case for multi-service providers with a single
                authentication and authorization system and is more typical in
                middleware architectures.
        
            - ID: ARC2
              description: |
                The following data elements are stored or accessible on the
                 authorization server:
        
                 o  usernames and passwords
        
                 o  client ids and secrets
        
                 o  client-specific refresh tokens
        
                 o  client-specific access tokens (in the case of handle-based design;
                     see Section 3.1)
        
                 o  HTTPS certificate/key
        
                 o  per-authorization process (in the case of handle-based design;
                     Section 3.1): "redirect_uri", "client_id", authorization "code"
        
            - ID: ARC3
              description: |
                The following data elements are stored or accessible on the resource
                server:
        
                o  user data (out of scope)
        
                o  HTTPS certificate/key
        
                o  either authorization server credentials (handle-based design; see
                    Section 3.1) or authorization server shared secret/public key
                    (assertion-based design; see Section 3.1)
        
                o  access tokens (per request)
        
                It is assumed that a resource server has no knowledge of refresh
                tokens, user passwords, or client secrets.
            - ID: ARC4
              description: |
                In OAuth, a client is an application making protected resource
                requests on behalf of the resource owner and with its authorization.
                There are different types of clients with different implementation
                and security characteristics, such as web, user-agent-based, and
                native applications.  A full definition of the different client types
                and profiles is given in [RFC6749], Section 2.1.
        
                The following data elements are stored or accessible on the client:
        
                o  client id (and client secret or corresponding client credential)
        
                o  one or more refresh tokens (persistent) and access tokens
                    (transient) per end user or other security-context or delegation
                    context
        
                o  trusted certification authority (CA) certificates (HTTPS)
        
                o  per-authorization process: "redirect_uri", authorization "code"
        
        
          attackers:
            - ID: ANONYMOUS
              description: |
                Anonymous internet user
              inScope: true
        
            - ID: RESOURCE_OWNER
              description: |
                An entity capable of granting access to a protected resource.
                When the resource owner is a person, it is referred to as an
                end-user.
              inScope: true
        
            - ID: RESOURCE_SERVER
              description: |
                The server hosting the protected resources, capable of accepting
                and responding to protected resource requests using access tokens.
              inScope: true
        
            - ID: CLIENT_OPERATOR
              description: |
                The operators of the CLIENT.
              # An application making protected resource requests on behalf of the
              # resource owner and with its authorization.  The term "client" does
              # not imply any particular implementation characteristics (e.g.,
              # whether the application executes on a server, a desktop, or other
              # devices).
              inScope: true
        
            - ID: AUTHORIZATION_SERVER_OPERATOR
              description: |
                The operators in the Authorization Server.
              # The server issuing access tokens to the client after successfully
              # authenticating the resource owner and obtaining authorization.
              inScope: true
        
        
        
        
        analysis:
        
         
        threats:
        ```
    Context: security Objectives
        The list of security objectives defines a high level security properties that the design, in any form should achieve. 
        Taxonomies like CIA (confidentiality integrity availability) are also necessary as common
        threat impacts those security objectives as necessary. This is used also to compose attack trees in the report.
    Context: assets
        This is a decompositino of what is being built. Threats refers alfo to assets (REFID: ASSET_ID) 
        Assets are also dataflow (e.g. connections), this is to do dataflow analysis and are also referred in the threat model.
    Context: attackers
        This section contain the list of plausible attacekr and threat agents, some can be also out of scope explicitly (for example system administrator
        of a software system)
    Context: threat model scope definition
        "What are we building?" and define what is is scope in a way that it will mainly facilitate the analysis of the threat. It will facilitate the analysis by allowing to only focus on what it is really in scope by reducing it. If we fail to reduce the scope to the essential, then the number of things that can go wrong grows exponentially and the effort becomes overwhelming and difficult to estimate and to measure progress. Rigorously defining the scope and classifying the various part of the system (we tend to call it 'assets' here) also allows to improve the system documentation by avoid ambiguity in names and having an holistic view of the system across dev teams etc.
        At an high level we know what is the broader scope, the 'title' of the whole threat model. IT will be something like "Threat model of system X" or "Threat Model of product Y". That is still a vague definition of its scope and is not allowing us to reduce it to the essential as many points are still undefined and many questions unanswered:
        The System X runs on a could infrastructure, is it the infrastructure (network, firewalls, load balancers etc) in scope ?
        Is the build pipeline from the source code repositories to the product release artifact repository in scope?
        Are the used imported libraries and artifact in scope?
        Are the possible weaknesses of this used cryptographic algorithm or the menace from future quantum computer braking it in scope?
        Most times the answer to those questions depend on the context in a of case by case scenario. And often people would not agree even inside the same organisation to what the answer should be. Let's try to adopt another more rigorous approach. We need to first of all define what are we building... So we reformulate the questions "are are we building ... ?
        [...] is it the infrastructure (network, firewalls, load balancers etc) in scope ?
        becomes
        [...] Are we building the infrastructure (network, firewalls, load balancers etc)?
        it may be the case that the developers are in fact delivering some form of infrastructure as part of the product itself (Kubernetes configurations, HELM charts, docker compose files, Terraform script and other IAC artifacts). in this case all of what is built is clearly in scope! On the other hand something that is not build but just "used" by the system, for example a mutual TLS connection (mTLS) may well be listed as a countermeasure of a specific identified threat not as an asset in scope an analysis.
        The same for the question "Is the build pipeline [...] in scope?" becomes "Are we building the build pipeline?" it will probably be in scope, specially if there's a DevOps teams building it, it will be what that teams build to be a specific part of the threat model.
        "Are the used imported libraries and artifact in scope?" ... almost by definition an imported library is not a created library. So the modified question "Are the building imported libraries and artifact in scope?" is a likely No. Nevertheless the dev team build the imports, chooses the library and the used version. For example if the software uses an Object Relationship Mapping (ORM) library like Hibernate, it may well be a countermeasure for some kind of SQL Injection but the library in itself will not be threat modeled. The fact that that version may have disclosed vulnerabilities (CVEs) that it is actively well maintained and used in a proper way is it indeed in scope. In fact the dev teams build an import of the libraries in the project configuration files and build the use of the library in the source code itself.
        And we need also to remember that threat modeling is not the beginning and the end of software security ... and not even of software security design. We are not going to capture all and every possible risk related to the final system, even trying to do so will become an infinite exercise. Our aim is to identify what can go wrong in what we build. The more we can focus our analysis (aka reduce the scope to the essence, to what we build) the best we are going to contribute to the security from the threat modeling practice.
        Defining a scope (or sub-scope) that exactly matches one dev team's work also makes the process more streamlined and actionable. Reviewing the findings, for example the missing countermeasures, can be done within a single's team responsibility, tools and processes.
    Context: yaml threats section
        This sectino contains indications about the threat in yaml (-ID:...)
        countermeasures: should be the last attribtue on the list (not fullyMitigated: or others)
        Use this order for attributes:
        In this version, the attributes are reordered as follows:
        - ID
        - title
        - attack
        - threatType
        - impactDesc
        - impactedSecObj
        - attackers
        - CVSS
        - fullyMitigated 
        - countermeasures (last one)
        it is important that countermeasures is the last, specially when asked to reorder attributes
        Do not get too repetitive with the IDs of the threats, like addind "ENHANCED" everywhere
    Context: CVSS section
        Here is an example of a threat CVSS section. Create the vector as in this example:
         ```yaml
            CVSS:
                  vector: CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N
            ```
         do not use "base:" attribute
    Context: Attacker
        YAML Referecnes to attackers needs the attacker itself to be previously defined e.g.- REFID: ECONOMIC_ACTORS needs a previous 
        definition is scope!
    Context: countermeasure yaml attributes
        There is not "details:", use only "description:"
    Context: order of main YAML attributes
        ID, title, version: , children, authors, scope, analysis, threats
    Context: how to interpret and read the final report
        What is the risk of a missing mitigation? it depends, if the threat is mitigated (status) then the countermeasure is not chosen.
        If the threat is not mitigated (status) then the countermeasure is missing and it is a risk.
        The risk level is determined by the impact and the likelihood of the threat. The impact is determined by the security objective impacted and the impact description.
        The likelihood is determined by the attacker capability and the countermeasure effectiveness.
        The risk level is determined by the combination of impact and likelihood (CVSS)
        The impact is a qualitative description of the risk, the attack is a qualitative description of the likelihood/process of attack.
        The CVSS gives quantitative values for impact and likelihood.
        