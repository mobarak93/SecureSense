# SecureSense Security Context & Coding Standards

This file establishes the persistent security context, coding guidelines, and threat modeling rules for the SecureSense Healthcare IoT Multi-Agent System. All subsequent development, code edits, and features must adhere strictly to these principles.

---

## 1. Input & Output Protection Standards

### Input Validation (Prompt Injection & Buffer Overflows)
- **Constraint**: All user-facing inputs must be validated using the functions defined in [input_validator.py](file:///f:/SecureSense/securesense/security/input_validator.py).
- **Size Limit**: Absolute maximum query length is **2000 characters**.
- **Blocked Patterns**:
  - `ignore previous instructions`
  - `you are now`
  - `system prompt`
  - `jailbreak`
  - `forget your instructions`
  - `act as`
- **Action**: Any validation failure must raise a `ValueError` immediately and log the event to `security.log`.

### Output Sanitization (Sensitive Data Protection)
- **PII Leak Protection**: System outputs must never contain plaintext Social Security Numbers (SSNs) or Credit Card Numbers (CCNs).
- **Credential Protection**: System outputs must never print passwords, API keys, tokens, or system secrets.
- **Action**: Use `sanitize_output` from [input_validator.py](file:///f:/SecureSense/securesense/security/input_validator.py). If sensitive data exposure is detected, block the transmission, log the violation to `security.log`, and raise a `ValueError`.

### Session Rate Limiting
- **Threshold**: Maximum **10 queries per minute** per user session.
- **Action**: Track query timestamps on a sliding window. Raise a `ValueError` on breaches.

---

## 2. Healthcare IoT Threat Modeling (STRIDE)

All healthcare IoT devices must be modeled against the STRIDE framework using [stride_analyzer.py](file:///f:/SecureSense/securesense/security/stride_analyzer.py). Core assets are mapped to compliance frameworks (NIS2, ISO 27001, NIST CSF) and must be mitigated:

| Threat | Description | Specific Healthcare IoT Vulnerability | Key Mitigation Strategy | Compliance Link |
| :--- | :--- | :--- | :--- | :--- |
| **S**poofing | Identity Verification | Attacker sending fake telemetry to an `ICU_MONITOR` or `VENTILATOR`. | Enforce **mutual TLS (mTLS)** & x.509 device certificates. | NIS2 Art 21(2)(j) |
| **T**ampering | Data Integrity | Injecting dosage command overrides into an `INFUSION_PUMP`. | Cryptographically sign firmware & validate input payload schemas. | NIS2 Art 21(2)(g) |
| **R**epudiation | Audit Trail | Deleting log entries to cover up unauthorized access to a `VENTILATOR`. | Stream logs in real-time to a secure, write-once SIEM. | ISO 27001 A.12.4 |
| **I**nformation Disclosure | PII/PHI Leaks | Eavesdropping on unencrypted medical telemetry or HL7 database exports. | Enforce **TLS 1.3** and data-at-rest encryption (AES-256). | GDPR Art 32(1)(a) |
| **D**enial of Service | Availability | Flooding patient monitors with junk traffic to disable alarm systems. | Configure strict rate limiters, VLAN segmentation, and packet filtering. | NIS2 Art 21(2)(b) |
| **E**levation of Privilege | Access Control | Exploding buffer overflows to run unauthorized code on `INFUSION_PUMP` gateways. | Enforce **least privilege policies (PoLP)** and strict VLAN isolation. | ISO 27001 A.9.1.1 |

---

## 3. Secure Agent Development Guidelines

1. **Agent Tool Security**: Never give sub-agents direct write permission to key files (like `.env`, `pyproject.toml`, or configuration databases) unless verified via validation routines.
2. **Offline Mode First**: When running tests or local validations, always activate the integration test mock (`os.environ["INTEGRATION_TEST"] = "TRUE"`) to prevent hangs or rate limits due to high model demand.
3. **Log Integrity**: Maintain clear logging of all security events to `security.log`. Do not log raw PII or raw authentication keys/tokens.
