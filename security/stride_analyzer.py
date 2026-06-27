from typing import Dict, List, Any

STRIDE_THREAT_DATABASE = {
    "S": {
        "category": "Spoofing",
        "description": "Identity verification threats",
        "scenarios": [
            "An attacker masquerades as a legitimate patient telemetry gateway to send spoofed patient vitals to the ICU monitor.",
            "Spoofing an administrator session via session hijacking or credential theft to access device interfaces."
        ],
        "affected_devices": ["ICU_MONITOR", "INFUSION_PUMP", "VENTILATOR"],
        "compliance_mappings": {
            "NIS2": "Article 21(2)(j) (MFA & access policies)",
            "ISO_27001": "A.9.4 (System and application access control)",
            "NIST_CSF": "PR.AC-1 (Access control policies)"
        },
        "mitigations": [
            "Enforce cryptographically secure device identities (e.g., x.509 certificates).",
            "Implement mutual TLS (mTLS) for all device-to-gateway and gateway-to-server communications.",
            "Enforce Multi-Factor Authentication (MFA) for administrative endpoints."
        ]
    },
    "T": {
        "category": "Tampering",
        "description": "Data integrity threats",
        "scenarios": [
            "Intercepting and altering infusion pump dosage commands in-transit over unencrypted Wi-Fi.",
            "Modifying MRI scanner firmware configurations via unauthorized physical USB access."
        ],
        "affected_devices": ["INFUSION_PUMP", "MRI_SCANNER", "VENTILATOR"],
        "compliance_mappings": {
            "NIS2": "Article 21(2)(g) (Cryptography and encryption)",
            "ISO_27001": "A.12.2 (Protection from malware) & A.14.1.2 (Securing application services on public networks)",
            "NIST_CSF": "PR.DS-1 (Data integrity at rest and in transit)"
        },
        "mitigations": [
            "Encrypt all data in transit using TLS 1.3.",
            "Digitally sign firmware updates and implement secure boot mechanisms on all medical hardware.",
            "Validate and sanitize input payload schemas at the application layer."
        ]
    },
    "R": {
        "category": "Repudiation",
        "description": "Audit trail threats",
        "scenarios": [
            "A malicious actor disables audit logs or deletes syslog records on the patient data aggregator to cover the trace of unauthorized access.",
            "Lack of non-repudiation mechanisms for critical control actions (like changing ventilator settings), preventing forensic accountability."
        ],
        "affected_devices": ["VENTILATOR", "ADMIN_PC", "PACEMAKER_CONTROLLER"],
        "compliance_mappings": {
            "NIS2": "Article 21(2)(c) (Incident handling & audit trail logging)",
            "ISO_27001": "A.12.4 (Logging and monitoring)",
            "NIST_CSF": "PR.PT-1 (Audit/log records generated and reviewed)"
        },
        "mitigations": [
            "Stream all logs in real-time to a write-once-read-many (WORM) log server or secure SIEM.",
            "Digitally sign audit log entries to guarantee non-repudiation.",
            "Restrict log deletion or modification permissions to secure root break-glass accounts."
        ]
    },
    "I": {
        "category": "Information Disclosure",
        "description": "PII/PHI leaks",
        "scenarios": [
            "Eavesdropping on unencrypted HL7/DICOM communications containing Patient Health Information (PHI) over the hospital network.",
            "Exposing sensitive patient vitals data through overly verbose error messages or insecure debug ports."
        ],
        "affected_devices": ["ICU_MONITOR", "MRI_SCANNER", "ADMIN_PC"],
        "compliance_mappings": {
            "NIS2": "Article 21(2)(g) (Cryptography) & GDPR Article 32(1)(a) (Encryption of personal data)",
            "ISO_27001": "A.8.2.3 (Labeling of information) & A.13.2.1 (Information transfer policies)",
            "NIST_CSF": "PR.DS-2 (Data-at-rest is protected)"
        },
        "mitigations": [
            "Encrypt PHI at rest using AES-256 and in transit using TLS 1.3.",
            "Implement data masking and tokenization for logs and administrative interfaces.",
            "Segment IoT device VLANs to isolate PHI data flows from general guest networks."
        ]
    },
    "D": {
        "category": "Denial of Service",
        "description": "Availability threats",
        "scenarios": [
            "Flooding ventilator control ports with malformed network packets, causing device crash or network disconnect.",
            "Broadcasting RF jamming signals to disrupt critical wireless communication between pacemakers and their controllers."
        ],
        "affected_devices": ["VENTILATOR", "PACEMAKER_CONTROLLER", "ICU_MONITOR"],
        "compliance_mappings": {
            "NIS2": "Article 21(2)(b) (Incident response & business continuity)",
            "ISO_27001": "A.17.1 (Information security continuity)",
            "NIST_CSF": "PR.IP-9 (Response plans and recovery plans are maintained)"
        },
        "mitigations": [
            "Configure rate-limiters and packet filtering on IoT gateway firewalls.",
            "Establish fail-safe offline local modes on all critical life-support devices.",
            "Deploy redundant network channels and load balancers to mitigate packet flood spikes."
        ]
    },
    "E": {
        "category": "Elevation of Privilege",
        "description": "Access control threats",
        "scenarios": [
            "Exploiting a buffer overflow in the administrative interface of an infusion pump to run arbitrary code with root access.",
            "Lateral movement from a compromised guest smart thermostat to the clinical network segment due to improper VLAN configuration."
        ],
        "affected_devices": ["INFUSION_PUMP", "SMART_THERMOSTAT", "ADMIN_PC"],
        "compliance_mappings": {
            "NIS2": "Article 21(2)(i) (Access control & human resources security)",
            "ISO_27001": "A.9.1.1 (Access control policy)",
            "NIST_CSF": "PR.AC-4 (Access permissions managed according to least privilege)"
        },
        "mitigations": [
            "Implement strict Role-Based Access Control (RBAC) and enforce Least Privilege.",
            "Conduct routine static/dynamic application security testing (SAST/DAST) on IoT gateway software.",
            "Enforce strict logical network micro-segmentation between medical and non-medical VLANs."
        ]
    }
}


def get_threats_by_category(category_key: str) -> Dict[str, Any]:
    """Retrieves threat scenario and mapping for a single STRIDE letter/category.

    Args:
        category_key: 'S', 'T', 'R', 'I', 'D', or 'E' (case-insensitive).
    """
    key = category_key.strip().upper()
    if key not in STRIDE_THREAT_DATABASE:
        valid_keys = list(STRIDE_THREAT_DATABASE.keys())
        raise ValueError(f"Invalid STRIDE category '{category_key}'. Must be one of: {', '.join(valid_keys)}")
    return STRIDE_THREAT_DATABASE[key]


def get_threats_by_device(device_name: str) -> List[Dict[str, Any]]:
    """Finds all threat scenarios affecting a specific device.

    Args:
        device_name: e.g. 'ICU_MONITOR', 'VENTILATOR'
    """
    device = device_name.strip().upper()
    matching_threats = []
    
    for key, val in STRIDE_THREAT_DATABASE.items():
        if device in val["affected_devices"]:
            matching_threats.append({
                "stride_key": key,
                "category": val["category"],
                "description": val["description"],
                "scenarios": val["scenarios"],
                "compliance_mappings": val["compliance_mappings"],
                "mitigations": val["mitigations"]
            })
            
    return matching_threats


def analyze_system(devices: List[str]) -> Dict[str, Any]:
    """Analyzes a set of devices to return their composite threat profiles and mitigation plan."""
    composite = {}
    all_mitigations = set()
    all_violations = set()
    
    for dev in devices:
        threats = get_threats_by_device(dev)
        for t in threats:
            key = t["stride_key"]
            if key not in composite:
                composite[key] = {
                    "category": t["category"],
                    "description": t["description"],
                    "scenarios": [],
                    "affected_devices": []
                }
            # Add unique scenarios
            for s in t["scenarios"]:
                if s not in composite[key]["scenarios"]:
                    composite[key]["scenarios"].append(s)
            # Log device
            if dev not in composite[key]["affected_devices"]:
                composite[key]["affected_devices"].append(dev)
                
            for mit in t["mitigations"]:
                all_mitigations.add(mit)
                
            for framework, control in t["compliance_mappings"].items():
                all_violations.add(f"{framework} - {control}")
                
    return {
        "threat_profile": composite,
        "recommended_mitigations": sorted(list(all_mitigations)),
        "compliance_references": sorted(list(all_violations))
    }
