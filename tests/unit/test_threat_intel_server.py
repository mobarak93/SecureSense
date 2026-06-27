import pytest
from mcp_server.threat_intel_server import (
    lookup_ioc,
    get_device_criticality,
    check_nis2_compliance,
    check_global_compliance,
    get_framework_mapping,
    get_mitre_mapping,
    calculate_cvss_risk,
    analyze_real_traffic
)

def test_lookup_ioc() -> None:
    res = lookup_ioc("45.227.254.10", "ip")
    assert res["threat_score"] == 95
    assert res["threat_type"] == "Botnet Brute Force C2"
    assert res["recommendation"] == "BLOCK"

    res_clean = lookup_ioc("8.8.8.8", "ip")
    assert res_clean["threat_score"] == 0
    assert res_clean["recommendation"] == "ALLOW"

def test_get_device_criticality() -> None:
    res = get_device_criticality("ICU_MONITOR")
    assert res["criticality_level"] == "CRITICAL"
    assert res["score"] == 95

def test_check_nis2_compliance() -> None:
    res = check_nis2_compliance("encryption")
    assert res["violation_severity"] == "HIGH"
    assert "AES-256" in res["checklist"][0]

def test_check_global_compliance() -> None:
    res = check_global_compliance("NIST_CSF", "DE.CM")
    assert res["title"] == "Continuous Monitoring"
    assert "network_monitored" in res["requirements"]

def test_get_framework_mapping() -> None:
    res = get_framework_mapping("no encryption")
    assert "GDPR" in res["violated_frameworks"]
    assert "NIS2" in res["violated_frameworks"]
    assert res["severity"] == "HIGH"

def test_get_mitre_mapping_valid() -> None:
    res = get_mitre_mapping("DoS")
    assert res["technique_id"] == "T1498"
    assert res["tactic"] == "Impact"
    assert "T1498.001 Direct Network Flood" in res["subtechniques"]

    res_ddos = get_mitre_mapping("DDoS")
    assert res_ddos["technique_id"] == "T1498"

    res_recon = get_mitre_mapping("Reconnaissance")
    assert res_recon["technique_id"] == "T1595"

def test_get_mitre_mapping_invalid() -> None:
    with pytest.raises(ValueError) as excinfo:
        get_mitre_mapping("MalwareExecution")
    assert "Invalid attack_type" in str(excinfo.value)

def test_calculate_cvss_risk_valid() -> None:
    # Test Ventilator + DoS + CVE-2024-3400 (CVSS 10.0) -> composite should be 99
    res = calculate_cvss_risk(attack_type="DoS", device_type="VENTILATOR", cve_id="CVE-2024-3400")
    assert res["cvss_score"] == 10.0
    assert res["patient_risk_score"] == "EXTREME"
    assert res["composite_score"] == 99
    assert res["priority"] == "CRITICAL"
    assert "IMMEDIATE ISOLATION REQUIRED" in res["immediate_actions"]

    # Test Smart Thermostat + Reconnaissance -> lower risk
    res_low = calculate_cvss_risk(attack_type="Reconnaissance", device_type="SMART_THERMOSTAT")
    assert res_low["composite_score"] < 40
    assert res_low["patient_risk_score"] == "LOW"

def test_calculate_cvss_risk_invalid() -> None:
    with pytest.raises(ValueError) as excinfo:
        calculate_cvss_risk(attack_type="DoS", device_type="INVALID_DEVICE")
    assert "Invalid device_type" in str(excinfo.value)

def test_analyze_real_traffic() -> None:
    features = [
        'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 
        'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 
        'psh_flag_number', 'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 
        'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count', 'HTTP', 
        'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 
        'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 
        'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance', 
        'Variance', 'Weight'
    ]
    sample = {f: 0.0 for f in features}
    res = analyze_real_traffic(sample)
    assert res["is_genuine_ml"] is True
    assert res["model"] == "XGBoost CIC-IoT-2023"

