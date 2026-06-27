import pytest
from security.stride_analyzer import (
    get_threats_by_category,
    get_threats_by_device,
    analyze_system
)

def test_get_threats_by_category_valid() -> None:
    threat = get_threats_by_category("S")
    assert threat["category"] == "Spoofing"
    assert "Identity verification" in threat["description"]
    assert "ICU_MONITOR" in threat["affected_devices"]
    assert len(threat["scenarios"]) > 0

    threat_lower = get_threats_by_category("t")
    assert threat_lower["category"] == "Tampering"

def test_get_threats_by_category_invalid() -> None:
    with pytest.raises(ValueError) as excinfo:
        get_threats_by_category("X")
    assert "Invalid STRIDE category" in str(excinfo.value)

def test_get_threats_by_device() -> None:
    threats = get_threats_by_device("ICU_MONITOR")
    # ICU MONITOR should have Spoofing (S), Information Disclosure (I), and Denial of Service (D)
    stride_keys = [t["stride_key"] for t in threats]
    assert "S" in stride_keys
    assert "I" in stride_keys
    assert "D" in stride_keys

def test_analyze_system() -> None:
    devices = ["VENTILATOR", "INFUSION_PUMP"]
    result = analyze_system(devices)
    
    assert "threat_profile" in result
    assert "recommended_mitigations" in result
    assert "compliance_references" in result

    # Ventilator should map to Spoofing (S), Tampering (T), Repudiation (R), Denial of Service (D)
    # Infusion Pump should map to Spoofing (S), Tampering (T), Elevation of Privilege (E)
    profile_keys = result["threat_profile"].keys()
    assert "S" in profile_keys
    assert "T" in profile_keys
    assert "R" in profile_keys
    assert "D" in profile_keys
    assert "E" in profile_keys

    assert len(result["recommended_mitigations"]) > 0
    assert len(result["compliance_references"]) > 0
