import pytest
from skills.real_ids_model import analyze_traffic_real, get_real_ids_model

def test_real_ids_model_prediction() -> None:
    # Construct a sample matching the 46 features expected by the model preprocessor
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
    
    res = analyze_traffic_real(sample)
    
    # Assert return structure
    assert res["is_genuine_ml"] is True
    assert res["model"] == "XGBoost CIC-IoT-2023"
    assert res["accuracy"] == "99.44%"
    assert "prediction" in res
    assert "confidence" in res
    assert "severity" in res
    assert "xai_explanation" in res
    assert "recommendation" in res
    
    xai = res["xai_explanation"]
    assert xai["method"] == "XGBoost Feature Importance"
    assert "top_features" in xai
    assert "reasoning" in xai

def test_get_real_ids_model_singleton() -> None:
    m1 = get_real_ids_model()
    m2 = get_real_ids_model()
    assert m1 is m2
