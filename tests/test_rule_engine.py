import pytest
from detection.rule_engine import RuleEngine
from config import settings

def test_rule_engine_high_rate():
    engine = RuleEngine()
    
    # Normal Rate
    stats_normal = {"req_count": 50, "unique_ports": 2, "syn_count": 10, "duration_sec": 60}
    res_normal = engine.evaluate("10.0.0.1", stats_normal)
    assert res_normal["triggered"] is False
    
    # High Rate (Limit is 100/min)
    stats_high = {"req_count": 150, "unique_ports": 1, "syn_count": 2, "duration_sec": 60}
    res_high = engine.evaluate("10.0.0.2", stats_high)
    assert res_high["triggered"] is True
    assert any("High request rate" in r for r in res_high["reasons"])

def test_rule_engine_port_scan():
    engine = RuleEngine()
    
    # High Ports (Over Max)
    stats = {"req_count": 20, "unique_ports": settings.MAX_PORTS_SCANNED + 5, "syn_count": 10, "duration_sec": 60}
    res = engine.evaluate("10.0.0.3", stats)
    
    assert res["triggered"] is True
    assert any("Port scanning" in r for r in res["reasons"])

def test_rule_engine_syn_flood():
    engine = RuleEngine()
    
    # Trigger SYN Flood (>50% SYN and >20 reqs)
    stats = {"req_count": 30, "unique_ports": 1, "syn_count": 20, "duration_sec": 10}
    res = engine.evaluate("10.0.0.4", stats)
    
    assert res["triggered"] is True
    assert any("SYN flood" in r for r in res["reasons"])
