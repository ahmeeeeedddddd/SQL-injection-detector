"""
test_engine.py - Unit tests for the SQLi detection engine.
"""
import pytest
from engine.detector import detect

def test_safe_input():
    """Test a clean safe input."""
    result = detect("Hello, how are you today?")
    assert result["verdict"] == "safe"
    assert result["score"] <= 2
    assert len(result["matched_rules"]) == 0

def test_classic_sqli():
    """Test a classic ' OR 1=1 -- payload."""
    payload = "' OR 1=1 --"
    result = detect(payload)
    assert result["verdict"] == "malicious"
    assert "classic_tautology" in result["matched_rules"]
    assert "comment_sequence" in result["matched_rules"]
    assert result["attack_type"] == "boolean-based"

def test_union_select():
    """Test a UNION SELECT payload."""
    payload = "admin' UNION SELECT password FROM users--"
    result = detect(payload)
    assert result["verdict"] == "malicious"
    assert "union_select" in result["matched_rules"]
    assert result["attack_type"] == "union-based"

def test_time_based():
    """Test a time-based SLEEP(5) payload."""
    payload = "'; SELECT SLEEP(5)--"
    result = detect(payload)
    assert result["verdict"] == "malicious"
    assert "time_based_sleep" in result["matched_rules"]
    assert result["attack_type"] == "time-based blind"

def test_stacked_query():
    """Test a stacked query payload."""
    payload = "1; DROP TABLE users"
    result = detect(payload)
    assert result["verdict"] == "malicious"
    assert "stacked_query" in result["matched_rules"]
    assert result["attack_type"] == "stacked queries"

def test_encoding_bypass():
    """Test an encoding bypass attempt (URL-encoded)."""
    # %27 is '
    payload = "%27 OR 1=1"
    result = detect(payload)
    # Even if classic doesn't match directly due to %, url_encoding_bypass should catch it
    assert len(result["matched_rules"]) > 0
    assert result["verdict"] in ["suspicious", "malicious"]
