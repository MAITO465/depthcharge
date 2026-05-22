import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reputation.checker import scan_reputation, check_osv_vulnerabilities
from modules.static.analyzer import check_typosquatting, levenshtein_distance, StaticASTVisitor
from scorer import calculate_score
import ast

def test_levenshtein_distance():
    assert levenshtein_distance("requests", "reqeusts") == 2
    assert levenshtein_distance("numpy", "numyp") == 2
    assert levenshtein_distance("flask", "flask") == 0
    assert levenshtein_distance("a", "") == 1

def test_typosquatting_detection():
    # 'reqeusts' is distance 2 from 'requests' (popular package)
    typo = check_typosquatting("reqeusts", "pypi")
    assert typo is not None
    assert typo["target"] == "requests"
    
    # 'requests' itself should not trigger typosquatting warning
    assert check_typosquatting("requests", "pypi") is None

def test_static_ast_visitor():
    code = """
import os
import subprocess
import base64

eval("print(1)")
subprocess.Popen(["ls"])
os.system("whoami")

sensitive_key = "AWS_ACCESS_KEY_ID"
"""
    # 1. Test generic file (not setup.py)
    tree = ast.parse(code)
    visitor_generic = StaticASTVisitor("test_file.py")
    visitor_generic.visit(tree)
    
    alerts_generic = visitor_generic.alerts
    types_generic = [a["type"] for a in alerts_generic]
    
    assert "dynamic_execution" in types_generic  # eval
    assert "sensitive_data" in types_generic     # AWS_ACCESS_KEY_ID
    assert "setup_hook_danger" not in types_generic  # not setup.py
    
    # 2. Test setup.py file
    visitor_setup = StaticASTVisitor("setup.py")
    visitor_setup.visit(tree)
    
    alerts_setup = visitor_setup.alerts
    types_setup = [a["type"] for a in alerts_setup]
    
    assert "setup_hook_danger" in types_setup     # setup.py hooks
    assert "dynamic_execution" in types_setup
    assert "sensitive_data" in types_setup

@patch('requests.post')
def test_osv_vulnerabilities(mock_post):
    # Mock OSV response with 1 vuln
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_ok = True
    mock_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-1234",
                "summary": "Mock vulnerability description",
                "details": "Details here...",
                "modified": "2026-05-21T00:00:00Z"
            }
        ]
    }
    mock_post.return_value = mock_response
    
    vulns = check_osv_vulnerabilities("somepackage", "pypi")
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-1234"

def test_scorer():
    # 1. Clean Package
    rep = {"vulnerabilities": [], "is_suspiciously_new": False, "days_old": 100, "releases_count": 20}
    stat = {"typosquatting": None, "alerts": []}
    dyn = {"docker_available": True, "installation_success": True, "import_success": True, "events": []}
    
    res = calculate_score(rep, stat, dyn)
    assert res["score"] == 0
    assert res["risk_level"] == "Low"
    
    # 2. Medium Risk Package (known malicious matches / vulns in database triggers +50)
    rep_med = {"vulnerabilities": [], "known_malicious": True, "is_suspiciously_new": False, "releases_count": 20}
    stat_med = {"typosquatting": None, "alerts": []}
    dyn_med = {"docker_available": True, "installation_success": True, "import_success": True, "events": []}
    
    res_med = calculate_score(rep_med, stat_med, dyn_med)
    assert res_med["score"] == 50
    assert res_med["risk_level"] == "Medium"

    # 3. High Risk Package (obfuscation + dangerous AST + suspicious runtime)
    rep_high = {"vulnerabilities": [], "is_suspiciously_new": False, "releases_count": 20}
    stat_high = {"typosquatting": None, "obfuscation_detected": True, "dangerous_ast_detected": True}
    dyn_high = {"docker_available": True, "suspicious_runtime_detected": True}
    
    res_high = calculate_score(rep_high, stat_high, dyn_high)
    assert res_high["score"] == 70  # 25 + 20 + 25 = 70
    assert res_high["risk_level"] == "High"

def test_scorer_capped_reasons():
    # Test that score is capped at 100 and risk reasons/breakdowns function correctly
    rep = {
        "known_malicious": True,
        "is_suspiciously_new": True,
        "releases_count": 2
    }
    stat = {
        "obfuscation_detected": True,
        "dangerous_ast_detected": True,
        "typosquatting": {"target": "requests"}
    }
    dyn = {
        "suspicious_runtime_detected": True
    }
    
    res = calculate_score(rep, stat, dyn)
    assert res["score"] == 100
    assert res["risk_level"] == "High"
    
    assert res["breakdown"]["known_malicious"] == 50
    assert res["breakdown"]["obfuscation"] == 25
    assert res["breakdown"]["dangerous_ast"] == 20
    assert res["breakdown"]["suspicious_runtime"] == 25
    assert res["breakdown"]["typosquatting"] == 15
    assert res["breakdown"]["suspicious_metadata"] == 10


def test_pdf_generation(tmp_path):
    # If reportlab is not installed, skip or verify import failure handling
    try:
        from modules.report.pdf_generator import generate_pdf_report
        pdf_available = True
    except ImportError:
        pdf_available = False
        
    if not pdf_available:
        pytest.skip("reportlab not installed, skipping PDF generation test")
        
    results = {
        "test-package": {
            "score": 45,
            "risk_level": "Medium",
            "reasons": ["Suspicious static patterns: dynamic execution", "Typo-squatting target: requests"],
            "reputation": {
                "ecosystem": "pypi",
                "version": "1.0.0",
                "author": "John Doe",
                "author_email": "john@example.com",
                "created_at": "2026-05-20T12:00:00",
                "releases_count": 5,
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-1234",
                        "summary": "Mock vulnerability for testing PDF generation",
                        "details": "Details of the vulnerability go here...",
                        "modified": "2026-05-20T12:00:00"
                    }
                ]
            },
            "static": {
                "alerts": [
                    {
                        "severity": "high",
                        "type": "dynamic_execution",
                        "file": "setup.py",
                        "line": 12,
                        "message": "Found dynamic execution via eval()"
                    }
                ]
            },
            "dynamic": {
                "docker_available": True,
                "installation_success": True,
                "import_success": True,
                "events": [
                    {
                        "type": "process_spawn",
                        "details": "python -c import socket"
                    }
                ]
            }
        }
    }
    
    output_pdf = os.path.join(str(tmp_path), "test_report.pdf")
    generate_pdf_report(results, output_pdf)
    
    assert os.path.exists(output_pdf)
    assert os.path.getsize(output_pdf) > 0

