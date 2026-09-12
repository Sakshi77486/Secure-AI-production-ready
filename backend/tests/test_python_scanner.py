from app.scanners.python_scanner import scan_python_source


VULNERABLE_CODE = """
import subprocess
import pickle
import hashlib

def vulnerable_function(user_input):
    result = eval(user_input)

    subprocess.run(user_input, shell=True)

    data = pickle.loads(user_input)

    password_hash = hashlib.md5(
        user_input.encode()
    ).hexdigest()

    return result, data, password_hash
"""


def test_python_scanner_detects_vulnerabilities():
    findings = scan_python_source(
        VULNERABLE_CODE,
        file_path="test_vulnerable.py",
    )

    rule_ids = {
        finding["rule_id"]
        for finding in findings
    }

    assert "PY001" in rule_ids
    assert "PY003" in rule_ids
    assert "PY004" in rule_ids
    assert "PY007" in rule_ids


def test_python_scanner_returns_file_information():
    findings = scan_python_source(
        VULNERABLE_CODE,
        file_path="test_vulnerable.py",
    )

    assert findings

    for finding in findings:
        assert finding["file_path"] == "test_vulnerable.py"
        assert finding["line"] > 0
        assert finding["severity"]
        assert finding["recommendation"]