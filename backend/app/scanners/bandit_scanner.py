from pathlib import Path
import json
import subprocess
from typing import Any


SEVERITY_MAP = {
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
}


def scan_python_with_bandit(
    file_path: Path,
) -> list[dict[str, Any]]:
    """
    Run Bandit against a Python file and convert
    Bandit's results into the SecureAI finding format.
    """

    try:
        result = subprocess.run(
            [
                "python",
                "-m",
                "bandit",
                "-q",
                "-f",
                "json",
                str(file_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

    except subprocess.TimeoutExpired:
        return []

    except OSError:
        return []

    # Bandit can return a non-zero exit code when
    # vulnerabilities are found.
    if not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[dict[str, Any]] = []

    for item in data.get("results", []):

        bandit_severity = str(
            item.get(
                "issue_severity",
                "MEDIUM",
            )
        ).upper()

        severity = SEVERITY_MAP.get(
            bandit_severity,
            "MEDIUM",
        )

        findings.append(
            {
                "rule_id": item.get(
                    "test_id",
                    "BANDIT",
                ),
                "vulnerability_type": _get_vulnerability_type(
                    item
                ),
                "severity": severity,
                "file_path": str(file_path),
                "line": item.get(
                    "line_number",
                    0,
                ),
                "column": item.get(
                    "col_offset",
                    0,
                ),
                "message": item.get(
                    "issue_text",
                    "Potential security issue detected.",
                ),
                "evidence": item.get(
                    "code",
                    "",
                ),
                "recommendation": _get_recommendation(
                    item
                ),
                "confidence": str(
                    item.get(
                        "issue_confidence",
                        "MEDIUM",
                    )
                ).upper(),
                "cwe_id": (
                    item.get(
                        "issue_cwe",
                        {}
                    ) or {}
                ).get("id"),
                "source": "bandit",
            }
        )

    return findings


def _get_vulnerability_type(
    item: dict[str, Any],
) -> str:
    """Convert Bandit test IDs into readable categories."""

    test_id = item.get(
        "test_id",
        "",
    )

    vulnerability_types = {
        "B307": "Code Injection",
        "B602": "Command Injection",
        "B301": "Unsafe Deserialization",
        "B324": "Weak Cryptographic Hash",
        "B403": "Unsafe Deserialization",
        "B404": "Command Execution",
    }

    return vulnerability_types.get(
        test_id,
        "Security Issue",
    )


def _get_recommendation(
    item: dict[str, Any],
) -> str:
    """Generate a basic remediation recommendation."""

    test_id = item.get(
        "test_id",
        "",
    )

    recommendations = {
        "B307": (
            "Avoid eval() with untrusted input. "
            "Use safer parsing such as ast.literal_eval() "
            "when appropriate."
        ),
        "B602": (
            "Avoid shell=True with untrusted input. "
            "Prefer subprocess arguments as a list "
            "without invoking a shell."
        ),
        "B301": (
            "Avoid deserializing untrusted data with pickle. "
            "Use a safer serialization format such as JSON "
            "when possible."
        ),
        "B324": (
            "Do not use MD5 for security-sensitive hashing. "
            "Use a modern cryptographic hash or password "
            "hashing algorithm appropriate to the use case."
        ),
        "B403": (
            "Avoid pickle for untrusted data and prefer "
            "a safer serialization format."
        ),
        "B404": (
            "Review subprocess usage and ensure commands "
            "cannot be controlled by untrusted input."
        ),
    }

    return recommendations.get(
        test_id,
        (
            "Review the reported code and apply "
            "appropriate secure coding practices."
        ),
    )