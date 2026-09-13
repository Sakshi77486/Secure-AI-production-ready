from pathlib import Path
import re
from typing import Any


SECRET_PATTERNS = [
    (
        "SEC001",
        "Hardcoded API Key",
        "HIGH",
        re.compile(
            r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']"""
        ),
    ),
    (
        "SEC002",
        "Hardcoded Password",
        "HIGH",
        re.compile(
            r"""(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']"""
        ),
    ),
    (
        "SEC003",
        "AWS Access Key",
        "CRITICAL",
        re.compile(
            r"""AKIA[0-9A-Z]{16}"""
        ),
    ),
    (
        "SEC004",
        "Private Key",
        "CRITICAL",
        re.compile(
            r"""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"""
        ),
    ),
    (
        "SEC005",
        "Hardcoded Secret",
        "HIGH",
        re.compile(
            r"""(?i)(secret|token)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']"""
        ),
    ),
]


def scan_secrets(file_path: Path) -> list[dict[str, Any]]:
    """
    Scan a source file for possible hardcoded secrets.
    """

    findings: list[dict[str, Any]] = []

    try:
        content = file_path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return findings

    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):
        for (
            rule_id,
            vulnerability_type,
            severity,
            pattern,
        ) in SECRET_PATTERNS:

            match = pattern.search(line)

            if not match:
                continue

            findings.append(
                {
                    "rule_id": rule_id,
                    "vulnerability_type": vulnerability_type,
                    "severity": severity,
                    "file_path": str(file_path),
                    "line": line_number,
                    "column": match.start() + 1,
                    "message": (
                        f"Potential {vulnerability_type.lower()} "
                        "detected."
                    ),
                    "evidence": line.strip(),
                    "recommendation": (
                        "Remove the secret from source code and "
                        "store it securely using environment "
                        "variables or a secrets manager."
                    ),
                    "confidence": "MEDIUM",
                    "source": "secret_scanner",
                }
            )

    return findings