from __future__ import annotations
import ast 
from dataclasses import dataclass,asdict
from pathlib import Path 
from typing import Any

@dataclass(slots=True)
class SecurityFinding:
    rule_id: str
    vulnerability_type: str
    severity: str
    file_path: str
    line: int
    column: int
    message: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source: str) -> None:
        self.file_path = file_path
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[SecurityFinding] = []

    def _evidence(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()

        return ""

    def _add_finding(
        self,
        *,
        rule_id: str,
        vulnerability_type: str,
        severity: str,
        node: ast.AST,
        message: str,
        recommendation: str,
    ) -> None:
        line = getattr(node, "lineno", 0)
        column = getattr(node, "col_offset", 0)

        self.findings.append(
            SecurityFinding(
                rule_id=rule_id,
                vulnerability_type=vulnerability_type,
                severity=severity,
                file_path=self.file_path,
                line=line,
                column=column,
                message=message,
                evidence=self._evidence(line),
                recommendation=recommendation,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        self._check_dangerous_execution(node)
        self._check_subprocess(node)
        self._check_pickle(node)
        self._check_yaml(node)
        self._check_weak_hashing(node)

        self.generic_visit(node)

    def _check_dangerous_execution(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self._add_finding(
                    rule_id="PY001",
                    vulnerability_type="Code Injection",
                    severity="CRITICAL",
                    node=node,
                    message=(
                        "eval() dynamically executes Python code and can allow "
                        "attacker-controlled input to execute arbitrary code."
                    ),
                    recommendation=(
                        "Avoid eval(). Replace it with explicit parsing or a "
                        "strictly controlled mapping of allowed operations."
                    ),
                )

            elif node.func.id == "exec":
                self._add_finding(
                    rule_id="PY002",
                    vulnerability_type="Code Injection",
                    severity="CRITICAL",
                    node=node,
                    message=(
                        "exec() executes dynamically supplied Python code and "
                        "can result in arbitrary code execution."
                    ),
                    recommendation=(
                        "Remove exec() and use explicit program logic or a "
                        "strictly validated parser."
                    ),
                )

    def _check_subprocess(self, node: ast.Call) -> None:
        if not self._is_subprocess_call(node):
            return

        shell_enabled = False

        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                shell_enabled = True
                break

        if shell_enabled:
            self._add_finding(
                rule_id="PY003",
                vulnerability_type="Command Injection",
                severity="HIGH",
                node=node,
                message=(
                    "subprocess is executed with shell=True. If command input "
                    "contains attacker-controlled data, this can enable command injection."
                ),
                recommendation=(
                    "Avoid shell=True. Pass commands as a list of arguments "
                    "and validate all externally supplied values."
                ),
            )

    @staticmethod
    def _is_subprocess_call(node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            return (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            )

        return False

    def _check_pickle(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute):
            return

        if not isinstance(node.func.value, ast.Name):
            return

        if node.func.value.id != "pickle":
            return

        dangerous_functions = {
            "load",
            "loads",
            "Unpickler",
        }

        if node.func.attr in dangerous_functions:
            self._add_finding(
                rule_id="PY004",
                vulnerability_type="Unsafe Deserialization",
                severity="CRITICAL",
                node=node,
                message=(
                    "Python pickle deserialization can execute arbitrary code "
                    "when processing untrusted serialized data."
                ),
                recommendation=(
                    "Do not deserialize untrusted data with pickle. Prefer "
                    "JSON or another data-only serialization format."
                ),
            )

    def _check_yaml(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute):
            return

        if not isinstance(node.func.value, ast.Name):
            return

        if node.func.value.id != "yaml":
            return

        if node.func.attr not in {"load", "unsafe_load", "full_load"}:
            return

        if node.func.attr in {"unsafe_load", "full_load"}:
            self._add_finding(
                rule_id="PY005",
                vulnerability_type="Unsafe YAML Deserialization",
                severity="HIGH",
                node=node,
                message=(
                    f"yaml.{node.func.attr}() can deserialize unsafe YAML "
                    "objects when processing untrusted input."
                ),
                recommendation=(
                    "Use yaml.safe_load() for untrusted YAML input."
                ),
            )
            return

        has_safe_loader = any(
            keyword.arg == "Loader"
            and isinstance(keyword.value, ast.Attribute)
            and isinstance(keyword.value.value, ast.Name)
            and keyword.value.value.id == "yaml"
            and keyword.value.attr == "SafeLoader"
            for keyword in node.keywords
        )

        if not has_safe_loader:
            self._add_finding(
                rule_id="PY006",
                vulnerability_type="Unsafe YAML Deserialization",
                severity="HIGH",
                node=node,
                message=(
                    "yaml.load() is used without an explicit SafeLoader. "
                    "Untrusted YAML can potentially lead to unsafe object deserialization."
                ),
                recommendation=(
                    "Replace yaml.load() with yaml.safe_load() when processing "
                    "untrusted YAML input."
                ),
            )

    def _check_weak_hashing(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute):
            return

        if not isinstance(node.func.value, ast.Name):
            return

        if node.func.value.id != "hashlib":
            return

        weak_algorithms = {
            "md5": "PY007",
            "sha1": "PY008",
        }

        rule_id = weak_algorithms.get(node.func.attr)

        if rule_id is None:
            return

        self._add_finding(
            rule_id=rule_id,
            vulnerability_type="Weak Cryptographic Hash",
            severity="MEDIUM",
            node=node,
            message=(
                f"hashlib.{node.func.attr}() uses a cryptographically weak "
                "hashing algorithm."
            ),
            recommendation=(
                "Use SHA-256 or stronger algorithms for integrity purposes. "
                "For passwords, use a password-specific hashing algorithm "
                "such as Argon2, bcrypt, or scrypt."
            ),
        )


def scan_python_source(
    source: str,
    file_path: str = "<memory>",
) -> list[dict[str, Any]]:
    """
    Analyze Python source code without executing it.

    Returns deterministic security findings suitable for the
    SecureAI analysis pipeline.
    """

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as exc:
        return [
            {
                "rule_id": "PY000",
                "vulnerability_type": "Invalid Python Syntax",
                "severity": "INFO",
                "file_path": file_path,
                "line": exc.lineno or 0,
                "column": exc.offset or 0,
                "message": f"Python source could not be parsed: {exc.msg}",
                "evidence": "",
                "recommendation": (
                    "Fix the Python syntax before security analysis."
                ),
            }
        ]

    visitor = PythonSecurityVisitor(
        file_path=file_path,
        source=source,
    )

    visitor.visit(tree)

    return [
        finding.to_dict()
        for finding in visitor.findings
    ]


def scan_python_file(file_path: str | Path) -> list[dict[str, Any]]:
    """
    Scan a Python file from disk.

    The target source code is parsed using Python's AST module.
    It is never imported or executed.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Python file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    source = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    return scan_python_source(
        source=source,
        file_path=str(path),
    )


def get_scanner_info() -> dict[str, str]:
    return {
        "scanner": "SecureAI Python Static Security Scanner",
        "language": "Python",
        "engine": "Python AST",
        "execution": "Never executes target source code",
        "purpose": "Deterministic security evidence generation",
    }
