from pathlib import Path
from typing import Any

from app.config import settings
from app.scanners.python_scanner import scan_python_file
from app.scanners.bandit_scanner import scan_python_with_bandit
from app.scanners.secret_scanner import scan_secrets


class ScanService:
    """Scan source files inside a repository."""

    def scan_repository(
        self,
        repository_path: str,
    ) -> dict[str, Any]:

        root = Path(repository_path)

        if not root.exists():
            raise FileNotFoundError(
                "Repository directory not found."
            )

        findings: list[dict[str, Any]] = []
        files_scanned = 0

        # File types currently supported by SecureAI.
        supported_extensions = {
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".php",
            ".java",
            ".go",
            ".rs",
            ".sql",
        }

        for file_path in root.rglob("*"):

            if not file_path.is_file():
                continue

            # Ignore generated/dependency directories.
            if any(
                directory in {
                    ".git",
                    "node_modules",
                    "__pycache__",
                    ".venv",
                    "venv",
                    "dist",
                    "build",
                }
                for directory in file_path.parts
            ):
                continue

            # Only count files that SecureAI supports.
            if file_path.suffix.lower() not in supported_extensions:
                continue

            try:
                if (
                    file_path.stat().st_size
                    > settings.MAX_FILE_SIZE_KB * 1024
                ):
                    continue

                relative_path = str(
                    file_path.relative_to(root)
                )

                # -----------------------------------
                # 1. Secret Scanner
                # -----------------------------------

                secret_findings = scan_secrets(
                    file_path
                )

                for finding in secret_findings:
                    finding["file_path"] = relative_path

                findings.extend(secret_findings)

                # -----------------------------------
                # 2. Python Security Scanners
                # -----------------------------------

                if file_path.suffix.lower() == ".py":

                    custom_findings = scan_python_file(
                        file_path
                    )

                    bandit_findings = (
                        scan_python_with_bandit(
                            file_path
                        )
                    )

                    python_findings = (
                        custom_findings
                        + bandit_findings
                    )

                    for finding in python_findings:
                        finding["file_path"] = relative_path

                    findings.extend(
                        python_findings
                    )

                # Count this supported file.
                files_scanned += 1

            except (OSError, SyntaxError):
                continue

        # -----------------------------------
        # 3. Remove duplicate findings
        # -----------------------------------

        findings = self._deduplicate_findings(
            findings
        )

        return {
            "files_scanned": files_scanned,
            "findings_count": len(findings),
            "findings": findings,
        }

    @staticmethod
    def _deduplicate_findings(
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Remove duplicate findings from different scanners."""

        unique_findings: list[dict[str, Any]] = []

        seen: set[tuple] = set()

        for finding in findings:

            key = (
                finding.get("file_path"),
                finding.get("line"),
                finding.get("vulnerability_type"),
            )

            if key in seen:
                continue

            seen.add(key)

            unique_findings.append(
                finding
            )

        return unique_findings


scan_service = ScanService()