from pathlib import Path
from typing import Any

from app.config import settings
from app.scanners.python_scanner import scan_python_file


class ScanService:
    """Scan source files inside a cloned repository."""

    def scan_repository(self, repository_path: str) -> dict[str, Any]:
        root = Path(repository_path)

        if not root.exists():
            raise FileNotFoundError("Repository directory not found.")

        findings: list[dict[str, Any]] = []
        files_scanned = 0

        for file_path in root.rglob("*.py"):
            if ".git" in file_path.parts:
                continue

            try:
                if file_path.stat().st_size > settings.MAX_FILE_SIZE_KB * 1024:
                    continue

                file_findings = scan_python_file(file_path)

                for finding in file_findings:
                    finding["file_path"] = str(
                        file_path.relative_to(root)
                    )

                findings.extend(file_findings)
                files_scanned += 1

            except (OSError, SyntaxError):
                continue

        return {
            "files_scanned": files_scanned,
            "findings_count": len(findings),
            "findings": findings,
        }


scan_service = ScanService()