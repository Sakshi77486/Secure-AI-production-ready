
from pathlib import Path
from typing import Any
import traceback

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.scanners.python_scanner import scan_python_source
from app.services.repository_service import repository_service
from app.services.scan_service import scan_service
from app.ai.ollama_service import ollama_service


router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"],
)


# ============================================================
# Python source-code scan
# ============================================================

class PythonScanRequest(BaseModel):
    file_name: str = Field(
        default="uploaded.py",
        min_length=1,
        max_length=255,
    )

    source_code: str = Field(
        min_length=1,
        max_length=500_000,
    )


class ScanFinding(BaseModel):
    rule_id: str
    vulnerability_type: str
    severity: str
    file_path: str
    line: int
    column: int
    message: str
    evidence: str
    recommendation: str
    ai_analysis: str | None = None


class PythonScanResponse(BaseModel):
    status: str
    file_name: str
    files_scanned: int
    findings_count: int
    findings: list[ScanFinding]


@router.post(
    "/python",
    response_model=PythonScanResponse,
)
async def scan_python(
    request: PythonScanRequest,
) -> dict[str, Any]:

    # Prevent directory traversal in displayed file name.
    file_name = Path(request.file_name).name

    if not file_name.lower().endswith(".py"):
        raise HTTPException(
            status_code=400,
            detail="Only Python (.py) files are supported by this scanner.",
        )

    try:
        findings = scan_python_source(
            source=request.source_code,
            file_path=file_name,
        )

        return {
            "status": "completed",
            "file_name": file_name,
            "files_scanned": 1,
            "findings_count": len(findings),
            "findings": findings,
        }

    except Exception as exc:
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=f"Security scan failed: {exc}",
        ) from exc


# ============================================================
# GitHub repository scan
# ============================================================

class RepositoryScanRequest(BaseModel):
    repository_url: str = Field(
        min_length=1,
        max_length=500,
    )


class RepositoryScanResponse(BaseModel):
    status: str
    source_type: str
    repository_url: str
    repository_id: str
    files_count: int
    files_scanned: int
    files: list[str]
    findings_count: int
    findings: list[ScanFinding]


@router.post(
    "/repository",
    response_model=RepositoryScanResponse,
)
async def scan_repository(
    request: RepositoryScanRequest,
) -> dict[str, Any]:

    repository_url = request.repository_url.strip()

    # Only allow HTTPS GitHub URLs for now.
    if not repository_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=400,
            detail="Only public GitHub repository URLs are supported.",
        )

    repository_path = None

    try:
        # ----------------------------------------------------
        # 1. Clone repository
        # ----------------------------------------------------

        repository = repository_service.clone_github_repository(
            repository_url
        )

        repository_path = repository["repository_path"]

        # ----------------------------------------------------
        # 2. Run security scanners
        # ----------------------------------------------------

        scan_result = scan_service.scan_repository(
            repository_path
        )

        # ----------------------------------------------------
        # 3. Analyze highest-priority finding with Ollama
        # ----------------------------------------------------

        findings = scan_result["findings"]

        # Make sure findings is always a list.
        if not isinstance(findings, list):
            raise TypeError(
                f"Expected findings to be a list, "
                f"got {type(findings).__name__}"
            )

        # ----------------------------------------------------
        # Normalize findings before processing.
        # ----------------------------------------------------

        for finding in findings:

            if not isinstance(finding, dict):
                raise TypeError(
                    f"Expected finding to be a dictionary, "
                    f"got {type(finding).__name__}"
                )

            # Normalize severity.
            severity = finding.get("severity", "LOW")

            # Some scanner rules may return severity as a list.
            if isinstance(severity, list):
                severity = (
                    severity[0]
                    if severity
                    else "LOW"
                )

            # Make sure severity is always a string.
            finding["severity"] = str(
                severity
            ).upper()

            # Make sure every finding has an AI field.
            finding.setdefault(
                "ai_analysis",
                None,
            )

        # ----------------------------------------------------
        # Severity priority
        # ----------------------------------------------------

        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }

        # Only the highest-priority finding is sent to Ollama.
        priority_findings = sorted(
            findings,
            key=lambda finding: severity_order.get(
                str(
                    finding.get(
                        "severity",
                        "LOW",
                    )
                ).upper(),
                3,
            ),
        )[:1]

        # ----------------------------------------------------
        # Send highest-priority finding to Ollama
        # ----------------------------------------------------

        for finding in priority_findings:
            try:
                ai_analysis = await ollama_service.analyze(
                    vulnerability_type=str(
                        finding.get(
                            "vulnerability_type",
                            "Unknown vulnerability",
                        )
                    ),
                    file_path=str(
                        finding.get(
                            "file_path",
                            "Unknown file",
                        )
                    ),
                    code=str(
                        finding.get(
                            "evidence",
                            "",
                        )
                    ),
                )

                finding["ai_analysis"] = ai_analysis

            except Exception as exc:
                # Do not fail the entire security scan
                # if Ollama analysis fails.
                finding["ai_analysis"] = (
                    f"AI analysis unavailable: {exc}"
                )

        # ----------------------------------------------------
        # 4. Return complete result to React
        # ----------------------------------------------------

        return {
            "status": "analysis_completed",
            "source_type": "github",
            "repository_url": repository_url,

            "repository_id": repository[
                "repository_id"
            ],

            # Number of supported source files discovered.
            "files_count": repository[
                "files_count"
            ],

            # Number of supported files actually scanned.
            "files_scanned": scan_result[
                "files_scanned"
            ],

            # Actual file names for React UI.
            "files": repository[
                "files"
            ],

            # Security findings.
            "findings_count": scan_result[
                "findings_count"
            ],

            # Return the processed findings.
            "findings": findings,
        }

    except RuntimeError as exc:
        traceback.print_exc()

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except FileNotFoundError as exc:
        traceback.print_exc()

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        # Print the complete traceback in the backend
        # terminal so we can identify the exact line
        # if another error occurs.
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=f"Repository scan failed: {exc}",
        ) from exc

    finally:
        # Always remove cloned repository after scanning.
        if repository_path:
            repository_service.cleanup(
                repository_path
            )

