from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.scanners.python_scanner import scan_python_source


router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"],
)


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
        raise HTTPException(
            status_code=500,
            detail=f"Security scan failed: {exc}",
        ) from exc