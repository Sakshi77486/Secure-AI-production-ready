from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.repository_service import repository_service
from app.services.scan_service import scan_service


router = APIRouter(
    prefix="/api/repositories",
    tags=["Repositories"],
)


class GitHubRepositoryRequest(BaseModel):
    url: str = Field(min_length=1, max_length=500)


class RepositoryResponse(BaseModel):
    status: str
    source_type: str
    repository_url: str
    repository_id: str
    files_count: int
    files: list[str]
    findings_count: int
    findings: list[dict[str, Any]]


@router.post("/github", response_model=RepositoryResponse)
async def analyze_github_repository(
    request: GitHubRepositoryRequest,
) -> dict[str, Any]:

    url = request.url.strip()

    if not (
        url.startswith("https://github.com/")
        or url.startswith("http://github.com/")
    ):
        raise HTTPException(
            status_code=400,
            detail="Please provide a valid GitHub repository URL.",
        )

    try:
        repository = repository_service.clone_github_repository(url)

        scan_result = scan_service.scan_repository(
            repository["repository_path"]
        )

        return {
            "status": "analysis_completed",
            "source_type": "github",
            "repository_url": repository["repository_url"],
            "repository_id": repository["repository_id"],
            "files_count": scan_result["files_scanned"],
            "files": repository["files"],
            "findings_count": scan_result["findings_count"],
            "findings": scan_result["findings"],
        }

    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Repository analysis failed: {exc}",
        ) from exc