from fastapi import APIRouter

from app.ai.ollama_service import ollama_service
from app.config import settings


router = APIRouter(
    tags=["Health"],
)


@router.get("/health")
async def health():
    """
    Return the health status of SecureAI and Ollama.
    """

    ollama_available = await ollama_service.health()

    return {
        "status": "healthy",
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "ollama": {
            "status": (
                "connected"
                if ollama_available
                else "unavailable"
            ),
            "model": settings.OLLAMA_MODEL,
        },
    }