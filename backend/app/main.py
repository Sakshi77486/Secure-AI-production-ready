from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai.ollama_service import ollama_service
from app.api.health import router as health_router
from app.api.repositories import router as repository_router
from app.api.scan import router as scan_router
from app.config import settings
from app.database import Base, engine

# Import models so SQLAlchemy knows about all database tables.

from app.models.project import Project
from app.models.scan import Scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    
    """
    Application startup and shutdown lifecycle.
    """

    # Create database tables if they do not already exist.
    Base.metadata.create_all(bind=engine)

    # Check Ollama connection.
    ollama_available = await ollama_service.health()

    if ollama_available:
        print("SecureAI: Ollama connected")
    else:
        print("SecureAI: Warning - Ollama unavailable")

    print("SecureAI: Database initialized")
    print("SecureAI: API started")

    yield

    print("SecureAI: API shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-powered source code security scanner",
    lifespan=lifespan,
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------

app.include_router(health_router)
app.include_router(repository_router)
app.include_router(scan_router)


# ---------------------------------------------------------
# ROOT ENDPOINT
# ---------------------------------------------------------

@app.get("/")
async def root():
    """
    SecureAI API information.
    """

    ollama_available = await ollama_service.health()

    return {
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "ai": {
            "provider": "ollama",
            "model": settings.OLLAMA_MODEL,
            "status": (
                "connected"
                if ollama_available
                else "unavailable"
            ),
        },
        "endpoints": {
            "documentation": "/docs",
            "health": "/health",
            "python_scan": "/api/scans/python",
        },
    }