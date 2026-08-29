from fastapi import FastAPI

app = FastAPI(
    title="SecureAI",
    description="AI-powered code security scanner",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "app": "SecureAI",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }