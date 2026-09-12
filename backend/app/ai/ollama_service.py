from ollama import AsyncClient

from app.config import settings


class OllamaService:
    """Service for communicating with the local Ollama server."""

    def __init__(self) -> None:
        self.client = AsyncClient(
            host=settings.OLLAMA_HOST,
            timeout=settings.OLLAMA_TIMEOUT,
        )
        self.model = settings.OLLAMA_MODEL

    async def health(self) -> bool:
        """Check whether the Ollama server is available."""

        try:
            await self.client.list()
            return True
        except Exception:
            return False

    async def analyze(
        self,
        vulnerability_type: str,
        file_path: str,
        code: str,
    ) -> str:
        """Analyze a security finding using Ollama."""

        system_prompt = (
            "You are SecureAI, an expert application security engineer.\n\n"
            "Rules:\n"
            "- Do not invent vulnerabilities.\n"
            "- Use only the provided evidence.\n"
            "- Explain why the code is dangerous.\n"
            "- Explain the security impact.\n"
            "- Explain a realistic attack scenario.\n"
            "- Recommend secure remediation.\n"
            "- Provide corrected code when possible."
        )

        user_prompt = (
            f"Security Finding:\n"
            f"{vulnerability_type}\n\n"
            f"File:\n"
            f"{file_path}\n\n"
            f"Code:\n"
            f"{code}\n\n"
            "Return:\n"
            "1. Vulnerability explanation\n"
            "2. Security impact\n"
            "3. Attack scenario\n"
            "4. Recommended remediation\n"
            "5. Secure corrected code"
        )

        response = await self.client.chat(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            options={
                "temperature": 0.2,
            },
        )

        return response.message.content


# Shared service instance used by FastAPI.
ollama_service = OllamaService()