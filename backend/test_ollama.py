import asyncio

from app.ai.ollama_service import ollama_service


async def main():
    result = await ollama_service.analyze(
        "Code Injection",
        "utils.py",
        "result = eval(user_input)",
    )

    print("\n========== OLLAMA RESULT ==========\n")
    print(result)
    print("\n===================================\n")


asyncio.run(main())