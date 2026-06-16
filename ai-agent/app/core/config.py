import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY")
    GROQ_API_KEY1: str = os.getenv("GROQ_API_KEY1")
    GROQ_API_KEY2: str = os.getenv("GROQ_API_KEY2")
    GROQ_API_KEY3: str = os.getenv("GROQ_API_KEY3")
    URL_LLM: str = os.getenv("URL_LLM")
    LITLE_MODEL_NAME: str = os.getenv("LITLE_MODEL_NAME")
    LARGE_MODEL_NAME: str = os.getenv("LARGE_MODEL_NAME")
    LLM_MAX_RETRIES: int = int(os.getenv("LLM_MAX_RETRIES", "5"))
    LLM_PARALLEL_KEYS: int = int(os.getenv("LLM_PARALLEL_KEYS", "4"))
    LLM_CONCURRENCY_PER_KEY: int = int(os.getenv("LLM_CONCURRENCY_PER_KEY", "2"))
    LLAMA_3_3_70B: str = os.getenv("LLAMA_3_3_70B")
    GPT_OOS_20B: str = os.getenv("GPT_OOS_20B")
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "groq")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1")
settings = Settings()


def get_groq_keys(limit: int | None = None) -> list[str]:
    keys = [
        settings.GROQ_API_KEY,
        settings.GROQ_API_KEY1,
        settings.GROQ_API_KEY2,
        settings.GROQ_API_KEY3,
    ]
    keys = [k for k in keys if k]
    if limit:
        return keys[:limit]
    return keys