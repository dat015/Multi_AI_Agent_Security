import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY")
    URL_LLM: str = os.getenv("URL_LLM")
    LITLE_MODEL_NAME: str = os.getenv("LITLE_MODEL_NAME")
    LARGE_MODEL_NAME: str = os.getenv("LARGE_MODEL_NAME")
settings = Settings()