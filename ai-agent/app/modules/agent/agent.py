import google.generativeai as genai

from app.core.config import settings
from app.core.constants import MODEL_NAME, AGENT_SYSTEM_PROMPT

genai.configure(api_key=settings.GOOGLE_API_KEY)


class AIAgent:

    def __init__(self):
        self.model = genai.GenerativeModel(MODEL_NAME)

    def ask(self, user_prompt: str):
        full_prompt = f"""
        {AGENT_SYSTEM_PROMPT}

        User request:
        {user_prompt}
        """

        response = self.model.generate_content(full_prompt)

        return response.text