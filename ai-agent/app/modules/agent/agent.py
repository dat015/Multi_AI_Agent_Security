from openai import OpenAI
from app.core.config import settings
from app.core.constants import NORMALIZER_PROMPT, AGENT_SYSTEM_PROMPT
class AIAgent:
    def __init__(self):
        self.client = OpenAI(
            base_url=settings.URL_LLM,
            api_key=settings.GROQ_API_KEY 
        )
        self.expert_model = settings.LARGE_MODEL_NAME

    # def normalize(self, findings):
    #     """Stage 3: Dùng NORMALIZER_PROMPT để chuẩn hóa dữ liệu"""
    #     # Gửi kèm hướng dẫn (System) và dữ liệu thô (User)
    #     user_content = f"Raw findings to translate: {findings}"
        
    #     return self.ask(
    #         system_prompt=NORMALIZER_PROMPT, 
    #         user_content=user_content,
    #         model=self.lite_model # Dùng model rẻ
    #     )

    def audit(self, normalized_data):
        """Stage 4: Dùng AGENT_SYSTEM_PROMPT để thiết kế kịch bản tấn công"""
        user_content = f"Design attack scenarios for these targets: {normalized_data}"
        
        return self.ask(
            system_prompt=AGENT_SYSTEM_PROMPT, 
            user_content=user_content,
            model=self.expert_model # Dùng model xịn
        )
    
    def ask(self, system_prompt: str, user_content: str, model: str):
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                # Lưu ý: Khi dùng json_object, prompt PHẢI có chữ "JSON"
                response_format={ "type": "json_object" } 
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Lỗi Groq: {str(e)}"