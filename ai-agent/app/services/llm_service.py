from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel
from app.core.config import settings
import json
import logging

class LLMService:
    def __init__(self, provider: str = "groq"):
        """
        Khởi tạo service. Bạn có thể truyền provider="openai" hoặc "groq" để linh hoạt.
        """
        self.provider = provider
        
        if provider == "openai":
            self.api_key = settings.OPENAI_API_KEY # Cần thêm vào settings nếu chưa có
            self.base_url = None # Dùng URL mặc định của OpenAI
            self.model = "gpt-4o"
        else: # Default là groq
            self.api_key = settings.GROQ_API_KEY
            self.base_url = settings.URL_LLM
            self.model = settings.LARGE_MODEL_NAME

        # Khởi tạo core LLM
        self.llm = ChatOpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            model=self.model,
            temperature=0.1
        )

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        """
        Dùng cho Recon Agent: Trả về string dạng JSON.
        """
        try:
            # Bind response_format để ép LLM trả về JSON
            llm_with_json = self.llm.bind(response_format={"type": "json_object"})
            
            messages = [
                ("system", system_prompt),
                ("human", user_prompt)
            ]
            response = llm_with_json.invoke(messages)
            return response.content
        except Exception as e:
            logging.error(f"Lỗi khi gọi LLM (generate_json): {e}")
            raise e

    def generate_structured(self, prompt_messages: list, input_variables: dict, pydantic_schema: type[BaseModel], fallback_method="json_mode"): # <-- Chuyển mặc định sang json_mode
        """
        Dùng cho Planning Agent: Ép kiểu dữ liệu trực tiếp ra Pydantic Object.
        """
        try:
            prompt_template = ChatPromptTemplate.from_messages(prompt_messages)
            
            # ÉP LANGCHAIN KHÔNG DÙNG json_schema NỮA BẰNG CÁCH CHỈ ĐỊNH method
            structured_llm = self.llm.with_structured_output(
                pydantic_schema, 
                method=fallback_method # Sẽ sử dụng "json_mode"
            )
            
            chain = prompt_template | structured_llm
            result = chain.invoke(input_variables)
            
            return result
        except Exception as e:
            logging.error(f"Lỗi khi gọi LLM (generate_structured): {e}")
            raise e