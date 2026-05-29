from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel
from app.core.config import settings
import json
import logging
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type, before_sleep_log

logger = logging.getLogger(__name__)

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
            max_retries = getattr(settings, "LLM_MAX_RETRIES", 5)
            @retry(
                wait=wait_exponential(multiplier=2, min=2, max=16),
                stop=stop_after_attempt(max_retries),
                retry=retry_if_exception_type(Exception),
                before_sleep=before_sleep_log(logger, logging.WARNING),
                reraise=True,
            )
            def _call():
                return llm_with_json.invoke(messages)

            response = _call()
            return response.content
        except Exception as e:
            logger.error(f"Lỗi khi gọi LLM (generate_json): {e}")
            raise

    def generate_structured(self, prompt_messages: list, input_variables: dict, pydantic_schema: type[BaseModel], fallback_method="json_mode"):
        """
        Dùng cho Planning/Analyzer Agent: Ép kiểu dữ liệu trực tiếp ra Pydantic Object.

        NOTE: Khi input_variables={} (không có template variable thật),
        ta invoke messages trực tiếp thay vì qua ChatPromptTemplate.
        Lý do: ChatPromptTemplate parse {} trong chuỗi như template placeholder,
        gây lỗi nếu message chứa JSON (vốn có {} của riêng nó).
        """
        try:
            structured_llm = self.llm.with_structured_output(
                pydantic_schema,
                method=fallback_method
            )

            max_retries = getattr(settings, "LLM_MAX_RETRIES", 5)

            @retry(
                wait=wait_exponential(multiplier=2, min=2, max=16),
                stop=stop_after_attempt(max_retries),
                retry=retry_if_exception_type(Exception),
                before_sleep=before_sleep_log(logger, logging.WARNING),
                reraise=True,
            )
            def _call():
                if not input_variables:
                    # Không có template variable → invoke trực tiếp
                    # Tránh ChatPromptTemplate parse {} trong JSON thành placeholder
                    return structured_llm.invoke(prompt_messages)
                else:
                    # Có template variable thật → dùng ChatPromptTemplate bình thường
                    prompt_template = ChatPromptTemplate.from_messages(prompt_messages)
                    chain = prompt_template | structured_llm
                    return chain.invoke(input_variables)

            result = _call()
            return result

        except Exception as e:
            logger.error(f"Lỗi khi gọi LLM (generate_structured): {e}")
            raise