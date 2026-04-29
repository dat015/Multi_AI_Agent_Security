from openai import OpenAI
from app.core.config import settings
from app.core.constants import AGENT_SYSTEM_PROMPT
import json
from pathlib import Path
from app.modules.parser.swagger_parser import SwaggerParser
from app.security.security_analyzer import SecurityAnalyzer
from app.core.constants import SWAGGER_DEFAULT_PATH
from app.modules.parser.swagger_extractor import SwaggerExtractor

class ReconAgent:
    def __init__(self):
        self.client = OpenAI(
            base_url=settings.URL_LLM,
            api_key=settings.GROQ_API_KEY 
        )
        self.expert_model = settings.LARGE_MODEL_NAME

    def load_kb(self):
        kb_path = Path(__file__).resolve().parent.parent.parent / "knowledge" / "owasp_kb.json"
        with open(kb_path, "r", encoding="utf-8") as f: 
            return json.load(f)

    def audit(self, normalized_data):
        """ Dùng AGENT_SYSTEM_PROMPT để thiết kế kịch bản tấn công"""
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


# =====================================================================
# HÀM NÀY PHẢI NẰM NGOÀI CLASS (SÁT MÉP LỀ TRÁI)
# =====================================================================
def recon_node(state):
    print("--- CHẠY RECON NODE ---")

    spec_content = state["raw_spec"]
    spec_format = state["spec_format"]

    spec = SwaggerParser.parse(spec_content, spec_format)

    parsed_data = SwaggerExtractor.extract(spec)
    potential_threats = SecurityAnalyzer.analyze(parsed_data.endpoints)

    agent = ReconAgent()
    result = agent.audit(normalized_data=potential_threats)
    print("KẾT QUẢ RECON:", result)

    try:
        parsed = json.loads(result)
    except:
        parsed = []
    return {
        **state,
        "filtered_endpoints": parsed 
    }