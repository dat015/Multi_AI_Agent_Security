from openai import OpenAI
from app.core.config import settings
from app.core.constants import AGENT_SYSTEM_PROMPT
import json
from pathlib import Path
from app.modules.parser.swagger_parser import SwaggerParser
from app.security.security_analyzer import SecurityAnalyzer
from app.core.constants import SWAGGER_DEFAULT_PATH
from app.modules.parser.swagger_extractor import SwaggerExtractor
from app.helper.markdown_chunker import chunk_endpoints_to_markdown
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
        user_content = (
            f"Here are the target API endpoints formatted in Markdown:\n\n"
            f"{normalized_data}\n\n"
            f"Analyze these targets and evaluate them strictly according to the System Prompt instructions. "
            f"Remember: Output MUST be a JSON object with the root key 'audits'."
        )
        
        return self.ask(
            system_prompt=AGENT_SYSTEM_PROMPT, 
            user_content=user_content,
            model=self.expert_model
        )
    
    def ask(self, system_prompt: str, user_content: str, model: str):
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                response_format={ "type": "json_object" } 
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Lỗi Groq: {str(e)}"


def recon_node(state):
    print("--- CHẠY RECON NODE ---")

    spec_content = state["raw_spec"]
    spec_format = state["spec_format"]

    spec = SwaggerParser.parse(spec_content, spec_format)

    parsed_data = SwaggerExtractor.extract(spec)
    for ep in parsed_data.endpoints:
        print(f"{ep.method} {ep.path} (Auth: {ep.requires_auth}) - Params: {[p.name for p in ep.parameters]}")
    potential_threats = SecurityAnalyzer.analyze(parsed_data.endpoints)
    markdown_chunks = chunk_endpoints_to_markdown(potential_threats, chunk_size=10)
    print(f"Đã chia thành {len(markdown_chunks)} chunks để xử lý.")

    agent = ReconAgent()
    aggregated_scenarios = [] # Nơi chứa toàn bộ kịch bản tấn công của tất cả chunks

    # 3. Duyệt qua từng chunk và gọi LLM
    for i, chunk in enumerate(markdown_chunks):
        print(f"> Đang Audit Chunk {i+1}/{len(markdown_chunks)}...")
        
        # Đưa Markdown vào Agent
        result_str = agent.audit(normalized_data=chunk["page_content"])
        
        try:
            parsed_json = json.loads(result_str)
            
            # Lấy list 'scenarios' mà ta đã yêu cầu LLM tạo ra ở hàm audit
            scenarios = parsed_json.get("audits", [])
            if scenarios:
                aggregated_scenarios.extend(scenarios)
            else:
                # Fallback: nếu LLM tự đẻ ra key khác chứa list
                for key, val in parsed_json.items():
                    if isinstance(val, list):
                        aggregated_scenarios.extend(val)
                        break

        except json.JSONDecodeError:
            print(f"Lỗi parse JSON ở Chunk {i+1}. Raw output: {result_str}")
        except Exception as e:
            print(f"Lỗi không xác định ở Chunk {i+1}: {e}")

    print(f"KẾT QUẢ RECON: Thu thập được tổng cộng {len(aggregated_scenarios)} attack scenarios.")

    return {
        **state,
        # Trả về data đã được gom lại từ tất cả các chunk
        "filtered_endpoints": aggregated_scenarios, 
        
        # (Tùy chọn) Lưu lại chunks thô nếu các Node sau trong LangGraph cần dùng
        "markdown_chunks": markdown_chunks 
    }