from openai import OpenAI
from app.core.config import settings
from app.core.constants import AGENT_SYSTEM_PROMPT
import json
import os
from pathlib import Path
from app.modules.parser.swagger_parser import SwaggerParser
from app.core.restler_parser import build_dependency_graph_from_restler
from app.security.security_analyzer import SecurityAnalyzer
from app.core.constants import SWAGGER_DEFAULT_PATH
from app.modules.parser.swagger_extractor import SwaggerExtractor
from app.helper.markdown_chunker import chunk_endpoints_to_markdown
from app.helper.file_saved import save_json_file, save_markdown_file
class ReconAgent:
    def __init__(self):
        self.client = OpenAI(
            base_url=settings.URL_LLM,
            api_key=settings.GROQ_API_KEY 
        )
        self.expert_model = settings.GPT_OOS_20B

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
            usage = response.usage

            prompt_tokens = usage.prompt_tokens
            completion_tokens = usage.completion_tokens
            total_tokens = usage.total_tokens

            print("\n===== TOKEN USAGE =====")
            print(f"Input Tokens     : {prompt_tokens}")
            print(f"Output Tokens    : {completion_tokens}")
            print(f"Total Tokens     : {total_tokens}")
            print("=======================\n")

            return response.choices[0].message.content

        except Exception as e:
            return f"Lỗi Groq: {str(e)}"


def recon_node(state):
    print("--- CHẠY RECON NODE ---")

    spec_content = state["raw_spec"]
    spec_format = state["spec_format"]

    spec = SwaggerParser.parse(spec_content, spec_format)
    parsed_data = SwaggerExtractor.extract(spec)
    potential_threats = SecurityAnalyzer.analyze(parsed_data.endpoints)

    markdown_chunks = chunk_endpoints_to_markdown(potential_threats, chunk_size=10)
    

    agent = ReconAgent()
    aggregated_scenarios = [] 

    for i, chunk in enumerate(markdown_chunks):
        print(f"> Đang Audit Chunk {i+1}/{len(markdown_chunks)}...")
        
        result_str = agent.audit(normalized_data=chunk["page_content"])
        
        try:
            parsed_json = json.loads(result_str)
            
            scenarios = parsed_json.get("audits", [])
            if scenarios:
                aggregated_scenarios.extend(scenarios)
            else:
                for key, val in parsed_json.items():
                    if isinstance(val, list):
                        aggregated_scenarios.extend(val)
                        break

        except json.JSONDecodeError:
            print(f"Lỗi parse JSON ở Chunk {i+1}. Raw output: {result_str}")
        except Exception as e:
            print(f"Lỗi không xác định ở Chunk {i+1}: {e}")

    print(f"Kết QUẢ RECON: Thu thập được tổng cộng {len(aggregated_scenarios)} attack scenarios.")

    compile_path = state.get("config", {}).get("restler_compile_path", "Compile")
    grammar_path = os.path.join(compile_path, "grammar.json")
    deps_path    = os.path.join(compile_path, "dependencies.json")

    try:
        dependency_data = build_dependency_graph_from_restler(grammar_path, deps_path)
        print(f"[RestlerParser] OK: {dependency_data['stats']['total_nodes']} nodes")
    except FileNotFoundError as e:
        print(f"[RestlerParser] Cảnh báo: Không tìm thấy file RESTler ({e}). Dùng graph rỗng.")
        dependency_data = {
            "execution_order": [],
            "graph": {"nodes": {}},
            "stats": {"total_nodes": 0, "source": "empty"},
        }
    except Exception as e:
        print(f"[RestlerParser] Lỗi không xác định: {e}. Dùng graph rỗng.")
        dependency_data = {
            "execution_order": [],
            "graph": {"nodes": {}},
            "stats": {"total_nodes": 0, "source": "error"},
        }
    save_json_file(
        data={
            "summary": {
                "attack_scenarios":
                    len(
                        aggregated_scenarios
                    )
            },
            "audits":
                aggregated_scenarios
        },
        file_name="recon_result"
    )

    save_json_file(
        data=dependency_data,
        file_name="dependency_graph"
    )
    save_markdown_file(
        markdown_chunks,
        f"recon_chunk_{i+1}"
    )
    return {
        **state,
        "filtered_endpoints": aggregated_scenarios, 
        "dependency_graph": dependency_data,
        "markdown_chunks": markdown_chunks 
    }


def main():
    import json
    from pathlib import Path

    from app.agents.recon_agent import recon_node
    from app.core.constants import SWAGGER_DEFAULT_PATH

    # Đọc file swagger
    swagger_path = SWAGGER_DEFAULT_PATH

    with open(swagger_path, "r", encoding="utf-8") as f:
        raw_spec = f.read()

    # Detect format
    ext = Path(swagger_path).suffix.lower()
    spec_format = "yaml" if ext in [".yaml", ".yml"] else "json"

    # Mock state cho recon_node
    state = {
        "raw_spec": raw_spec,
        "spec_format": spec_format
    }

    # Chạy node
    result = recon_node(state)

    # In kết quả
    # print("\n========== RESULT ==========\n")
    # print(json.dumps(result.get("filtered_endpoints", []), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()