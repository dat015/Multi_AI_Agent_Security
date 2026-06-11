import logging
from app.core.config import settings, get_groq_keys
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
from app.services.llm_service import LLMService
from app.services.llm_scheduler import LLMTaskScheduler

logger = logging.getLogger(__name__)
class ReconAgent:
    def __init__(self, api_key: str):
        self.api_key = api_key
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
            service = LLMService(
                api_key=self.api_key,
                model=model,
                base_url=settings.URL_LLM,
            )
            return service.generate_json(system_prompt, user_content)

        except Exception as e:
            return f"Lỗi Groq: {str(e)}"


def recon_node(state):
    print("--- CHẠY RECON NODE ---")

    spec_content = state["raw_spec"]
    spec_format = state["spec_format"]

    spec = SwaggerParser.parse(spec_content, spec_format)
    parsed_data = SwaggerExtractor.extract(spec)
    potential_threats = SecurityAnalyzer.analyze(parsed_data.endpoints)

    markdown_chunks = chunk_endpoints_to_markdown(potential_threats, chunk_size=5)

    api_keys = get_groq_keys(settings.LLM_PARALLEL_KEYS)
    scheduler = LLMTaskScheduler(
        api_keys=api_keys,
        concurrency_per_key=settings.LLM_CONCURRENCY_PER_KEY,
        logger=logger,
    )
    aggregated_scenarios = [] 

    tasks = []
    for chunk in markdown_chunks:
        user_content = (
            f"Here are the target API endpoints formatted in Markdown:\n\n"
            f"{chunk['page_content']}\n\n"
            f"Analyze these targets and evaluate them strictly according to the System Prompt instructions. "
            f"Remember: Output MUST be a JSON object with the root key 'audits'."
        )

        def _make_task(content: str):
            def _task(api_key: str, key_index: int):
                agent = ReconAgent(api_key=api_key)
                return agent.ask(
                    system_prompt=AGENT_SYSTEM_PROMPT,
                    user_content=content,
                    model=settings.GPT_OOS_20B,
                )

            return _task

        tasks.append(_make_task(user_content))

    results, errors = scheduler.map(tasks, fail_soft=True)

    for i, chunk in enumerate(markdown_chunks):
        print(f"> Đang Audit Chunk {i+1}/{len(markdown_chunks)}...")
        result_str = results[i]
        if errors[i] is not None or not result_str:
            logger.warning("Chunk %s failed or empty result.", i + 1)
            continue
        
        try:
            parsed_json = json.loads(result_str)
            
            # Lấy mảng audits
            scenarios = parsed_json.get("audits", [])
            valid_scenarios = []
            if isinstance(scenarios, list):
                valid_scenarios = [s for s in scenarios if isinstance(s, dict)]

            if valid_scenarios:
                aggregated_scenarios.extend(valid_scenarios)
            else:
                # Fallback: tìm list đầu tiên trong các giá trị của parsed_json
                found = False
                for key, val in parsed_json.items():
                    if isinstance(val, list):
                        valid_val = [v for v in val if isinstance(v, dict)]
                        if valid_val:
                            aggregated_scenarios.extend(valid_val)
                            found = True
                            break
                if not found:
                    logger.warning("Chunk %s has no valid audit list.", i+1)

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