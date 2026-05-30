"""
run_plan_only.py
────────────────
Tái sinh test_plan.json từ RESTler Compile output + kết quả Recon đã lưu.
Không cần chạy lại Recon LLM (tiết kiệm token).

Luồng:
    RESTler grammar.json + dependencies.json
        → RestlerParser → dependency_graph
        → planning_node  (attack steps dùng LLM, setup steps deterministic)
        → outputs/test_plan.json

Cách dùng:
    python -m app.agents.run_plan_only
    python -m app.agents.run_plan_only --config app/input/config_template.json
    python -m app.agents.run_plan_only --recon outputs/recon_result.json
"""

import json
import logging
import argparse
from pathlib import Path

from app.core.restler_parser import build_dependency_graph_from_restler
from app.agents.planning_agent import planning_node

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:%(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH  = "app/input/config_template.json"
DEFAULT_RECON_PATH   = "outputs/recon_result.json"
DEFAULT_OUTPUT_PATH  = "outputs/test_plan.json"


def load_json(path: str, label: str) -> dict | list | None:
    p = Path(path)
    if not p.exists():
        logger.warning(f"[{label}] Không tìm thấy: {p.resolve()}")
        return None
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.info(f"[{label}] Đã load: {p.resolve()}")
    return data


def main():
    parser = argparse.ArgumentParser(description="Tái sinh test plan từ RESTler output")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"File config JSON (default: {DEFAULT_CONFIG_PATH})"
    )
    parser.add_argument(
        "--recon",
        default=DEFAULT_RECON_PATH,
        help=f"File recon_result JSON (default: {DEFAULT_RECON_PATH})"
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_PATH,
        help=f"File output test plan (default: {DEFAULT_OUTPUT_PATH})"
    )
    args = parser.parse_args()

    # ── 1. Load config ──────────────────────────────────────
    config = load_json(args.config, "Config")
    if not config:
        raise FileNotFoundError(f"Bắt buộc cần config: {args.config}")

    # ── 2. Build dependency graph từ RESTler ────────────────
    compile_path = config.get("restler_compile_path", "Compile")
    grammar_path = Path(compile_path) / "grammar.json"
    deps_path    = Path(compile_path) / "dependencies.json"

    logger.info(f"[RestlerParser] Đọc: {grammar_path}, {deps_path}")
    dependency_graph = build_dependency_graph_from_restler(
        str(grammar_path), str(deps_path)
    )
    logger.info(
        f"[RestlerParser] OK: {dependency_graph['stats']['total_nodes']} nodes, "
        f"{len(dependency_graph['execution_order'])} bước"
    )

    # ── 3. Load recon results (nếu có) ─────────────────────
    recon_data = load_json(args.recon, "Recon")
    if recon_data:
        # recon_result.json format: {"summary": {...}, "audits": [...]}
        filtered_endpoints = (
            recon_data.get("audits", [])
            if isinstance(recon_data, dict)
            else recon_data
        )
        logger.info(f"[Recon] {len(filtered_endpoints)} attack scenarios")
    else:
        filtered_endpoints = []
        logger.warning(
            "[Recon] Không có recon data. "
            "Tất cả endpoints sẽ là setup steps (is_attack=False). "
            "Hãy chạy recon trước nếu muốn test attack."
        )

    # ── 4. Tạo state và chạy planning_node ─────────────────
    state = {
        "config":             config,
        "filtered_endpoints": filtered_endpoints,
        "dependency_graph":   dependency_graph,
        # Placeholder cho các field khác của SystemState
        "raw_spec":           "",
        "spec_format":        "",
        "recon_summary":      "",
        "markdown_chunks":    [],
        "execution_results":  [],
        "current_endpoint":   None,
        "raw_traffic":        [],
        "vuln_findings":      [],
        "iteration_count":    0,
        "confidence_score":   0.0,
        "max_iterations":     1,
        "test_plan":          [],
        "final_report":       None,
        "error":              None,
    }

    print(f"\nChạy Planning Node ({len(dependency_graph['execution_order'])} endpoints)...")
    result_state = planning_node(state)

    # ── 5. Lưu kết quả ─────────────────────────────────────
    test_plan = result_state.get("test_plan", [])
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(test_plan, f, ensure_ascii=False, indent=2)

    # ── 6. Thống kê ────────────────────────────────────────
    setup_count  = sum(1 for p in test_plan if not p.get("is_attack"))
    attack_count = sum(1 for p in test_plan if p.get("is_attack"))

    print("\n" + "═" * 50)
    print("  KẾT QUẢ PLANNING")
    print("═" * 50)
    print(f"  Tổng test plans: {len(test_plan)}")
    print(f"    ├─ Setup  (is_attack=False): {setup_count}")
    print(f"    └─ Attack (is_attack=True) : {attack_count}")
    print(f"  Đã lưu tại: {output_path.resolve()}")
    print("═" * 50 + "\n")


if __name__ == "__main__":
    main()
