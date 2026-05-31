"""
run_exec_only.py
────────────────
Chạy RIÊNG execution_agent + analyzer_agent từ test plan có sẵn.
Không cần chạy lại Recon + Planning.

Cách dùng:
    # Từ thư mục gốc của project (ai-agent/)
    python -m app.agents.run_exec_only

    # Hoặc chỉ định file cụ thể:
    python -m app.agents.run_exec_only --plan outputs/test_plan.json --config config.json
"""

import json
import uuid
import argparse
import logging
from pathlib import Path

# Fix: import đúng module
from app.core.orchestrator import build_graph
from app.core.state import SystemState

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:%(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Paths mặc định — chỉnh theo nhu cầu của bạn
# ──────────────────────────────────────────────
DEFAULT_CONFIG_PATH    = "app/input/config_template.json"
DEFAULT_TEST_PLAN_PATH = "outputs/test_plan.json"
OUTPUT_REPORT_PATH     = "outputs/exec_only_report1.json"


def load_config(path: str) -> dict:
    """Load file config.json (credentials + target URL)"""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"Không tìm thấy config: {config_path.resolve()}\n"
            f"Hãy đặt file config.json vào thư mục gốc, hoặc dùng --config <path>"
        )
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.info(f"[Config] Đã load: {config_path.resolve()}")
    return data


def load_test_plan(path: str) -> list:
    """Load test_plan.json (output từ planning_agent)"""
    plan_path = Path(path)
    if not plan_path.exists():
        # Tìm file mới nhất trong outputs/ nếu không chỉ định
        outputs_dir = Path("outputs")
        candidates = sorted(
            outputs_dir.glob("*_test_plan.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        if candidates:
            plan_path = candidates[0]
            logger.info(f"[Test Plan] Không tìm thấy {path}, dùng file mới nhất: {plan_path}")
        else:
            raise FileNotFoundError(
                f"Không tìm thấy test plan tại: {Path(path).resolve()}\n"
                f"Hãy chạy pipeline phase1 trước, hoặc dùng --plan <path>"
            )

    with open(plan_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Hỗ trợ 2 format:
    # 1. {"test_plan": [...]}  ← output từ pipeline
    # 2. [...]                 ← raw list
    if isinstance(data, dict):
        test_plan = data.get("test_plan", [])
    elif isinstance(data, list):
        test_plan = data
    else:
        raise ValueError("Định dạng test plan không hợp lệ. Phải là list hoặc dict có key 'test_plan'")

    logger.info(f"[Test Plan] Đã load: {plan_path.resolve()} — {len(test_plan)} nodes")
    return test_plan


def print_summary(result: dict):
    """In tóm tắt kết quả ra terminal"""
    execution_results = result.get("execution_results", [])
    final_report      = result.get("final_report", []) or []

    attack_count  = sum(1 for r in execution_results if r.get("is_attack"))
    setup_count   = sum(1 for r in execution_results if not r.get("is_attack"))
    vuln_count    = sum(1 for r in final_report if r.get("assessment", {}).get("is_vulnerable"))

    print("\n" + "═" * 55)
    print("  KẾT QUẢ EXECUTION + ANALYZER")
    print("═" * 55)
    print(f"  Requests đã gửi      : {len(execution_results)}")
    print(f"    ├─ Setup (API mồi) : {setup_count}")
    print(f"    └─ Attack requests : {attack_count}")
    print(f"  Findings được phân tích: {len(final_report)}")
    print(f"  Vulnerable           : {vuln_count}")
    print(f"  Safe                 : {len(final_report) - vuln_count}")
    print("═" * 55)

    if final_report:
        print("\n  Chi tiết:")
        for item in final_report:
            assessment = item.get("assessment", {})
            status = "🔴 VULNERABLE" if assessment.get("is_vulnerable") else "🟢 SAFE"
            print(f"\n  {status} | {item.get('node_id')} | {item.get('vuln_type')}")
            print(f"  Role: {item.get('role')} | Confidence: {assessment.get('confidence_score')}%")
            print(f"  Lý do: {assessment.get('reasoning', '')[:120]}...")

    print(f"\n  Report đã lưu tại: {OUTPUT_REPORT_PATH}\n")


def main():
    parser = argparse.ArgumentParser(description="Chạy Execution + Analyzer từ test plan có sẵn")
    parser.add_argument(
        "--plan",
        default=DEFAULT_TEST_PLAN_PATH,
        help=f"Đường dẫn tới file test plan JSON (default: {DEFAULT_TEST_PLAN_PATH})"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Đường dẫn tới file config JSON (default: {DEFAULT_CONFIG_PATH})"
    )
    args = parser.parse_args()

    # ── 1. Load files ──────────────────────────────────────
    config    = load_config(args.config)
    test_plan = load_test_plan(args.plan)

    if not test_plan:
        logger.error("Test plan rỗng. Không có gì để thực thi.")
        return

    # ── 2. Build graph exec_only ───────────────────────────
    graph = build_graph(phase="exec_only")

    # ── 3. Initial state ───────────────────────────────────
    initial_state: SystemState = {
        # Bắt buộc cho execution_node
        "config":    config,
        "test_plan": test_plan,

        # Các field còn lại — để trống, exec_only không cần
        "raw_spec":           "",
        "spec_format":        "",
        "filtered_endpoints": [],
        "recon_summary":      "",
        "dependency_graph":   {},
        "markdown_chunks":    [],
        "execution_results":  [],
        "current_endpoint":   None,
        "raw_traffic":        [],
        "vuln_findings":      [],
        "iteration_count":    0,
        "confidence_score":   0.0,
        "max_iterations":     1,
        "final_report":       None,
        "error":              None,
    }

    # ── 4. Run ─────────────────────────────────────────────
    session_id = str(uuid.uuid4())
    lg_config  = {"configurable": {"thread_id": session_id}}

    logger.info(f"[Pipeline] Bắt đầu exec_only — session: {session_id}")
    final_state = graph.invoke(initial_state, config=lg_config)

    # ── 5. Lưu kết quả ────────────────────────────────────
    Path("outputs").mkdir(exist_ok=True)
    with open(OUTPUT_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {
                "session_id":       session_id,
                "execution_results": final_state.get("execution_results", []),
                "final_report":      final_state.get("final_report", []),
            },
            f,
            ensure_ascii=False,
            indent=2
        )

    # ── 6. In tóm tắt ─────────────────────────────────────
    print_summary(final_state)


if __name__ == "__main__":
    main()