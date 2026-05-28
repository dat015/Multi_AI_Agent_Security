import json
from pathlib import Path

from app.graph import build_graph


def main():
    # ===============================
    # Load config
    # ===============================
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    # ===============================
    # Load test plan có sẵn
    # ===============================
    test_plan_path = "outputs/test_plan.json"

    with open(test_plan_path, "r", encoding="utf-8") as f:
        test_plan_data = json.load(f)

    # Nếu file có structure:
    # { "test_plan": [...] }
    if isinstance(test_plan_data, dict):
        test_plan = test_plan_data.get("test_plan", [])
    else:
        test_plan = test_plan_data

    print(f"Loaded {len(test_plan)} test plans")

    # ===============================
    # Build graph: execution only
    # ===============================
    graph = build_graph("exec_only")

    # ===============================
    # Initial State
    # ===============================
    initial_state = {
        "config": config,
        "test_plan": test_plan,

        # optional fields
        "execution_results": [],
        "final_report": [],
        "confidence_score": 0.0,
        "iteration_count": 0,
        "max_iterations": 1,
    }

    # ===============================
    # Run graph
    # ===============================
    result = graph.invoke(initial_state)

    print("\n===== DONE =====")
    print(f"Execution count: {len(result.get('execution_results', []))}")
    print(f"Findings: {len(result.get('final_report', []))}")


if __name__ == "__main__":
    main()