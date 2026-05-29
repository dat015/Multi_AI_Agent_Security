from langgraph.graph import StateGraph, END
from app.core.state import SystemState
from app.agents.recon_agent import recon_node
from app.agents.planning_agent import planning_node
from app.agents.execution_agent import execution_node
from app.agents.analyzer_agent import analyzer_node
from langgraph.checkpoint.memory import MemorySaver

# ── Điều kiện rẽ nhánh ──────────────
def should_continue_or_report(state: SystemState) -> str:
    confidence = state.get("confidence_score", 0.0)
    iteration  = state.get("iteration_count", 0)
    max_iter   = state.get("max_iterations", 5)

    if confidence >= 0.85:
        return "reporting"
    elif iteration >= max_iter:
        return "reporting"
    else:
        return "execution"

# ── DUMMY NODE ──────────────
def dummy_reporting_node(state: SystemState) -> dict:
    print("\n--- [DUMMY] CHẠY REPORTING NODE ---")
    print("Dữ liệu đã sẵn sàng để xuất báo cáo.")
    return state


def build_graph(phase: str = "phase2") -> any:
    graph = StateGraph(SystemState)

    if phase == "phase1":
        print("Chạy PHASE 1: Recon ➔ Planning")
        graph.add_node("recon", recon_node)
        graph.add_node("planning", planning_node)
        graph.set_entry_point("recon")
        graph.add_edge("recon", "planning")
        graph.add_edge("planning", END)

    elif phase == "phase2":
        print("Chạy PHASE 2: Recon ➔ Planning ➔ Execution ➔ Analyzer")
        graph.add_node("recon", recon_node)
        graph.add_node("planning", planning_node)
        graph.add_node("execution", execution_node)
        graph.add_node("analyzer", analyzer_node)
        graph.set_entry_point("recon")
        graph.add_edge("recon", "planning")
        graph.add_edge("planning", "execution")
        graph.add_edge("execution", "analyzer")
        graph.add_edge("analyzer", END)

    elif phase == "exec_only":
        print("Chạy PHASE: Execution (từ Test Plan có sẵn) ➔ Analyzer")
        # Chỉ add đúng 2 node cần thiết — không có recon/planning
        graph.add_node("execution", execution_node)
        graph.add_node("analyzer", analyzer_node)
        graph.set_entry_point("execution")
        graph.add_edge("execution", "analyzer")
        graph.add_edge("analyzer", END)

    elif phase == "full":
        print("Chạy FULL PIPELINE (Có vòng lặp)")
        graph.add_node("recon", recon_node)
        graph.add_node("planning", planning_node)
        graph.add_node("execution", execution_node)
        graph.add_node("analyzer", analyzer_node)
        graph.add_node("reporting", dummy_reporting_node)
        graph.set_entry_point("recon")
        graph.add_edge("recon", "planning")
        graph.add_edge("planning", "execution")
        graph.add_edge("execution", "analyzer")
        graph.add_conditional_edges(
            "analyzer",
            should_continue_or_report,
            {
                "execution": "execution",
                "reporting": "reporting",
            }
        )
        graph.add_edge("reporting", END)

    memory = MemorySaver()
    return graph.compile(checkpointer=memory)