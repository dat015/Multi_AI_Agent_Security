from langgraph.graph import StateGraph, END
from app.core.state import SystemState
from app.agents.recon_agent import recon_node
from app.agents.planning_agent import planning_node
from langgraph.checkpoint.memory import MemorySaver

# from agents.execution_agent import execution_node    # mở khóa sau
# from agents.analyzer_agent import analyzer_node      # mở khóa sau
# from agents.reporting_agent import reporting_node    # mở khóa sau


# ── Điều kiện rẽ nhánh (dùng cho execution loop sau này) ──────────────
def should_continue_or_report(state: SystemState) -> str:
    """
    Hàm này quyết định sau Analyzer thì đi đâu.
    Trả về tên node tiếp theo dưới dạng string.
    """
    confidence = state.get("confidence_score", 0.0)
    iteration  = state.get("iteration_count", 0)
    max_iter   = state.get("max_iterations", 5)

    if confidence >= 0.85:
        # Đủ bằng chứng → chuyển sang reporting
        return "reporting"
    elif iteration >= max_iter:
        # Hết lượt → chuyển sang reporting dù chưa chắc chắn
        return "reporting"
    else:
        # Chưa đủ → quay lại execution với payload mới
        return "execution"


def build_graph(phase: str = "phase1") -> any:
    """
    phase="phase1" → chỉ chạy recon + planning (hiện tại)
    phase="full"   → chạy toàn bộ 5 agent (sau này)
    
    Tại sao có tham số phase?
    Để bạn test từng phần mà không phải sửa code,
    chỉ đổi tham số khi gọi build_graph().
    """
    graph = StateGraph(SystemState)

    # ── PHASE 1: Recon + Planning ─────────────────────────────────────
    graph.add_node("recon", recon_node)
    graph.add_node("planning", planning_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "planning")

    if phase == "phase1":
        # Dừng sau planning — đủ để test giai đoạn hiện tại
        print("Chạy PHASE 1: Recon + Planning")
        graph.add_edge("planning", END)

    # ── FULL PIPELINE: thêm 3 agent còn lại ──────────────────────────
    elif phase == "full":
        # graph.add_node("execution", execution_node)
        # graph.add_node("analyzer",  analyzer_node)
        # graph.add_node("reporting", reporting_node)

        graph.add_edge("planning",   "execution")
        graph.add_edge("execution",  "analyzer")

        # Đây là conditional edge — trái tim của vòng lặp
        # Sau analyzer, LangGraph gọi should_continue_or_report()
        # để biết đi tiếp đâu
        graph.add_conditional_edges(
            "analyzer",                     # node hiện tại
            should_continue_or_report,      # hàm quyết định
            {                               # map kết quả → node
                "execution": "execution",
                "reporting": "reporting",
            }
        )

        graph.add_edge("reporting", END)

    # Memory để LangGraph lưu state giữa các bước
    # (quan trọng khi có vòng lặp execution ↔ analyzer)
    memory = MemorySaver()
    return graph.compile(checkpointer=memory)
