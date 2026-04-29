from schemas import SystemState
def executor_node(state: SystemState):
    """Node chịu trách nhiệm thực thi test và cập nhật kết quả."""
    current_iteration = state.get("iteration_count", 0)
    print(f"[Executor] Thực thi lần thứ: {current_iteration + 1}")
    
    # Logic thực thi test (gọi API, test endpoints, v.v.)
    mock_result = {
        "iteration": current_iteration + 1,
        "success": True,
        "log": f"Tested {len(state['endpoints'])} endpoints successfully."
    }
    
    # Trả về kết quả mới (sẽ được append vào mảng cũ) và tăng iteration_count
    return {
        "results": [mock_result], 
        "iteration_count": current_iteration + 1
    }