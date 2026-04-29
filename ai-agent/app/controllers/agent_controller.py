import uuid
import json
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from app.core.orchestrator import build_graph
from app.core.state import SystemState

router = APIRouter()

# Lưu trạng thái các session đang chạy (Tạm thời dùng Dict cho local)
session_store: dict[str, dict] = {}

# ── Schema response ────────────────────────────────────────────────────
class AnalysisResult(BaseModel):
    session_id: str
    status: str                    # "running" | "done" | "error"
    recon_summary: Optional[str]   = None
    endpoints_found: Optional[int] = None
    test_plan: Optional[list]      = None
    error: Optional[str]           = None

# ── Route: upload file và chạy pipeline ───────────────────────────────
@router.post("/analyze", response_model=AnalysisResult)
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    phase: str = "phase1",
    max_iter: int = 5,
):
    if not file.filename.endswith((".yaml", ".yml", ".json")):
        raise HTTPException(status_code=400, detail="Chỉ chấp nhận file .yaml, .yml hoặc .json")

    content = await file.read()
    try:
        spec_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File không đọc được (không phải UTF-8)")

    spec_format = "json" if file.filename.endswith(".json") else "yaml"
    session_id = str(uuid.uuid4())

    session_store[session_id] = {
        "status": "running",
        "recon_summary": None,
        "endpoints_found": None,
        "test_plan": None,
        "error": None,
    }

    # Đưa tác vụ vào Background
    background_tasks.add_task(
        run_pipeline,
        session_id=session_id,
        spec_content=spec_content,
        spec_format=spec_format,
        phase=phase,
        max_iter=max_iter,
    )

    return AnalysisResult(session_id=session_id, status="running")

# ── Route: frontend polling kết quả ───────────────────────────────────
@router.get("/result/{session_id}", response_model=AnalysisResult)
def get_result(session_id: str):
    if session_id not in session_store:
        raise HTTPException(status_code=404, detail="Session không tồn tại")
    
    data = session_store[session_id]
    return AnalysisResult(session_id=session_id, **data)

# ── Route: download test_plan.json ────────────────────────────────────
@router.get("/download/{session_id}")
def download_plan(session_id: str):
    plan_path = Path("outputs") / f"{session_id}_test_plan.json"
    if not plan_path.exists():
        raise HTTPException(status_code=404, detail="File chưa sẵn sàng")
    
    return FileResponse(
        plan_path,
        media_type="application/json",
        filename=f"test_plan_{session_id}.json"
    )

# ── Hàm Service (Logic chạy ngầm) ─────────────────────────────────────
def run_pipeline(
    session_id: str,
    spec_content: str,
    spec_format: str,
    phase: str,
    max_iter: int,
):
    try:
        initial_state: SystemState = {
            "raw_spec": spec_content,
            "spec_format": spec_format,
            "filtered_endpoints": [],
            "recon_summary": "",
            "test_plan": [],
            "current_endpoint": None,
            "raw_traffic": [],
            "vuln_findings": [],
            "iteration_count": 0,
            "max_iterations": max_iter,
            "confidence_score": 0.0,
            "final_report": None,
            "error": None,
        }

        graph = build_graph(phase=phase)
        config = {"configurable": {"thread_id": session_id}}

        final_state = None
        for event in graph.stream(initial_state, config=config):
            for node_output in event.values():
                if isinstance(node_output, dict):
                    final_state = node_output

        if not final_state:
            raise ValueError("Pipeline không trả về kết quả")

        output_dir = Path("outputs")
        output_dir.mkdir(exist_ok=True)
        plan_path = output_dir / f"{session_id}_test_plan.json"
        
        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(final_state.get("test_plan", []), f, ensure_ascii=False, indent=2)

        session_store[session_id] = {
            "status": "done",
            "recon_summary": final_state.get("recon_summary", ""),
            "endpoints_found": len(final_state.get("filtered_endpoints", [])),
            "test_plan": final_state.get("test_plan", []),
            "error": None,
        }

    except Exception as e:
        session_store[session_id] = {
            "status": "error",
            "recon_summary": None,
            "endpoints_found": None,
            "test_plan": None,
            "error": str(e),
        }