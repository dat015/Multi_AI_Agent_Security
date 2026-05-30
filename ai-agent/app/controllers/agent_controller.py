import uuid
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from app.core.orchestrator import build_graph
from app.core.state import SystemState
from app.core.session_store import CONFIG_STORE, SESSION_STORE  # ← shared stores

router = APIRouter()

# Dùng SESSION_STORE từ shared module (thay cho local dict cũ)
session_store = SESSION_STORE

# ── Schema response ────────────────────────────────────────────────────
class AnalysisResult(BaseModel):
    session_id: str
    status: str                    # "running" | "done" | "error"
    recon_summary: Optional[str]   = None
    endpoints_found: Optional[int] = None
    test_plan: Optional[list]      = None
    error: Optional[str]           = None


def _save_uploaded_spec(session_id: str, filename: str, content: bytes) -> Path:
    ext = Path(filename).suffix.lower()
    upload_dir = Path("input") / "uploads" / session_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    spec_path = upload_dir / f"spec{ext}"
    spec_path.write_bytes(content)
    return spec_path


def _run_restler_compile(spec_path: Path, compile_path: str) -> None:
    restler_exe = os.getenv("RESTLER_EXE", r"C:\RESTler_Bin\restler\Restler.exe")
    exe_path = Path(restler_exe)
    if not exe_path.exists():
        raise FileNotFoundError(f"RESTler executable not found: {exe_path}")

    # Uvicorn --reload thường chỉ watch các file Python (*.py). RESTler compile tạo ra
    # Compile/grammar.py và Compile/custom_value_gen_template.py, khiến dev server reload
    # và hủy background task (CancelledError) => mất session in-memory và frontend poll 404.
    # Giải pháp: compile trong thư mục tạm (ngoài workspace) và chỉ copy các artifact JSON.
    target_compile_dir = Path(compile_path)
    target_compile_dir.mkdir(parents=True, exist_ok=True)

    spec_abs = spec_path.resolve()

    with tempfile.TemporaryDirectory(prefix="restler_compile_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        default_compile_dir = tmp_root / "Compile"

        result = subprocess.run(
            [str(exe_path), "compile", "--api_spec", str(spec_abs)],
            cwd=tmp_root,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"RESTler compile failed: {stderr}")

        if not default_compile_dir.exists():
            raise RuntimeError(
                f"RESTler compile finished but output folder not found: {default_compile_dir}"
            )

        artifacts = [
            "grammar.json",
            "dependencies.json",
            "dict.json",
            "unresolved_dependencies.json",
            "dependencies_debug.json",
        ]

        missing_required = []
        for name in ("grammar.json", "dependencies.json"):
            if not (default_compile_dir / name).exists():
                missing_required.append(name)

        if missing_required:
            raise RuntimeError(
                "Missing required RESTler artifacts: " + ", ".join(missing_required)
            )

        for name in artifacts:
            src = default_compile_dir / name
            if src.exists():
                shutil.copy2(src, target_compile_dir / name)

# ── Route: upload file và chạy pipeline ───────────────────────────────
@router.post("/analyze", response_model=AnalysisResult)
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    phase: str = "full",              # ← đổi default sang "full"
    config_id: Optional[str] = None,  # ← nhận config_id từ frontend
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
    spec_path = _save_uploaded_spec(session_id, file.filename, content)

    # Lấy config từ CONFIG_STORE dứa trên config_id frontend gửi lên
    user_config = CONFIG_STORE.get(config_id, {}) if config_id else {}

    # Bắt buộc config khi phase có execution
    if phase in ("phase2", "full", "exec_only") and not user_config:
        raise HTTPException(
            status_code=400,
            detail="Thiếu config_id hợp lệ cho phase có execution."
        )

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
        spec_path=str(spec_path),
        phase=phase,
        user_config=user_config,   # ← truyền config vào pipeline
        max_iter=max_iter,
    )

    return AnalysisResult(session_id=session_id, status="running")

# ── Route: frontend polling kết quả ───────────────────────────────────
@router.get("/result/{session_id}", response_model=AnalysisResult)
def get_result(session_id: str):
    data = session_store.get(session_id)
    if not data:
        # Server reload sẽ reset in-memory store. Fallback đọc plan từ disk nếu có.
        plan_path = Path("outputs") / f"{session_id}_test_plan.json"
        if plan_path.exists():
            try:
                test_plan = json.loads(plan_path.read_text(encoding="utf-8"))
            except Exception:
                test_plan = None
            return AnalysisResult(
                session_id=session_id,
                status="done",
                recon_summary=None,
                endpoints_found=None,
                test_plan=test_plan,
                error=None,
            )

        raise HTTPException(status_code=404, detail="Session không tồn tại")

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

# ── Hàm Service (Logic chạy ngầm) ─────────────────────────────────────────────────────
def run_pipeline(
    session_id: str,
    spec_content: str,
    spec_format: str,
    spec_path: str,
    phase: str,
    user_config: dict,   # ← nhận config từ caller
    max_iter: int,
):
    try:
        compile_path = user_config.get("restler_compile_path", "Compile")
        _run_restler_compile(Path(spec_path), compile_path)

        initial_state: SystemState = {
            "raw_spec": spec_content,
            "spec_format": spec_format,
            "config": user_config,          # ← đưa config vào state
            "filtered_endpoints": [],
            "recon_summary": "",
            "dependency_graph": {},         # ← recon_node sẽ ghi vào
            "markdown_chunks": [],          # ← recon_node sẽ ghi vào
            "test_plan": [],
            "execution_results": [],        # ← execution_node sẽ ghi vào
            "current_endpoint": None,
            "raw_traffic": [],
            "vuln_findings": [],
            "iteration_count": 0,
            "confidence_score": 0.0,
            "max_iterations": max_iter,
            "final_report": None,
            "error": None,
        }

        graph = build_graph(phase=phase)
        config = {"configurable": {"thread_id": session_id}}

        # Dùng invoke() — trả về toàn bộ final state sau khi graph kết thúc
        final_state = graph.invoke(initial_state, config=config)

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