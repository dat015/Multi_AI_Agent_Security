import uuid
import json
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

from app.core.auth_manager import AuthManager
from app.core.constants import CONFIG_TEMPLATE
from app.core.credential_store import CredentialStore
from app.core.orchestrator import build_graph
from app.core.state import SystemState
from app.validator.config_validator import ConfigValidator

app = APIRouter()
# main.py — 2 route mới

@app.get("/config/template")
def download_template():
    """Người dùng tải về file mẫu để điền vào."""
    return JSONResponse(content=CONFIG_TEMPLATE)


@app.post("/upload-config")
async def upload_config(file: UploadFile = File(...)):
    # Kiểm tra extension
    if not file.filename.endswith(".json"):
        raise HTTPException(400, "Chỉ chấp nhận file .json")

    raw = await file.read()

    # Layer 1: parse JSON
    data, parse_error = ConfigValidator.parse_json(raw)
    if parse_error:
        return JSONResponse(status_code=400, content={
            "status":  "parse_error",
            "message": parse_error,
            "hint":    "Dùng https://jsonlint.com để kiểm tra JSON"
        })

    # Layer 2+3: validate schema + business rules
    result = ConfigValidator.validate(data)
    if not result.is_valid:
        return JSONResponse(status_code=422, content={
            "status":   "invalid",
            **result.to_response(),
            "hint": "Sửa các lỗi trên rồi upload lại. "
                    "Tải file mẫu tại GET /config/template"
        })

    # Load vào store
    store   = CredentialStore()
    store.load(data)
    manager = AuthManager(store)

    config_id = str(uuid.uuid4())
    session_store = {}

    session_store[f"cfg_{config_id}"] = {
        "store":   store,
        "manager": manager,
    }

    return {
        "status":        "ok",
        "config_id":     config_id,
        "roles_loaded":  store.all_roles(),
        "warnings":      result.to_response()["warnings"],
    }

