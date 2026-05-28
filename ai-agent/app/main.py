from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import uuid
import json

from app.controllers import agent_controller
from app.core.auth_manager import AuthManager
from app.core.constants import CONFIG_TEMPLATE
from app.core.credential_store import CredentialStore
from app.validator.config_validator import ConfigValidator
from app.core.session_store import CONFIG_STORE  # ← shared store

app = FastAPI(title="API Security Tester", version="1.0.0")

# 1. Cấu hình CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Cấu hình Static Files & Trang chủ (Nằm ở main là chuẩn nhất)
BASE_DIR = Path(__file__).resolve().parent

# Mount thư mục static để load css, js
app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static"
)

@app.get("/")
def serve_frontend():
    """Trang chủ UI"""
    index_path = BASE_DIR / "static" / "index.html"
    return FileResponse(str(index_path))

# 3. Nhúng API Router
# Các API sẽ có dạng: /api/agent/analyze, /api/agent/result/...
app.include_router(
    agent_controller.router, 
    prefix="/api/agent", 
    tags=["Agent Controller"]
)


# CONFIG_STORE được import từ app.core.session_store (shared với agent_controller)


@app.get("/config/template")
def download_template():
    """Return the config template as JSON for users to download/fill."""
    return JSONResponse(content=CONFIG_TEMPLATE)


@app.post("/upload-config")
async def upload_config(file: UploadFile = File(...)):
    # Only accept .json files
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

    # Load into store and auth manager
    store = CredentialStore()
    store.load(data)
    manager = AuthManager(store)

    config_id = str(uuid.uuid4())

    # Persist original data for later download/export (in-memory)
    CONFIG_STORE[config_id] = data

    return {
        "status":        "ok",
        "config_id":     config_id,
        "roles_loaded":  store.all_roles(),
        "warnings":      result.to_response().get("warnings", []),
    }


@app.get("/config/download/{config_id}")
def download_config(config_id: str):
    """Allow user to download an uploaded config by id."""
    if config_id not in CONFIG_STORE:
        raise HTTPException(404, "Config not found")

    data = CONFIG_STORE[config_id]
    content = json.dumps(data, indent=2, ensure_ascii=False)
    filename = f"config_{config_id}.json"
    return Response(content=content, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })