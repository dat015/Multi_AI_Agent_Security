from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from app.controllers import agent_controller

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