from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
class APIRequestInput(BaseModel):
    method: str = Field(..., description="HTTP Method (GET, POST, PUT, DELETE, PATCH)")
    url: str = Field(..., description="URL endpoint đầy đủ")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="HTTP Headers (bao gồm cả Authorization token nếu có)")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Query parameters trên URL")
    data: Optional[Dict[str, Any]] = Field(None, description="Body payload (thường dùng cho JSON)")