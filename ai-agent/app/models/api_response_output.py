
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
class APIResponseOutput(BaseModel):
    status_code: int
    response_time_ms: float
    headers: Dict[str, str]
    body: str
    is_error: bool = False
    error_message: Optional[str] = None