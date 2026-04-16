from pydantic import BaseModel
from typing import List, Optional

class NormalizedEndpoint(BaseModel):
    method: str
    path: str
    resource_id_param: Optional[str]  # Định danh tài nguyên mục tiêu
    owner_id_param: Optional[str]     # Định danh chủ sở hữu tài nguyên
    action_type: str                  # READ, CREATE, UPDATE, DELETE
    is_admin_function: bool
    potential_vulnerability: List[str] # ["BOLA", "BFLA"]
    reasoning: str                    