from pydantic import BaseModel
from typing import List, Optional


class APIParameter(BaseModel):
    name: str
    location: str  # path, query, body
    required: bool
    type: Optional[str]


class APIEndpoint(BaseModel):
    path: str
    method: str
    summary: Optional[str]
    parameters: List[APIParameter]
    requires_auth: bool


class ParsedSpec(BaseModel):
    endpoints: List[APIEndpoint]