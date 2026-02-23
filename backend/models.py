from pydantic import BaseModel
from enum import Enum
from typing import List, Dict, Optional

class RuleType(str, Enum):
    IP = "ip"
    APP = "app"
    DOMAIN = "domain"

class Rule(BaseModel):
    type: RuleType
    value: str

class AnalysisRequest(BaseModel):
    rules: Optional[List[Rule]] = None

class AnalysisResult(BaseModel):
    job_id: str
    total_packets: int
    forwarded: int
    dropped: int
    app_breakdown: Dict[str, int]
    output_file: str