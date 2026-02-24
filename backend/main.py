from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import uuid
from typing import List, Optional
from pydantic import BaseModel
from enum import Enum

# Import your custom DPI modules
from packet_analyzer.dpi_engine import DPIEngine
from packet_analyzer.rule_manager import RuleManager
from packet_analyzer.types import AppType

# -------------------- Pydantic Models --------------------
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
    app_breakdown: dict[str, int]
    output_file: str

# -------------------- FastAPI App --------------------
app = FastAPI(title="DPI Engine API")

# CORS – allow frontend (optional now, but harmless)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (your frontend) from the "static" folder
app.mount("/static", StaticFiles(directory="backend/static"), name="static")

# Serve the main HTML page at the root
@app.get("/")
async def serve_frontend():
    return FileResponse("backend/static/index.html")

# -------------------- Global Rule Manager --------------------
rules = RuleManager()

# -------------------- API Endpoints --------------------
@app.post("/analyze", response_model=AnalysisResult)
async def analyze_pcap(
    file: UploadFile = File(...),
    request: Optional[AnalysisRequest] = None
):
    # Save uploaded file temporarily
    file_id = str(uuid.uuid4())
    temp_path = f"/tmp/{file_id}.pcap"
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    output_path = f"/tmp/{file_id}_out.pcap"

    # Apply any rules sent with the request
    if request and request.rules:
        for rule in request.rules:
            if rule.type == RuleType.IP:
                rules.add_block_ip(rule.value)
            elif rule.type == RuleType.APP:
                # Convert string to AppType enum
                try:
                    app_type = AppType[rule.value.upper()]
                    rules.add_block_app(app_type)
                except KeyError:
                    raise HTTPException(status_code=400, detail=f"Unknown app: {rule.value}")
            elif rule.type == RuleType.DOMAIN:
                rules.add_block_domain(rule.value)

    # Run DPI engine (multi‑threaded version)
    engine = DPIEngine(temp_path, output_path, rules, num_lbs=2, num_fps_per_lb=2)
    engine.run_multi()   # or run_simple() if you prefer

    stats = engine.stats

    # Clean up input file (output file is kept for possible download)
    os.remove(temp_path)

    return AnalysisResult(
        job_id=file_id,
        total_packets=stats['total_packets'],
        forwarded=stats['forwarded'],
        dropped=stats['dropped'],
        app_breakdown=stats['app_counts'],
        output_file=output_path
    )

@app.post("/rules")
async def add_rule(rule: Rule):
    if rule.type == RuleType.IP:
        rules.add_block_ip(rule.value)
    elif rule.type == RuleType.APP:
        try:
            app_type = AppType[rule.value.upper()]
            rules.add_block_app(app_type)
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Unknown app: {rule.value}")
    elif rule.type == RuleType.DOMAIN:
        rules.add_block_domain(rule.value)
    return {"status": "added"}

@app.get("/rules")
async def get_rules():
    return {
        "blocked_ips": list(rules.blocked_ips),
        "blocked_apps": [app.name for app in rules.blocked_apps],
        "blocked_domains": list(rules.blocked_domains),
    }