from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import uuid
from typing import List
from backend.dependencies import get_engine, get_model
from .models import AnalysisRequest, AnalysisResult, Rule, RuleType
from packet_analyzer.dpi_engine import DPIEngine
from packet_analyzer.rule_manager import RuleManager
from packet_analyzer.types import AppType

app = FastAPI(title="DPI Engine API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

jobs = {}
rules = RuleManager()

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_pcap(file: UploadFile = File(...), request: AnalysisRequest = None):
    file_id = str(uuid.uuid4())
    temp_path = f"/tmp/{file_id}.pcap"
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    output_path = f"/tmp/{file_id}_out.pcap"
    
    if request and request.rules:
        for rule in request.rules:
            if rule.type == RuleType.IP:
                rules.add_block_ip(rule.value)
            elif rule.type == RuleType.APP:
                app_type = AppType[rule.value.upper()]
                rules.add_block_app(app_type)
            elif rule.type == RuleType.DOMAIN:
                rules.add_block_domain(rule.value)
    
    engine = DPIEngine(temp_path, output_path, rules, num_lbs=2, num_fps_per_lb=2)
    engine.run_multi()
    
    stats = engine.stats
    
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
        app_type = AppType[rule.value.upper()]
        rules.add_block_app(app_type)
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