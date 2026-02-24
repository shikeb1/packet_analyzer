from fastapi import APIRouter, UploadFile, File, Form
from fastapi.responses import JSONResponse
import shutil
import os
import uuid
import json
from scapy.all import rdpcap
from .rules import apply_rules
from .stats import generate_stats

router = APIRouter()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    rules: str = Form(...)
):
    # Save uploaded file
    job_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{job_id}.pcap")

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Load packets
    packets = rdpcap(file_path)

    # Parse rules JSON
    rule_data = json.loads(rules)

    # Apply rules
    forwarded, dropped, breakdown = apply_rules(packets, rule_data)

    # Generate stats
    result = generate_stats(job_id, forwarded, dropped, breakdown)

    return JSONResponse(content=result)