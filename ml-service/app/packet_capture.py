from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile, HTTPException

from app.flow_extractor import extract_flows
from app.database import save_pcap_flow


PROJECT_DIR = Path("D:/AI-NIDS")
UPLOAD_DIR = PROJECT_DIR / "datasets" / "uploads"

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


async def analyze_pcap_file(file: UploadFile):
    """Save, analyze and store an uploaded PCAP file."""

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file was selected."
        )

    extension = Path(file.filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Only PCAP and PCAPNG files are supported."
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    saved_path = UPLOAD_DIR / f"{uuid4().hex}{extension}"

    try:
        content = await file.read()

        if not content:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty."
            )

        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail="Maximum upload size is 50 MB."
            )

        saved_path.write_bytes(content)

        # Extract network flows
        flows = extract_flows(str(saved_path))

        # Save extracted flows into PostgreSQL
        saved_flows = []

        for flow in flows:
            saved_record = save_pcap_flow(flow)
            saved_flows.append(saved_record)

        return {
            "status": "success",
            "filename": Path(file.filename).name,
            "total_flows": len(flows),
            "total_packets": sum(
                flow["packets"] for flow in flows
            ),
            "database_saved": len(saved_flows),
            "saved_records": saved_flows,
            "flows": flows,
            "data_source": "offline_pcap",
            "note": "Offline packet analysis only. No live traffic captured."
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"PCAP analysis failed: {str(error)}"
        )

    finally:
        if saved_path.exists():
            saved_path.unlink()