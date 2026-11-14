from app.database import (
    save_prediction,
    get_prediction_history,
    get_dashboard_statistics,
    update_detection_event_status,
    get_detection_events
)
from pathlib import Path

import joblib
import pandas as pd
import time
import psutil

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Project configuration
PROJECT_DIR = Path("D:/AI-NIDS")
MODEL_PATH = PROJECT_DIR / "ml-service" / "models" / "ids_model.joblib"

# Create the API application
app = FastAPI(
    title="AI-Based Network Intrusion Detection API",
    description="API for classifying synthetic network traffic during development.",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained model
model = None

if MODEL_PATH.exists():
    model = joblib.load(MODEL_PATH)
# Network monitoring configuration
NETWORK_REFRESH_INTERVAL = 3


def get_network_stats():
    """Return actual network interface counters and traffic rates."""

    current_time = time.time()
    current_stats = psutil.net_io_counters(pernic=True)

    interfaces = []

    for name, counters in current_stats.items():
        interfaces.append({
            "interface": name,
            "bytes_sent": counters.bytes_sent,
            "bytes_received": counters.bytes_recv,
            "packets_sent": counters.packets_sent,
            "packets_received": counters.packets_recv,
            "errors_in": counters.errin,
            "errors_out": counters.errout,
            "drops_in": counters.dropin,
            "drops_out": counters.dropout,
        })

    return {
        "timestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%S",
            time.localtime(current_time),
        ),
        "data_source": "actual_system_network_counters",
        "interfaces": interfaces,
        "note": (
            "These are cumulative interface counters. "
            "Traffic rates will be calculated by the frontend."
        ),
    }


# Network traffic input schema
class NetworkTraffic(BaseModel):
    duration: float = Field(ge=0)
    src_bytes: int = Field(ge=0)
    dst_bytes: int = Field(ge=0)
    packets: int = Field(ge=0)
    failed_connections: int = Field(ge=0)


@app.get("/")
def home():
    return {
        "message": "AI-Based Network Intrusion Detection API",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/network/stats")
def network_stats():
    """Expose actual network interface statistics."""
    return get_network_stats()

@app.get("/health")
def health():
    return {
        "api_status": "running",
        "model_loaded": model is not None,
        "model_type": "Random Forest",
        "training_data": "synthetic"
    }


@app.post("/predict")
def predict_traffic(traffic: NetworkTraffic):

    if model is None:
        raise HTTPException(
            status_code=503,
            detail="Trained model is not available."
        )

    # Prepare network traffic features
    features = pd.DataFrame(
        [{
            "duration": traffic.duration,
            "src_bytes": traffic.src_bytes,
            "dst_bytes": traffic.dst_bytes,
            "packets": traffic.packets,
            "failed_connections": traffic.failed_connections
        }]
    )

    # Run machine learning prediction
    prediction = int(model.predict(features)[0])
    probabilities = model.predict_proba(features)[0]

    predicted_label = "ATTACK" if prediction == 1 else "NORMAL"

    attack_probability = round(float(probabilities[1]), 4)
    normal_probability = round(float(probabilities[0]), 4)

    # Save prediction to PostgreSQL
    try:
        database_result = save_prediction(
            traffic=traffic,
            predicted_label=predicted_label,
            normal_probability=normal_probability,
            attack_probability=attack_probability
        )

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Prediction persistence failed: {str(error)}"
        )

    return {
        "prediction": f"{predicted_label} (synthetic)",
        "prediction_code": prediction,
        "attack_probability": attack_probability,
        "normal_probability": normal_probability,
        "data_type": "synthetic",
        "database_saved": True,
        "database_records": database_result,
        "warning": (
            "Experimental model trained on synthetic data; "
            "not validated on real network traffic."
        )
    }

    # Convert the input into the feature order used during training
    features = pd.DataFrame(
        [{
            "duration": traffic.duration,
            "src_bytes": traffic.src_bytes,
            "dst_bytes": traffic.dst_bytes,
            "packets": traffic.packets,
            "failed_connections": traffic.failed_connections
        }]
    )

    prediction = int(model.predict(features)[0])
    probabilities = model.predict_proba(features)[0]

    label = "ATTACK (synthetic)" if prediction == 1 else "NORMAL (synthetic)"

    return {
        "prediction": label,
        "prediction_code": prediction,
        "attack_probability": round(float(probabilities[1]), 4),
        "normal_probability": round(float(probabilities[0]), 4),
        "data_type": "synthetic",
        "warning": "Experimental model trained on synthetic data; not validated on real network traffic."
    }

@app.get("/predictions")
def get_predictions(limit: int = 20):

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100."
        )

    try:
        predictions = get_prediction_history(limit)

        return {
            "total": len(predictions),
            "predictions": predictions
        }

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to retrieve prediction history: {str(error)}"
        )
@app.get("/dashboard/stats")
def dashboard_statistics():

    try:
        statistics = get_dashboard_statistics()

        return {
            "status": "success",
            "statistics": statistics
        }

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to retrieve dashboard statistics: {str(error)}"
        )
# Get security events from PostgreSQL
@app.get("/security/events")
def security_events(limit: int = 20):

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100."
        )

    try:
        events = get_detection_events(limit)

        return {
            "status": "success",
            "total": len(events),
            "events": events
        }

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to retrieve security events: {str(error)}"
        )


# Update security event status
@app.patch("/security/events/{event_id}")
def update_security_event(event_id: int, status: str):

    allowed_statuses = ["OPEN", "INVESTIGATING", "RESOLVED"]

    status = status.upper()

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Use OPEN, INVESTIGATING or RESOLVED."
        )

    try:
        updated_event = update_detection_event_status(
            event_id,
            status
        )

        if updated_event is None:
            raise HTTPException(
                status_code=404,
                detail="Security event not found."
            )

        return {
            "status": "success",
            "message": "Security event status updated successfully.",
            "event": updated_event
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to update security event: {str(error)}"
        )