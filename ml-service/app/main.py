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