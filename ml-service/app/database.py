import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv

# Project configuration
PROJECT_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_DIR / ".env"

load_dotenv(ENV_FILE)

DATABASE_URL = os.getenv("DATABASE_URL")


def get_connection():
    """Create a PostgreSQL database connection."""

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing from .env")

    return psycopg.connect(DATABASE_URL)


def test_database_connection():
    """Test PostgreSQL connectivity."""

    try:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT current_database();"
                )
                result = cursor.fetchone()

        return {
            "connected": True,
            "database": result[0],
            "message": "PostgreSQL connection successful."
        }

    except Exception as error:
        return {
            "connected": False,
            "database": None,
            "message": str(error)
        }


def save_prediction(
    traffic,
    predicted_label,
    normal_probability,
    attack_probability
):
    """Save traffic, prediction and classified attack event transactionally."""

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # Store network traffic features
            cursor.execute(
                """
                INSERT INTO network_traffic (
                    duration,
                    src_bytes,
                    dst_bytes,
                    packets,
                    failed_connections,
                    source_type
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING traffic_id;
                """,
                (
                    traffic.duration,
                    traffic.src_bytes,
                    traffic.dst_bytes,
                    traffic.packets,
                    traffic.failed_connections,
                    "manual"
                )
            )

            traffic_id = cursor.fetchone()[0]

            # Store prediction result
            cursor.execute(
                """
                INSERT INTO prediction_logs (
                    traffic_id,
                    predicted_label,
                    normal_probability,
                    attack_probability,
                    model_name
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING prediction_id;
                """,
                (
                    traffic_id,
                    predicted_label,
                    normal_probability,
                    attack_probability,
                    "Random Forest"
                )
            )

            prediction_id = cursor.fetchone()[0]

            event_id = None

            # Create event only for ATTACK predictions
            if predicted_label == "ATTACK" and attack_probability >= 0.50:

                # Determine experimental severity
                if attack_probability >= 0.95:
                    severity = "CRITICAL"
                elif attack_probability >= 0.85:
                    severity = "HIGH"
                elif attack_probability >= 0.70:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                cursor.execute(
                    """
                    INSERT INTO detection_events (
                        prediction_id,
                        severity,
                        description,
                        status
                    )
                    VALUES (%s, %s, %s, %s)
                    RETURNING event_id;
                    """,
                    (
                        prediction_id,
                        severity,
                        f"Traffic classified as ATTACK by the experimental synthetic-data model. Attack probability: {attack_probability:.2%}.",
                        "OPEN"
                    )
                )

                event_id = cursor.fetchone()[0]

    return {
        "traffic_id": traffic_id,
        "prediction_id": prediction_id,
        "event_id": event_id
    }

def get_prediction_history(limit: int = 20):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    p.prediction_id,
                    t.traffic_id,
                    p.predicted_label,
                    p.normal_probability,
                    p.attack_probability,
                    p.model_name,
                    p.created_at,
                    t.src_bytes,
                    t.dst_bytes,
                    t.packets,
                    t.failed_connections
                FROM prediction_logs p
                JOIN network_traffic t
                    ON p.traffic_id = t.traffic_id
                ORDER BY p.created_at DESC
                LIMIT %s
                """,
                (limit,)
            )

            rows = cursor.fetchall()

            columns = [
                "prediction_id",
                "traffic_id",
                "predicted_label",
                "normal_probability",
                "attack_probability",
                "model_name",
                "created_at",
                "src_bytes",
                "dst_bytes",
                "packets",
                "failed_connections"
            ]

            return [
                dict(zip(columns, row))
                for row in rows
            ]
def get_dashboard_statistics():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_predictions,
                    COUNT(*) FILTER (
                        WHERE predicted_label = 'NORMAL'
                    ) AS normal_predictions,
                    COUNT(*) FILTER (
                        WHERE predicted_label = 'ATTACK'
                    ) AS attack_predictions
                FROM prediction_logs
                """
            )

            row = cursor.fetchone()

            cursor.execute(
                "SELECT COUNT(*) FROM detection_events"
            )

            total_events = cursor.fetchone()[0]

            return {
                "total_predictions": row[0],
                "normal_predictions": row[1],
                "attack_predictions": row[2],
                "total_detection_events": total_events
            }

def get_detection_events(limit: int = 20):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    e.event_id,
                    e.prediction_id,
                    e.severity,
                    e.description,
                    e.status,
                    e.created_at,
                    p.predicted_label,
                    p.attack_probability,
                    t.src_bytes,
                    t.dst_bytes,
                    t.packets
                FROM detection_events e
                JOIN prediction_logs p
                    ON e.prediction_id = p.prediction_id
                JOIN network_traffic t
                    ON p.traffic_id = t.traffic_id
                ORDER BY e.created_at DESC
                LIMIT %s
                """,
                (limit,)
            )

            rows = cursor.fetchall()

            columns = [
                "event_id",
                "prediction_id",
                "severity",
                "description",
                "status",
                "created_at",
                "predicted_label",
                "attack_probability",
                "src_bytes",
                "dst_bytes",
                "packets"
            ]

            return [
                dict(zip(columns, row))
                for row in rows
            ]
            
def update_detection_event_status(event_id: int, new_status: str):
    """Update the status of an existing security event."""

    allowed_statuses = ["OPEN", "INVESTIGATING", "RESOLVED"]

    if new_status not in allowed_statuses:
        raise ValueError("Invalid security event status.")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE detection_events
                SET status = %s
                WHERE event_id = %s
                RETURNING event_id, status, created_at;
                """,
                (new_status, event_id)
            )

            row = cursor.fetchone()

            if row is None:
                return None

            return {
                "event_id": row[0],
                "status": row[1],
                "created_at": row[2]
            }
