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
                    source_type,
                    source_ip,
                    destination_ip
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING traffic_id;
                """,
                (
                    traffic.duration,
                    traffic.src_bytes,
                    traffic.dst_bytes,
                    traffic.packets,
                    traffic.failed_connections,
                    "manual",
                    str(traffic.source_ip) if traffic.source_ip else None,
                    str(traffic.destination_ip) if traffic.destination_ip else None
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
def get_ip_analysis(ip_address: str, limit: int = 100):
    """Retrieve traffic and security events associated with an IP."""

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # Get traffic and prediction statistics
            cursor.execute(
                """
                SELECT
                    COUNT(DISTINCT t.traffic_id),
                    COUNT(DISTINCT p.prediction_id),
                    COUNT(DISTINCT e.event_id),
                    COUNT(DISTINCT p.prediction_id)
                        FILTER (WHERE p.predicted_label = 'ATTACK'),
                    COUNT(DISTINCT p.prediction_id)
                        FILTER (WHERE p.predicted_label = 'NORMAL')
                FROM network_traffic t
                LEFT JOIN prediction_logs p
                    ON t.traffic_id = p.traffic_id
                LEFT JOIN detection_events e
                    ON p.prediction_id = e.prediction_id
                WHERE t.source_ip = %s::inet
                   OR t.destination_ip = %s::inet
                """,
                (ip_address, ip_address)
            )

            stats = cursor.fetchone()

            # Retrieve matching traffic records
            cursor.execute(
                """
                SELECT
                    t.traffic_id,
                    t.source_ip::text,
                    t.destination_ip::text,
                    t.duration,
                    t.src_bytes,
                    t.dst_bytes,
                    t.packets,
                    t.failed_connections,
                    t.created_at,
                    p.prediction_id,
                    p.predicted_label,
                    p.attack_probability,
                    e.event_id,
                    e.severity,
                    e.status
                FROM network_traffic t
                LEFT JOIN prediction_logs p
                    ON t.traffic_id = p.traffic_id
                LEFT JOIN detection_events e
                    ON p.prediction_id = e.prediction_id
                WHERE t.source_ip = %s::inet
                   OR t.destination_ip = %s::inet
                ORDER BY t.created_at DESC
                LIMIT %s
                """,
                (ip_address, ip_address, limit)
            )

            rows = cursor.fetchall()

            columns = [
                "traffic_id",
                "source_ip",
                "destination_ip",
                "duration",
                "src_bytes",
                "dst_bytes",
                "packets",
                "failed_connections",
                "created_at",
                "prediction_id",
                "predicted_label",
                "attack_probability",
                "event_id",
                "severity",
                "status"
            ]

            records = [
                dict(zip(columns, row))
                for row in rows
            ]

            return {
                "ip_address": ip_address,
                "total_traffic_records": stats[0],
                "total_predictions": stats[1],
                "total_detection_events": stats[2],
                "attack_predictions": stats[3] or 0,
                "normal_predictions": stats[4] or 0,
                "records": records
            }
    
def save_pcap_flow(flow):
    """Save an extracted PCAP network flow to PostgreSQL."""

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO network_traffic (
                    duration,
                    src_bytes,
                    dst_bytes,
                    packets,
                    failed_connections,
                    source_type,
                    source_ip,
                    destination_ip
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING traffic_id;
                """,
                (
                    flow["duration"],
                    flow["src_bytes"],
                    flow["dst_bytes"],
                    flow["packets"],
                    0,
                    "pcap",
                    flow["source_ip"],
                    flow["destination_ip"]
                )
            )

            traffic_id = cursor.fetchone()[0]

            return {
                "traffic_id": traffic_id,
                "source_ip": flow["source_ip"],
                "destination_ip": flow["destination_ip"],
                "source_type": "pcap"
            }