import React, { useEffect, useMemo, useState } from "react";
import "./ReportsAnalytics.css";

const API_URL = "http://127.0.0.1:8000";

function ReportsAnalytics() {
  const [statistics, setStatistics] = useState(null);
  const [predictions, setPredictions] = useState([]);
  const [events, setEvents] = useState([]);

  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [generatedAt, setGeneratedAt] = useState(null);

  async function loadReports() {
    setLoading(true);
    setError("");

    try {
      const [statsResponse, predictionsResponse, eventsResponse] =
        await Promise.all([
          fetch(`${API_URL}/dashboard/stats`),
          fetch(`${API_URL}/predictions?limit=100`),
          fetch(`${API_URL}/security/events?limit=100`),
        ]);

      if (
        !statsResponse.ok ||
        !predictionsResponse.ok ||
        !eventsResponse.ok
      ) {
        throw new Error("Unable to retrieve report data from the API.");
      }

      const statsData = await statsResponse.json();
      const predictionData = await predictionsResponse.json();
      const eventData = await eventsResponse.json();

      setStatistics(statsData.statistics);
      setPredictions(predictionData.predictions || []);
      setEvents(eventData.events || []);
      setGeneratedAt(new Date());
    } catch (err) {
      setError(err.message || "Unable to load reports.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReports();
  }, []);

  const filteredPredictions = useMemo(() => {
    return predictions.filter((item) => {
      const date = new Date(item.created_at);

      if (startDate && date < new Date(`${startDate}T00:00:00`)) {
        return false;
      }

      if (endDate && date > new Date(`${endDate}T23:59:59.999`)) {
        return false;
      }

      return true;
    });
  }, [predictions, startDate, endDate]);

  const filteredEvents = useMemo(() => {
    return events.filter((item) => {
      const date = new Date(item.created_at);

      if (startDate && date < new Date(`${startDate}T00:00:00`)) {
        return false;
      }

      if (endDate && date > new Date(`${endDate}T23:59:59.999`)) {
        return false;
      }

      return true;
    });
  }, [events, startDate, endDate]);

  const attackCount = filteredPredictions.filter(
    (item) => item.predicted_label === "ATTACK"
  ).length;

  const normalCount = filteredPredictions.filter(
    (item) => item.predicted_label === "NORMAL"
  ).length;

 const severityCounts = {
  CRITICAL: filteredEvents.filter(
    (item) => item.severity === "CRITICAL"
  ).length,

  HIGH: filteredEvents.filter(
    (item) => item.severity === "HIGH"
  ).length,

  MEDIUM: filteredEvents.filter(
    (item) => item.severity === "MEDIUM"
  ).length,

  LOW: filteredEvents.filter(
    (item) => item.severity === "LOW"
  ).length,

  UNCLASSIFIED: filteredEvents.filter(
    (item) => !item.severity || item.severity === "UNCLASSIFIED"
  ).length,
};

  function downloadCSV() {
    const headers = [
      "Prediction ID",
      "Traffic ID",
      "Classification",
      "Attack Probability",
      "Normal Probability",
      "Source Bytes",
      "Destination Bytes",
      "Packets",
      "Timestamp",
    ];

    const rows = filteredPredictions.map((item) => [
      item.prediction_id,
      item.traffic_id,
      item.predicted_label,
      item.attack_probability,
      item.normal_probability,
      item.src_bytes,
      item.dst_bytes,
      item.packets,
      item.created_at,
    ]);

    const escapeCSV = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const csvContent = [
      headers.map(escapeCSV).join(","),
      ...rows.map((row) => row.map(escapeCSV).join(",")),
    ].join("\r\n");

    const blob = new Blob(
      ["\uFEFF" + csvContent],
      { type: "text/csv;charset=utf-8;" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "Sentinel_AI_Prediction_Report.csv";
    link.click();

    URL.revokeObjectURL(url);
  }

  function downloadPDF() {
    window.print();
  }

  return (
    <div className="reports-page">

      <div className="reports-header">
        <div>
          <p className="reports-eyebrow">SECURITY INTELLIGENCE</p>
          <h1>Reports & Analytics</h1>
          <p>Analyze historical network predictions and security events.</p>
        </div>

        <button
          className="reports-refresh"
          onClick={loadReports}
          disabled={loading}
        >
          {loading ? "Loading..." : "↻ Refresh Reports"}
        </button>
      </div>

      {error && (
        <div className="reports-error">{error}</div>
      )}

      <section className="reports-filter no-print">
        <div>
          <label>Start Date</label>
          <input
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
          />
        </div>

        <div>
          <label>End Date</label>
          <input
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
          />
        </div>

        <button
          onClick={() => {
            setStartDate("");
            setEndDate("");
          }}
        >
          Clear Filters
        </button>

        <button
          className="reports-csv"
          onClick={downloadCSV}
          disabled={loading || filteredPredictions.length === 0}
        >
          Download CSV
        </button>

        <button
          className="reports-pdf"
          onClick={downloadPDF}
          disabled={loading || !statistics}
        >
          Generate PDF
        </button>
      </section>

      {loading ? (
        <div className="reports-empty">Loading report information...</div>
      ) : statistics ? (
        <>
          <section className="reports-summary">

            <div className="report-stat-card">
              <span>All-Time Predictions</span>
              <h2>{statistics.total_predictions}</h2>
            </div>

            <div className="report-stat-card">
              <span>All-Time Attacks</span>
              <h2 className="report-attack">
                {statistics.attack_predictions}
              </h2>
            </div>

            <div className="report-stat-card">
              <span>All-Time Normal</span>
              <h2 className="report-normal">
                {statistics.normal_predictions}
              </h2>
            </div>

            <div className="report-stat-card">
              <span>Detection Events</span>
              <h2>{statistics.total_detection_events}</h2>
            </div>

          </section>

          <section className="reports-panel">

            <h2>Filtered Prediction Summary</h2>

            <div className="report-progress">
              <div className="report-progress-normal">
                <span>Normal: {normalCount}</span>
              </div>

              <div className="report-progress-attack">
                <span>Attack: {attackCount}</span>
              </div>
            </div>

            <p>
              Filtered predictions: {filteredPredictions.length}
            </p>

          </section>

          <section className="reports-panel">

            <h2>Detection Severity Distribution</h2>

            <div className="severity-report-grid">
              {Object.entries(severityCounts).map(([severity, count]) => (
                <div className="severity-report-card" key={severity}>
                  <span>{severity}</span>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>

            <p>
              Filtered security events: {filteredEvents.length}
            </p>

          </section>

          <section className="reports-panel">

            <div className="reports-table-heading">
              <h2>Prediction History</h2>
              <span>{filteredPredictions.length} RECORDS</span>
            </div>

            <div className="reports-table-wrapper">
              <table className="reports-table">

                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Classification</th>
                    <th>Attack Probability</th>
                    <th>Normal Probability</th>
                    <th>Packets</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredPredictions.map((item) => (
                    <tr key={item.prediction_id}>
                      <td>#{item.prediction_id}</td>

                      <td>
                        <span className={
                          item.predicted_label === "ATTACK"
                            ? "report-attack"
                            : "report-normal"
                        }>
                          {item.predicted_label}
                        </span>
                      </td>

                      <td>
                        {(item.attack_probability * 100).toFixed(2)}%
                      </td>

                      <td>
                        {(item.normal_probability * 100).toFixed(2)}%
                      </td>

                      <td>{item.packets}</td>

                      <td>
                        {new Date(item.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}

                  {filteredPredictions.length === 0 && (
                    <tr>
                      <td colSpan="6">No predictions found for this period.</td>
                    </tr>
                  )}

                </tbody>

              </table>
            </div>

          </section>

          <section className="reports-panel">

            <div className="reports-table-heading">
              <h2>Security Event Report</h2>
              <span>{filteredEvents.length} EVENTS</span>
            </div>

            <div className="reports-table-wrapper">
              <table className="reports-table">

                <thead>
                  <tr>
                    <th>Event ID</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredEvents.map((event) => (
                    <tr key={event.event_id}>
                      <td>#{event.event_id}</td>
                      <td>{event.severity}</td>
                      <td>{event.description}</td>
                      <td>{event.status}</td>
                      <td>
                        {new Date(event.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}

                  {filteredEvents.length === 0 && (
                    <tr>
                      <td colSpan="5">No security events found for this period.</td>
                    </tr>
                  )}

                </tbody>

              </table>
            </div>

          </section>

          <footer className="reports-footer">
            <span>Sentinel AI · Security Report</span>

            <span>
              Generated: {generatedAt?.toLocaleString()}
            </span>

            <span>
              Experimental model · Synthetic training data
            </span>
          </footer>

        </>
      ) : null}

    </div>
  );
}

export default ReportsAnalytics;