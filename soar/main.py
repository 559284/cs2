from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse
from datetime import datetime
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
import json


app = FastAPI()

INCIDENT_LOG = "incidents.log"
BLOCKLIST_FILE = "blocklist.txt"


# --------------------------------------------------
# Prometheus metrics
# --------------------------------------------------

ALERTS_RECEIVED = Counter(
    "soar_alerts_received_total",
    "Total number of security alerts received by the SOAR",
    ["alert_type"]
)

ACTIONS_SUCCESS = Counter(
    "soar_actions_success_total",
    "Total number of successful automated SOAR actions",
    ["action_type"]
)

ACTIONS_FAILED = Counter(
    "soar_actions_failed_total",
    "Total number of failed automated SOAR actions",
    ["action_type"]
)


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "status": "SOAR application is running"
    }


# --------------------------------------------------
# Prometheus metrics endpoint
# --------------------------------------------------

@app.get("/metrics")
def metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# --------------------------------------------------
# Blocklist endpoint
# --------------------------------------------------

@app.get("/blocklist", response_class=PlainTextResponse)
def get_blocklist():
    try:
        with open(BLOCKLIST_FILE, "r") as file:
            return file.read()
    except FileNotFoundError:
        return ""


# --------------------------------------------------
# Save security incidents
# --------------------------------------------------

def save_incident(incident):
    with open(INCIDENT_LOG, "a") as file:
        file.write(json.dumps(incident) + "\n")


# --------------------------------------------------
# Add IP to SOAR blocklist
# --------------------------------------------------

def add_to_blocklist(ip):
    try:
        with open(BLOCKLIST_FILE, "r") as file:
            blocked_ips = file.read().splitlines()
    except FileNotFoundError:
        blocked_ips = []

    if ip in blocked_ips:
        print(f"IP already in blocklist: {ip}")
        return True

    try:
        with open(BLOCKLIST_FILE, "a") as file:
            file.write(ip + "\n")

        print(f"IP added to blocklist: {ip}")

        ACTIONS_SUCCESS.labels(
            action_type="block_ip"
        ).inc()

        return True

    except Exception as error:
        print(f"Failed to add IP to blocklist: {error}")

        ACTIONS_FAILED.labels(
            action_type="block_ip"
        ).inc()

        return False


# --------------------------------------------------
# SOAR rule engine
# --------------------------------------------------

def handle_alert(alert_name, alert_data):
    name = alert_name.lower()

    # Ignore Grafana NoData alerts
    if "datasourcenodata" in name:
        print("Grafana DatasourceNoData alert ignored")
        return None

    # Rule 1: Possible Port Scan
    if "port scan" in name:

        ALERTS_RECEIVED.labels(
            alert_type="port_scan"
        ).inc()

        severity = "high"

        labels = alert_data.get("labels", {})
        source_ip = labels.get("source_ip")

        if source_ip:
            success = add_to_blocklist(source_ip)

            if success:
                action = (
                    f"Possible port scan detected - "
                    f"{source_ip} added to blocklist"
                )
            else:
                action = (
                    f"Possible port scan detected - "
                    f"failed to add {source_ip} to blocklist"
                )

        else:
            ACTIONS_FAILED.labels(
                action_type="block_ip"
            ).inc()

            action = (
                "Possible port scan detected - "
                "source IP not found"
            )

    # Rule 2: SSH brute force
    elif "ssh" in name:

        ALERTS_RECEIVED.labels(
            alert_type="ssh_failed_login"
        ).inc()

        severity = "high"

        action = (
            "Possible SSH brute-force attack detected - "
            "incident logged"
        )

    # Rule 3: Unknown alert
    else:

        ALERTS_RECEIVED.labels(
            alert_type="unknown"
        ).inc()

        severity = "medium"
        action = "Unknown security alert received"

    incident = {
        "timestamp": datetime.now().isoformat(),
        "alert_name": alert_name,
        "severity": severity,
        "action": action,
        "alert_data": alert_data
    }

    save_incident(incident)

    print("\n===== SECURITY INCIDENT =====")
    print("Alert:", alert_name)
    print("Severity:", severity)
    print("Response:", action)
    print("=============================\n")

    return incident


# --------------------------------------------------
# Grafana webhook receiver
# --------------------------------------------------

@app.post("/alert")
async def receive_alert(request: Request):
    data = await request.json()

    print("\nAlert received from Grafana")

    incidents = []

    # Normal Grafana webhook structure
    if "alerts" in data:
        for alert in data["alerts"]:

            labels = alert.get("labels", {})

            alert_name = (
                labels.get("alertname")
                or labels.get("rulename")
                or data.get("title")
                or "unknown"
            )

            incident = handle_alert(
                alert_name,
                alert
            )

            if incident is not None:
                incidents.append(incident)

    # Manual JSON testing
    else:
        alert_name = (
            data.get("alert_name")
            or data.get("event")
            or data.get("title")
            or "unknown"
        )

        incident = handle_alert(
            alert_name,
            data
        )

        if incident is not None:
            incidents.append(incident)

    return {
        "status": "processed",
        "incidents_processed": len(incidents),
        "incidents": incidents
    }
