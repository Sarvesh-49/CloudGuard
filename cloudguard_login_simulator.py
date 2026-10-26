import ipaddress
from datetime import datetime, timezone
from uuid import uuid4


SIMULATOR_USERNAME = "demo-user"
SIMULATOR_IP_ADDRESS = "192.0.2.10"
HIGH_RISK_THRESHOLD = 5


def severity_for_failed_attempts(failed_attempts):
    if isinstance(failed_attempts, bool) or not isinstance(failed_attempts, int) or failed_attempts < 1:
        raise ValueError("Failed-attempt count must be a positive integer.")
    if failed_attempts >= HIGH_RISK_THRESHOLD:
        return "High"
    if failed_attempts >= 3:
        return "Medium"
    return "Normal"


def create_failed_login_event(username, ip_address, failed_attempts):
    username = str(username).strip()
    if not username or len(username) > 64:
        raise ValueError("Simulator username must contain 1 to 64 characters.")
    try:
        normalized_ip = str(ipaddress.ip_address(ip_address))
    except ValueError as error:
        raise ValueError("Simulator source IP must be a valid IP address.") from error

    severity = severity_for_failed_attempts(failed_attempts)
    return {
        "event_id": f"SIM-{uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "status": "Failed",
        "username": username,
        "ip_address": normalized_ip,
        "failed_attempts": failed_attempts,
        "message": f"Simulated failed login attempt {failed_attempts}.",
        "source": "Login simulator",
    }