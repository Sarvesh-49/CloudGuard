import json
from urllib.parse import urlsplit, urlunsplit

import pandas as pd


EVENT_COLUMNS = [
    "event_id",
    "timestamp",
    "severity",
    "status",
    "username",
    "ip_address",
    "failed_attempts",
    "message",
]


def normalize_api_url(url):
    """Remove a trailing path slash without modifying a query string."""
    parsed = urlsplit(url)
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


def parse_api_payload(payload):
    """Unwrap supported API Gateway response shapes and discard malformed rows."""
    result = payload
    if isinstance(result, dict) and "statusCode" in result:
        try:
            status_code = int(result["statusCode"])
        except (TypeError, ValueError) as error:
            raise ValueError("The API response has an invalid status code.") from error
        if not 200 <= status_code < 300:
            raise ValueError(f"The events API returned status {status_code}.")

    if isinstance(result, dict) and "body" in result:
        result = result["body"]
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError as error:
                raise ValueError("The API response body is not valid JSON.") from error

    if isinstance(result, dict):
        result = result.get("events")
    if not isinstance(result, list):
        raise ValueError("The API response must contain an events list.")

    records = [event for event in result if isinstance(event, dict)]
    return records, len(result) - len(records)


def safe_text(value):
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if value is None or pd.isna(value):
        return ""
    return str(value)


def build_event_frame(events):
    frame = pd.DataFrame(events)
    for column in EVENT_COLUMNS:
        if column not in frame.columns:
            frame[column] = None

    frame["_timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame["_attempts"] = pd.to_numeric(frame["failed_attempts"], errors="coerce")
    frame["_severity"] = frame["severity"].map(safe_text).replace("", "Unknown")
    frame["_status"] = frame["status"].map(safe_text).replace("", "Unknown")
    frame["_username"] = frame["username"].map(safe_text)
    frame["_ip_address"] = frame["ip_address"].map(safe_text)
    return frame


def filter_events(
    frame,
    search="",
    severities=(),
    statuses=(),
    usernames=(),
    ip_addresses=(),
    date_range=None,
    sort_by="Newest first",
):
    filtered = frame.copy()
    if severities:
        filtered = filtered[filtered["_severity"].isin(severities)]
    if statuses:
        filtered = filtered[filtered["_status"].isin(statuses)]
    if usernames:
        filtered = filtered[filtered["_username"].isin(usernames)]
    if ip_addresses:
        filtered = filtered[filtered["_ip_address"].isin(ip_addresses)]

    search_term = safe_text(search).strip().casefold()
    if search_term:
        search_columns = ["event_id", "_username", "_ip_address", "_severity", "_status"]
        matches = pd.Series(False, index=filtered.index)
        for column in search_columns:
            matches |= filtered[column].map(safe_text).str.casefold().str.contains(
                search_term,
                regex=False,
                na=False,
            )
        filtered = filtered[matches]

    if isinstance(date_range, (tuple, list)) and len(date_range) == 2:
        start_date, end_date = date_range
        valid_timestamps = filtered["_timestamp"].notna()
        date_matches = filtered["_timestamp"].dt.date.between(start_date, end_date)
        available_timestamps = frame["_timestamp"].dropna()
        if not available_timestamps.empty:
            full_range = (
                start_date == available_timestamps.min().date()
                and end_date == available_timestamps.max().date()
            )
            if full_range:
                date_matches |= ~valid_timestamps
        filtered = filtered[date_matches]

    if sort_by == "Oldest first":
        filtered = filtered.sort_values("_timestamp", ascending=True, na_position="last")
    elif sort_by == "Highest risk":
        risk_rank = filtered["_severity"].str.casefold().map(
            {"high": 3, "medium": 2, "normal": 1}
        ).fillna(0)
        filtered = filtered.assign(_risk_rank=risk_rank).sort_values(
            ["_risk_rank", "_attempts", "_timestamp"],
            ascending=False,
            na_position="last",
        ).drop(columns="_risk_rank")
    else:
        filtered = filtered.sort_values("_timestamp", ascending=False, na_position="last")
    return filtered


def calculate_metrics(frame):
    statuses = frame["_status"].str.casefold()
    outcomes = statuses.isin(["success", "successful", "succeeded", "failed", "failure"])
    known_outcomes = int(outcomes.sum())
    successes = int(statuses.isin(["success", "successful", "succeeded"]).sum())
    return {
        "events": len(frame),
        "high_risk": int(frame["_severity"].str.casefold().eq("high").sum()),
        "medium_risk": int(frame["_severity"].str.casefold().eq("medium").sum()),
        "failures": int(statuses.isin(["failed", "failure"]).sum()),
        "success_rate": round(successes / known_outcomes * 100) if known_outcomes else None,
        "users": int(frame.loc[frame["_username"] != "", "_username"].nunique()),
        "source_ips": int(frame.loc[frame["_ip_address"] != "", "_ip_address"].nunique()),
    }


def timeline_events(frame):
    timestamps = frame["_timestamp"].dropna()
    if timestamps.empty:
        return pd.DataFrame(columns=["timestamp", "events"]), "Unavailable"

    span = timestamps.max() - timestamps.min()
    if span <= pd.Timedelta(hours=3):
        frequency, interval = "min", "Minute"
    elif span <= pd.Timedelta(days=1):
        frequency, interval = "15min", "15-minute"
    elif span <= pd.Timedelta(days=14):
        frequency, interval = "6h", "Every 6 hours"
    elif span <= pd.Timedelta(days=120):
        frequency, interval = "D", "Daily"
    else:
        frequency, interval = "W", "Weekly"

    counts = pd.Series(1, index=pd.DatetimeIndex(timestamps)).resample(frequency).sum()
    return counts.rename_axis("timestamp").rename("events").reset_index(), interval


def top_failed_ips(frame, limit=5):
    failures = frame[
        frame["_status"].str.casefold().isin(["failed", "failure"])
        & frame["_ip_address"].ne("")
    ]
    return (
        failures.groupby("_ip_address", as_index=False)
        .size()
        .rename(columns={"_ip_address": "Source IP", "size": "Failures"})
        .sort_values("Failures", ascending=False)
        .head(limit)
    )


def explain_event(event):
    attempts = pd.to_numeric(pd.Series([event.get("failed_attempts")]), errors="coerce").iloc[0]
    reported = safe_text(event.get("severity")) or "Unknown"

    if pd.notna(attempts) and attempts >= 5:
        baseline = "High: at least 5 failed attempts."
        expected = "high"
    elif pd.notna(attempts) and attempts >= 3:
        baseline = "Medium: 3 or 4 failed attempts."
        expected = "medium"
    else:
        baseline = "Normal: fewer than 3 failed attempts, or no usable attempt count."
        expected = "normal"

    if reported.casefold() != expected:
        return (
            f"API-reported severity: {reported}. The documented attempt-count rule would indicate "
            f"{baseline.lower()} The dashboard does not change the API classification."
        )
    return f"API-reported severity: {reported}. {baseline}"