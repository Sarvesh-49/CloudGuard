import json
import os
import re
from datetime import datetime, timezone


S3_PREFIX = "cloudguard/login-simulator/"
MAX_ARCHIVED_EVENTS = 100
ARCHIVE_EVENT_FIELDS = frozenset(
    {
        "event_id",
        "timestamp",
        "severity",
        "status",
        "username",
        "ip_address",
        "failed_attempts",
        "message",
        "source",
    }
)


def _s3_client():
    import boto3

    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    return boto3.client("s3", region_name=region)


def archive_login_event(event, bucket, s3_client=None):
    if not bucket or not bucket.strip():
        raise ValueError("CLOUDGUARD_S3_BUCKET is not configured.")
    if not isinstance(event, dict):
        raise ValueError("The archived event must be an object.")

    timestamp = datetime.now(timezone.utc)
    event_id = re.sub(r"[^A-Za-z0-9_-]", "", str(event.get("event_id", "")))
    if not event_id:
        raise ValueError("The archived event must have an event ID.")

    metadata = {key: value for key, value in event.items() if key in ARCHIVE_EVENT_FIELDS}
    key = f"{S3_PREFIX}{timestamp:%Y/%m/%d}/{event_id}.json"
    client = s3_client or _s3_client()
    client.put_object(
        Bucket=bucket.strip(),
        Key=key,
        Body=json.dumps(metadata, ensure_ascii=True, separators=(",", ":")).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )
    return key


def load_archived_login_events(bucket, s3_client=None, limit=MAX_ARCHIVED_EVENTS):
    if not bucket or not bucket.strip():
        return []

    client = s3_client or _s3_client()
    response = client.list_objects_v2(
        Bucket=bucket.strip(),
        Prefix=S3_PREFIX,
        MaxKeys=min(max(int(limit), 1), MAX_ARCHIVED_EVENTS),
    )
    objects = sorted(
        response.get("Contents", []),
        key=lambda item: item.get("LastModified", datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )

    events = []
    for item in objects:
        key = item.get("Key")
        if not key:
            continue
        body = client.get_object(Bucket=bucket.strip(), Key=key)["Body"].read()
        try:
            event = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(event, dict):
            event["source"] = "S3 login simulator"
            events.append(event)
    return events