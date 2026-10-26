# CloudGuard

CloudGuard is an educational Streamlit dashboard for reviewing login events returned by the existing API Gateway and Lambda integration. It does not create or modify AWS resources, and its severity labels are indicators rather than proof of malicious activity.

## Local setup

PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
Copy-Item .env.example .env
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

The existing API Gateway endpoint is the default, so the dashboard can run without editing source code. Set `CLOUDGUARD_API_URL` in `.env` to use another compatible endpoint. The app loads `.env` only when `CLOUDGUARD_APP_ENV` is `development` (the default).

## Dashboard

- **Overview:** filtered KPIs, severity and login-outcome charts, a time-bucketed event timeline, recent high-risk events, frequent failed-login source IPs, and recent activity.
- **Event explorer:** combined search and filters, sorting, event details, and CSV export of the filtered records.
- **Login simulator:** generates synthetic failed-login events without requesting or storing passwords. Attempts 1–2 are Normal, attempts 3–4 are Medium, and attempt 5 or later is High.
- Overview and Event Explorer use configured API records plus simulator events from this session and, when configured, the S3 archive. The simulator is explicitly separate from real authentication.
- API results are cached for 60 seconds. Use **Refresh events** to request a fresh copy.

### Presentation walkthrough

1. Open **Login simulator**.
2. Click **Run five-attempt demo**. This creates five synthetic log records in order.
3. Explain that the CloudGuard **rule engine** evaluates `failed_attempts`: the fifth record is classified High. This is not a machine-learning model and does not prove malicious activity.
4. With `CLOUDGUARD_S3_BUCKET` configured, the five metadata-only events are written to the existing private S3 bucket with SSE-S3 encryption. Without it, the app clearly reports that the demo is session-only.
5. Open **Overview** or **Event explorer**. The new High event and the other simulator records appear alongside the live API data.

## Tests

Run the deterministic helper tests with:

```powershell
python -m unittest discover -s tests -v
```

The tests use isolated event fixtures; the running dashboard always uses API data.

## Configuration and deployment notes

- Never put AWS access keys, passwords, or private event logs in source control. `.env` is gitignored.
- On EC2, set `CLOUDGUARD_APP_ENV=production` and `CLOUDGUARD_API_URL` in the process environment. The app then does not load a local `.env` file.
- Live API reads use HTTPS through API Gateway and do not require AWS SDK credentials. Optional S3 archiving/loading uses the normal AWS credential provider chain and needs the restricted bucket permissions below.
- Restrict inbound network access. For public access, use a TLS-terminating reverse proxy or managed front end rather than exposing Streamlit directly. If exposing Streamlit on port 8501 for a private demonstration, limit access to the necessary network.
- Optional simulator archiving uses `CLOUDGUARD_S3_BUCKET` and an **existing private bucket**. The app never creates buckets or changes AWS resources. Leave the value empty to keep simulator events in the current Streamlit session only.
- Keep S3 Block Public Access enabled. The app stores only allowlisted event metadata under `cloudguard/login-simulator/` and requests SSE-S3 (`AES256`) encryption.
- Use an EC2 instance role or the normal AWS credential provider chain, never source-code access keys. Grant only `s3:PutObject` and `s3:GetObject` for `arn:aws:s3:::YOUR_BUCKET/cloudguard/login-simulator/*`, plus `s3:ListBucket` on `arn:aws:s3:::YOUR_BUCKET` restricted to the `cloudguard/login-simulator/*` prefix. Do not grant bucket creation, public ACL, or public-read permissions.
- Real S3 uploads require a configured bucket and valid AWS identity/permissions. The automated tests use a fake S3 client and do not create or contact AWS resources. SNS notifications are not implemented.