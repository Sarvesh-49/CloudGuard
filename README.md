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
- Data is fetched from the configured API. There is no demo or mock-data mode.
- API results are cached for 60 seconds. Use **Refresh events** to request a fresh copy.

## Tests

Run the deterministic helper tests with:

```powershell
python -m unittest discover -s tests -v
```

The tests use isolated event fixtures; the running dashboard always uses API data.

## Configuration and deployment notes

- Never put AWS access keys, passwords, or private event logs in source control. `.env` is gitignored.
- On EC2, set `CLOUDGUARD_APP_ENV=production` and `CLOUDGUARD_API_URL` in the process environment. The app then does not load a local `.env` file.
- The dashboard reads events over HTTPS from API Gateway; it does not call DynamoDB or require AWS SDK credentials.
- Restrict inbound network access. For public access, use a TLS-terminating reverse proxy or managed front end rather than exposing Streamlit directly. If exposing Streamlit on port 8501 for a private demonstration, limit access to the necessary network.
- Do not create AWS resources as part of app startup. S3 archiving and SNS notifications are not implemented.