# CloudGuard — Product Requirements Document (PRD)

**Version:** 1.0  
**Status:** Implementation specification  
**Project type:** Cloud security monitoring mini-project  
**Target deployment:** Amazon EC2  
**Primary region:** `us-east-1` (N. Virginia)

---

## 1. Product Overview

CloudGuard is an educational cloud-based suspicious login activity detection and monitoring system. It receives login-event data, applies transparent rule-based risk classification, stores events in Amazon DynamoDB, exposes event data through Amazon API Gateway, and presents analytics in a Streamlit dashboard. Amazon S3 will be used for private report/log archives, and Amazon SNS may be used for email alerts.

The goal is to turn the existing working prototype into a polished, secure, demonstrable project before deploying the dashboard to EC2.

### Current implementation (preserve this)

- `CloudGuardDetector` AWS Lambda function classifies login events and writes records to DynamoDB.
- DynamoDB table: `CloudGuardEvents`.
- `CloudGuardGetEvents` Lambda function reads stored events.
- API Gateway REST API: `CloudGuardAPI`, stage: `dev`.
- The API endpoint has been tested successfully and returns JSON events.
- A local Streamlit dashboard fetches events from the API and displays metrics, a chart, a table, and CSV export.
- AWS resources are in `us-east-1`.

**Important:** Inspect the existing repository and code before changing anything. Preserve working AWS integration and existing resource names. Do not replace real API data with mock data in the application. Use mock data only in isolated tests or a clearly labelled demo mode.

---

## 2. Goals

1. Create a professional, responsive, security-operations-center (SOC)-style dashboard.
2. Improve event search, filtering, sorting, analytics, and CSV reporting.
3. Improve explainability of risk detections and provide more useful detection rules.
4. Prepare the app for safe deployment on EC2.
5. Add private S3 report archiving and optional SNS email notifications without breaking the current pipeline.
6. Keep the project easy for a student to understand, configure, test, and demonstrate.

## 3. Non-goals

- Do not claim the prototype is a production-grade SIEM or intrusion-detection platform.
- Do not implement offensive security features, exploit scanning, credential collection, or real-account monitoring.
- Do not use real credentials, real user passwords, or sensitive production logs.
- Do not add machine learning until the rule-based baseline and its evaluation are clear.
- Do not rewrite the backend or recreate AWS resources unnecessarily.
- Do not migrate to another cloud provider.

---

## 4. Users and Primary Use Cases

### Primary user
A student/developer demonstrating cloud computing, serverless processing, event storage, and security analytics.

### Use cases
- View recent login/security events from AWS.
- Understand why an event was marked Normal, Medium, or High.
- Search and filter events by severity, username, IP address, status, and time.
- Review charts and summary metrics.
- Export filtered results to CSV.
- Archive reports to a private S3 bucket (after configuration).
- Receive an email notification for High-risk events (optional, after configuration).
- Run the dashboard locally during development and on EC2 after deployment.

---

## 5. Required Architecture

```text
Login Event / Test Input
          |
          v
CloudGuardDetector (AWS Lambda)
          |
          +----> CloudGuardEvents (DynamoDB)
          |
          +----> [Optional] SNS notification for High severity
          |
          +----> [Optional] S3 report/archive workflow

Streamlit Dashboard (local development / EC2 hosting)
          |
          v
API Gateway REST API (CloudGuardAPI, stage dev)
          |
          v
CloudGuardGetEvents (AWS Lambda)
          |
          v
CloudGuardEvents (DynamoDB)
```

Keep the existing API contract and AWS resource names unless code inspection reveals a concrete incompatibility. Any required contract change must be documented and backward-compatible where practical.

---

## 6. Functional Requirements

### FR-1: Live AWS data
- The default dashboard mode must fetch data from the configured API Gateway URL.
- Show loading state while fetching.
- Show a clear, user-friendly error when the API is unavailable or returns invalid JSON.
- Include a manual refresh control.
- Display the last successful refresh time.
- Do not show fake data as though it were live AWS data.
- Add optional demo mode only if clearly labelled and isolated from live mode.

### FR-2: Visual design and navigation
- Use a professional SOC-inspired dark theme with strong contrast and readable typography.
- Use Streamlit-native components and Plotly charts; do not introduce a separate frontend framework unless the existing repository already uses one.
- Use a clean layout with a header, sidebar controls, KPI cards, chart area, and event explorer.
- Prefer consistent spacing, concise labels, restrained accent colors, and clear severity indicators.
- Keep the UI usable on laptop and smaller screens.
- Avoid excessive animation, decorative clutter, and huge headings.

Suggested layout:
1. Header: CloudGuard logo/emoji, title, subtitle, API connection status, refresh action.
2. KPI row: total events, failed logins, high-risk events, unique users or unique source IPs.
3. Analytics: events by severity, success/failure distribution, events over time.
4. Event explorer: search, filters, sorting, paginated or bounded table.
5. Event details: selected event's fields and detection explanation.
6. Footer: educational prototype notice and data freshness timestamp.

### FR-3: KPI metrics
Compute all metrics from the fetched data, not hardcoded numbers:
- Total events.
- Failed login events.
- High-risk events.
- Unique usernames or unique source IPs.
- Optional: Medium-risk events and success rate.

Handle empty, missing, and null fields without crashing.

### FR-4: Charts
Use Plotly for interactive charts:
- Event count by severity.
- Successful vs. failed logins.
- Event timeline using timestamp where available.
- Optional: top source IPs or usernames associated with failed attempts.

Charts must be based on actual loaded records and handle empty or malformed datasets gracefully. Clearly label any charts that use aggregated counts.

### FR-5: Search, filters, and event table
- Free-text search across username, IP address, severity, status, and event ID.
- Filters for severity, status, username, IP address, and date/time range when timestamps are available.
- Allow users to clear filters.
- Sort by timestamp and relevant risk fields.
- Display a readable event table with useful columns.
- Show a details panel/expander for a selected event, including `message` and any detection reason.
- Export the currently filtered records to CSV.
- Sanitize or safely encode displayed content; treat event values as untrusted data.

### FR-6: Detection rules and explainability
Preserve the current transparent baseline:
- `failed_attempts >= 5` → High.
- `failed_attempts >= 3` → Medium.
- Otherwise → Normal.

Improve event explanations, but do not silently change existing backend classification. If enhanced time-window rules are implemented, make them a separately tested enhancement and document the expected input fields and limits. Do not imply that a severity label proves malicious activity.

Potential future rule enhancements (only when sufficient event data exists):
- Repeated failures by a user within a time window.
- Multiple usernames targeted from a single source IP.
- Repeated failures followed by a successful login.
- Explainable reasons for each triggered rule.

If backend changes are needed, preserve existing API request/response compatibility or document the migration.

### FR-7: API configuration and resilience
- Read the API URL from an environment variable, e.g. `CLOUDGUARD_API_URL`.
- Never hardcode secrets or account credentials.
- Normalize a trailing slash safely without changing the path or query string.
- Set a sensible HTTP timeout.
- Validate response status and JSON shape.
- Handle API errors, timeouts, empty results, and malformed records gracefully.
- Avoid unbounded API calls or automatic rapid polling.
- Do not disable TLS verification.
- Do not log sensitive event content unnecessarily.

### FR-8: CSV reports
- Allow CSV download of filtered records.
- Use UTF-8 encoding and stable column names.
- Ensure the export contains the filtered dataset, not always the full dataset.
- Handle missing fields and empty data.
- Do not include credentials or secrets in the report.

### FR-9: Amazon S3 integration (optional phase)
- Use a private S3 bucket for report/archive storage; keep Block Public Access enabled.
- Bucket name must come from environment/configuration, e.g. `CLOUDGUARD_S3_BUCKET`.
- Use the AWS SDK (`boto3`) only if this dependency is appropriate for the existing project.
- Use IAM roles, not hardcoded access keys.
- Restrict permissions to the required bucket and actions.
- Use a clear object-key scheme, e.g. `reports/YYYY/MM/DD/cloudguard-events-<timestamp>.csv`.
- Display success/failure feedback when archive is requested.
- Do not upload automatically on every page rerun.
- Do not make the bucket or objects public.
- S3 integration must be optional: dashboard should still work if S3 is not configured.

### FR-10: SNS notifications (optional phase)
- Add High-risk email alerts only after the user explicitly configures SNS.
- Read the SNS topic ARN from `CLOUDGUARD_SNS_TOPIC_ARN`.
- Prefer publishing from Lambda after the event is stored successfully.
- Avoid duplicate alerts for the same event where feasible.
- Use IAM roles and least-privilege `sns:Publish` access.
- Document that email subscriptions must be confirmed.
- If SNS is not configured, the main app must still work normally.

### FR-11: EC2 deployment readiness
- App must run locally and on EC2 with the same configuration pattern.
- Provide `requirements.txt`.
- Provide `.env.example` with placeholders only, and ensure `.env` is gitignored.
- Provide a README with setup, run, test, and deployment instructions.
- Provide a production-oriented launch command using Streamlit's supported configuration.
- Do not embed AWS credentials in source files.
- Prefer an EC2 instance profile/instance role for AWS SDK access if the app itself calls AWS directly.
- Keep inbound ports restricted. Do not recommend opening all ports to `0.0.0.0/0` without explanation.
- Explain that Streamlit's default port is 8501 and should be exposed only as needed. Prefer HTTPS via a reverse proxy or an appropriate managed front end for public access.
- Never commit private keys, `.env`, AWS access keys, or real event logs.

---

## 7. Configuration

Use environment variables and provide safe defaults for non-secret UI settings.

Suggested `.env.example`:

```dotenv
# Required for live dashboard mode
CLOUDGUARD_API_URL=https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/dev/

# Optional: private S3 archive bucket
CLOUDGUARD_S3_BUCKET=

# Optional: SNS topic for configured alerts
CLOUDGUARD_SNS_TOPIC_ARN=

# Optional app settings
CLOUDGUARD_APP_ENV=development
```

If adding `python-dotenv`, load `.env` only for local development and include the dependency. On EC2, prefer environment configuration or instance-role permissions. Never place AWS access keys in this file.

---

## 8. Recommended Project Structure

Adapt to the repository that exists. Do not blindly move files if that would break the current app.

```text
CloudGuard/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── pages/                    # optional Streamlit multipage app
│   ├── 1_Overview.py
│   ├── 2_Event_Explorer.py
│   └── 3_Reports.py
├── cloudguard/
│   ├── __init__.py
│   ├── api_client.py
│   ├── analytics.py
│   ├── detection.py
│   └── s3_archive.py          # optional
└── tests/
    ├── test_analytics.py
    ├── test_detection.py
    └── test_api_client.py
```

A single `app.py` is acceptable for an initial upgrade. Prioritize correctness and maintainability over unnecessary complexity.

---

## 9. Non-functional Requirements

- **Reliability:** missing fields, empty data, network failures, and API errors must not crash the whole dashboard.
- **Security:** no hardcoded credentials; private S3 bucket; least-privilege IAM; no secrets in logs or Git.
- **Performance:** bounded API reads; avoid repeated API calls during a single Streamlit rerun where caching is appropriate.
- **Usability:** clear labels, informative empty states, legible charts, consistent severity colors.
- **Maintainability:** separate API access, analytics, and archive logic when practical.
- **Testability:** deterministic tests for metrics, filters, severity logic, and error handling.
- **Transparency:** identify the application as an educational prototype and clearly describe rule-based detection limitations.

---

## 10. Error Handling and Edge Cases

Handle at least:
- API timeout or connection error.
- HTTP 4xx/5xx response.
- Invalid JSON response.
- API response with no `events` key or an empty `events` array.
- Event with missing or null username, IP, severity, status, or timestamp.
- Malformed timestamps.
- Numeric fields arriving as strings or null.
- Empty filtered results.
- S3 not configured, access denied, or upload failure.
- Optional SNS configuration missing or subscription unconfirmed.

Show actionable but safe error messages. Do not display stack traces to dashboard users; send technical details to development logs without leaking secrets.

---

## 11. Testing and Acceptance Criteria

The implementation is accepted when:

1. The app launches locally using documented instructions.
2. Live mode fetches records from the configured API URL.
3. No mock records are presented as real AWS events.
4. The app shows clear loading, empty, error, and last-refresh states.
5. KPI values match the currently loaded records.
6. Charts update based on loaded records and handle empty data.
7. Search and filters combine correctly.
8. CSV download exports the filtered rows.
9. Event detail view shows fields and detection explanation safely.
10. Missing fields and malformed timestamps do not crash the dashboard.
11. API timeouts and non-success HTTP responses are handled.
12. S3 archive is private, optional, and works only when configured.
13. SNS is optional and does not break the app when not configured.
14. No credentials or secrets are committed to the repository.
15. `requirements.txt`, `.env.example`, `.gitignore`, and README are included.
16. Tests for analytics and core helper logic pass.
17. The app can be configured for EC2 without source-code edits.
18. Deployment documentation includes safe network access and AWS billing cautions.

---

## 12. Implementation Plan

Implement incrementally in this order:

### Phase 1 — Inspect and stabilize
- Inspect existing files and current API response shape.
- Identify existing dependencies and avoid unnecessary rewrites.
- Keep the current working AWS resources and API contract.
- Add environment-based API configuration and robust error handling.

### Phase 2 — UI refresh
- Add a consistent SOC-style theme and layout.
- Add dynamic KPI cards.
- Add Plotly severity, login-status, and timeline charts.
- Add search, filters, sorting, event details, and filtered CSV export.

### Phase 3 — Quality
- Add helper modules where useful.
- Add tests for metrics, filtering, detection explanations, and API parsing.
- Update README and requirements.
- Verify behavior with live data and test fixtures.

### Phase 4 — S3 and SNS
- Add optional S3 CSV archiving using private storage and least-privilege IAM.
- Add optional SNS alerts after successful high-risk event storage.
- Ensure both features remain disabled unless explicitly configured.

### Phase 5 — EC2 preparation
- Confirm app runs with environment variables.
- Document an EC2 instance profile, network restrictions, installation, and launch.
- Do not launch or modify AWS infrastructure automatically from the code assistant.
- Ask before making destructive changes or altering existing AWS resources.

---

## 13. Instructions for GitHub Copilot in VS Code

**Work on the existing project, not a fresh rewrite.**

1. Inspect the repository, current `app.py`, dependencies, and current API response shape before editing.
2. Provide a brief plan and list files to change.
3. Implement Phase 1 and Phase 2 first.
4. Keep the working API Gateway integration and use the actual configured API URL.
5. Do not invent an API URL, AWS account ID, bucket name, or SNS topic ARN.
6. Do not put secrets in source code.
7. Do not create or modify AWS resources automatically.
8. Make small, coherent edits and explain important changes.
9. Add tests and run them where possible.
10. At the end, report changed files, commands to run locally, test results, any manual AWS configuration still required, and known limitations.
11. If a requirement conflicts with the current repository, explain the conflict and choose the least disruptive compatible solution.
12. Do not add S3/SNS features before the core UI refresh works. Keep optional integrations optional.
13. Preserve the current rule-based detector behavior unless a change is explicitly tested and documented.
14. Keep the application honest about the limitations of its educational detection rules.

---

## 14. Final Deliverables

- Refreshed Streamlit dashboard.
- Live API data integration retained.
- Interactive security charts and event filtering.
- CSV export of filtered events.
- Optional private S3 report archiving.
- Optional SNS High-risk email notifications.
- `requirements.txt`, `.env.example`, `.gitignore`, README, and tests.
- EC2 deployment guide.
- Updated architecture description and known limitations.

**Definition of success:** CloudGuard presents live AWS security events in a professional, usable dashboard, supports filtering and reporting, remains safe to configure, and is ready to deploy on EC2 after the documented AWS permissions and network settings are completed.
