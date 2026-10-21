import html
import os
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from dotenv import load_dotenv

from cloudguard_analytics import (
    EVENT_COLUMNS,
    build_event_frame,
    calculate_metrics,
    explain_event,
    filter_events,
    normalize_api_url,
    parse_api_payload,
    safe_text,
    timeline_events,
    top_failed_ips,
)


st.set_page_config(
    page_title="CloudGuard | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DEFAULT_API_URL = "https://xh2un2w7y6.execute-api.us-east-1.amazonaws.com/dev"
if os.getenv("CLOUDGUARD_APP_ENV", "development").casefold() == "development":
    load_dotenv()
API_URL = os.getenv("CLOUDGUARD_API_URL", "").strip() or DEFAULT_API_URL
SEVERITY_COLORS = {
    "Critical": "#f04452",
    "High": "#ff7a36",
    "Medium": "#f5b942",
    "Low": "#4f92dc",
    "Normal": "#39b98a",
    "Informational": "#8290a1",
    "Unknown": "#8290a1",
}
STATUS_COLORS = {
    "Success": "#39b98a",
    "Successful": "#39b98a",
    "Succeeded": "#39b98a",
    "Failed": "#f04452",
    "Failure": "#f04452",
    "Unknown": "#8290a1",
}

st.markdown(
    """
    <style>
    :root {
        --cg-bg: #080d12;
        --cg-rail: #0b1219;
        --cg-panel: #10171e;
        --cg-line: #202c36;
        --cg-text: #e7edf2;
        --cg-muted: #8796a4;
        --cg-cyan: #58c6d1;
        --cg-red: #f04452;
        --cg-amber: #f5b942;
        --cg-green: #39b98a;
    }
    .stApp { background: var(--cg-bg); color: var(--cg-text); }
    header[data-testid="stHeader"] { background: rgba(8, 13, 18, 0.94); }
    section[data-testid="stSidebar"] { width: 230px !important; min-width: 230px !important; max-width: 230px !important; background: var(--cg-rail); border-right: 1px solid var(--cg-line); }
    [data-testid="stSidebar"] > div:first-child { padding-top: 1rem; }
    [data-testid="stMainBlockContainer"] { max-width: 1700px; padding: 2rem 1.25rem 2rem; }
    h1, h2, h3, h4 { color: var(--cg-text); letter-spacing: 0; }
    h1 { font-size: 1.55rem !important; line-height: 1.2 !important; margin: 0.1rem 0 0.25rem !important; }
    h2 { font-size: 1.15rem !important; margin: 0.2rem 0 0.8rem !important; }
    h3 { font-size: 0.96rem !important; margin: 0.1rem 0 0.55rem !important; }
    p, label, [data-testid="stCaptionContainer"] { color: var(--cg-muted); }
    [data-testid="stMetric"] { min-width: 0; padding: 0.8rem 0.72rem; background: var(--cg-panel); border: 1px solid var(--cg-line); border-radius: 4px; }
    [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] * { color: var(--cg-muted); font-size: 0.72rem; white-space: normal !important; }
    [data-testid="stMetricValue"] { color: var(--cg-text); font-size: 1.4rem; }
    [data-testid="stPlotlyChart"], [data-testid="stDataFrame"] { background: var(--cg-panel); border: 1px solid var(--cg-line); border-radius: 4px; overflow: hidden; }
    [data-testid="stVerticalBlockBorderWrapper"] { background: var(--cg-panel); border-color: var(--cg-line); border-radius: 4px; }
    [data-testid="stButton"] button, [data-testid="stDownloadButton"] button { min-height: 2.3rem; border-radius: 4px; }
    [data-testid="stSelectbox"] [data-baseweb="select"], [data-testid="stMultiSelect"] [data-baseweb="select"], [data-testid="stTextInput"] input { background: #0d141b; }
    .cg-brand { color: var(--cg-text); font-size: 0.9rem; font-weight: 700; padding: 0.2rem 0 1rem; }
    .cg-brand-mark { display: inline-flex; width: 1.65rem; height: 1.65rem; align-items: center; justify-content: center; margin-right: 0.45rem; border: 1px solid #315764; border-radius: 4px; color: var(--cg-cyan); }
    .cg-page-title { color: var(--cg-text); font-size: 1.45rem; line-height: 1.2; font-weight: 700; }
    .cg-page-subtitle { color: var(--cg-muted); font-size: 0.78rem; margin-top: 0.2rem; }
    .cg-live { color: var(--cg-green); font-size: 0.74rem; font-weight: 700; text-align: right; white-space: nowrap; }
    .cg-refresh-meta { color: var(--cg-muted); font-size: 0.68rem; text-align: right; }
    .cg-feed-row { padding: 0.48rem 0; border-bottom: 1px solid var(--cg-line); }
    .cg-feed-title { color: var(--cg-text); font-size: 0.76rem; font-weight: 600; }
    .cg-feed-meta { color: var(--cg-muted); font-size: 0.67rem; padding-top: 0.15rem; }
    .cg-context { padding: 0.72rem; border-left: 2px solid var(--cg-amber); background: #0c131a; color: var(--cg-text); font-size: 0.78rem; line-height: 1.45; }
    .cg-pipeline { display: flex; align-items: center; justify-content: center; flex-wrap: wrap; gap: 0.3rem; padding: 1rem 0 0.35rem; }
    .cg-pipeline-step { padding: 0.42rem 0.48rem; border: 1px solid var(--cg-line); border-radius: 4px; color: var(--cg-text); font-size: 0.66rem; text-align: center; }
    .cg-pipeline-arrow { color: var(--cg-cyan); font-size: 1rem; }
    .cg-divider { border-top: 1px solid var(--cg-line); margin: 0.65rem 0 1rem; }
    @media (max-width: 900px) {
        [data-testid="stMainBlockContainer"] { padding: 3rem 1rem 2rem; }
        [data-testid="stMetricValue"] { font-size: 1.15rem; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(ttl=60, show_spinner=False)
def load_events(api_url):
    response = requests.get(normalize_api_url(api_url), timeout=15)
    response.raise_for_status()
    events, malformed_count = parse_api_payload(response.json())
    return events, malformed_count, datetime.now(timezone.utc)


def make_chart_layout(figure, height=260):
    figure.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#cbd5dd", "family": "Segoe UI, sans-serif", "size": 10},
        margin={"l": 10, "r": 10, "t": 42, "b": 10},
        height=height,
        title={"font": {"size": 12, "color": "#e7edf2"}},
        legend={"font": {"size": 9}},
    )
    return figure


def event_table(source):
    table = source[EVENT_COLUMNS].copy()
    for column in EVENT_COLUMNS:
        table[column] = source[column].map(safe_text)
    table["timestamp"] = source["_timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC").fillna("")
    table["failed_attempts"] = source["_attempts"].map(
        lambda value: "" if pd.isna(value) else int(value)
    )
    return table


st.sidebar.markdown(
    '<div class="cg-brand"><span class="cg-brand-mark">C</span> CLOUDGUARD <span style="color:#58c6d1">/ SOC</span></div>',
    unsafe_allow_html=True,
)
st.sidebar.markdown("#### Workspace")
page = st.sidebar.radio(
    "Workspace view",
    ["Overview", "Event explorer"],
    label_visibility="collapsed",
    key="active_page",
)
st.sidebar.markdown('<div class="cg-divider"></div>', unsafe_allow_html=True)
st.sidebar.markdown("#### Event filters")
if st.sidebar.button("Clear filters", width="stretch"):
    for key in (
        "search_filter",
        "severity_filter",
        "status_filter",
        "username_filter",
        "ip_filter",
        "date_filter",
        "sort_filter",
    ):
        st.session_state.pop(key, None)
    st.rerun()
st.sidebar.text_input("Search events", placeholder="User, IP, severity, status, ID", key="search_filter")

try:
    with st.spinner("Loading live events from the configured API..."):
        events, malformed_count, refreshed_at = load_events(API_URL)
except requests.exceptions.Timeout:
    st.error("The events API did not respond within 15 seconds. Check the API URL and network, then refresh.")
    st.stop()
except requests.exceptions.RequestException:
    st.error("Could not reach the events API. Check the configured API URL and network, then refresh.")
    st.stop()
except (ValueError, TypeError):
    st.error("The events API returned an invalid response. Check the API response format, then refresh.")
    st.stop()

frame = build_event_frame(events)
severity_options = sorted(frame["_severity"].unique().tolist())
status_options = sorted(frame["_status"].unique().tolist())
username_options = sorted(value for value in frame["_username"].unique().tolist() if value)
ip_options = sorted(value for value in frame["_ip_address"].unique().tolist() if value)
selected_severity = st.sidebar.multiselect("Severity", severity_options, key="severity_filter")
selected_status = st.sidebar.multiselect("Status", status_options, key="status_filter")
selected_usernames = st.sidebar.multiselect("Username", username_options, key="username_filter")
selected_ips = st.sidebar.multiselect("Source IP", ip_options, key="ip_filter")
sort_choice = st.sidebar.selectbox(
    "Sort events",
    ["Newest first", "Oldest first", "Highest risk"],
    key="sort_filter",
)

timestamp_values = frame["_timestamp"].dropna()
date_range = None
if not timestamp_values.empty:
    min_date = timestamp_values.min().date()
    max_date = timestamp_values.max().date()
    date_range = st.sidebar.date_input(
        "Timestamp range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
        key="date_filter",
    )
else:
    st.sidebar.caption("No valid timestamps are available for date filtering.")

filtered = filter_events(
    frame,
    search=st.session_state.get("search_filter", ""),
    severities=selected_severity,
    statuses=selected_status,
    usernames=selected_usernames,
    ip_addresses=selected_ips,
    date_range=date_range,
    sort_by=sort_choice,
)
metrics = calculate_metrics(filtered)

header_columns = st.columns([3, 1])
with header_columns[0]:
    st.markdown(
        f'<div class="cg-page-title">{page}</div><div class="cg-page-subtitle">Login activity monitoring · AWS API Gateway</div>',
        unsafe_allow_html=True,
    )
with header_columns[1]:
    if st.button("Refresh", icon=":material/refresh:", help="Fetch live events now", width="stretch"):
        load_events.clear()
        st.rerun()
    st.markdown('<div class="cg-live">● API LIVE</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="cg-refresh-meta">Updated {refreshed_at.strftime("%H:%M:%S UTC")}</div>',
        unsafe_allow_html=True,
    )
if malformed_count:
    st.warning(f"Ignored {malformed_count} malformed event record(s) returned by the API.")

metric_columns = st.columns(6)
metric_values = [
    ("Events", metrics["events"]),
    ("High risk", metrics["high_risk"]),
    ("Failed logins", metrics["failures"]),
    ("Success rate", f'{metrics["success_rate"]}%' if metrics["success_rate"] is not None else "—"),
    ("Unique users", metrics["users"]),
    ("Source IPs", metrics["source_ips"]),
]
for column, (label, value) in zip(metric_columns, metric_values):
    column.metric(label, value)
st.caption(f"Metrics reflect {len(filtered)} event(s) matching the current sidebar filters.")

if page == "Overview":
    if filtered.empty:
        st.info("No events match the current filters. Adjust the filters or clear them to continue.")
    else:
        dashboard_columns = st.columns([0.95, 1.2, 1.05])
        severity_counts = filtered["_severity"].value_counts().rename_axis("Severity").reset_index(name="Events")
        severity_chart = px.pie(
            severity_counts,
            names="Severity",
            values="Events",
            hole=0.65,
            color="Severity",
            color_discrete_map=SEVERITY_COLORS,
            title="Alerts by severity",
            template="plotly_dark",
        )
        severity_chart.update_traces(textinfo="none", showlegend=True)
        severity_chart.add_annotation(
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            text=f"<b>{len(filtered)}</b><br><span style='font-size:10px'>TOTAL</span>",
            showarrow=False,
            align="center",
            font={"size": 19, "color": "#e7edf2"},
        )
        with dashboard_columns[0]:
            with st.container(border=True):
                st.plotly_chart(
                    make_chart_layout(severity_chart, height=260),
                    width="stretch",
                    config={"displayModeBar": False},
                )
                st.markdown("#### Login outcomes")
                status_counts = filtered["_status"].value_counts().rename_axis("Status").reset_index(name="Events")
                status_chart = px.pie(
                    status_counts,
                    names="Status",
                    values="Events",
                    hole=0.65,
                    color="Status",
                    color_discrete_map=STATUS_COLORS,
                    template="plotly_dark",
                )
                status_chart.update_traces(textinfo="none", showlegend=True)
                status_chart.add_annotation(
                    x=0.5,
                    y=0.5,
                    xref="paper",
                    yref="paper",
                    text=f"<b>{len(filtered)}</b><br><span style='font-size:10px'>EVENTS</span>",
                    showarrow=False,
                    align="center",
                    font={"size": 18, "color": "#e7edf2"},
                )
                st.plotly_chart(
                    make_chart_layout(status_chart, height=235),
                    width="stretch",
                    config={"displayModeBar": False},
                )

        timeline, interval = timeline_events(filtered)
        with dashboard_columns[1]:
            with st.container(border=True):
                st.markdown("#### Events over time")
                if not timeline.empty:
                    timeline_chart = px.area(
                        timeline,
                        x="timestamp",
                        y="events",
                        title=f"Activity · {interval.lower()}",
                        labels={"timestamp": "Time", "events": "Events"},
                        template="plotly_dark",
                    )
                    timeline_chart.update_traces(
                        line_color="#ef444d",
                        fillcolor="rgba(239,68,77,0.15)",
                        mode="lines+markers",
                        marker_size=6,
                    )
                    tick_count = min(len(timeline), 6)
                    tick_indexes = sorted(
                        {
                            round(index * (len(timeline) - 1) / max(tick_count - 1, 1))
                            for index in range(tick_count)
                        }
                    )
                    tick_rows = timeline.iloc[tick_indexes]
                    tick_labels = tick_rows["timestamp"].dt.strftime("%H:%M")
                    if tick_labels.duplicated().any():
                        tick_labels = tick_rows["timestamp"].dt.strftime("%H:%M:%S")
                    timeline_span = timeline["timestamp"].max() - timeline["timestamp"].min()
                    timeline_padding = max(timeline_span * 0.1, pd.Timedelta(seconds=30))
                    timeline_chart.update_xaxes(
                        tickmode="array",
                        tickvals=tick_rows["timestamp"].tolist(),
                        ticktext=tick_labels.tolist(),
                        range=[
                            (timeline["timestamp"].min() - timeline_padding).isoformat(),
                            (timeline["timestamp"].max() + timeline_padding).isoformat(),
                        ],
                        tickangle=0,
                        showgrid=False,
                    )
                    timeline_chart.update_yaxes(dtick=1, rangemode="tozero", gridcolor="#202c36")
                    st.plotly_chart(
                        make_chart_layout(timeline_chart, height=255),
                        width="stretch",
                        config={"displayModeBar": False},
                    )
                else:
                    st.info("No valid timestamps are available for the event timeline.")

                st.markdown("#### Top failed-login sources")
                noisy_ips = top_failed_ips(filtered)
                if noisy_ips.empty:
                    st.info("No failed login source IPs in this result set.")
                else:
                    st.dataframe(noisy_ips, width="stretch", hide_index=True, height=200)

        high_risk_events = filtered[filtered["_severity"].str.casefold().isin(["high", "critical"])]
        with dashboard_columns[2]:
            with st.container(border=True):
                st.markdown("#### Recent high-risk alerts")
                if high_risk_events.empty:
                    st.info("No high-risk events in this result set.")
                else:
                    for _, event in high_risk_events.head(5).iterrows():
                        severity = html.escape(safe_text(event.get("severity")) or "Unknown")
                        severity_color = SEVERITY_COLORS.get(safe_text(event.get("severity")), SEVERITY_COLORS["Unknown"])
                        message = html.escape(safe_text(event.get("message")) or "Login event")
                        username = html.escape(safe_text(event.get("username")) or "Unknown user")
                        ip_address = html.escape(safe_text(event.get("ip_address")) or "Unknown IP")
                        timestamp = event["_timestamp"]
                        time_label = timestamp.strftime("%H:%M UTC") if pd.notna(timestamp) else "Time unavailable"
                        st.markdown(
                            '<div class="cg-feed-row">'
                            f'<div class="cg-feed-title"><span style="color:{severity_color}">● {severity}</span> · {message}</div>'
                            f'<div class="cg-feed-meta">{username} · {ip_address} · {time_label}</div>'
                            '</div>',
                            unsafe_allow_html=True,
                        )

            with st.container(border=True):
                st.markdown("#### Detection context")
                context_event = high_risk_events.iloc[0] if not high_risk_events.empty else filtered.iloc[0]
                st.caption(
                    f'{safe_text(context_event.get("username")) or "Unknown user"} · '
                    f'{safe_text(context_event.get("ip_address")) or "Unknown IP"}'
                )
                explanation = html.escape(explain_event(context_event.to_dict()))
                st.markdown(f'<div class="cg-context">{explanation}</div>', unsafe_allow_html=True)

        bottom_columns = st.columns([1.65, 1])
        with bottom_columns[0]:
            with st.container(border=True):
                st.markdown("#### Recent activity")
                activity = event_table(filtered).head(12)
                activity = activity[["timestamp", "username", "ip_address", "status", "severity"]]
                st.dataframe(activity, width="stretch", hide_index=True, height=310)

        with bottom_columns[1]:
            with st.container(border=True):
                st.markdown("#### Event pipeline")
                st.caption("Existing CloudGuard request and storage path")
                pipeline = ["Login", "Lambda", "DynamoDB", "API", "UI"]
                pipeline_html = '<div class="cg-pipeline">'
                for index, step in enumerate(pipeline):
                    pipeline_html += f'<span class="cg-pipeline-step">{step}</span>'
                    if index < len(pipeline) - 1:
                        pipeline_html += '<span class="cg-pipeline-arrow">›</span>'
                pipeline_html += "</div>"
                st.markdown(pipeline_html, unsafe_allow_html=True)

        st.caption("Live API records · Severity labels are rule-based indicators, not proof of malicious activity.")

else:
    explorer_header = st.columns([3, 1])
    explorer_header[0].markdown("#### Event explorer")
    explorer_header[0].caption("Search, filter, inspect, and export matching live API records.")
    explorer_header[1].download_button(
        "Download filtered CSV",
        data=event_table(filtered).to_csv(index=False, columns=EVENT_COLUMNS).encode("utf-8"),
        file_name="cloudguard_filtered_events.csv",
        mime="text/csv; charset=utf-8",
        disabled=filtered.empty,
        width="stretch",
    )
    page_size = st.selectbox("Rows shown", [25, 50, 100], index=0)
    st.caption(f"Showing {min(page_size, len(filtered))} of {len(filtered)} matching events.")
    st.dataframe(event_table(filtered).head(page_size), width="stretch", hide_index=True, height=520)

    if not filtered.empty:
        event_options = filtered.to_dict("records")
        selected_index = st.selectbox(
            "Inspect event",
            options=range(len(event_options)),
            format_func=lambda index: (
                f'{safe_text(event_options[index].get("event_id")) or "Event"} · '
                f'{safe_text(event_options[index].get("username")) or "Unknown user"} · '
                f'{safe_text(event_options[index].get("severity")) or "Unknown"}'
            ),
        )
        selected_event = event_options[selected_index]
        st.markdown("#### Detection context")
        explanation = html.escape(explain_event(selected_event))
        st.markdown(f'<div class="cg-context">{explanation}</div>', unsafe_allow_html=True)
        message = safe_text(selected_event.get("message"))
        if message:
            st.write(message)
        detail_columns = st.columns(4)
        for column, (label, key) in zip(
            detail_columns,
            [("Event ID", "event_id"), ("Username", "username"), ("Source IP", "ip_address"), ("Status", "status")],
        ):
            column.caption(label)
            column.write(safe_text(selected_event.get(key)) or "Not provided")

st.markdown('<div class="cg-divider"></div>', unsafe_allow_html=True)
st.caption(
    "Educational prototype · Live events via configured API · Last successful refresh "
    f"{refreshed_at.strftime('%Y-%m-%d %H:%M:%S UTC')} · Detection labels are indicators, not proof of malicious activity."
)
