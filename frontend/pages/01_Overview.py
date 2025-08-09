import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

from utils.api_client import get_api_client
from components.charts import (
    create_time_series_chart, create_pie_chart, create_bar_chart,
    display_metric_cards, create_heatmap
)
from components.tables import render_statistics_table, render_technique_table

st.set_page_config(page_title="Overview - CloudTrail Dashboard", layout="wide")

st.title("📊 Overview Dashboard")
st.markdown("Real-time overview of CloudTrail security events and threat detection metrics.")

# Initialize API client
client = get_api_client()

# Fetch statistics
with st.spinner("Loading dashboard data..."):
    stats = client.get_statistics()
    techniques = client.get_techniques()
    
    if not stats or not techniques:
        st.error("Failed to load data from API. Please check if the backend server is running.")
        st.stop()
    
    # Get time series data for last 7 days
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    timeseries_all = client.get_timeseries(
        granularity="day",
        start_time=start_time,
        end_time=end_time
    )
    
    timeseries_malicious = client.get_timeseries(
        granularity="day",
        start_time=start_time,
        end_time=end_time,
        is_malicious=True
    )

if not stats:
    st.error("Unable to fetch statistics. Please ensure the API is running.")
    st.stop()

# Key Metrics
st.subheader("🎯 Key Metrics")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total Events",
        f"{stats.get('total_logs', 0):,}",
        delta="Last 7 days"
    )

with col2:
    st.metric(
        "Malicious Events",
        f"{stats.get('malicious_logs', 0):,}",
        delta=f"{stats.get('malicious_logs', 0) / stats.get('total_logs', 1) * 100:.1f}%",
        delta_color="inverse"
    )

with col3:
    st.metric(
        "Unique Techniques",
        len(stats.get('malicious_breakdown', {})),
        help="Number of unique MITRE ATT&CK techniques detected"
    )

with col4:
    if stats.get('time_range', {}).get('start') and stats.get('time_range', {}).get('end'):
        start_time = datetime.fromisoformat(stats['time_range']['start'].replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(stats['time_range']['end'].replace('Z', '+00:00'))
        days_covered = (end_time - start_time).days
        st.metric(
            "Days Covered",
            days_covered,
            help="Time span of the dataset"
        )
    else:
        st.metric("Days Covered", "N/A")

# Charts Row 1
st.markdown("---")
col1, col2 = st.columns(2)

with col1:
    st.subheader("📈 Event Timeline")
    if timeseries_all:
        # Combine normal and malicious timeseries
        df_all = pd.DataFrame(timeseries_all)
        df_mal = pd.DataFrame(timeseries_malicious)
        
        if not df_mal.empty:
            df_mal['category'] = 'Malicious'
            df_all['category'] = 'Total'
            
            fig = create_time_series_chart(
                timeseries_all,
                title="Events Over Time (7 Days)"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No time series data available")
    else:
        st.info("No time series data available")

with col2:
    st.subheader("🍩 Event Distribution")
    event_dist = {
        "Malicious": stats.get('malicious_logs', 0),
        "Normal": stats.get('normal_logs', 0)
    }
    fig = create_pie_chart(event_dist, title="Malicious vs Normal Events")
    st.plotly_chart(fig, use_container_width=True)

# Charts Row 2
col1, col2 = st.columns(2)

with col1:
    st.subheader("🎯 Top MITRE ATT&CK Techniques")
    if techniques:
        # Show top 10 techniques
        top_techniques = techniques[:10]
        fig = create_bar_chart(
            top_techniques,
            x_field="id",
            y_field="count",
            title="Top 10 Attack Techniques"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No technique data available")

with col2:
    st.subheader("🌍 Geographic Distribution")
    if stats.get('regions'):
        fig = create_pie_chart(
            stats['regions'],
            title="Events by AWS Region"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No geographic data available")

# Detailed Tables
st.markdown("---")
st.subheader("📊 Detailed Statistics")

tab1, tab2, tab3 = st.tabs(["Summary", "Techniques", "Top Users & IPs"])

with tab1:
    render_statistics_table(stats)
    
    # Show malicious breakdown
    if stats.get('malicious_breakdown'):
        st.subheader("Malicious Event Breakdown")
        breakdown_df = pd.DataFrame([
            {"Technique ID": k, "Count": v, "Percentage": f"{v/stats.get('malicious_logs', 1)*100:.1f}%"}
            for k, v in stats['malicious_breakdown'].items()
        ])
        st.dataframe(breakdown_df, use_container_width=True, hide_index=True)

with tab2:
    if techniques:
        render_technique_table(techniques)
    else:
        st.info("No technique data available")

with tab3:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Top Users")
        if stats.get('top_users'):
            users_df = pd.DataFrame(stats['top_users'])
            st.dataframe(users_df, use_container_width=True, hide_index=True)
        else:
            st.info("No user data available")
    
    with col2:
        st.subheader("Top Source IPs")
        if stats.get('top_ips'):
            ips_df = pd.DataFrame(stats['top_ips'])
            st.dataframe(ips_df, use_container_width=True, hide_index=True)
        else:
            st.info("No IP data available")

# Recent Anomalies
st.markdown("---")
st.subheader("🚨 Recent Anomalies")

with st.spinner("Checking for anomalies..."):
    anomalies = client.get_anomalies(time_window_hours=24)

if anomalies:
    # Group by severity
    severity_counts = {}
    for anomaly in anomalies:
        severity = anomaly.get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Display severity metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Critical", severity_counts.get('critical', 0), delta_color="inverse")
    with col2:
        st.metric("High", severity_counts.get('high', 0), delta_color="inverse")
    with col3:
        st.metric("Medium", severity_counts.get('medium', 0))
    with col4:
        st.metric("Low", severity_counts.get('low', 0))
    
    # Show recent anomalies
    st.write("Latest Anomalies (Last 24 Hours):")
    anomaly_data = []
    for anomaly in anomalies[:5]:  # Show top 5
        anomaly_data.append({
            "Time": anomaly.get('timestamp', ''),
            "Severity": anomaly.get('severity', ''),
            "Type": anomaly.get('anomaly_type', ''),
            "Description": anomaly.get('description', '')
        })
    
    if anomaly_data:
        anomaly_df = pd.DataFrame(anomaly_data)
        st.dataframe(anomaly_df, use_container_width=True, hide_index=True)
else:
    st.success("No anomalies detected in the last 24 hours")

# Quick Actions
st.markdown("---")
st.subheader("⚡ Quick Actions")

col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("🔄 Refresh Data"):
        st.experimental_rerun()

with col2:
    if st.button("🧹 Clear Cache"):
        if client.clear_cache():
            st.success("Cache cleared successfully")
        else:
            st.error("Failed to clear cache")

with col3:
    if st.button("📊 View All Logs", type="primary"):
        st.switch_page("pages/11_Log_Explorer.py")

with col4:
    if st.button("🤖 ML Analytics", type="primary"):
        st.switch_page("pages/12_Analytics.py")

# Footer
st.markdown("---")
st.caption(f"Dashboard last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")