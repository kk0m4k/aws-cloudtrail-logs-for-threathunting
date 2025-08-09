import streamlit as st
from datetime import datetime

from utils.api_client import get_api_client
from components.charts import (
    create_time_series_chart, create_pie_chart, create_gauge_chart
)
from components.tables import render_log_table

st.set_page_config(page_title="Persistence - CloudTrail Dashboard", layout="wide")

st.title("🔒 Persistence")
st.markdown("""
Analysis of Persistence tactics based on MITRE ATT&CK framework.
Technique: **T1098** (Account Manipulation)
""")

client = get_api_client()

with st.spinner("Loading Persistence data..."):
    analytics = client.get_technique_analytics("T1098")
    logs = client.get_technique_logs("T1098", limit=100)

if analytics:
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events", f"{analytics.get('total_events', 0):,}")
    with col2:
        st.metric("Unique Users", analytics.get('unique_users', 0))
    with col3:
        st.metric("Unique IPs", analytics.get('unique_ips', 0))
    with col4:
        fig = create_gauge_chart(analytics.get('risk_score', 0), title="Risk Score")
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown(f"""
    **Use Cases**:
    - Create New IAM User for Backdoor Access
    - Modify IAM Role Trust Policy
    - Low and Slow Periodic Access
    
    **Description**: {analytics.get('description', 'N/A')}
    """)
    
    if analytics.get('time_distribution'):
        fig = create_time_series_chart(
            analytics['time_distribution'],
            title="Persistence Events Over Time"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    if logs:
        st.subheader("Sample Logs")
        render_log_table(logs[:20])
else:
    st.info("No data available for Persistence tactics")