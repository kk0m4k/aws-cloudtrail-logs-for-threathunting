import streamlit as st
import pandas as pd
from datetime import datetime

from utils.api_client import get_api_client
from components.charts import (
    create_time_series_chart, create_pie_chart, create_bar_chart,
    create_gauge_chart, create_timeline_chart
)
from components.tables import render_log_table
from components.filters import render_time_filter

st.set_page_config(page_title="Initial Access - CloudTrail Dashboard", layout="wide")

st.title("🚪 Initial Access")
st.markdown("""
Analysis of Initial Access tactics based on MITRE ATT&CK framework.
Includes techniques: **T1078.004** (Valid Accounts) and **T1190** (Exploit Public-Facing Application)
""")

# Initialize API client
client = get_api_client()

# Time filter
with st.sidebar:
    st.subheader("Filters")
    start_time, end_time = render_time_filter("initial_access")

# Fetch data for Initial Access techniques
with st.spinner("Loading Initial Access data..."):
    # T1078.004 - Valid Accounts
    valid_accounts_analytics = client.get_technique_analytics("T1078.004")
    valid_accounts_logs = client.get_technique_logs("T1078.004", limit=100)
    
    # T1190 - Exploit Public-Facing Application
    exploit_analytics = client.get_technique_analytics("T1190")
    exploit_logs = client.get_technique_logs("T1190", limit=100)

# Overview metrics
st.subheader("📊 Initial Access Overview")
col1, col2, col3, col4 = st.columns(4)

total_events = 0
unique_users = 0
unique_ips = 0

if valid_accounts_analytics:
    total_events += valid_accounts_analytics.get('total_events', 0)
    unique_users += valid_accounts_analytics.get('unique_users', 0)
    unique_ips += valid_accounts_analytics.get('unique_ips', 0)

if exploit_analytics:
    total_events += exploit_analytics.get('total_events', 0)
    unique_users += exploit_analytics.get('unique_users', 0)
    unique_ips += exploit_analytics.get('unique_ips', 0)

with col1:
    st.metric("Total Events", f"{total_events:,}")

with col2:
    st.metric("Unique Users", unique_users)

with col3:
    st.metric("Unique IPs", unique_ips)

with col4:
    avg_risk = 0
    count = 0
    if valid_accounts_analytics:
        avg_risk += valid_accounts_analytics.get('risk_score', 0)
        count += 1
    if exploit_analytics:
        avg_risk += exploit_analytics.get('risk_score', 0)
        count += 1
    if count > 0:
        avg_risk = avg_risk / count
    st.metric("Avg Risk Score", f"{avg_risk:.1f}/10")

# Technique Analysis Tabs
tab1, tab2, tab3 = st.tabs([
    "T1078.004 - Valid Accounts",
    "T1190 - Exploit Public-Facing",
    "Combined Analysis"
])

with tab1:
    st.subheader("Valid Accounts - Compromised Credentials")
    
    if valid_accounts_analytics:
        # Risk gauge
        col1, col2 = st.columns([1, 2])
        
        with col1:
            fig = create_gauge_chart(
                valid_accounts_analytics.get('risk_score', 0),
                title="Risk Score"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown(f"""
            **Use Case**: {valid_accounts_analytics.get('usecase', 'N/A')}
            
            **Description**: {valid_accounts_analytics.get('description', 'N/A')}
            
            **Key Indicators**:
            - Access from unusual geographic locations
            - Failed authentication attempts followed by success
            - Access at abnormal times
            - Use of TOR/VPN networks
            """)
        
        # Event breakdown
        col1, col2 = st.columns(2)
        
        with col1:
            if valid_accounts_analytics.get('event_breakdown'):
                fig = create_pie_chart(
                    valid_accounts_analytics['event_breakdown'],
                    title="Event Types"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if valid_accounts_analytics.get('geographic_distribution'):
                fig = create_pie_chart(
                    valid_accounts_analytics['geographic_distribution'],
                    title="Geographic Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # Timeline
        if valid_accounts_analytics.get('time_distribution'):
            st.subheader("Timeline Analysis")
            fig = create_time_series_chart(
                valid_accounts_analytics['time_distribution'],
                title="Valid Account Abuse Over Time"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Sample logs
        st.subheader("Sample Logs")
        if valid_accounts_logs:
            render_log_table(valid_accounts_logs[:10])
        else:
            st.info("No logs found for this technique")
    else:
        st.info("No data available for T1078.004")

with tab2:
    st.subheader("Exploit Public-Facing Application - EKS Exposure")
    
    if exploit_analytics:
        # Risk gauge
        col1, col2 = st.columns([1, 2])
        
        with col1:
            fig = create_gauge_chart(
                exploit_analytics.get('risk_score', 0),
                title="Risk Score"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown(f"""
            **Use Case**: {exploit_analytics.get('usecase', 'N/A')}
            
            **Description**: {exploit_analytics.get('description', 'N/A')}
            
            **Key Indicators**:
            - UpdateClusterConfig events
            - endpointPublicAccess changed to true
            - publicAccessCidrs containing 0.0.0.0/0
            - Unauthorized configuration changes
            """)
        
        # Event analysis
        if exploit_logs:
            st.subheader("EKS Configuration Changes")
            
            # Extract EKS specific data
            eks_changes = []
            for log in exploit_logs:
                if log.get('eventName') == 'UpdateClusterConfig':
                    eks_changes.append({
                        "Time": log.get('eventTime', ''),
                        "User": log.get('userIdentity', {}).get('userName', 'Unknown'),
                        "Cluster": log.get('requestParameters', {}).get('name', 'Unknown'),
                        "Public Access": log.get('requestParameters', {}).get('resourcesVpcConfig', {}).get('endpointPublicAccess', False),
                        "CIDRs": ', '.join(log.get('requestParameters', {}).get('resourcesVpcConfig', {}).get('publicAccessCidrs', []))
                    })
            
            if eks_changes:
                df = pd.DataFrame(eks_changes)
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                # Highlight risky configurations
                risky_configs = [change for change in eks_changes if '0.0.0.0/0' in change['CIDRs']]
                if risky_configs:
                    st.error(f"⚠️ Found {len(risky_configs)} EKS clusters with public access from 0.0.0.0/0")
        
        # Sample logs
        st.subheader("Sample Logs")
        if exploit_logs:
            render_log_table(exploit_logs[:10])
        else:
            st.info("No logs found for this technique")
    else:
        st.info("No data available for T1190")

with tab3:
    st.subheader("Combined Initial Access Analysis")
    
    # Combined timeline
    all_logs = []
    if valid_accounts_logs:
        all_logs.extend(valid_accounts_logs[:50])
    if exploit_logs:
        all_logs.extend(exploit_logs[:50])
    
    if all_logs:
        # Sort by time
        all_logs.sort(key=lambda x: x.get('eventTime', ''), reverse=True)
        
        # Create timeline
        st.subheader("Combined Event Timeline")
        fig = create_timeline_chart(all_logs[:20], title="Initial Access Events")
        st.plotly_chart(fig, use_container_width=True)
        
        # Geographic analysis
        st.subheader("Geographic Analysis")
        
        # Extract IPs and categorize
        ip_categories = {"Internal": 0, "External": 0, "VPN/TOR": 0}
        suspicious_ips = []
        
        for log in all_logs:
            ip = log.get('sourceIPAddress', '')
            if ip.startswith(('10.', '172.', '192.168.')):
                ip_categories["Internal"] += 1
            elif ip.startswith(('23.129.64.', '162.247.74.', '185.220.101.', '209.58.188.', '45.32.')):
                ip_categories["VPN/TOR"] += 1
                suspicious_ips.append({
                    "IP": ip,
                    "User": log.get('userIdentity', {}).get('userName', 'Unknown'),
                    "Event": log.get('eventName', ''),
                    "Time": log.get('eventTime', '')
                })
            else:
                ip_categories["External"] += 1
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig = create_pie_chart(ip_categories, title="IP Categories")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if suspicious_ips:
                st.warning(f"⚠️ Found {len(suspicious_ips)} events from VPN/TOR exit nodes")
                with st.expander("View Suspicious IPs"):
                    st.dataframe(pd.DataFrame(suspicious_ips), use_container_width=True, hide_index=True)
        
        # User behavior analysis
        st.subheader("User Behavior Analysis")
        
        user_events = {}
        for log in all_logs:
            user = log.get('userIdentity', {}).get('userName', 'Unknown')
            if user not in user_events:
                user_events[user] = {
                    "events": [],
                    "ips": set(),
                    "event_types": set()
                }
            user_events[user]["events"].append(log)
            user_events[user]["ips"].add(log.get('sourceIPAddress', ''))
            user_events[user]["event_types"].add(log.get('eventName', ''))
        
        # Find suspicious users
        suspicious_users = []
        for user, data in user_events.items():
            if len(data["ips"]) > 3:  # Multiple IPs
                suspicious_users.append({
                    "User": user,
                    "Unique IPs": len(data["ips"]),
                    "Event Types": len(data["event_types"]),
                    "Total Events": len(data["events"])
                })
        
        if suspicious_users:
            st.warning("Users with suspicious activity patterns:")
            st.dataframe(pd.DataFrame(suspicious_users), use_container_width=True, hide_index=True)
    else:
        st.info("No logs available for combined analysis")

# Recommendations
st.markdown("---")
st.subheader("🛡️ Security Recommendations")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    **For Valid Account Protection:**
    - Enable MFA for all IAM users
    - Implement IP allowlisting for sensitive accounts
    - Monitor for impossible travel scenarios
    - Alert on access from TOR/VPN services
    - Review and rotate access keys regularly
    """)

with col2:
    st.markdown("""
    **For EKS Security:**
    - Keep EKS API endpoints private when possible
    - Use specific CIDR ranges instead of 0.0.0.0/0
    - Enable EKS audit logging
    - Use RBAC for fine-grained access control
    - Monitor UpdateClusterConfig events
    """)

# Footer
st.markdown("---")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")