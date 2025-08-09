import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.graph_objects as go

from utils.api_client import get_api_client
from components.charts import (
    create_time_series_chart, create_scatter_plot, 
    create_heatmap, create_bar_chart
)
from components.tables import render_anomaly_table
from components.filters import render_slider_filter

st.set_page_config(page_title="Analytics - CloudTrail Dashboard", layout="wide")

st.title("🤖 ML Analytics & Insights")
st.markdown("Machine Learning-powered analysis of CloudTrail logs for advanced threat detection.")

# Initialize API client
client = get_api_client()

# Sidebar controls
with st.sidebar:
    st.subheader("Analytics Controls")
    
    # Time window for anomaly detection
    time_window = render_slider_filter(
        "Anomaly Detection Window (hours)",
        min_value=1,
        max_value=168,
        default=24,
        step=1,
        key="anomaly_window"
    )
    
    # Refresh button
    if st.button("🔄 Refresh Analytics"):
        st.experimental_rerun()

# Main content tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "🚨 Anomaly Detection",
    "📊 Behavioral Analysis", 
    "🔬 Pattern Discovery",
    "📈 Predictive Insights"
])

with tab1:
    st.header("Anomaly Detection")
    
    with st.spinner("Detecting anomalies..."):
        anomalies = client.get_anomalies(time_window_hours=time_window)
    
    if anomalies:
        # Anomaly summary
        col1, col2, col3, col4 = st.columns(4)
        
        severity_counts = {}
        anomaly_types = {}
        
        for anomaly in anomalies:
            # Count by severity
            severity = anomaly.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            atype = anomaly.get('anomaly_type', 'unknown')
            anomaly_types[atype] = anomaly_types.get(atype, 0) + 1
        
        with col1:
            st.metric("Total Anomalies", len(anomalies))
        
        with col2:
            critical_count = severity_counts.get('critical', 0)
            st.metric(
                "Critical Severity",
                critical_count,
                delta=f"{critical_count/len(anomalies)*100:.0f}%" if anomalies else "0%",
                delta_color="inverse"
            )
        
        with col3:
            high_count = severity_counts.get('high', 0)
            st.metric(
                "High Severity",
                high_count,
                delta=f"{high_count/len(anomalies)*100:.0f}%" if anomalies else "0%",
                delta_color="inverse"
            )
        
        with col4:
            unique_types = len(anomaly_types)
            st.metric("Anomaly Types", unique_types)
        
        # Anomaly visualizations
        col1, col2 = st.columns(2)
        
        with col1:
            # Severity distribution
            severity_df = pd.DataFrame([
                {"Severity": k.title(), "Count": v}
                for k, v in severity_counts.items()
            ])
            fig = create_bar_chart(
                severity_df.to_dict('records'),
                x_field="Severity",
                y_field="Count",
                title="Anomalies by Severity"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Type distribution
            type_df = pd.DataFrame([
                {"Type": k.replace('_', ' ').title(), "Count": v}
                for k, v in anomaly_types.items()
            ])
            fig = create_bar_chart(
                type_df.to_dict('records'),
                x_field="Type",
                y_field="Count",
                title="Anomalies by Type"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Anomaly timeline
        st.subheader("Anomaly Timeline")
        
        # Group anomalies by hour
        timeline_data = {}
        for anomaly in anomalies:
            timestamp = anomaly.get('timestamp', '')
            if timestamp:
                # Convert to timezone-naive datetime for consistent comparison
                dt = pd.to_datetime(timestamp)
                if dt.tz is not None:
                    dt = dt.tz_localize(None)
                hour = dt.replace(minute=0, second=0, microsecond=0)
                timeline_data[hour] = timeline_data.get(hour, 0) + 1
        
        if timeline_data:
            timeline_df = pd.DataFrame([
                {"timestamp": k, "count": v}
                for k, v in sorted(timeline_data.items(), key=lambda x: x[0])
            ])
            fig = create_time_series_chart(
                timeline_df.to_dict('records'),
                title=f"Anomalies Over Last {time_window} Hours"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Detailed anomaly table
        st.subheader("Anomaly Details")
        render_anomaly_table(anomalies)
        
    else:
        st.success(f"No anomalies detected in the last {time_window} hours")

with tab2:
    st.header("Behavioral Analysis")
    
    # User behavior analysis
    st.subheader("User Behavior Patterns")
    
    with st.spinner("Analyzing user behavior..."):
        # Get logs for behavior analysis
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        behavior_logs = client.get_logs(
            start_time=start_time,
            end_time=end_time,
            limit=1000
        )
    
    if behavior_logs and 'items' in behavior_logs:
        logs = behavior_logs['items']
        
        # Analyze user patterns
        user_patterns = {}
        for log in logs:
            user = log.get('userIdentity', {}).get('userName', 'Unknown')
            if user not in user_patterns:
                user_patterns[user] = {
                    'events': [],
                    'ips': set(),
                    'regions': set(),
                    'hours': []
                }
            
            user_patterns[user]['events'].append(log.get('eventName', ''))
            user_patterns[user]['ips'].add(log.get('sourceIPAddress', ''))
            user_patterns[user]['regions'].add(log.get('awsRegion', ''))
            
            # Extract hour
            event_time = log.get('eventTime', '')
            if event_time:
                hour = pd.to_datetime(event_time).hour
                user_patterns[user]['hours'].append(hour)
        
        # Create user behavior metrics
        user_metrics = []
        for user, patterns in user_patterns.items():
            if len(patterns['events']) > 5:  # Only show active users
                user_metrics.append({
                    'User': user,
                    'Total Events': len(patterns['events']),
                    'Unique IPs': len(patterns['ips']),
                    'Unique Regions': len(patterns['regions']),
                    'Unique Events': len(set(patterns['events'])),
                    'Avg Hour': sum(patterns['hours']) / len(patterns['hours']) if patterns['hours'] else 0
                })
        
        if user_metrics:
            # Sort by total events
            user_metrics.sort(key=lambda x: x['Total Events'], reverse=True)
            
            # Display top users
            st.subheader("Most Active Users (Last 24 Hours)")
            user_df = pd.DataFrame(user_metrics[:10])
            st.dataframe(user_df, use_container_width=True, hide_index=True)
            
            # Scatter plot: Events vs Unique IPs
            fig = create_scatter_plot(
                user_metrics,
                x_field='Total Events',
                y_field='Unique IPs',
                title="User Activity Pattern: Events vs IP Diversity"
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Activity heatmap
            st.subheader("User Activity Heatmap")
            
            # Create hour-based heatmap
            heatmap_data = {}
            for user, patterns in list(user_patterns.items())[:20]:  # Top 20 users
                hour_counts = {}
                for hour in patterns['hours']:
                    hour_counts[hour] = hour_counts.get(hour, 0) + 1
                heatmap_data[user] = hour_counts
            
            if heatmap_data:
                # Convert to proper format
                hours = list(range(24))
                heatmap_matrix = []
                users = []
                
                for user, hour_data in heatmap_data.items():
                    users.append(user)
                    row = [hour_data.get(h, 0) for h in hours]
                    heatmap_matrix.append(row)
                
                fig = go.Figure(data=go.Heatmap(
                    z=heatmap_matrix,
                    x=[f"{h:02d}:00" for h in hours],
                    y=users,
                    colorscale='RdYlBu_r'
                ))
                
                fig.update_layout(
                    title="User Activity by Hour (UTC)",
                    xaxis_title="Hour of Day",
                    yaxis_title="User",
                    height=600
                )
                
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No behavioral data available")

with tab3:
    st.header("Pattern Discovery")
    
    # Attack pattern analysis
    st.subheader("Attack Pattern Analysis")
    
    with st.spinner("Discovering patterns..."):
        techniques = client.get_techniques()
    
    if techniques:
        # Create pattern visualization
        pattern_data = []
        for tech in techniques:
            pattern_data.append({
                'Technique': tech['id'],
                'Name': tech['name'],
                'Count': tech['count'],
                'Category': tech['id'].split('.')[0]  # Extract main category
            })
        
        # Sunburst chart would be ideal here, but using bar chart for simplicity
        fig = create_bar_chart(
            pattern_data,
            x_field='Technique',
            y_field='Count',
            title='Attack Technique Frequency'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Pattern correlations
        st.subheader("Technique Correlations")
        
        # Get time series for top techniques
        top_techniques = techniques[:5]
        correlation_data = {}
        
        for tech in top_techniques:
            ts_data = client.get_timeseries(
                technique_ids=[tech['id']],
                granularity='hour',
                start_time=datetime.utcnow() - timedelta(days=7),
                end_time=datetime.utcnow()
            )
            
            if ts_data:
                correlation_data[tech['id']] = {
                    'name': tech['name'],
                    'data': ts_data
                }
        
        if correlation_data:
            st.write("Time series correlation between top attack techniques:")
            
            # Create multi-line chart
            fig = go.Figure()
            
            for tech_id, tech_data in correlation_data.items():
                df = pd.DataFrame(tech_data['data'])
                fig.add_trace(go.Scatter(
                    x=pd.to_datetime(df['timestamp']),
                    y=df['count'],
                    mode='lines+markers',
                    name=f"{tech_id} - {tech_data['name']}"
                ))
            
            fig.update_layout(
                title="Attack Technique Patterns Over Time",
                xaxis_title="Time",
                yaxis_title="Event Count",
                hovermode='x unified'
            )
            
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No pattern data available")

with tab4:
    st.header("Predictive Insights")
    
    st.info("🚧 Predictive analytics features coming soon!")
    
    st.markdown("""
    **Planned Features:**
    - Risk score predictions
    - Attack likelihood forecasting
    - Resource usage predictions
    - Threat trend analysis
    - Automated recommendations
    
    These features will use advanced ML models to predict future security events
    based on historical patterns.
    """)
    
    # Show current risk assessment
    st.subheader("Current Risk Assessment")
    
    with st.spinner("Calculating risk scores..."):
        techniques = client.get_techniques()
        
        if techniques:
            # Calculate overall risk
            total_malicious = sum(t['count'] for t in techniques)
            risk_factors = []
            
            # Factor 1: Volume of attacks
            if total_malicious > 10000:
                risk_factors.append(("High attack volume", 3))
            elif total_malicious > 1000:
                risk_factors.append(("Moderate attack volume", 2))
            else:
                risk_factors.append(("Low attack volume", 1))
            
            # Factor 2: Diversity of attacks
            if len(techniques) > 10:
                risk_factors.append(("High attack diversity", 3))
            elif len(techniques) > 5:
                risk_factors.append(("Moderate attack diversity", 2))
            else:
                risk_factors.append(("Low attack diversity", 1))
            
            # Factor 3: Critical techniques present
            critical_techniques = ['T1485', 'T1496', 'T1562.001']
            critical_present = [t for t in techniques if t['id'] in critical_techniques]
            if critical_present:
                risk_factors.append(("Critical techniques detected", 4))
            
            # Calculate overall risk
            total_risk = sum(score for _, score in risk_factors)
            max_risk = 10
            risk_percentage = (total_risk / max_risk) * 100
            
            # Display risk assessment
            col1, col2 = st.columns([1, 2])
            
            with col1:
                # Risk gauge
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=risk_percentage,
                    title={'text': "Overall Risk Score"},
                    domain={'x': [0, 1], 'y': [0, 1]},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkred" if risk_percentage > 70 else "orange" if risk_percentage > 40 else "green"},
                        'steps': [
                            {'range': [0, 40], 'color': "lightgreen"},
                            {'range': [40, 70], 'color': "yellow"},
                            {'range': [70, 100], 'color': "lightcoral"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 90
                        }
                    }
                ))
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.subheader("Risk Factors")
                for factor, score in risk_factors:
                    severity = "🔴" if score >= 3 else "🟡" if score >= 2 else "🟢"
                    st.write(f"{severity} {factor} (Score: {score})")
                
                st.markdown("---")
                
                if risk_percentage > 70:
                    st.error("⚠️ **HIGH RISK**: Immediate action recommended")
                    st.markdown("""
                    **Recommendations:**
                    - Review and disable compromised accounts
                    - Enable additional monitoring
                    - Implement stricter access controls
                    - Investigate critical events immediately
                    """)
                elif risk_percentage > 40:
                    st.warning("⚠️ **MODERATE RISK**: Enhanced monitoring advised")
                    st.markdown("""
                    **Recommendations:**
                    - Review security policies
                    - Monitor suspicious activities closely
                    - Update security configurations
                    - Plan security improvements
                    """)
                else:
                    st.success("✅ **LOW RISK**: System appears secure")
                    st.markdown("""
                    **Recommendations:**
                    - Maintain current security posture
                    - Continue regular monitoring
                    - Keep security tools updated
                    - Conduct periodic reviews
                    """)

# Footer
st.markdown("---")
st.caption(f"Analytics last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")