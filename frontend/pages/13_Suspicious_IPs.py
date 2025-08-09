import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
import requests

from utils.api_client import get_api_client
from components.charts import create_bar_chart, create_pie_chart, create_time_series_chart
from components.tables import render_logs_table
from components.filters import render_time_filter

st.set_page_config(page_title="Suspicious IP Analysis - CloudTrail Dashboard", layout="wide")

st.title("🌐 Suspicious IP Analysis")
st.markdown("Monitor and analyze access from TOR exit nodes, VPN services, and high-risk countries.")

# Initialize API client
client = get_api_client()

# Known TOR exit nodes (sample list - in production, this would be fetched from a TOR exit node list API)
TOR_EXIT_NODES = [
    "185.220.101.",  # TOR prefix
    "23.129.64.",    # TOR prefix
    "162.247.74.",   # TOR prefix
    "209.58.188.",   # TOR prefix
    "45.32.225.",    # TOR prefix
]

# Known VPN IP ranges (sample list)
VPN_RANGES = [
    "10.8.",         # Common OpenVPN range
    "172.16.",       # Common VPN range
    "192.168.",      # Common VPN range
]

# High-risk countries (based on cybersecurity threat intelligence)
RISKY_COUNTRIES = {
    "211.": "North Korea",
    "185.220.": "Russia/Eastern Europe",
    "162.247.": "Anonymous Proxy",
    "23.129.": "TOR Network",
    "45.32.": "VPS Provider (Often abused)",
}

def classify_ip(ip: str) -> dict:
    """Classify an IP address as TOR, VPN, or from a risky country"""
    classification = {
        "is_tor": False,
        "is_vpn": False,
        "is_risky_country": False,
        "risk_type": "Normal",
        "risk_level": "Low"
    }
    
    # Check TOR
    for tor_prefix in TOR_EXIT_NODES:
        if ip.startswith(tor_prefix):
            classification["is_tor"] = True
            classification["risk_type"] = "TOR Exit Node"
            classification["risk_level"] = "High"
            return classification
    
    # Check VPN
    for vpn_prefix in VPN_RANGES:
        if ip.startswith(vpn_prefix):
            classification["is_vpn"] = True
            classification["risk_type"] = "VPN Service"
            classification["risk_level"] = "Medium"
            return classification
    
    # Check risky countries
    for prefix, country in RISKY_COUNTRIES.items():
        if ip.startswith(prefix):
            classification["is_risky_country"] = True
            classification["risk_type"] = f"Risky Country ({country})"
            classification["risk_level"] = "High" if "Korea" in country or "TOR" in country else "Medium"
            return classification
    
    return classification

# Sidebar filters
with st.sidebar:
    st.header("Filters")
    
    # Risk type filter
    risk_types = st.multiselect(
        "Risk Type",
        ["TOR Exit Node", "VPN Service", "Risky Country"],
        default=["TOR Exit Node", "VPN Service", "Risky Country"]
    )
    
    # Time filter
    start_time, end_time = render_time_filter("suspicious_ip")
    
    # Risk level filter
    risk_levels = st.multiselect(
        "Risk Level",
        ["High", "Medium", "Low"],
        default=["High", "Medium"]
    )

# Fetch suspicious IPs data
try:
    with st.spinner("Analyzing IP addresses..."):
        # Make direct API call
        params = {
            "limit": 1000,
            "offset": 0
        }
        
        if start_time:
            params["start_time"] = start_time.isoformat()
        if end_time:
            params["end_time"] = end_time.isoformat()
        if risk_types:
            params["risk_types"] = risk_types
        
        # Get base URL from client
        base_url = client.base_url
        api_response = requests.get(f"{base_url}/api/suspicious-ips", params=params)
        api_response.raise_for_status()
        response = api_response.json()
        
        # Extract data from response
        suspicious_ips_data = response.get('suspicious_ips', [])
        suspicious_logs = response.get('recent_logs', [])
        risk_breakdown = response.get('risk_type_breakdown', {})
        
        # Convert to the format expected by the visualizations
        ip_analysis = {}
        for ip_data in suspicious_ips_data:
            ip = ip_data['ip']
            ip_analysis[ip] = {
                'count': ip_data['event_count'],
                'classification': {
                    'risk_type': ip_data['risk_info']['type'],
                    'risk_level': ip_data['risk_info']['level'],
                    'is_tor': 'TOR' in ip_data['risk_info']['type'],
                    'is_vpn': 'VPN' in ip_data['risk_info']['type'],
                    'is_risky_country': 'Country' in ip_data['risk_info']['type']
                },
                'events': ip_data['events'],
                'users': set(ip_data['users'])
            }

    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Suspicious IPs",
            len(ip_analysis),
            help="Unique IPs identified as suspicious"
        )
    
    with col2:
        tor_count = sum(1 for ip_data in ip_analysis.values() if ip_data['classification']['is_tor'])
        st.metric(
            "TOR Exit Nodes",
            tor_count,
            help="IPs identified as TOR exit nodes"
        )
    
    with col3:
        vpn_count = sum(1 for ip_data in ip_analysis.values() if ip_data['classification']['is_vpn'])
        st.metric(
            "VPN Services",
            vpn_count,
            help="IPs identified as VPN services"
        )
    
    with col4:
        risky_country_count = sum(1 for ip_data in ip_analysis.values() if ip_data['classification']['is_risky_country'])
        st.metric(
            "Risky Countries",
            risky_country_count,
            help="IPs from high-risk countries"
        )

    # Risk Distribution Chart
    if ip_analysis:
        st.subheader("Risk Distribution")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk type distribution
            risk_type_data = {}
            for ip_data in ip_analysis.values():
                risk_type = ip_data['classification']['risk_type']
                risk_type_data[risk_type] = risk_type_data.get(risk_type, 0) + ip_data['count']
            
            fig = create_pie_chart(
                risk_type_data,
                title="Access by Risk Type"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Top suspicious IPs
            top_ips = sorted(ip_analysis.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
            
            fig = create_bar_chart(
                [{"name": ip, "value": data['count']} for ip, data in top_ips],
                x_field="name",
                y_field="value",
                title="Top 10 Suspicious IPs",
                orientation="h"
            )
            st.plotly_chart(fig, use_container_width=True)

    # Timeline of suspicious access
    if suspicious_logs:
        st.subheader("Suspicious Access Timeline")
        
        # Group by hour
        timeline_data = {}
        for log in suspicious_logs:
            timestamp = log.get('eventTime', '')
            if timestamp:
                hour = pd.to_datetime(timestamp).replace(minute=0, second=0, microsecond=0)
                if hour.tz is not None:
                    hour = hour.tz_localize(None)
                
                # Get risk type for this IP
                ip = log.get('sourceIPAddress', '')
                risk_type = "Unknown"
                if ip in ip_analysis:
                    risk_type = ip_analysis[ip]['classification']['risk_type']
                
                if hour not in timeline_data:
                    timeline_data[hour] = {}
                timeline_data[hour][risk_type] = timeline_data[hour].get(risk_type, 0) + 1
        
        # Convert to list for chart
        timeline_list = []
        for timestamp, risk_types in sorted(timeline_data.items()):
            for risk_type, count in risk_types.items():
                timeline_list.append({
                    "timestamp": timestamp,
                    "count": count,
                    "category": risk_type
                })
        
        if timeline_list:
            # Create a grouped time series chart
            df = pd.DataFrame(timeline_list)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig = go.Figure()
            
            # Add a trace for each risk type
            for risk_type in df['category'].unique():
                risk_data = df[df['category'] == risk_type]
                fig.add_trace(go.Scatter(
                    x=risk_data['timestamp'],
                    y=risk_data['count'],
                    mode='lines+markers',
                    name=risk_type,
                    stackgroup='one'  # This will create a stacked area chart
                ))
            
            fig.update_layout(
                title="Suspicious Access Over Time",
                xaxis_title="Time",
                yaxis_title="Event Count",
                hovermode='x unified',
                template='plotly_white',
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)

    # Periodic Access Pattern Detection
    if suspicious_logs:
        st.subheader("🔄 Periodic Access Pattern Analysis")
        st.markdown("Detecting recurring access patterns from suspicious IPs (hourly and daily patterns)")
        
        # Analyze access patterns
        ip_time_patterns = {}
        
        for log in suspicious_logs:
            ip = log.get('sourceIPAddress', '')
            timestamp = log.get('eventTime', '')
            
            if ip and timestamp:
                dt = pd.to_datetime(timestamp)
                if dt.tz is not None:
                    dt = dt.tz_localize(None)
                
                if ip not in ip_time_patterns:
                    ip_time_patterns[ip] = {
                        'timestamps': [],
                        'hourly_pattern': {},
                        'weekday_pattern': {},
                        'hourly_weekday_pattern': {}
                    }
                
                ip_time_patterns[ip]['timestamps'].append(dt)
                
                # Track hourly pattern (0-23)
                hour = dt.hour
                ip_time_patterns[ip]['hourly_pattern'][hour] = ip_time_patterns[ip]['hourly_pattern'].get(hour, 0) + 1
                
                # Track weekday pattern (0=Monday, 6=Sunday)
                weekday = dt.weekday()
                ip_time_patterns[ip]['weekday_pattern'][weekday] = ip_time_patterns[ip]['weekday_pattern'].get(weekday, 0) + 1
                
                # Track combined pattern
                key = f"{weekday}_{hour}"
                ip_time_patterns[ip]['hourly_weekday_pattern'][key] = ip_time_patterns[ip]['hourly_weekday_pattern'].get(key, 0) + 1
        
        # Find IPs with periodic patterns
        periodic_ips = []
        
        for ip, patterns in ip_time_patterns.items():
            if len(patterns['timestamps']) >= 5:  # Need at least 5 events to detect pattern
                # Check for hourly concentration (e.g., always at the same hour)
                hourly_values = list(patterns['hourly_pattern'].values())
                if hourly_values:
                    max_hour_count = max(hourly_values)
                    total_count = sum(hourly_values)
                    hourly_concentration = max_hour_count / total_count
                    
                    # Check for weekday concentration
                    weekday_values = list(patterns['weekday_pattern'].values())
                    max_weekday_count = max(weekday_values) if weekday_values else 0
                    weekday_concentration = max_weekday_count / total_count if total_count > 0 else 0
                    
                    # If more than 50% of accesses happen at the same hour or same weekday
                    if hourly_concentration > 0.5 or weekday_concentration > 0.5:
                        periodic_ips.append({
                            'ip': ip,
                            'total_accesses': len(patterns['timestamps']),
                            'hourly_concentration': hourly_concentration,
                            'weekday_concentration': weekday_concentration,
                            'peak_hour': max(patterns['hourly_pattern'], key=patterns['hourly_pattern'].get),
                            'peak_weekday': max(patterns['weekday_pattern'], key=patterns['weekday_pattern'].get) if patterns['weekday_pattern'] else None,
                            'patterns': patterns
                        })
        
        if periodic_ips:
            # Sort by total accesses
            periodic_ips = sorted(periodic_ips, key=lambda x: x['total_accesses'], reverse=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Show periodic IPs summary
                st.metric(
                    "IPs with Periodic Patterns",
                    len(periodic_ips),
                    help="IPs showing recurring access patterns"
                )
                
                # Create hourly heatmap for top periodic IPs
                st.markdown("### Hourly Access Patterns (Top 5 IPs)")
                
                # Prepare data for heatmap
                heatmap_data = []
                weekday_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                
                for i, ip_info in enumerate(periodic_ips[:5]):
                    ip = ip_info['ip']
                    patterns = ip_info['patterns']['hourly_weekday_pattern']
                    
                    # Create a matrix for this IP
                    for weekday in range(7):
                        for hour in range(24):
                            key = f"{weekday}_{hour}"
                            count = patterns.get(key, 0)
                            if count > 0:
                                heatmap_data.append({
                                    'IP': f"IP {i+1}: {ip}",
                                    'Hour': hour,
                                    'Weekday': weekday_names[weekday],
                                    'Count': count
                                })
                
                if heatmap_data:
                    df_heatmap = pd.DataFrame(heatmap_data)
                    
                    # Create heatmap using plotly
                    fig_heatmap = px.density_heatmap(
                        df_heatmap,
                        x='Hour',
                        y='IP',
                        z='Count',
                        title="Access Patterns by Hour (Darker = More Frequent)",
                        color_continuous_scale='Reds'
                    )
                    
                    fig_heatmap.update_layout(
                        xaxis_title="Hour of Day",
                        yaxis_title="Suspicious IP",
                        height=300
                    )
                    
                    st.plotly_chart(fig_heatmap, use_container_width=True)
            
            with col2:
                # Show detailed pattern analysis
                st.markdown("### Pattern Details")
                
                pattern_df_data = []
                for ip_info in periodic_ips[:10]:
                    weekday_names_short = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                    peak_weekday_name = weekday_names_short[ip_info['peak_weekday']] if ip_info['peak_weekday'] is not None else 'N/A'
                    
                    pattern_df_data.append({
                        'IP Address': ip_info['ip'],
                        'Total Accesses': ip_info['total_accesses'],
                        'Peak Hour': f"{ip_info['peak_hour']}:00",
                        'Peak Day': peak_weekday_name,
                        'Hourly Pattern %': f"{ip_info['hourly_concentration']*100:.1f}%",
                        'Daily Pattern %': f"{ip_info['weekday_concentration']*100:.1f}%"
                    })
                
                pattern_df = pd.DataFrame(pattern_df_data)
                
                # Highlight high concentration patterns
                def highlight_patterns(row):
                    hourly_pct = float(row['Hourly Pattern %'].strip('%'))
                    daily_pct = float(row['Daily Pattern %'].strip('%'))
                    
                    if hourly_pct > 70 or daily_pct > 70:
                        return ['background-color: #ffcdd2'] * len(row)
                    elif hourly_pct > 50 or daily_pct > 50:
                        return ['background-color: #fff3cd'] * len(row)
                    else:
                        return [''] * len(row)
                
                st.dataframe(
                    pattern_df.style.apply(highlight_patterns, axis=1),
                    use_container_width=True,
                    hide_index=True
                )
                
                st.caption("🔴 Red: >70% concentration | 🟡 Yellow: >50% concentration")
            
            # Timeline visualization for the most periodic IP
            if periodic_ips:
                st.markdown("### Timeline View - Most Periodic IP")
                top_periodic_ip = periodic_ips[0]
                
                # Create timeline chart for this IP
                ip_logs = [log for log in suspicious_logs if log.get('sourceIPAddress') == top_periodic_ip['ip']]
                
                timeline_data = []
                for log in ip_logs:
                    dt = pd.to_datetime(log.get('eventTime', ''))
                    if dt.tz is not None:
                        dt = dt.tz_localize(None)
                    
                    timeline_data.append({
                        'timestamp': dt,
                        'event': log.get('eventName', 'Unknown'),
                        'hour': dt.hour,
                        'weekday': dt.weekday()
                    })
                
                if timeline_data:
                    df_timeline = pd.DataFrame(timeline_data)
                    
                    # Create scatter plot showing access times
                    fig_timeline = go.Figure()
                    
                    # Add markers for each access
                    fig_timeline.add_trace(go.Scatter(
                        x=df_timeline['timestamp'],
                        y=df_timeline['hour'],
                        mode='markers',
                        marker=dict(
                            size=10,
                            color=df_timeline['weekday'],
                            colorscale='Viridis',
                            showscale=True,
                            colorbar=dict(title="Weekday")
                        ),
                        text=df_timeline['event'],
                        hovertemplate='Time: %{x}<br>Hour: %{y}<br>Event: %{text}<extra></extra>'
                    ))
                    
                    fig_timeline.update_layout(
                        title=f"Access Timeline for {top_periodic_ip['ip']} (Showing {top_periodic_ip['total_accesses']} accesses)",
                        xaxis_title="Date/Time",
                        yaxis_title="Hour of Day",
                        yaxis=dict(range=[-1, 24]),
                        height=400,
                        template='plotly_white'
                    )
                    
                    st.plotly_chart(fig_timeline, use_container_width=True)
                    
                    risk_type = ip_analysis.get(top_periodic_ip['ip'], {}).get('classification', {}).get('risk_type', 'Unknown')
                    st.info(f"This IP ({risk_type}) shows a strong periodic pattern with {top_periodic_ip['hourly_concentration']*100:.1f}% of accesses occurring at {top_periodic_ip['peak_hour']}:00")
        
        else:
            st.info("No periodic access patterns detected in the current data. Periodic patterns require at least 5 accesses from the same IP.")

    # Detailed IP Analysis Table
    st.subheader("Detailed IP Analysis")
    
    if ip_analysis:
        # Convert to dataframe for display
        ip_df_data = []
        for ip, data in sorted(ip_analysis.items(), key=lambda x: x[1]['count'], reverse=True):
            ip_df_data.append({
                "IP Address": ip,
                "Risk Type": data['classification']['risk_type'],
                "Risk Level": data['classification']['risk_level'],
                "Access Count": data['count'],
                "Unique Users": len(data['users']),
                "Top Events": ", ".join(sorted(set(data['events']), key=data['events'].count, reverse=True)[:3])
            })
        
        ip_df = pd.DataFrame(ip_df_data)
        
        # Add color coding based on risk level
        def highlight_risk_level(row):
            if row['Risk Level'] == 'High':
                return ['background-color: #ffcdd2'] * len(row)
            elif row['Risk Level'] == 'Medium':
                return ['background-color: #fff3cd'] * len(row)
            else:
                return [''] * len(row)
        
        st.dataframe(
            ip_df.style.apply(highlight_risk_level, axis=1),
            use_container_width=True,
            hide_index=True
        )
        
        # Show recent suspicious logs
        st.subheader("Recent Suspicious Activities")
        
        # Display recent logs
        recent_logs = sorted(suspicious_logs, key=lambda x: x.get('eventTime', ''), reverse=True)[:100]
        
        if recent_logs:
            # Prepare data for display
            display_logs = []
            for log in recent_logs:
                ip = log.get('sourceIPAddress', 'N/A')
                risk_type = "Unknown"
                if ip in ip_analysis:
                    risk_type = ip_analysis[ip]['classification']['risk_type']
                
                display_log = {
                    "Timestamp": log.get('eventTime', 'N/A'),
                    "IP Address": ip,
                    "Risk Type": risk_type,
                    "User": log.get('userIdentity', {}).get('userName', 'N/A'),
                    "Event": log.get('eventName', 'N/A'),
                    "Service": log.get('eventSource', 'N/A'),
                    "Region": log.get('awsRegion', 'N/A')
                }
                display_logs.append(display_log)
            
            render_logs_table(display_logs)
        
    else:
        st.info("No suspicious IP addresses detected in the selected time range.")

except Exception as e:
    st.error(f"Error analyzing suspicious IPs: {str(e)}")
    st.exception(e)