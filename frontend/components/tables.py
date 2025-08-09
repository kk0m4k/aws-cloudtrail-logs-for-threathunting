import streamlit as st
import pandas as pd
from typing import List, Dict, Any, Optional
import json
from datetime import datetime

def render_log_table(
    logs: List[Dict[str, Any]],
    show_details: bool = True,
    max_rows: Optional[int] = None
) -> None:
    """Render CloudTrail logs in a table"""
    if not logs:
        st.info("No logs to display")
        return
    
    # Convert to DataFrame for display
    df_data = []
    for log in logs[:max_rows] if max_rows else logs:
        row = {
            "Time": log.get("eventTime", ""),
            "Event": log.get("eventName", ""),
            "User": log.get("userIdentity", {}).get("userName", 
                    log.get("userIdentity", {}).get("arn", "").split("/")[-1]),
            "Source IP": log.get("sourceIPAddress", ""),
            "Region": log.get("awsRegion", ""),
            "Event Source": log.get("eventSource", ""),
            "Error": log.get("errorCode", "")
        }
        
        if "tags" in log and log["tags"]:
            row["Technique"] = log["tags"].get("technique_id", "")
            row["Use Case"] = log["tags"].get("usecase", "")
        
        df_data.append(row)
    
    df = pd.DataFrame(df_data)
    
    # Display table
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Time": st.column_config.DatetimeColumn(
                "Time",
                format="DD/MM/YYYY HH:mm:ss"
            ),
            "Error": st.column_config.TextColumn(
                "Error",
                help="Error code if the API call failed"
            )
        }
    )
    
    # Show details in expander
    if show_details and logs:
        st.subheader("Log Details")
        
        # Let user select a log to view details
        log_index = st.selectbox(
            "Select a log to view details",
            range(len(logs[:max_rows] if max_rows else logs)),
            format_func=lambda x: f"{logs[x]['eventTime']} - {logs[x]['eventName']} - {logs[x].get('userIdentity', {}).get('userName', 'Unknown')}"
        )
        
        if log_index is not None:
            selected_log = logs[log_index]
            
            # Display in columns
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Basic Information**")
                st.json({
                    "eventTime": selected_log.get("eventTime"),
                    "eventName": selected_log.get("eventName"),
                    "eventSource": selected_log.get("eventSource"),
                    "awsRegion": selected_log.get("awsRegion"),
                    "sourceIPAddress": selected_log.get("sourceIPAddress"),
                    "userAgent": selected_log.get("userAgent")
                })
                
                if "userIdentity" in selected_log:
                    st.write("**User Identity**")
                    st.json(selected_log["userIdentity"])
            
            with col2:
                if "requestParameters" in selected_log:
                    st.write("**Request Parameters**")
                    st.json(selected_log["requestParameters"])
                
                if "responseElements" in selected_log:
                    st.write("**Response Elements**")
                    st.json(selected_log["responseElements"])
                
                if "tags" in selected_log:
                    st.write("**Tags**")
                    st.json(selected_log["tags"])
            
            # Show full JSON
            with st.expander("View Full JSON"):
                st.json(selected_log)

def render_statistics_table(stats: Dict[str, Any]) -> None:
    """Render statistics in a table format"""
    if not stats:
        st.info("No statistics available")
        return
    
    # Create summary table
    summary_data = {
        "Metric": ["Total Logs", "Malicious Logs", "Normal Logs", "Malicious Ratio"],
        "Value": [
            f"{stats.get('total_logs', 0):,}",
            f"{stats.get('malicious_logs', 0):,}",
            f"{stats.get('normal_logs', 0):,}",
            f"{stats.get('malicious_logs', 0) / stats.get('total_logs', 1) * 100:.1f}%"
        ]
    }
    
    st.dataframe(
        pd.DataFrame(summary_data),
        use_container_width=True,
        hide_index=True
    )

def render_anomaly_table(anomalies: List[Dict[str, Any]]) -> None:
    """Render anomalies in a table"""
    if not anomalies:
        st.info("No anomalies detected")
        return
    
    # Convert to DataFrame
    df_data = []
    for anomaly in anomalies:
        df_data.append({
            "Time": anomaly.get("timestamp", ""),
            "Severity": anomaly.get("severity", ""),
            "Type": anomaly.get("anomaly_type", ""),
            "Description": anomaly.get("description", ""),
            "Related Logs": len(anomaly.get("related_logs", []))
        })
    
    df = pd.DataFrame(df_data)
    
    # Apply color coding based on severity
    def severity_color(severity):
        colors = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢"
        }
        return f"{colors.get(severity, '')} {severity}"
    
    df["Severity"] = df["Severity"].apply(severity_color)
    
    # Display table
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )
    
    # Show details
    if anomalies:
        st.subheader("Anomaly Details")
        
        anomaly_index = st.selectbox(
            "Select an anomaly to view details",
            range(len(anomalies)),
            format_func=lambda x: f"{anomalies[x]['timestamp']} - {anomalies[x]['description']}"
        )
        
        if anomaly_index is not None:
            selected_anomaly = anomalies[anomaly_index]
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Anomaly Information**")
                st.json({
                    "anomaly_id": selected_anomaly.get("anomaly_id"),
                    "timestamp": selected_anomaly.get("timestamp"),
                    "severity": selected_anomaly.get("severity"),
                    "anomaly_type": selected_anomaly.get("anomaly_type"),
                    "description": selected_anomaly.get("description")
                })
            
            with col2:
                st.write("**Indicators**")
                st.json(selected_anomaly.get("indicators", {}))
            
            # Show related logs
            if selected_anomaly.get("related_logs"):
                st.write("**Related Logs**")
                render_log_table(selected_anomaly["related_logs"], show_details=False, max_rows=5)

def render_technique_table(techniques: List[Dict[str, Any]]) -> None:
    """Render techniques in a table"""
    if not techniques:
        st.info("No techniques found")
        return
    
    df = pd.DataFrame(techniques)
    
    # Add percentage column
    total = sum(t["count"] for t in techniques)
    df["percentage"] = df["count"].apply(lambda x: f"{x/total*100:.1f}%")
    
    # Display table
    st.dataframe(
        df[["id", "name", "count", "percentage"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "id": "Technique ID",
            "name": "Technique Name",
            "count": st.column_config.NumberColumn(
                "Event Count",
                format="%d"
            ),
            "percentage": "Percentage"
        }
    )

def render_logs_table(logs: List[Dict[str, Any]]) -> None:
    """Render logs in a simple table format"""
    if not logs:
        st.info("No logs to display")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(logs)
    
    # Display table with custom formatting
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Timestamp": st.column_config.DatetimeColumn(
                "Timestamp",
                format="DD/MM/YYYY HH:mm:ss"
            ),
            "Risk Type": st.column_config.TextColumn(
                "Risk Type",
                help="Type of risk associated with the IP"
            ),
            "IP Address": st.column_config.TextColumn(
                "IP Address",
                help="Source IP address"
            )
        }
    )