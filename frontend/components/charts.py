import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict, Any, Optional
import pandas as pd
from datetime import datetime

def create_time_series_chart(
    data: List[Dict[str, Any]], 
    title: str = "Events Over Time",
    y_label: str = "Event Count"
) -> go.Figure:
    """Create a time series chart"""
    if not data:
        return go.Figure().add_annotation(text="No data available", showarrow=False)
    
    df = pd.DataFrame(data)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['count'],
        mode='lines+markers',
        name='Events',
        line=dict(color='#1f77b4', width=2),
        marker=dict(size=6)
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title="Time",
        yaxis_title=y_label,
        hovermode='x unified',
        template='plotly_white'
    )
    
    return fig

def create_pie_chart(
    data: Dict[str, int],
    title: str = "Distribution"
) -> go.Figure:
    """Create a pie chart"""
    if not data:
        return go.Figure().add_annotation(text="No data available", showarrow=False)
    
    fig = go.Figure(data=[go.Pie(
        labels=list(data.keys()),
        values=list(data.values()),
        hole=0.3
    )])
    
    fig.update_layout(
        title=title,
        template='plotly_white'
    )
    
    return fig

def create_bar_chart(
    data: List[Dict[str, Any]],
    x_field: str,
    y_field: str,
    title: str = "Bar Chart",
    orientation: str = "v"
) -> go.Figure:
    """Create a bar chart"""
    if not data:
        return go.Figure().add_annotation(text="No data available", showarrow=False)
    
    df = pd.DataFrame(data)
    
    if orientation == "h":
        fig = px.bar(df, x=y_field, y=x_field, orientation='h')
    else:
        fig = px.bar(df, x=x_field, y=y_field)
    
    fig.update_layout(
        title=title,
        template='plotly_white'
    )
    
    return fig

def create_heatmap(
    data: Dict[str, Dict[str, int]],
    title: str = "Activity Heatmap"
) -> go.Figure:
    """Create a heatmap"""
    if not data:
        return go.Figure().add_annotation(text="No data available", showarrow=False)
    
    # Convert to DataFrame
    df = pd.DataFrame(data).fillna(0)
    
    fig = go.Figure(data=go.Heatmap(
        z=df.values,
        x=df.columns,
        y=df.index,
        colorscale='RdYlBu_r'
    ))
    
    fig.update_layout(
        title=title,
        template='plotly_white'
    )
    
    return fig

def create_gauge_chart(
    value: float,
    max_value: float = 10,
    title: str = "Risk Score"
) -> go.Figure:
    """Create a gauge chart"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title},
        gauge={
            'axis': {'range': [None, max_value]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, max_value * 0.3], 'color': "lightgreen"},
                {'range': [max_value * 0.3, max_value * 0.7], 'color': "yellow"},
                {'range': [max_value * 0.7, max_value], 'color': "lightcoral"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': max_value * 0.9
            }
        }
    ))
    
    fig.update_layout(height=300)
    return fig

def create_scatter_plot(
    data: List[Dict[str, Any]],
    x_field: str,
    y_field: str,
    color_field: Optional[str] = None,
    title: str = "Scatter Plot"
) -> go.Figure:
    """Create a scatter plot"""
    if not data:
        return go.Figure().add_annotation(text="No data available", showarrow=False)
    
    df = pd.DataFrame(data)
    
    fig = px.scatter(
        df, 
        x=x_field, 
        y=y_field, 
        color=color_field,
        title=title
    )
    
    fig.update_layout(template='plotly_white')
    return fig

def create_sunburst_chart(
    data: List[Dict[str, Any]],
    path: List[str],
    values: str,
    title: str = "Hierarchical View"
) -> go.Figure:
    """Create a sunburst chart"""
    if not data:
        return go.Figure().add_annotation(text="No data available", showarrow=False)
    
    df = pd.DataFrame(data)
    
    fig = px.sunburst(
        df,
        path=path,
        values=values,
        title=title
    )
    
    fig.update_layout(template='plotly_white')
    return fig

def display_metric_cards(metrics: Dict[str, Any]):
    """Display metrics in a card layout"""
    cols = st.columns(len(metrics))
    
    for i, (label, value) in enumerate(metrics.items()):
        with cols[i]:
            st.metric(label=label, value=value)

def create_timeline_chart(
    events: List[Dict[str, Any]],
    title: str = "Event Timeline"
) -> go.Figure:
    """Create a timeline chart for events"""
    if not events:
        return go.Figure().add_annotation(text="No events available", showarrow=False)
    
    fig = go.Figure()
    
    # Group events by type
    event_types = {}
    for event in events:
        event_type = event.get('eventName', 'Unknown')
        if event_type not in event_types:
            event_types[event_type] = []
        event_types[event_type].append(event)
    
    # Create traces for each event type
    for i, (event_type, type_events) in enumerate(event_types.items()):
        times = [datetime.fromisoformat(e['eventTime'].replace('Z', '+00:00')) 
                for e in type_events]
        
        fig.add_trace(go.Scatter(
            x=times,
            y=[i] * len(times),
            mode='markers',
            name=event_type,
            marker=dict(size=10),
            text=[f"{e.get('userIdentity', {}).get('userName', 'Unknown')}<br>{e.get('sourceIPAddress', 'Unknown')}" 
                  for e in type_events],
            hoverinfo='text+x'
        ))
    
    fig.update_layout(
        title=title,
        yaxis=dict(
            tickmode='array',
            tickvals=list(range(len(event_types))),
            ticktext=list(event_types.keys())
        ),
        xaxis_title="Time",
        hovermode='closest',
        template='plotly_white',
        height=max(400, len(event_types) * 50)
    )
    
    return fig