import streamlit as st
from datetime import datetime, timedelta, date
from typing import Optional, List, Tuple, Any, Dict

def render_time_filter(key_prefix: str = "") -> Tuple[Optional[datetime], Optional[datetime]]:
    """Render time range filter"""
    col1, col2 = st.columns(2)
    
    with col1:
        start_date = st.date_input(
            "Start Date",
            value=date.today() - timedelta(days=7),
            key=f"{key_prefix}_start_date"
        )
        start_time = st.time_input(
            "Start Time",
            value=datetime.min.time(),
            key=f"{key_prefix}_start_time"
        )
    
    with col2:
        end_date = st.date_input(
            "End Date",
            value=date.today(),
            key=f"{key_prefix}_end_date"
        )
        end_time = st.time_input(
            "End Time",
            value=datetime.max.time().replace(microsecond=0),
            key=f"{key_prefix}_end_time"
        )
    
    start_datetime = datetime.combine(start_date, start_time) if start_date else None
    end_datetime = datetime.combine(end_date, end_time) if end_date else None
    
    return start_datetime, end_datetime

def render_multiselect_filter(
    label: str,
    options: List[Any],
    default: Optional[List[Any]] = None,
    key: Optional[str] = None
) -> List[Any]:
    """Render multiselect filter"""
    return st.multiselect(
        label,
        options=options,
        default=default,
        key=key
    )

def render_selectbox_filter(
    label: str,
    options: List[Any],
    default: Optional[Any] = None,
    key: Optional[str] = None
) -> Any:
    """Render selectbox filter"""
    return st.selectbox(
        label,
        options=options,
        index=options.index(default) if default in options else 0,
        key=key
    )

def render_checkbox_filter(
    label: str,
    default: bool = False,
    key: Optional[str] = None
) -> bool:
    """Render checkbox filter"""
    return st.checkbox(label, value=default, key=key)

def render_slider_filter(
    label: str,
    min_value: int,
    max_value: int,
    default: int,
    step: int = 1,
    key: Optional[str] = None
) -> int:
    """Render slider filter"""
    return st.slider(
        label,
        min_value=min_value,
        max_value=max_value,
        value=default,
        step=step,
        key=key
    )

def render_text_input_filter(
    label: str,
    placeholder: str = "",
    key: Optional[str] = None
) -> str:
    """Render text input filter"""
    return st.text_input(
        label,
        placeholder=placeholder,
        key=key
    )

def render_log_filters(available_options: Dict[str, List[Any]]) -> Dict[str, Any]:
    """Render comprehensive log filters"""
    filters = {}
    
    with st.expander("Filters", expanded=True):
        # Time filter
        start_time, end_time = render_time_filter("log")
        if start_time:
            filters["start_time"] = start_time
        if end_time:
            filters["end_time"] = end_time
        
        # Event filters
        col1, col2 = st.columns(2)
        
        with col1:
            if "event_names" in available_options:
                event_names = render_multiselect_filter(
                    "Event Names",
                    available_options["event_names"],
                    key="filter_event_names"
                )
                if event_names:
                    filters["event_names"] = event_names
            
            if "event_sources" in available_options:
                event_sources = render_multiselect_filter(
                    "Event Sources",
                    available_options["event_sources"],
                    key="filter_event_sources"
                )
                if event_sources:
                    filters["event_sources"] = event_sources
            
            if "regions" in available_options:
                regions = render_multiselect_filter(
                    "Regions",
                    available_options["regions"],
                    key="filter_regions"
                )
                if regions:
                    filters["regions"] = regions
        
        with col2:
            if "user_names" in available_options:
                user_names = render_multiselect_filter(
                    "User Names",
                    available_options["user_names"],
                    key="filter_user_names"
                )
                if user_names:
                    filters["user_names"] = user_names
            
            if "technique_ids" in available_options:
                technique_ids = render_multiselect_filter(
                    "Technique IDs",
                    available_options["technique_ids"],
                    key="filter_technique_ids"
                )
                if technique_ids:
                    filters["technique_ids"] = technique_ids
            
            # Malicious filter
            malicious_option = st.radio(
                "Log Type",
                ["All", "Malicious Only", "Normal Only"],
                key="filter_malicious"
            )
            if malicious_option == "Malicious Only":
                filters["is_malicious"] = True
            elif malicious_option == "Normal Only":
                filters["is_malicious"] = False
        
        # Advanced filters
        with st.expander("Advanced Filters"):
            # IP address filter
            ip_input = render_text_input_filter(
                "Source IP (comma-separated)",
                placeholder="e.g., 192.168.1.1, 10.0.0.1",
                key="filter_ips"
            )
            if ip_input:
                filters["source_ips"] = [ip.strip() for ip in ip_input.split(",")]
            
            # Limit filter
            limit = render_slider_filter(
                "Max Results",
                min_value=10,
                max_value=1000,
                default=100,
                step=10,
                key="filter_limit"
            )
            filters["limit"] = limit
    
    return filters

def render_quick_filters() -> Dict[str, Any]:
    """Render quick filter buttons"""
    st.write("Quick Filters:")
    
    col1, col2, col3, col4 = st.columns(4)
    
    filters = {}
    
    with col1:
        if st.button("Last 24 Hours"):
            filters["start_time"] = datetime.utcnow() - timedelta(hours=24)
            filters["end_time"] = datetime.utcnow()
    
    with col2:
        if st.button("Last 7 Days"):
            filters["start_time"] = datetime.utcnow() - timedelta(days=7)
            filters["end_time"] = datetime.utcnow()
    
    with col3:
        if st.button("Malicious Only"):
            filters["is_malicious"] = True
    
    with col4:
        if st.button("Critical Events"):
            filters["event_names"] = [
                "StopLogging", "DeleteTrail", "DisableSecurityHub",
                "DeleteDetector", "CreateUser", "AttachUserPolicy"
            ]
    
    return filters