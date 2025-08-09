import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import json

from utils.api_client import get_api_client
from components.filters import render_log_filters, render_quick_filters
from components.tables import render_log_table

st.set_page_config(page_title="Log Explorer - CloudTrail Dashboard", layout="wide")

st.title("🔍 Log Explorer")
st.markdown("Search, filter, and analyze CloudTrail logs in detail.")

# Initialize API client
client = get_api_client()

# Initialize session state for pagination
if 'current_page' not in st.session_state:
    st.session_state.current_page = 1
if 'page_size' not in st.session_state:
    st.session_state.page_size = 50

# Quick filters
quick_filters = render_quick_filters()

# Get available filter options
with st.spinner("Loading filter options..."):
    stats = client.get_statistics()
    techniques = client.get_techniques()
    
    # Extract filter options from stats
    filter_options = {
        "event_names": [],
        "event_sources": [],
        "regions": list(stats.get('regions', {}).keys()) if stats else [],
        "user_names": [u['name'] for u in stats.get('top_users', [])] if stats else [],
        "technique_ids": [t['id'] for t in techniques] if techniques else []
    }
    
    # Get sample logs to extract more options
    sample_logs = client.get_logs(limit=100)
    if sample_logs and 'items' in sample_logs:
        for log in sample_logs['items']:
            if log.get('eventName') and log['eventName'] not in filter_options['event_names']:
                filter_options['event_names'].append(log['eventName'])
            if log.get('eventSource') and log['eventSource'] not in filter_options['event_sources']:
                filter_options['event_sources'].append(log['eventSource'])

# Render filters
filters = render_log_filters(filter_options)

# Apply quick filters if any button was clicked
if quick_filters:
    filters.update(quick_filters)

# Search button
col1, col2, col3 = st.columns([1, 1, 3])
with col1:
    search_clicked = st.button("🔍 Search", type="primary", use_container_width=True)
with col2:
    if st.button("🔄 Reset Filters", use_container_width=True):
        st.session_state.current_page = 1
        st.experimental_rerun()

# Perform search
if search_clicked or filters:
    with st.spinner("Searching logs..."):
        # Calculate offset based on current page
        offset = (st.session_state.current_page - 1) * st.session_state.page_size
        
        # Add pagination params
        filters['limit'] = st.session_state.page_size
        filters['offset'] = offset
        
        # Fetch logs
        result = client.get_logs(**filters)
        
        if result and 'items' in result:
            logs = result['items']
            total_logs = result.get('total', 0)
            
            # Display results summary
            st.success(f"Found {total_logs:,} logs matching your criteria")
            
            # Pagination controls
            total_pages = (total_logs + st.session_state.page_size - 1) // st.session_state.page_size
            
            col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])
            
            with col1:
                if st.button("⬅️ Previous", disabled=st.session_state.current_page <= 1):
                    st.session_state.current_page -= 1
                    st.experimental_rerun()
            
            with col2:
                if st.button("➡️ Next", disabled=st.session_state.current_page >= total_pages):
                    st.session_state.current_page += 1
                    st.experimental_rerun()
            
            with col3:
                st.write(f"Page {st.session_state.current_page} of {total_pages}")
            
            with col4:
                new_page_size = st.selectbox(
                    "Page size",
                    [25, 50, 100, 200],
                    index=[25, 50, 100, 200].index(st.session_state.page_size)
                )
                if new_page_size != st.session_state.page_size:
                    st.session_state.page_size = new_page_size
                    st.session_state.current_page = 1
                    st.experimental_rerun()
            
            # Export options
            with col5:
                if st.button("📥 Export", help="Export current page"):
                    # Convert logs to JSON
                    json_str = json.dumps(logs, indent=2)
                    st.download_button(
                        label="Download JSON",
                        data=json_str,
                        file_name=f"cloudtrail_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            
            # Display logs
            if logs:
                # Quick stats for current page
                st.subheader("Current Page Statistics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                # Count events by type
                event_counts = {}
                user_counts = {}
                malicious_count = 0
                
                for log in logs:
                    # Event counts
                    event_name = log.get('eventName', 'Unknown')
                    event_counts[event_name] = event_counts.get(event_name, 0) + 1
                    
                    # User counts
                    user = log.get('userIdentity', {}).get('userName', 'Unknown')
                    user_counts[user] = user_counts.get(user, 0) + 1
                    
                    # Malicious count
                    if log.get('tags'):
                        malicious_count += 1
                
                with col1:
                    st.metric("Events on Page", len(logs))
                
                with col2:
                    st.metric("Unique Events", len(event_counts))
                
                with col3:
                    st.metric("Unique Users", len(user_counts))
                
                with col4:
                    st.metric("Malicious", malicious_count)
                
                # Log table
                st.subheader("Log Details")
                render_log_table(logs, show_details=True)
                
                # Additional analysis
                with st.expander("📊 Page Analysis"):
                    tab1, tab2, tab3 = st.tabs(["Events", "Users", "Timeline"])
                    
                    with tab1:
                        event_df = pd.DataFrame([
                            {"Event": k, "Count": v}
                            for k, v in sorted(event_counts.items(), key=lambda x: x[1], reverse=True)
                        ])
                        st.dataframe(event_df, use_container_width=True, hide_index=True)
                    
                    with tab2:
                        user_df = pd.DataFrame([
                            {"User": k, "Count": v}
                            for k, v in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
                        ])
                        st.dataframe(user_df, use_container_width=True, hide_index=True)
                    
                    with tab3:
                        # Create timeline visualization
                        timeline_data = []
                        for log in logs:
                            timeline_data.append({
                                "Time": log.get('eventTime', ''),
                                "Event": log.get('eventName', ''),
                                "User": log.get('userIdentity', {}).get('userName', 'Unknown'),
                                "IP": log.get('sourceIPAddress', '')
                            })
                        
                        timeline_df = pd.DataFrame(timeline_data)
                        if not timeline_df.empty:
                            timeline_df['Time'] = pd.to_datetime(timeline_df['Time'])
                            timeline_df = timeline_df.sort_values('Time')
                            st.dataframe(timeline_df, use_container_width=True, hide_index=True)
            else:
                st.info("No logs found matching your criteria")
        else:
            st.error("Failed to fetch logs. Please check your filters and try again.")
else:
    st.info("👆 Configure filters and click Search to explore logs")

# Search tips
with st.expander("💡 Search Tips"):
    st.markdown("""
    **Filter Tips:**
    - Use time filters to narrow down to specific incidents
    - Combine multiple filters for precise searches
    - Use technique IDs to find specific attack patterns
    - Filter by malicious/normal to focus on threats
    
    **Performance Tips:**
    - Start with smaller time ranges for faster results
    - Use specific event names when possible
    - Increase page size for bulk analysis
    
    **Export Options:**
    - Export current page as JSON for further analysis
    - Use filters to export specific subsets of data
    """)

# Footer
st.markdown("---")
st.caption(f"Log Explorer - Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")