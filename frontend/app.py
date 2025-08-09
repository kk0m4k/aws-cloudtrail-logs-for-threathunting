import streamlit as st
from datetime import datetime
import os

# Page configuration
st.set_page_config(
    page_title="CloudTrail Threat Hunting Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main {
        padding-top: 2rem;
    }
    .stMetric {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    div[data-testid="metric-container"] {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .css-1d391kg {
        padding-top: 3rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'api_url' not in st.session_state:
    st.session_state.api_url = os.getenv('CLOUDTRAIL_API_URL', 'http://localhost:8000')

# Sidebar
with st.sidebar:
    st.title("🔍 CloudTrail Threat Hunting")
    st.markdown("---")
    
    # API Status
    st.subheader("API Status")
    api_status = st.empty()
    
    # Try to check API status
    try:
        from utils.api_client import get_api_client
        client = get_api_client()
        stats = client.get_statistics()
        if stats:
            api_status.success("API Connected")
        else:
            api_status.error("API Not Responding")
    except:
        api_status.warning("API Connection Pending")
    
    st.markdown("---")
    
    # Navigation info
    st.info("""
    Navigate through different pages using the sidebar menu.
    
    **Available Pages:**
    - Overview: Dashboard summary
    - Tactics: MITRE ATT&CK analysis
    - Log Explorer: Search logs
    - Analytics: ML insights
    """)
    
    # Footer
    st.markdown("---")
    st.caption(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Main content
st.title("AWS CloudTrail Threat Hunting Dashboard")
st.markdown("""
Welcome to the CloudTrail Threat Hunting Dashboard. This tool helps you analyze AWS CloudTrail logs 
for security threats based on the MITRE ATT&CK framework.

### Getting Started

1. **Overview Page**: View overall statistics and key metrics
2. **Tactic Pages**: Analyze specific MITRE ATT&CK tactics
3. **Log Explorer**: Search and filter through raw logs
4. **Analytics**: View ML-powered insights and anomalies

### Quick Stats

Use the sidebar navigation to explore different sections of the dashboard.
""")

# Quick connection guide
with st.expander("🚀 Quick Start Guide"):
    st.markdown("""
    ### Prerequisites
    
    1. **Start the Backend API**:
       ```bash
       cd backend
       pip install -r requirements.txt
       python -m uvicorn main:app --reload
       ```
    
    2. **Access the Dashboard**:
       - The dashboard should be running on http://localhost:8501
       - The API should be running on http://localhost:8000
    
    ### Features
    
    - **Real-time Analysis**: View logs and analytics in real-time
    - **MITRE ATT&CK Mapping**: All threats mapped to MITRE framework
    - **Interactive Visualizations**: Charts and graphs for better insights
    - **Advanced Filtering**: Filter logs by multiple criteria
    - **Anomaly Detection**: ML-powered anomaly detection
    
    ### Navigation
    
    Use the sidebar to navigate between different pages:
    - Each tactic has its own dedicated page
    - Log Explorer for raw log analysis
    - Analytics for ML insights
    """)

# Display basic info if API is connected
try:
    from utils.api_client import get_api_client
    client = get_api_client()
    stats = client.get_statistics()
    
    if stats:
        st.subheader("📊 Current Dataset")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Logs", f"{stats.get('total_logs', 0):,}")
        
        with col2:
            st.metric("Malicious Logs", f"{stats.get('malicious_logs', 0):,}")
        
        with col3:
            st.metric("Normal Logs", f"{stats.get('normal_logs', 0):,}")
        
        with col4:
            malicious_ratio = stats.get('malicious_logs', 0) / stats.get('total_logs', 1) * 100
            st.metric("Malicious %", f"{malicious_ratio:.1f}%")
except:
    st.warning("Please ensure the backend API is running to view statistics.")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center'>
        <p>Built for AWS CloudTrail threat hunting and analysis</p>
    </div>
    """,
    unsafe_allow_html=True
)