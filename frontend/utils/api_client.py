import requests
from typing import Dict, List, Any, Optional
import streamlit as st
from datetime import datetime

class APIClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def _handle_response(self, response: requests.Response) -> Any:
        """Handle API response and errors"""
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            st.error(f"API Error: {response.status_code} - {response.text}")
            return None
        except Exception as e:
            st.error(f"Request failed: {str(e)}")
            return None
    
    def get_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_names: Optional[List[str]] = None,
        event_sources: Optional[List[str]] = None,
        user_names: Optional[List[str]] = None,
        source_ips: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        technique_ids: Optional[List[str]] = None,
        is_malicious: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Optional[Dict[str, Any]]:
        """Get CloudTrail logs with filters"""
        params = {
            "limit": limit,
            "offset": offset
        }
        
        if start_time:
            params["start_time"] = start_time.isoformat()
        if end_time:
            params["end_time"] = end_time.isoformat()
        if event_names:
            params["event_names"] = event_names
        if event_sources:
            params["event_sources"] = event_sources
        if user_names:
            params["user_names"] = user_names
        if source_ips:
            params["source_ips"] = source_ips
        if regions:
            params["regions"] = regions
        if technique_ids:
            params["technique_ids"] = technique_ids
        if is_malicious is not None:
            params["is_malicious"] = is_malicious
        
        try:
            response = self.session.get(f"{self.base_url}/api/logs", params=params)
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_statistics(self) -> Optional[Dict[str, Any]]:
        """Get overall log statistics"""
        try:
            response = self.session.get(f"{self.base_url}/api/statistics")
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_technique_analytics(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get analytics for a specific technique"""
        try:
            response = self.session.get(f"{self.base_url}/api/techniques/{technique_id}/analytics")
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_technique_logs(self, technique_id: str, limit: int = 100) -> Optional[List[Dict[str, Any]]]:
        """Get logs for a specific technique"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/techniques/{technique_id}/logs",
                params={"limit": limit}
            )
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_anomalies(self, time_window_hours: int = 24) -> Optional[List[Dict[str, Any]]]:
        """Get detected anomalies"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/anomalies",
                params={"time_window_hours": time_window_hours}
            )
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_timeseries(
        self,
        metric: str = "event_count",
        granularity: str = "hour",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        technique_ids: Optional[List[str]] = None,
        is_malicious: Optional[bool] = None
    ) -> Optional[List[Dict[str, Any]]]:
        """Get time series data for visualization"""
        params = {
            "metric": metric,
            "granularity": granularity
        }
        
        if start_time:
            params["start_time"] = start_time.isoformat()
        if end_time:
            params["end_time"] = end_time.isoformat()
        if technique_ids:
            params["technique_ids"] = technique_ids
        if is_malicious is not None:
            params["is_malicious"] = is_malicious
        
        try:
            response = self.session.get(f"{self.base_url}/api/timeseries", params=params)
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_techniques(self) -> Optional[List[Dict[str, Any]]]:
        """Get list of all available techniques"""
        try:
            response = self.session.get(f"{self.base_url}/api/techniques")
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_cache_stats(self) -> Optional[Dict[str, Any]]:
        """Get cache statistics"""
        try:
            response = self.session.get(f"{self.base_url}/api/cache/stats")
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def clear_cache(self) -> bool:
        """Clear the cache"""
        try:
            response = self.session.post(f"{self.base_url}/api/cache/clear")
            return response.status_code == 200
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return False
    
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """Generic GET request to any endpoint"""
        try:
            response = self.session.get(f"{self.base_url}{endpoint}", params=params)
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None
    
    def get_suspicious_ips(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        risk_types: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Optional[Dict[str, Any]]:
        """Get analysis of suspicious IP addresses"""
        params = {
            "limit": limit,
            "offset": offset
        }
        
        if start_time:
            params["start_time"] = start_time.isoformat()
        if end_time:
            params["end_time"] = end_time.isoformat()
        if risk_types:
            params["risk_types"] = risk_types
        
        try:
            response = self.session.get(f"{self.base_url}/api/suspicious-ips", params=params)
            return self._handle_response(response)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API server at {self.base_url}. Please ensure the backend is running.")
            return None

# Global API client instance
@st.cache_resource
def get_api_client():
    api_url = st.session_state.get('api_url', 'http://localhost:8000')
    return APIClient(base_url=api_url)