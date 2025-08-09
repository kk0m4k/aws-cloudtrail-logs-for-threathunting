from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import uvicorn

from config import settings
from models import (
    CloudTrailLog, LogFilter, LogStatistics, PaginatedResponse,
    UseCaseAnalytics, AnomalyDetection, TimeSeriesData
)
from services.log_reader import LogReaderService
from services.analytics import AnalyticsService
from services.cache import cache, cache_result

# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="API for CloudTrail threat hunting and analysis"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
log_reader = LogReaderService()
analytics_service = AnalyticsService(log_reader)

# Add cache to services
log_reader._cache = cache
analytics_service._cache = cache

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.app_name,
        "version": settings.version,
        "status": "running"
    }

@app.get("/api/logs", response_model=PaginatedResponse)
async def get_logs(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    event_names: Optional[List[str]] = Query(None),
    event_sources: Optional[List[str]] = Query(None),
    user_names: Optional[List[str]] = Query(None),
    source_ips: Optional[List[str]] = Query(None),
    regions: Optional[List[str]] = Query(None),
    technique_ids: Optional[List[str]] = Query(None),
    is_malicious: Optional[bool] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0)
):
    """Get CloudTrail logs with filters"""
    try:
        filters = LogFilter(
            start_time=start_time,
            end_time=end_time,
            event_names=event_names,
            event_sources=event_sources,
            user_names=user_names,
            source_ips=source_ips,
            regions=regions,
            technique_ids=technique_ids,
            is_malicious=is_malicious,
            limit=limit,
            offset=offset
        )
        
        logs = await log_reader.get_logs(filters)
        
        # Get total count for pagination
        total_filters = filters.copy()
        total_filters.limit = 100000  # Large number to get all
        all_logs = await log_reader.get_logs(total_filters)
        total = len(all_logs)
        
        return PaginatedResponse(
            items=logs,
            total=total,
            offset=offset,
            limit=limit,
            has_more=(offset + limit) < total
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/statistics", response_model=LogStatistics)
@cache_result("statistics")
async def get_statistics():
    """Get overall log statistics"""
    try:
        return await log_reader.get_statistics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/techniques/{technique_id}/analytics", response_model=UseCaseAnalytics)
@cache_result("technique_analytics")
async def get_technique_analytics(technique_id: str):
    """Get analytics for a specific technique"""
    try:
        return await analytics_service.get_usecase_analytics(technique_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/techniques/{technique_id}/logs", response_model=List[CloudTrailLog])
async def get_technique_logs(
    technique_id: str,
    limit: int = Query(default=100, le=1000)
):
    """Get logs for a specific technique"""
    try:
        return await log_reader.get_logs_by_technique(technique_id, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/anomalies", response_model=List[AnomalyDetection])
@cache_result("anomalies")
async def get_anomalies(
    time_window_hours: int = Query(default=24, ge=1, le=168)
):
    """Get detected anomalies"""
    try:
        return await analytics_service.detect_anomalies(time_window_hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/timeseries", response_model=List[TimeSeriesData])
async def get_timeseries(
    metric: str = Query(default="event_count"),
    granularity: str = Query(default="hour", regex="^(hour|day)$"),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    technique_ids: Optional[List[str]] = Query(None),
    is_malicious: Optional[bool] = None
):
    """Get time series data for visualization"""
    try:
        filters = LogFilter(
            start_time=start_time,
            end_time=end_time,
            technique_ids=technique_ids,
            is_malicious=is_malicious,
            limit=10000
        )
        
        return await analytics_service.get_time_series_analysis(
            metric=metric,
            granularity=granularity,
            filters=filters
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cache/stats")
async def get_cache_stats():
    """Get cache statistics"""
    return cache.stats()

@app.post("/api/cache/clear")
async def clear_cache():
    """Clear the cache"""
    cache.clear()
    return {"message": "Cache cleared"}

@app.get("/api/techniques")
async def get_techniques():
    """Get list of all available techniques"""
    try:
        stats = await log_reader.get_statistics()
        techniques = []
        
        # Mapping of technique IDs to names
        technique_names = {
            "T1078.004": "Valid Accounts - Cloud Accounts",
            "T1190": "Exploit Public-Facing Application",
            "T1098": "Account Manipulation",
            "T1562.001": "Impair Defenses - Disable or Modify Tools",
            "T1090.003": "Proxy - Multi-hop Proxy",
            "T1552.005": "Unsecured Credentials - Cloud Instance Metadata API",
            "T1580": "Cloud Infrastructure Discovery",
            "T1213": "Data from Information Repositories",
            "T1537": "Transfer Data to Cloud Account",
            "T1041": "Exfiltration Over C2 Channel",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1496": "Resource Hijacking",
            "T1485": "Data Destruction"
        }
        
        for technique_id, count in stats.malicious_breakdown.items():
            techniques.append({
                "id": technique_id,
                "name": technique_names.get(technique_id, technique_id),
                "count": count
            })
        
        return sorted(techniques, key=lambda x: x["count"], reverse=True)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/suspicious-ips")
async def get_suspicious_ips(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    risk_types: Optional[List[str]] = Query(None),
    limit: int = Query(default=100, le=10000),
    offset: int = Query(default=0, ge=0)
):
    """Get analysis of suspicious IP addresses (TOR, VPN, risky countries)"""
    try:
        # Known suspicious IP patterns
        TOR_PREFIXES = ["185.220.101.", "23.129.64.", "162.247.74.", "209.58.188.", "45.32.225."]
        VPN_PREFIXES = ["10.8.", "172.16.", "192.168."]
        RISKY_COUNTRY_PREFIXES = {
            "211.": "North Korea",
            "185.220.": "Russia/Eastern Europe",
            "162.247.": "Anonymous Proxy",
            "23.129.": "TOR Network",
            "45.32.": "VPS Provider"
        }
        
        # Get logs
        filters = LogFilter(
            start_time=start_time,
            end_time=end_time,
            limit=limit * 10,  # Get more logs to analyze
            offset=offset
        )
        
        all_logs = await log_reader.get_logs(filters)
        
        # Analyze IPs
        suspicious_ips = {}
        suspicious_logs = []
        
        for log in all_logs:
            ip = log.sourceIPAddress if hasattr(log, 'sourceIPAddress') else ''
            if not ip:
                continue
            
            risk_info = None
            
            # Check TOR
            for tor_prefix in TOR_PREFIXES:
                if ip.startswith(tor_prefix):
                    risk_info = {
                        "type": "TOR Exit Node",
                        "level": "High",
                        "description": "Known TOR exit node"
                    }
                    break
            
            # Check VPN
            if not risk_info:
                for vpn_prefix in VPN_PREFIXES:
                    if ip.startswith(vpn_prefix):
                        risk_info = {
                            "type": "VPN Service",
                            "level": "Medium",
                            "description": "Common VPN IP range"
                        }
                        break
            
            # Check risky countries
            if not risk_info:
                for prefix, country in RISKY_COUNTRY_PREFIXES.items():
                    if ip.startswith(prefix):
                        risk_info = {
                            "type": f"Risky Country - {country}",
                            "level": "High" if "Korea" in country else "Medium",
                            "description": f"IP from {country}"
                        }
                        break
            
            if risk_info:
                # Filter by risk type if specified
                if risk_types and risk_info["type"] not in risk_types:
                    continue
                
                if ip not in suspicious_ips:
                    suspicious_ips[ip] = {
                        "ip": ip,
                        "risk_info": risk_info,
                        "event_count": 0,
                        "events": [],
                        "users": set(),
                        "first_seen": log.eventTime,
                        "last_seen": log.eventTime
                    }
                
                suspicious_ips[ip]["event_count"] += 1
                suspicious_ips[ip]["events"].append(log.eventName)
                suspicious_ips[ip]["last_seen"] = log.eventTime
                
                user = log.userIdentity.userName if hasattr(log.userIdentity, 'userName') and log.userIdentity.userName else None
                if user:
                    suspicious_ips[ip]["users"].add(user)
                
                # Convert log to dict for response
                suspicious_logs.append(log.model_dump())
        
        # Convert sets to lists for JSON serialization
        for ip_data in suspicious_ips.values():
            ip_data["users"] = list(ip_data["users"])
            ip_data["unique_events"] = list(set(ip_data["events"]))
            ip_data["event_breakdown"] = {}
            for event in ip_data["events"]:
                ip_data["event_breakdown"][event] = ip_data["event_breakdown"].get(event, 0) + 1
        
        # Prepare response
        result = {
            "suspicious_ips": list(suspicious_ips.values()),
            "total_suspicious_ips": len(suspicious_ips),
            "total_suspicious_events": len(suspicious_logs),
            "risk_type_breakdown": {},
            "recent_logs": suspicious_logs[:limit]
        }
        
        # Calculate risk type breakdown
        for ip_data in suspicious_ips.values():
            risk_type = ip_data["risk_info"]["type"]
            result["risk_type_breakdown"][risk_type] = result["risk_type_breakdown"].get(risk_type, 0) + 1
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )