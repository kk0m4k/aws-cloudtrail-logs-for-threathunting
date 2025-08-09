from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
import ipaddress

from models import (
    CloudTrailLog, UseCaseAnalytics, TimeSeriesData, 
    AnomalyDetection, LogFilter
)
from .log_reader import LogReaderService

class AnalyticsService:
    def __init__(self, log_reader: LogReaderService):
        self.log_reader = log_reader
        
    async def get_usecase_analytics(self, technique_id: str) -> UseCaseAnalytics:
        """Get analytics for a specific use case/technique"""
        logs = await self.log_reader.get_logs_by_technique(technique_id)
        
        if not logs:
            return UseCaseAnalytics(
                technique_id=technique_id,
                usecase="Unknown",
                description="No logs found",
                total_events=0,
                unique_users=0,
                unique_ips=0,
                time_distribution=[],
                event_breakdown={},
                geographic_distribution={},
                risk_score=0.0
            )
        
        # Extract use case info from first log
        sample_log = logs[0]
        usecase = sample_log.tags.usecase if sample_log.tags else "Unknown"
        description = sample_log.tags.description if sample_log.tags else "No description"
        
        # Calculate metrics
        unique_users = set()
        unique_ips = set()
        event_counts = defaultdict(int)
        time_buckets = defaultdict(int)
        geo_distribution = defaultdict(int)
        
        for log in logs:
            # Unique users
            user_name = log.userIdentity.userName or log.userIdentity.arn.split('/')[-1]
            unique_users.add(user_name)
            
            # Unique IPs
            unique_ips.add(log.sourceIPAddress)
            
            # Event breakdown
            event_counts[log.eventName] += 1
            
            # Time distribution (hourly buckets)
            log_time = datetime.fromisoformat(log.eventTime.replace('Z', '+00:00'))
            bucket = log_time.replace(minute=0, second=0, microsecond=0)
            time_buckets[bucket] += 1
            
            # Geographic distribution (simplified - by IP class)
            try:
                ip = ipaddress.ip_address(log.sourceIPAddress)
                if ip.is_private:
                    geo_distribution["Internal"] += 1
                else:
                    # Simple geographic inference based on IP ranges
                    first_octet = int(str(ip).split('.')[0])
                    if 1 <= first_octet <= 50:
                        geo_distribution["North America"] += 1
                    elif 51 <= first_octet <= 100:
                        geo_distribution["Europe"] += 1
                    elif 101 <= first_octet <= 150:
                        geo_distribution["Asia Pacific"] += 1
                    else:
                        geo_distribution["Other"] += 1
            except:
                geo_distribution["Unknown"] += 1
        
        # Convert time buckets to TimeSeriesData
        time_distribution = [
            TimeSeriesData(timestamp=ts, count=count)
            for ts, count in sorted(time_buckets.items())
        ]
        
        # Calculate risk score (0-10)
        risk_factors = []
        
        # Factor 1: Event volume
        if len(logs) > 100:
            risk_factors.append(min(len(logs) / 100, 3))
        
        # Factor 2: Unique IPs
        if len(unique_ips) > 10:
            risk_factors.append(min(len(unique_ips) / 10, 2))
        
        # Factor 3: External IPs
        external_ips = sum(1 for ip in unique_ips 
                          if not ipaddress.ip_address(ip).is_private)
        if external_ips > 0:
            risk_factors.append(min(external_ips / len(unique_ips) * 3, 3))
        
        # Factor 4: Time concentration
        if time_distribution:
            max_hour_count = max(td.count for td in time_distribution)
            avg_hour_count = statistics.mean(td.count for td in time_distribution)
            if max_hour_count > avg_hour_count * 3:
                risk_factors.append(2)
        
        risk_score = min(sum(risk_factors), 10)
        
        return UseCaseAnalytics(
            technique_id=technique_id,
            usecase=usecase,
            description=description,
            total_events=len(logs),
            unique_users=len(unique_users),
            unique_ips=len(unique_ips),
            time_distribution=time_distribution,
            event_breakdown=dict(event_counts),
            geographic_distribution=dict(geo_distribution),
            risk_score=risk_score
        )
    
    async def detect_anomalies(self, time_window_hours: int = 24) -> List[AnomalyDetection]:
        """Detect anomalies in the logs"""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_window_hours)
        
        filters = LogFilter(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        logs = await self.log_reader.get_logs(filters)
        anomalies = []
        
        # Anomaly 1: Unusual access patterns
        anomalies.extend(await self._detect_unusual_access_patterns(logs))
        
        # Anomaly 2: Privilege escalation chains
        anomalies.extend(await self._detect_privilege_escalation_chains(logs))
        
        # Anomaly 3: Data exfiltration patterns
        anomalies.extend(await self._detect_data_exfiltration_patterns(logs))
        
        # Anomaly 4: Defense evasion activities
        anomalies.extend(await self._detect_defense_evasion(logs))
        
        return anomalies
    
    async def _detect_unusual_access_patterns(self, logs: List[CloudTrailLog]) -> List[AnomalyDetection]:
        """Detect unusual access patterns"""
        anomalies = []
        
        # Group logs by user
        user_logs = defaultdict(list)
        for log in logs:
            user_name = log.userIdentity.userName or log.userIdentity.arn
            user_logs[user_name].append(log)
        
        for user, user_log_list in user_logs.items():
            # Check for access from multiple IPs
            ips = set(log.sourceIPAddress for log in user_log_list)
            if len(ips) > 5:
                anomalies.append(AnomalyDetection(
                    anomaly_id=f"multi-ip-{user}",
                    timestamp=datetime.utcnow(),
                    severity="medium",
                    anomaly_type="unusual_access_pattern",
                    description=f"User {user} accessed from {len(ips)} different IPs",
                    related_logs=user_log_list[:5],
                    indicators={
                        "user": user,
                        "ip_count": len(ips),
                        "ips": list(ips)[:10]
                    }
                ))
            
            # Check for unusual time access
            hours = [datetime.fromisoformat(log.eventTime.replace('Z', '+00:00')).hour 
                    for log in user_log_list]
            night_access = sum(1 for h in hours if h < 6 or h > 22)
            if night_access > len(hours) * 0.5:
                anomalies.append(AnomalyDetection(
                    anomaly_id=f"night-access-{user}",
                    timestamp=datetime.utcnow(),
                    severity="low",
                    anomaly_type="unusual_access_pattern",
                    description=f"User {user} has {night_access} night-time accesses",
                    related_logs=user_log_list[:5],
                    indicators={
                        "user": user,
                        "night_access_count": night_access,
                        "total_access": len(hours)
                    }
                ))
        
        return anomalies
    
    async def _detect_privilege_escalation_chains(self, logs: List[CloudTrailLog]) -> List[AnomalyDetection]:
        """Detect privilege escalation chains"""
        anomalies = []
        
        # Look for AssumeRole chains
        assume_role_logs = [log for log in logs if log.eventName == "AssumeRole"]
        
        # Group by session
        session_chains = defaultdict(list)
        for log in assume_role_logs:
            if log.responseElements:
                session_id = log.responseElements.get("assumedRoleUser", {}).get("arn", "")
                session_chains[session_id].append(log)
        
        # Detect chains
        for session_id, chain_logs in session_chains.items():
            if len(chain_logs) > 2:
                anomalies.append(AnomalyDetection(
                    anomaly_id=f"role-chain-{session_id[:20]}",
                    timestamp=datetime.utcnow(),
                    severity="high",
                    anomaly_type="privilege_escalation",
                    description=f"Role assumption chain detected with {len(chain_logs)} hops",
                    related_logs=chain_logs,
                    indicators={
                        "chain_length": len(chain_logs),
                        "roles": [log.requestParameters.get("roleArn", "") 
                                 for log in chain_logs if log.requestParameters]
                    }
                ))
        
        return anomalies
    
    async def _detect_data_exfiltration_patterns(self, logs: List[CloudTrailLog]) -> List[AnomalyDetection]:
        """Detect data exfiltration patterns"""
        anomalies = []
        
        # Look for S3 GetObject spikes
        s3_gets = [log for log in logs 
                  if log.eventName == "GetObject" and log.eventSource == "s3.amazonaws.com"]
        
        # Group by user and time window
        user_windows = defaultdict(lambda: defaultdict(int))
        for log in s3_gets:
            user = log.userIdentity.userName or log.userIdentity.arn
            log_time = datetime.fromisoformat(log.eventTime.replace('Z', '+00:00'))
            window = log_time.replace(minute=0, second=0, microsecond=0)
            user_windows[user][window] += 1
        
        # Detect spikes
        for user, windows in user_windows.items():
            max_count = max(windows.values())
            avg_count = statistics.mean(windows.values())
            
            if max_count > avg_count * 5 and max_count > 50:
                spike_window = max(windows, key=windows.get)
                spike_logs = [log for log in s3_gets 
                             if (log.userIdentity.userName or log.userIdentity.arn) == user
                             and datetime.fromisoformat(log.eventTime.replace('Z', '+00:00')).replace(minute=0, second=0, microsecond=0) == spike_window]
                
                anomalies.append(AnomalyDetection(
                    anomaly_id=f"s3-spike-{user[:20]}-{spike_window.timestamp()}",
                    timestamp=datetime.utcnow(),
                    severity="critical",
                    anomaly_type="data_exfiltration",
                    description=f"S3 GetObject spike detected for user {user}: {max_count} requests in one hour",
                    related_logs=spike_logs[:10],
                    indicators={
                        "user": user,
                        "spike_count": max_count,
                        "average_count": avg_count,
                        "spike_time": spike_window.isoformat()
                    }
                ))
        
        return anomalies
    
    async def _detect_defense_evasion(self, logs: List[CloudTrailLog]) -> List[AnomalyDetection]:
        """Detect defense evasion activities"""
        anomalies = []
        
        # Critical security service modifications
        critical_events = {
            "StopLogging": "CloudTrail logging disabled",
            "DeleteTrail": "CloudTrail deleted",
            "DisableSecurityHub": "Security Hub disabled",
            "DeleteDetector": "GuardDuty detector deleted",
            "StopMonitoringMembers": "GuardDuty monitoring stopped"
        }
        
        for log in logs:
            if log.eventName in critical_events:
                anomalies.append(AnomalyDetection(
                    anomaly_id=f"defense-evasion-{log.eventID}",
                    timestamp=datetime.fromisoformat(log.eventTime.replace('Z', '+00:00')),
                    severity="critical",
                    anomaly_type="defense_evasion",
                    description=critical_events[log.eventName],
                    related_logs=[log],
                    indicators={
                        "event": log.eventName,
                        "user": log.userIdentity.userName or log.userIdentity.arn,
                        "source_ip": log.sourceIPAddress,
                        "region": log.awsRegion
                    }
                ))
        
        return anomalies
    
    async def get_time_series_analysis(
        self, 
        metric: str = "event_count",
        granularity: str = "hour",
        filters: Optional[LogFilter] = None
    ) -> List[TimeSeriesData]:
        """Get time series data for visualization"""
        if not filters:
            filters = LogFilter(limit=10000)
        
        logs = await self.log_reader.get_logs(filters)
        
        # Determine time bucket function
        if granularity == "hour":
            bucket_fn = lambda dt: dt.replace(minute=0, second=0, microsecond=0)
        elif granularity == "day":
            bucket_fn = lambda dt: dt.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            bucket_fn = lambda dt: dt.replace(minute=0, second=0, microsecond=0)
        
        # Count by time bucket
        buckets = defaultdict(int)
        for log in logs:
            log_time = datetime.fromisoformat(log.eventTime.replace('Z', '+00:00'))
            bucket = bucket_fn(log_time)
            buckets[bucket] += 1
        
        # Convert to TimeSeriesData
        return [
            TimeSeriesData(timestamp=ts, count=count)
            for ts, count in sorted(buckets.items())
        ]