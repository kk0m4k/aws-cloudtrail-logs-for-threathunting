import gzip
import json
import os
from typing import List, Dict, Any, Optional, Generator
from datetime import datetime
import glob
from collections import defaultdict
import asyncio
from concurrent.futures import ThreadPoolExecutor

from models import CloudTrailLog, LogFilter, LogStatistics
from config import settings

class LogReaderService:
    def __init__(self):
        self.data_dir = settings.data_dir
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    def _read_gzipped_file(self, filepath: str) -> Generator[Dict[str, Any], None, None]:
        """Read gzipped JSON lines file"""
        try:
            with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        yield json.loads(line)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
    
    def _read_json_file(self, filepath: str) -> Generator[Dict[str, Any], None, None]:
        """Read plain JSON lines file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        yield json.loads(line)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
    
    def _get_log_files(self, is_malicious: Optional[bool] = None) -> List[str]:
        """Get list of log files to read"""
        files = []
        
        if is_malicious is None:
            # Get both malicious and normal logs
            files.extend(glob.glob(os.path.join(self.data_dir, "malicious", "*.json*")))
            files.extend(glob.glob(os.path.join(self.data_dir, "normal", "*.json*")))
        elif is_malicious:
            files.extend(glob.glob(os.path.join(self.data_dir, "malicious", "*.json*")))
        else:
            files.extend(glob.glob(os.path.join(self.data_dir, "normal", "*.json*")))
        
        return sorted(files)
    
    def _apply_filters(self, log: Dict[str, Any], filters: LogFilter) -> bool:
        """Apply filters to a log entry"""
        # Time filter
        if filters.start_time or filters.end_time:
            log_time = datetime.fromisoformat(log['eventTime'].replace('Z', '+00:00'))
            
            # Ensure filter times are timezone-aware (assume UTC if naive)
            start_time = filters.start_time
            if start_time and start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=log_time.tzinfo)
                
            end_time = filters.end_time
            if end_time and end_time.tzinfo is None:
                end_time = end_time.replace(tzinfo=log_time.tzinfo)
            
            if start_time and log_time < start_time:
                return False
            if end_time and log_time > end_time:
                return False
        
        # Event name filter
        if filters.event_names and log.get('eventName') not in filters.event_names:
            return False
        
        # Event source filter
        if filters.event_sources and log.get('eventSource') not in filters.event_sources:
            return False
        
        # User name filter
        if filters.user_names:
            user_name = log.get('userIdentity', {}).get('userName', '')
            if not user_name or user_name not in filters.user_names:
                return False
        
        # Source IP filter
        if filters.source_ips and log.get('sourceIPAddress') not in filters.source_ips:
            return False
        
        # Region filter
        if filters.regions and log.get('awsRegion') not in filters.regions:
            return False
        
        # Technique ID filter
        if filters.technique_ids:
            technique_id = log.get('tags', {}).get('technique_id', '')
            if not technique_id or technique_id not in filters.technique_ids:
                return False
        
        return True
    
    async def get_logs(self, filters: LogFilter) -> List[CloudTrailLog]:
        """Get logs with filters applied"""
        logs = []
        files = self._get_log_files(filters.is_malicious)
        
        # Read files in parallel
        loop = asyncio.get_event_loop()
        
        for filepath in files:
            if filepath.endswith('.gz'):
                file_logs = await loop.run_in_executor(
                    self.executor, 
                    lambda: list(self._read_gzipped_file(filepath))
                )
            else:
                file_logs = await loop.run_in_executor(
                    self.executor,
                    lambda: list(self._read_json_file(filepath))
                )
            
            # Apply filters
            for log in file_logs:
                if self._apply_filters(log, filters):
                    logs.append(log)
                    
                    # Check limit
                    if len(logs) >= filters.offset + filters.limit:
                        break
            
            if len(logs) >= filters.offset + filters.limit:
                break
        
        # Apply pagination
        start_idx = filters.offset
        end_idx = filters.offset + filters.limit
        paginated_logs = logs[start_idx:end_idx]
        
        # Convert to CloudTrailLog models
        return [CloudTrailLog(**log) for log in paginated_logs]
    
    async def get_statistics(self) -> LogStatistics:
        """Get overall log statistics"""
        stats_file = os.path.join(self.data_dir, "dataset_statistics.json")
        
        if os.path.exists(stats_file):
            with open(stats_file, 'r') as f:
                raw_stats = json.load(f)
        else:
            # Calculate statistics from logs
            raw_stats = await self._calculate_statistics()
        
        # Get additional statistics
        all_logs = await self.get_logs(LogFilter(limit=10000))
        
        # Time range
        time_range = {"start": None, "end": None}
        if all_logs:
            times = [datetime.fromisoformat(log.eventTime.replace('Z', '+00:00')) 
                    for log in all_logs]
            time_range["start"] = min(times)
            time_range["end"] = max(times)
        
        # Top users
        user_counts = defaultdict(int)
        ip_counts = defaultdict(int)
        event_counts = defaultdict(int)
        region_counts = defaultdict(int)
        
        for log in all_logs:
            user_name = log.userIdentity.userName or log.userIdentity.arn.split('/')[-1]
            user_counts[user_name] += 1
            ip_counts[log.sourceIPAddress] += 1
            event_counts[log.eventName] += 1
            region_counts[log.awsRegion] += 1
        
        top_users = sorted([{"name": k, "count": v} for k, v in user_counts.items()], 
                          key=lambda x: x["count"], reverse=True)[:10]
        top_ips = sorted([{"ip": k, "count": v} for k, v in ip_counts.items()],
                        key=lambda x: x["count"], reverse=True)[:10]
        top_events = sorted([{"event": k, "count": v} for k, v in event_counts.items()],
                           key=lambda x: x["count"], reverse=True)[:10]
        
        return LogStatistics(
            total_logs=raw_stats.get("total_logs", 0),
            malicious_logs=raw_stats.get("malicious_logs", 0),
            normal_logs=raw_stats.get("normal_logs", 0),
            malicious_breakdown=raw_stats.get("malicious_breakdown", {}),
            time_range=time_range,
            top_users=top_users,
            top_ips=top_ips,
            top_event_names=top_events,
            regions=dict(region_counts)
        )
    
    async def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate statistics from log files"""
        stats = {
            "total_logs": 0,
            "malicious_logs": 0,
            "normal_logs": 0,
            "malicious_breakdown": defaultdict(int)
        }
        
        # Count malicious logs
        malicious_files = glob.glob(os.path.join(self.data_dir, "malicious", "*.json*"))
        for filepath in malicious_files:
            if filepath.endswith('.gz'):
                for log in self._read_gzipped_file(filepath):
                    stats["malicious_logs"] += 1
                    stats["total_logs"] += 1
                    if "tags" in log and "technique_id" in log["tags"]:
                        stats["malicious_breakdown"][log["tags"]["technique_id"]] += 1
            else:
                for log in self._read_json_file(filepath):
                    stats["malicious_logs"] += 1
                    stats["total_logs"] += 1
                    if "tags" in log and "technique_id" in log["tags"]:
                        stats["malicious_breakdown"][log["tags"]["technique_id"]] += 1
        
        # Count normal logs
        normal_files = glob.glob(os.path.join(self.data_dir, "normal", "*.json*"))
        for filepath in normal_files:
            if filepath.endswith('.gz'):
                for _ in self._read_gzipped_file(filepath):
                    stats["normal_logs"] += 1
                    stats["total_logs"] += 1
            else:
                for _ in self._read_json_file(filepath):
                    stats["normal_logs"] += 1
                    stats["total_logs"] += 1
        
        stats["malicious_breakdown"] = dict(stats["malicious_breakdown"])
        return stats
    
    async def get_logs_by_technique(self, technique_id: str, limit: int = 1000) -> List[CloudTrailLog]:
        """Get logs for a specific technique ID"""
        filters = LogFilter(technique_ids=[technique_id], limit=limit)
        return await self.get_logs(filters)