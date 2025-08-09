from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any, Union
from datetime import datetime
from enum import Enum

class UserIdentityType(str, Enum):
    IAM_USER = "IAMUser"
    ASSUMED_ROLE = "AssumedRole"
    FEDERATED_USER = "FederatedUser"
    ROOT = "Root"
    AWS_SERVICE = "AWSService"

class SessionContext(BaseModel):
    sessionIssuer: Optional[Dict[str, Any]] = None
    attributes: Optional[Dict[str, Any]] = None
    ec2RoleDelivery: Optional[str] = None

class UserIdentity(BaseModel):
    type: UserIdentityType
    principalId: str
    arn: str
    accountId: str
    userName: Optional[str] = None
    accessKeyId: Optional[str] = None
    sessionContext: Optional[SessionContext] = None

class LogTags(BaseModel):
    usecase: str
    description: str
    technique_id: str

class CloudTrailLog(BaseModel):
    eventVersion: str
    userIdentity: UserIdentity
    eventTime: str
    eventSource: str
    eventName: str
    awsRegion: str
    sourceIPAddress: str
    userAgent: str
    requestID: str
    eventID: str
    readOnly: bool
    eventType: str
    managementEvent: bool
    recipientAccountId: str
    errorCode: Optional[str] = None
    errorMessage: Optional[str] = None
    requestParameters: Optional[Dict[str, Any]] = None
    responseElements: Optional[Dict[str, Any]] = None
    additionalEventData: Optional[Dict[str, Any]] = None
    resources: Optional[List[Dict[str, Any]]] = None
    tags: Optional[LogTags] = None

class LogFilter(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    event_names: Optional[List[str]] = None
    event_sources: Optional[List[str]] = None
    user_names: Optional[List[str]] = None
    source_ips: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    technique_ids: Optional[List[str]] = None
    is_malicious: Optional[bool] = None
    limit: int = Field(default=1000, le=10000)
    offset: int = Field(default=0, ge=0)

class LogStatistics(BaseModel):
    total_logs: int
    malicious_logs: int
    normal_logs: int
    malicious_breakdown: Dict[str, int]
    time_range: Dict[str, Union[datetime, str]]
    top_users: List[Dict[str, Any]]
    top_ips: List[Dict[str, Any]]
    top_event_names: List[Dict[str, Any]]
    regions: Dict[str, int]

class TimeSeriesData(BaseModel):
    timestamp: datetime
    count: int
    category: Optional[str] = None

class UseCaseAnalytics(BaseModel):
    technique_id: str
    usecase: str
    description: str
    total_events: int
    unique_users: int
    unique_ips: int
    time_distribution: List[TimeSeriesData]
    event_breakdown: Dict[str, int]
    geographic_distribution: Dict[str, int]
    risk_score: float

class AnomalyDetection(BaseModel):
    anomaly_id: str
    timestamp: datetime
    severity: str  # low, medium, high, critical
    anomaly_type: str
    description: str
    related_logs: List[CloudTrailLog]
    indicators: Dict[str, Any]

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    offset: int
    limit: int
    has_more: bool