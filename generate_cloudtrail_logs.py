#!/usr/bin/env python3
"""
AWS CloudTrail Log Generator for MITRE ATT&CK Use Cases
Generates synthetic CloudTrail logs based on threat detection use cases
"""

import json
import random
import uuid
import hashlib
import gzip
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import ipaddress

# Known Tor Exit Nodes and VPN IPs (sample list - in production, use a comprehensive threat intel feed)
TOR_EXIT_NODES = [
    "185.220.101.45", "185.220.101.46", "185.220.101.48", "185.220.101.49",
    "185.220.102.242", "185.220.102.243", "185.220.102.244", "185.220.102.245",
    "23.129.64.210", "23.129.64.211", "23.129.64.212", "23.129.64.213",
    "199.87.154.255", "192.42.116.16", "162.247.74.74", "162.247.74.27",
    "178.17.174.14", "109.70.100.21", "51.75.64.23", "51.255.106.85",
    "185.100.87.206", "185.100.87.207", "185.100.87.208", "185.100.87.209"
]

VPN_IPS = [
    "45.83.64.1", "45.83.65.2", "45.83.66.3", "45.83.67.4",  # ExpressVPN
    "89.187.178.1", "89.187.178.2", "89.187.178.3", "89.187.178.4",  # NordVPN
    "198.8.94.170", "198.8.94.171", "198.8.94.172", "198.8.94.173",  # CyberGhost
    "209.58.188.13", "209.58.188.14", "209.58.188.15", "209.58.188.16",  # PIA
    "37.19.205.206", "37.19.205.207", "37.19.205.208", "37.19.205.209"  # Surfshark
]

# High-risk countries for geographic anomaly detection
HIGH_RISK_COUNTRIES = ["CN", "RU", "KP", "IR"]
SUSPICIOUS_REGIONS = ["af-south-1", "me-south-1", "eu-south-1", "ap-south-1"]

# Normal operating regions/IPs for the simulated organization
NORMAL_IPS = [
    "54.239.28.85", "52.94.228.167", "52.219.96.224",  # AWS IPs
    "203.255.254.100", "211.110.60.100", "125.131.190.100",  # Korean IPs
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"  # Private IPs
]

class CloudTrailLogGenerator:
    def __init__(self):
        self.logs = []
        self.account_id = "123456789012"
        self.start_date = datetime.utcnow() - timedelta(days=180)
        self.end_date = datetime.utcnow()
        
        # Sample users and roles
        self.iam_users = [
            "admin-user", "developer-1", "developer-2", "ops-user", 
            "readonly-user", "service-account-1", "contractor-temp"
        ]
        
        self.iam_roles = [
            "AdminRole", "DeveloperRole", "ReadOnlyRole", "EC2-SSM-Role",
            "Lambda-Execution-Role", "CrossAccountRole", "ServiceRole"
        ]
        
        self.ec2_instances = [f"i-0{i:015x}" for i in range(1, 20)]
        self.s3_buckets = ["production-data", "backup-files", "logs-bucket", 
                          "public-assets", "sensitive-documents", "config-bucket"]
        self.rds_instances = ["prod-mysql", "dev-postgres", "analytics-db"]
        
    def generate_timestamp(self, specific_date: Optional[datetime] = None) -> str:
        """Generate a random timestamp within the specified date range"""
        if specific_date:
            return specific_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        time_between = self.end_date - self.start_date
        days_between = time_between.days
        random_days = random.randrange(days_between)
        random_seconds = random.randrange(86400)
        
        random_date = self.start_date + timedelta(days=random_days, seconds=random_seconds)
        return random_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    def generate_request_id(self) -> str:
        """Generate a realistic AWS request ID"""
        return str(uuid.uuid4())
    
    def generate_event_id(self) -> str:
        """Generate a realistic CloudTrail event ID"""
        return str(uuid.uuid4())
    
    def get_random_ip(self, use_suspicious: bool = False, use_tor: bool = False, 
                     use_vpn: bool = False) -> str:
        """Generate or select an IP address based on requirements"""
        if use_tor:
            return random.choice(TOR_EXIT_NODES)
        elif use_vpn:
            return random.choice(VPN_IPS)
        elif use_suspicious:
            # Generate IPs from suspicious countries/regions
            suspicious_ips = [
                f"223.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",  # China
                f"91.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",   # Russia
                f"175.45.{random.randint(0,255)}.{random.randint(0,255)}",  # North Korea
                f"2.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"     # Iran
            ]
            return random.choice(suspicious_ips)
        else:
            # Return normal IP
            if random.random() < 0.7:
                # 70% chance of AWS IP
                return random.choice(NORMAL_IPS[:3])
            else:
                # 30% chance of office IP
                return random.choice(NORMAL_IPS[3:6])
    
    def generate_user_agent(self, suspicious: bool = False) -> str:
        """Generate a user agent string"""
        normal_agents = [
            "aws-cli/2.13.0 Python/3.11.4 Darwin/22.5.0 exe/x86_64 prompt/off command/s3.ls",
            "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0 exe/x86_64 prompt/off command/iam.list-users",
            "AWS-Console/1.0",
            "Boto3/1.28.57 Python/3.9.7 Linux/5.4.0-42-generic Botocore/1.31.57",
            "aws-sdk-go/1.44.122 (go1.19.3; linux; amd64)"
        ]
        
        suspicious_agents = [
            "python-requests/2.31.0",
            "curl/7.88.1",
            "Boto3/1.18.0 Python/2.7.18 Linux/4.9.0-6-amd64 Botocore/1.21.0",
            "custom-scanner/1.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ]
        
        return random.choice(suspicious_agents if suspicious else normal_agents)
    
    def create_base_event(self, event_name: str, event_source: str, 
                         source_ip: str, user_identity: Dict[str, Any],
                         timestamp: str, error_code: Optional[str] = None,
                         request_parameters: Optional[Dict] = None,
                         response_elements: Optional[Dict] = None,
                         read_only: bool = True) -> Dict[str, Any]:
        """Create a base CloudTrail event"""
        event = {
            "eventVersion": "1.08",
            "userIdentity": user_identity,
            "eventTime": timestamp,
            "eventSource": event_source,
            "eventName": event_name,
            "awsRegion": random.choice(["us-east-1", "us-west-2", "ap-northeast-2", "eu-west-1"]),
            "sourceIPAddress": source_ip,
            "userAgent": self.generate_user_agent("suspicious" in str(user_identity)),
            "requestID": self.generate_request_id(),
            "eventID": self.generate_event_id(),
            "readOnly": read_only,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": self.account_id
        }
        
        if error_code:
            event["errorCode"] = error_code
            event["errorMessage"] = self.get_error_message(error_code)
        
        if request_parameters:
            event["requestParameters"] = request_parameters
            
        if response_elements:
            event["responseElements"] = response_elements
            
        return event
    
    def get_error_message(self, error_code: str) -> str:
        """Get appropriate error message for error code"""
        error_messages = {
            "AccessDenied": "User is not authorized to perform this action",
            "UnauthorizedOperation": "You are not authorized to perform this operation",
            "InvalidUserID.NotFound": "The specified user does not exist",
            "NoSuchBucket": "The specified bucket does not exist",
            "TokenRefreshRequired": "The security token included in the request is expired"
        }
        return error_messages.get(error_code, "An error occurred")
    
    def add_tags_to_event(self, event: Dict[str, Any], usecase_name: str, 
                         description: str, technique_id: str) -> Dict[str, Any]:
        """Add tags field to the event for tracking use cases"""
        event["tags"] = {
            "usecase": usecase_name,
            "description": description,
            "technique_id": technique_id
        }
        return event
    
    # Use Case 1.1: Valid Accounts - Compromised IAM User Credentials
    def generate_compromised_credentials_logs(self, count: int = 100):
        """Generate logs for compromised IAM user credentials"""
        usecase_name = "Valid Accounts - Compromised IAM User Credentials"
        description = "Attacker uses stolen IAM user credentials for initial access"
        technique_id = "T1078.004"
        
        for i in range(count):
            # Select a compromised user
            compromised_user = random.choice(self.iam_users)
            
            # Generate failed login attempts (brute force)
            if random.random() < 0.3:  # 30% chance of showing brute force attempts
                for _ in range(random.randint(3, 10)):
                    timestamp = self.generate_timestamp()
                    source_ip = self.get_random_ip(use_suspicious=True)
                    
                    user_identity = {
                        "type": "IAMUser",
                        "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                        "arn": f"arn:aws:iam::{self.account_id}:user/{compromised_user}",
                        "accountId": self.account_id,
                        "userName": compromised_user
                    }
                    
                    event = self.create_base_event(
                        event_name="ConsoleLogin",
                        event_source="signin.amazonaws.com",
                        source_ip=source_ip,
                        user_identity=user_identity,
                        timestamp=timestamp,
                        error_code="Failed authentication",
                        read_only=False
                    )
                    
                    event["additionalEventData"] = {
                        "LoginTo": f"https://console.aws.amazon.com/console/home?region={event['awsRegion']}",
                        "MobileVersion": "No",
                        "MFAUsed": "No"
                    }
                    
                    event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                    self.logs.append(event)
            
            # Successful login from suspicious location
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_tor=random.random() < 0.3, 
                                          use_vpn=random.random() < 0.3,
                                          use_suspicious=random.random() < 0.4)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{compromised_user}",
                "accountId": self.account_id,
                "userName": compromised_user
            }
            
            # Console login
            event = self.create_base_event(
                event_name="ConsoleLogin",
                event_source="signin.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=False
            )
            
            event["responseElements"] = {"ConsoleLogin": "Success"}
            event["additionalEventData"] = {
                "LoginTo": f"https://console.aws.amazon.com/console/home?region={event['awsRegion']}",
                "MobileVersion": "No",
                "MFAUsed": "No"  # Suspicious - no MFA
            }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
            
            # Follow-up reconnaissance activity
            base_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            recon_events = ["ListUsers", "ListRoles", "ListBuckets", "DescribeInstances", 
                           "GetAccountAuthorizationDetails", "ListAccessKeys"]
            
            for j, recon_event in enumerate(random.sample(recon_events, random.randint(2, 5))):
                new_timestamp = (base_time + timedelta(minutes=j+1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                
                event_sources = {
                    "ListUsers": "iam.amazonaws.com",
                    "ListRoles": "iam.amazonaws.com",
                    "ListBuckets": "s3.amazonaws.com",
                    "DescribeInstances": "ec2.amazonaws.com",
                    "GetAccountAuthorizationDetails": "iam.amazonaws.com",
                    "ListAccessKeys": "iam.amazonaws.com"
                }
                
                event = self.create_base_event(
                    event_name=recon_event,
                    event_source=event_sources[recon_event],
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=new_timestamp,
                    read_only=True
                )
                
                # Add some failed attempts
                if random.random() < 0.2:
                    event["errorCode"] = "AccessDenied"
                
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                self.logs.append(event)
    
    # Use Case 1.2: Access from Unusual Geographic Locations
    def generate_geographic_anomaly_logs(self, count: int = 100):
        """Generate logs for access from unusual geographic locations"""
        usecase_name = "Access from Unusual Geographic Locations"
        description = "Access from high-risk countries or unexpected regions"
        technique_id = "T1078.004"
        
        for i in range(count):
            # Choose between IAM user or assumed role
            if random.random() < 0.6:
                # IAM User
                user = random.choice(self.iam_users)
                user_identity = {
                    "type": "IAMUser",
                    "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                    "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                    "accountId": self.account_id,
                    "userName": user
                }
            else:
                # Assumed Role
                role = random.choice(self.iam_roles)
                session_name = f"session-{random.randint(1000, 9999)}"
                user_identity = {
                    "type": "AssumedRole",
                    "principalId": f"AROA{random.randint(100000000000, 999999999999)}:{session_name}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role}/{session_name}",
                    "accountId": self.account_id,
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": f"AROA{random.randint(100000000000, 999999999999)}",
                            "arn": f"arn:aws:iam::{self.account_id}:role/{role}",
                            "accountId": self.account_id,
                            "userName": role
                        },
                        "attributes": {
                            "mfaAuthenticated": "false",
                            "creationDate": self.generate_timestamp()
                        }
                    }
                }
            
            # Generate IP from suspicious location
            source_ip = self.get_random_ip(use_suspicious=True)
            
            # Generate various API calls
            api_calls = [
                ("ConsoleLogin", "signin.amazonaws.com", False),
                ("AssumeRole", "sts.amazonaws.com", False),
                ("ListBuckets", "s3.amazonaws.com", True),
                ("GetObject", "s3.amazonaws.com", True),
                ("RunInstances", "ec2.amazonaws.com", False),
                ("CreateAccessKey", "iam.amazonaws.com", False)
            ]
            
            event_name, event_source, read_only = random.choice(api_calls)
            timestamp = self.generate_timestamp()
            
            event = self.create_base_event(
                event_name=event_name,
                event_source=event_source,
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=read_only
            )
            
            # Add specific parameters for certain events
            if event_name == "AssumeRole":
                event["requestParameters"] = {
                    "roleArn": f"arn:aws:iam::{self.account_id}:role/{random.choice(self.iam_roles)}",
                    "roleSessionName": f"suspicious-session-{random.randint(1000, 9999)}"
                }
            elif event_name == "GetObject":
                event["requestParameters"] = {
                    "bucketName": random.choice(self.s3_buckets),
                    "key": f"sensitive/data-{random.randint(1, 100)}.csv"
                }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 1.3: Exposed EKS Cluster API Endpoint
    def generate_eks_exposure_logs(self, count: int = 100):
        """Generate logs for exposed EKS cluster API endpoints"""
        usecase_name = "Exposed EKS Cluster API Endpoint"
        description = "EKS cluster API endpoint changed from private to public"
        technique_id = "T1190"
        
        eks_clusters = ["production-cluster", "dev-cluster", "staging-cluster", "analytics-cluster"]
        
        for i in range(count):
            cluster_name = random.choice(eks_clusters)
            user = random.choice(self.iam_users)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip()
            
            # UpdateClusterConfig event
            event = self.create_base_event(
                event_name="UpdateClusterConfig",
                event_source="eks.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=False
            )
            
            # Make endpoint public with permissive access
            event["requestParameters"] = {
                "name": cluster_name,
                "resourcesVpcConfig": {
                    "endpointPublicAccess": True,
                    "publicAccessCidrs": ["0.0.0.0/0"] if random.random() < 0.7 else ["10.0.0.0/8", "172.16.0.0/12"]
                }
            }
            
            event["responseElements"] = {
                "update": {
                    "id": str(uuid.uuid4()),
                    "status": "InProgress",
                    "type": "EndpointAccessUpdate"
                }
            }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 2.1: Create New IAM User for Backdoor Access
    def generate_backdoor_user_logs(self, count: int = 100):
        """Generate logs for creating backdoor IAM users"""
        usecase_name = "Create New IAM User for Backdoor Access"
        description = "Attacker creates new IAM user to maintain access"
        technique_id = "T1098"
        
        suspicious_usernames = ["backup-admin", "admin-temp", "support-user", "service-backup",
                               "recovery-user", "emergency-access", "system-admin2"]
        
        for i in range(count):
            attacker_user = random.choice(self.iam_users)
            new_username = random.choice(suspicious_usernames) + f"-{random.randint(100, 999)}"
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{attacker_user}",
                "accountId": self.account_id,
                "userName": attacker_user
            }
            
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.5)
            
            # CreateUser event
            event1 = self.create_base_event(
                event_name="CreateUser",
                event_source="iam.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event1["requestParameters"] = {"userName": new_username}
            event1["responseElements"] = {
                "user": {
                    "path": "/",
                    "userName": new_username,
                    "userId": f"AIDA{random.randint(100000000000, 999999999999)}",
                    "arn": f"arn:aws:iam::{self.account_id}:user/{new_username}",
                    "createDate": base_time.isoformat() + "Z"
                }
            }
            
            event1 = self.add_tags_to_event(event1, usecase_name, description, technique_id)
            self.logs.append(event1)
            
            # CreateLoginProfile event
            event2_time = base_time + timedelta(seconds=random.randint(5, 30))
            event2 = self.create_base_event(
                event_name="CreateLoginProfile",
                event_source="iam.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=event2_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event2["requestParameters"] = {
                "userName": new_username,
                "passwordResetRequired": False
            }
            
            event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
            self.logs.append(event2)
            
            # CreateAccessKey event
            event3_time = event2_time + timedelta(seconds=random.randint(5, 30))
            event3 = self.create_base_event(
                event_name="CreateAccessKey",
                event_source="iam.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=event3_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event3["requestParameters"] = {"userName": new_username}
            event3["responseElements"] = {
                "accessKey": {
                    "userName": new_username,
                    "accessKeyId": f"AKIA{random.randint(100000000000, 999999999999)}",
                    "status": "Active",
                    "createDate": event3_time.isoformat() + "Z"
                }
            }
            
            event3 = self.add_tags_to_event(event3, usecase_name, description, technique_id)
            self.logs.append(event3)
            
            # AttachUserPolicy event
            event4_time = event3_time + timedelta(seconds=random.randint(5, 30))
            event4 = self.create_base_event(
                event_name="AttachUserPolicy",
                event_source="iam.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=event4_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            policies = [
                "arn:aws:iam::aws:policy/AdministratorAccess",
                "arn:aws:iam::aws:policy/PowerUserAccess",
                "arn:aws:iam::aws:policy/IAMFullAccess"
            ]
            
            event4["requestParameters"] = {
                "userName": new_username,
                "policyArn": random.choice(policies)
            }
            
            event4 = self.add_tags_to_event(event4, usecase_name, description, technique_id)
            self.logs.append(event4)
    
    # Use Case 2.2: Modify IAM Role Trust Policy
    def generate_trust_policy_modification_logs(self, count: int = 100):
        """Generate logs for modifying IAM role trust policies"""
        usecase_name = "Modify IAM Role Trust Policy"
        description = "Attacker modifies role trust policy to allow external account"
        technique_id = "T1098"
        
        external_accounts = ["999888777666", "111222333444", "555666777888"]
        
        for i in range(count):
            role = random.choice(self.iam_roles)
            user = random.choice(self.iam_users)
            external_account = random.choice(external_accounts)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.4)
            
            event = self.create_base_event(
                event_name="UpdateAssumeRolePolicy",
                event_source="iam.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=False
            )
            
            # Trust policy allowing external account
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": [
                                f"arn:aws:iam::{self.account_id}:root",
                                f"arn:aws:iam::{external_account}:root"  # External account
                            ]
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            event["requestParameters"] = {
                "roleName": role,
                "policyDocument": json.dumps(trust_policy)
            }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 2.3: Low and Slow Periodic Access
    def generate_low_slow_access_logs(self, count: int = 100):
        """Generate logs for low and slow periodic access patterns"""
        usecase_name = "Low and Slow Periodic Access"
        description = "Attacker maintains access with periodic low-frequency activity"
        technique_id = "T1078"
        
        # Create patterns of access exactly every 24 hours (+/- few minutes)
        compromised_keys = [f"AKIA{random.randint(100000000000, 999999999999)}" for _ in range(5)]
        
        for key in compromised_keys:
            user = random.choice(self.iam_users)
            base_time = self.start_date + timedelta(days=random.randint(0, 90))
            
            # Generate periodic accesses
            for day in range(count // len(compromised_keys)):
                # Add some randomness to make it look automated but not perfect
                jitter_minutes = random.randint(-5, 5)
                access_time = base_time + timedelta(days=day, minutes=jitter_minutes)
                
                if access_time > self.end_date:
                    break
                
                user_identity = {
                    "type": "IAMUser",
                    "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                    "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                    "accountId": self.account_id,
                    "accessKeyId": key,
                    "userName": user
                }
                
                # Simple reconnaissance call
                event = self.create_base_event(
                    event_name="GetCallerIdentity",
                    event_source="sts.amazonaws.com",
                    source_ip=self.get_random_ip(use_vpn=True),
                    user_identity=user_identity,
                    timestamp=access_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=True
                )
                
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                self.logs.append(event)
                
                # Sometimes add a List operation
                if random.random() < 0.3:
                    list_operations = ["ListBuckets", "ListUsers", "DescribeInstances"]
                    list_op = random.choice(list_operations)
                    list_time = access_time + timedelta(seconds=random.randint(10, 60))
                    
                    event_sources = {
                        "ListBuckets": "s3.amazonaws.com",
                        "ListUsers": "iam.amazonaws.com",
                        "DescribeInstances": "ec2.amazonaws.com"
                    }
                    
                    event2 = self.create_base_event(
                        event_name=list_op,
                        event_source=event_sources[list_op],
                        source_ip=self.get_random_ip(use_vpn=True),
                        user_identity=user_identity,
                        timestamp=list_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        read_only=True
                    )
                    
                    event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
                    self.logs.append(event2)
    
    # Use Case 3.1: Exploiting Misconfigured IAM Policies
    def generate_privilege_escalation_logs(self, count: int = 100):
        """Generate logs for privilege escalation via misconfigured policies"""
        usecase_name = "Exploiting Misconfigured IAM Policies"
        description = "User exploits misconfig to grant themselves admin access"
        technique_id = "T1068"
        
        for i in range(count):
            user = random.choice(self.iam_users[2:])  # Non-admin users
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            source_ip = self.get_random_ip()
            
            # CreatePolicyVersion
            event1 = self.create_base_event(
                event_name="CreatePolicyVersion",
                event_source="iam.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }]
            }
            
            event1["requestParameters"] = {
                "policyArn": f"arn:aws:iam::{self.account_id}:policy/CustomUserPolicy",
                "policyDocument": json.dumps(policy_document),
                "setAsDefault": True
            }
            
            event1 = self.add_tags_to_event(event1, usecase_name, description, technique_id)
            self.logs.append(event1)
            
            # AttachUserPolicy
            event2_time = base_time + timedelta(seconds=random.randint(10, 60))
            event2 = self.create_base_event(
                event_name="AttachUserPolicy",
                event_source="iam.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=event2_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event2["requestParameters"] = {
                "userName": user,
                "policyArn": f"arn:aws:iam::{self.account_id}:policy/CustomUserPolicy"
            }
            
            event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
            self.logs.append(event2)
    
    # Use Case 3.2: Malicious Role Assumption via STS
    def generate_malicious_assume_role_logs(self, count: int = 100):
        """Generate logs for malicious role assumption"""
        usecase_name = "Malicious Role Assumption via STS"
        description = "Attacker uses AssumeRole to escalate privileges"
        technique_id = "T1078.004"
        
        high_privilege_roles = ["AdminRole", "PowerUserRole", "SecurityAuditRole"]
        
        for i in range(count):
            source_user = random.choice(self.iam_users)
            target_role = random.choice(high_privilege_roles)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{source_user}",
                "accountId": self.account_id,
                "userName": source_user
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.3)
            
            # AssumeRole event
            event = self.create_base_event(
                event_name="AssumeRole",
                event_source="sts.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=False
            )
            
            session_name = f"suspicious-session-{random.randint(10000, 99999)}"
            
            event["requestParameters"] = {
                "roleArn": f"arn:aws:iam::{self.account_id}:role/{target_role}",
                "roleSessionName": session_name
            }
            
            assumed_role_id = f"AROA{random.randint(100000000000, 999999999999)}"
            event["responseElements"] = {
                "credentials": {
                    "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}",
                    "sessionToken": "FQoGZXIvYXdzE...truncated...",
                    "expiration": (datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ") + 
                                 timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                },
                "assumedRoleUser": {
                    "assumedRoleId": f"{assumed_role_id}:{session_name}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{target_role}/{session_name}"
                }
            }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
            
            # Follow-up activity with assumed role
            if random.random() < 0.7:
                assumed_identity = {
                    "type": "AssumedRole",
                    "principalId": f"{assumed_role_id}:{session_name}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{target_role}/{session_name}",
                    "accountId": self.account_id,
                    "accessKeyId": event["responseElements"]["credentials"]["accessKeyId"],
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": assumed_role_id,
                            "arn": f"arn:aws:iam::{self.account_id}:role/{target_role}",
                            "accountId": self.account_id,
                            "userName": target_role
                        },
                        "attributes": {
                            "mfaAuthenticated": "false",
                            "creationDate": timestamp
                        }
                    }
                }
                
                # Perform privileged action
                priv_actions = ["CreateUser", "PutRolePolicy", "CreateAccessKey", 
                               "AttachUserPolicy", "CreateRole"]
                action = random.choice(priv_actions)
                
                action_time = (datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ") + 
                             timedelta(minutes=random.randint(1, 10)))
                
                priv_event = self.create_base_event(
                    event_name=action,
                    event_source="iam.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=assumed_identity,
                    timestamp=action_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=False
                )
                
                priv_event = self.add_tags_to_event(priv_event, usecase_name, description, technique_id)
                self.logs.append(priv_event)
    
    # Use Case 3.3: Cross-Account Access via Assumed Role
    def generate_cross_account_assumption_logs(self, count: int = 100):
        """Generate logs for cross-account role assumption"""
        usecase_name = "Cross-Account Access via Assumed Role Exploitation"
        description = "Attacker uses role assumption to access different account"
        technique_id = "T1078.004"
        
        target_accounts = ["999888777666", "111222333444", "555666777888"]
        
        for i in range(count):
            source_role = random.choice(self.iam_roles)
            target_account = random.choice(target_accounts)
            target_role = random.choice(["CrossAccountAdminRole", "ExternalAuditorRole", 
                                        "PartnerAccessRole", "VendorRole"])
            
            # Source identity (already assumed role)
            session_name = f"initial-session-{random.randint(1000, 9999)}"
            user_identity = {
                "type": "AssumedRole",
                "principalId": f"AROA{random.randint(100000000000, 999999999999)}:{session_name}",
                "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{source_role}/{session_name}",
                "accountId": self.account_id,
                "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": f"AROA{random.randint(100000000000, 999999999999)}",
                        "arn": f"arn:aws:iam::{self.account_id}:role/{source_role}",
                        "accountId": self.account_id,
                        "userName": source_role
                    },
                    "attributes": {
                        "mfaAuthenticated": "false",
                        "creationDate": self.generate_timestamp()
                    }
                }
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.4)
            
            # Cross-account AssumeRole
            event = self.create_base_event(
                event_name="AssumeRole",
                event_source="sts.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=False
            )
            
            cross_session_name = f"cross-account-{random.randint(10000, 99999)}"
            
            event["requestParameters"] = {
                "roleArn": f"arn:aws:iam::{target_account}:role/{target_role}",
                "roleSessionName": cross_session_name
            }
            
            event["responseElements"] = {
                "credentials": {
                    "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}",
                    "sessionToken": "FQoGZXIvYXdzE...truncated...",
                    "expiration": (datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ") + 
                                 timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                },
                "assumedRoleUser": {
                    "assumedRoleId": f"AROA{random.randint(100000000000, 999999999999)}:{cross_session_name}",
                    "arn": f"arn:aws:sts::{target_account}:assumed-role/{target_role}/{cross_session_name}"
                }
            }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 3.4: AssumeRole Chaining Attack
    def generate_role_chaining_logs(self, count: int = 100):
        """Generate logs for role chaining attacks"""
        usecase_name = "AssumeRole Chaining Attack"
        description = "Attacker chains multiple AssumeRole calls"
        technique_id = "T1078.004"
        
        for i in range(count // 3):  # Each chain will have 3+ events
            # Start with a user
            initial_user = random.choice(self.iam_users)
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.3)
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            
            # First hop: User -> Role A
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{initial_user}",
                "accountId": self.account_id,
                "userName": initial_user
            }
            
            role_a = random.choice(self.iam_roles)
            session_a = f"chain-1-{random.randint(1000, 9999)}"
            
            event1 = self.create_base_event(
                event_name="AssumeRole",
                event_source="sts.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event1["requestParameters"] = {
                "roleArn": f"arn:aws:iam::{self.account_id}:role/{role_a}",
                "roleSessionName": session_a
            }
            
            role_a_id = f"AROA{random.randint(100000000000, 999999999999)}"
            access_key_a = f"ASIA{random.randint(100000000000, 999999999999)}"
            
            event1["responseElements"] = {
                "credentials": {
                    "accessKeyId": access_key_a,
                    "sessionToken": "FQoGZXIvYXdzE...truncated...",
                    "expiration": (base_time + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                },
                "assumedRoleUser": {
                    "assumedRoleId": f"{role_a_id}:{session_a}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role_a}/{session_a}"
                }
            }
            
            event1 = self.add_tags_to_event(event1, usecase_name, description, technique_id)
            self.logs.append(event1)
            
            # Second hop: Role A -> Role B
            role_b = random.choice([r for r in self.iam_roles if r != role_a])
            session_b = f"chain-2-{random.randint(1000, 9999)}"
            hop2_time = base_time + timedelta(minutes=random.randint(1, 5))
            
            assumed_identity_a = {
                "type": "AssumedRole",
                "principalId": f"{role_a_id}:{session_a}",
                "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role_a}/{session_a}",
                "accountId": self.account_id,
                "accessKeyId": access_key_a,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": role_a_id,
                        "arn": f"arn:aws:iam::{self.account_id}:role/{role_a}",
                        "accountId": self.account_id,
                        "userName": role_a
                    },
                    "attributes": {
                        "mfaAuthenticated": "false",
                        "creationDate": base_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                }
            }
            
            event2 = self.create_base_event(
                event_name="AssumeRole",
                event_source="sts.amazonaws.com",
                source_ip=source_ip,
                user_identity=assumed_identity_a,
                timestamp=hop2_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event2["requestParameters"] = {
                "roleArn": f"arn:aws:iam::{self.account_id}:role/{role_b}",
                "roleSessionName": session_b
            }
            
            role_b_id = f"AROA{random.randint(100000000000, 999999999999)}"
            access_key_b = f"ASIA{random.randint(100000000000, 999999999999)}"
            
            event2["responseElements"] = {
                "credentials": {
                    "accessKeyId": access_key_b,
                    "sessionToken": "FQoGZXIvYXdzE...truncated...",
                    "expiration": (hop2_time + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                },
                "assumedRoleUser": {
                    "assumedRoleId": f"{role_b_id}:{session_b}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role_b}/{session_b}"
                }
            }
            
            event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
            self.logs.append(event2)
            
            # Third hop: Role B -> Role C (AdminRole)
            role_c = "AdminRole"  # Final escalation to admin
            session_c = f"chain-3-{random.randint(1000, 9999)}"
            hop3_time = hop2_time + timedelta(minutes=random.randint(1, 5))
            
            assumed_identity_b = {
                "type": "AssumedRole",
                "principalId": f"{role_b_id}:{session_b}",
                "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role_b}/{session_b}",
                "accountId": self.account_id,
                "accessKeyId": access_key_b,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": role_b_id,
                        "arn": f"arn:aws:iam::{self.account_id}:role/{role_b}",
                        "accountId": self.account_id,
                        "userName": role_b
                    },
                    "attributes": {
                        "mfaAuthenticated": "false",
                        "creationDate": hop2_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                }
            }
            
            event3 = self.create_base_event(
                event_name="AssumeRole",
                event_source="sts.amazonaws.com",
                source_ip=source_ip,
                user_identity=assumed_identity_b,
                timestamp=hop3_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event3["requestParameters"] = {
                "roleArn": f"arn:aws:iam::{self.account_id}:role/{role_c}",
                "roleSessionName": session_c
            }
            
            role_c_id = f"AROA{random.randint(100000000000, 999999999999)}"
            access_key_c = f"ASIA{random.randint(100000000000, 999999999999)}"
            
            event3["responseElements"] = {
                "credentials": {
                    "accessKeyId": access_key_c,
                    "sessionToken": "FQoGZXIvYXdzE...truncated...",
                    "expiration": (hop3_time + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                },
                "assumedRoleUser": {
                    "assumedRoleId": f"{role_c_id}:{session_c}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role_c}/{session_c}"
                }
            }
            
            event3 = self.add_tags_to_event(event3, usecase_name, description, technique_id)
            self.logs.append(event3)
    
    # Use Case 4.1: Disabling or Deleting Security Logs
    def generate_disable_logging_logs(self, count: int = 100):
        """Generate logs for disabling or deleting CloudTrail"""
        usecase_name = "Disabling or Deleting Security Logs"
        description = "Attacker disables CloudTrail to hide activities"
        technique_id = "T1562.001"
        
        trail_names = ["main-trail", "security-trail", "audit-trail", "compliance-trail"]
        
        for i in range(count):
            user = random.choice(self.iam_users)
            trail = random.choice(trail_names)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.6)
            
            # Choose action
            actions = ["StopLogging", "DeleteTrail", "UpdateTrail"]
            action = random.choice(actions)
            
            event = self.create_base_event(
                event_name=action,
                event_source="cloudtrail.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=False
            )
            
            if action == "StopLogging":
                event["requestParameters"] = {
                    "name": f"arn:aws:cloudtrail:{event['awsRegion']}:{self.account_id}:trail/{trail}"
                }
            elif action == "DeleteTrail":
                event["requestParameters"] = {
                    "name": f"arn:aws:cloudtrail:{event['awsRegion']}:{self.account_id}:trail/{trail}"
                }
            elif action == "UpdateTrail":
                # Disable logging by changing S3 bucket
                event["requestParameters"] = {
                    "name": f"arn:aws:cloudtrail:{event['awsRegion']}:{self.account_id}:trail/{trail}",
                    "s3BucketName": "non-existent-bucket-12345"
                }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 4.2: Disabling Security Services
    def generate_disable_security_services_logs(self, count: int = 100):
        """Generate logs for disabling GuardDuty and Security Hub"""
        usecase_name = "Disabling Security Services"
        description = "Attacker disables threat detection services"
        technique_id = "T1562.001"
        
        for i in range(count):
            user = random.choice(self.iam_users)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.5)
            
            # Alternate between GuardDuty and Security Hub
            if random.random() < 0.5:
                # GuardDuty
                actions = ["DeleteDetector", "UpdateDetector", "StopMonitoringMembers"]
                action = random.choice(actions)
                
                event = self.create_base_event(
                    event_name=action,
                    event_source="guardduty.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=timestamp,
                    read_only=False
                )
                
                detector_id = str(uuid.uuid4()).replace('-', '')[:32]
                
                if action == "DeleteDetector":
                    event["requestParameters"] = {"detectorId": detector_id}
                elif action == "UpdateDetector":
                    event["requestParameters"] = {
                        "detectorId": detector_id,
                        "enable": False
                    }
                elif action == "StopMonitoringMembers":
                    event["requestParameters"] = {
                        "detectorId": detector_id,
                        "accountIds": [self.account_id]
                    }
            else:
                # Security Hub
                event = self.create_base_event(
                    event_name="DisableSecurityHub",
                    event_source="securityhub.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=timestamp,
                    read_only=False
                )
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 4.3: Access from Anonymizing Services
    def generate_tor_vpn_access_logs(self, count: int = 100):
        """Generate logs for access from Tor/VPN"""
        usecase_name = "Access from Anonymizing Services (Tor/VPN)"
        description = "Attacker uses Tor or VPN to hide true IP"
        technique_id = "T1090.003"
        
        for i in range(count):
            # Alternate between Tor and VPN
            use_tor = random.random() < 0.5
            source_ip = self.get_random_ip(use_tor=use_tor, use_vpn=not use_tor)
            
            # Choose identity type
            if random.random() < 0.6:
                # IAM User
                user = random.choice(self.iam_users)
                user_identity = {
                    "type": "IAMUser",
                    "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                    "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                    "accountId": self.account_id,
                    "accessKeyId": f"AKIA{random.randint(100000000000, 999999999999)}",
                    "userName": user
                }
            else:
                # Assumed Role
                role = random.choice(self.iam_roles)
                session_name = f"tor-session-{random.randint(1000, 9999)}"
                user_identity = {
                    "type": "AssumedRole",
                    "principalId": f"AROA{random.randint(100000000000, 999999999999)}:{session_name}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role}/{session_name}",
                    "accountId": self.account_id,
                    "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}"
                }
            
            # Generate sensitive API calls
            sensitive_actions = [
                ("ConsoleLogin", "signin.amazonaws.com", False),
                ("AssumeRole", "sts.amazonaws.com", False),
                ("CreateUser", "iam.amazonaws.com", False),
                ("RunInstances", "ec2.amazonaws.com", False),
                ("GetSecretValue", "secretsmanager.amazonaws.com", True),
                ("CreateAccessKey", "iam.amazonaws.com", False)
            ]
            
            event_name, event_source, read_only = random.choice(sensitive_actions)
            timestamp = self.generate_timestamp()
            
            event = self.create_base_event(
                event_name=event_name,
                event_source=event_source,
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=read_only
            )
            
            # Add parameters for specific events
            if event_name == "RunInstances":
                event["requestParameters"] = {
                    "instanceType": "t3.large",
                    "maxCount": 5,
                    "minCount": 5
                }
            elif event_name == "GetSecretValue":
                event["requestParameters"] = {
                    "secretId": f"prod/database/credentials-{random.randint(1, 10)}"
                }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 5.1: Accessing Secrets from Secrets Manager
    def generate_secrets_access_logs(self, count: int = 100):
        """Generate logs for accessing secrets"""
        usecase_name = "Accessing Secrets from Secrets Manager"
        description = "Attacker retrieves sensitive data from Secrets Manager"
        technique_id = "T1552.005"
        
        secret_names = [
            "prod/database/master-password",
            "prod/api/external-api-key",
            "prod/rds/admin-credentials",
            "prod/service/oauth-token",
            "prod/payment/stripe-api-key",
            "prod/infra/ssh-private-key"
        ]
        
        for i in range(count):
            # Often from EC2 instance role
            if random.random() < 0.6:
                instance_id = random.choice(self.ec2_instances)
                role = "EC2-SSM-Role"
                user_identity = {
                    "type": "AssumedRole",
                    "principalId": f"AROA{random.randint(100000000000, 999999999999)}:{instance_id}",
                    "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role}/{instance_id}",
                    "accountId": self.account_id,
                    "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}"
                }
            else:
                user = random.choice(self.iam_users)
                user_identity = {
                    "type": "IAMUser",
                    "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                    "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                    "accountId": self.account_id,
                    "userName": user
                }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.3)
            
            event = self.create_base_event(
                event_name="GetSecretValue",
                event_source="secretsmanager.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=True
            )
            
            # Multiple secret access in short time is suspicious
            if random.random() < 0.4:
                # Generate burst of secret access
                base_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
                for j in range(random.randint(3, 8)):
                    secret = random.choice(secret_names)
                    burst_time = base_time + timedelta(seconds=j*10)
                    
                    burst_event = self.create_base_event(
                        event_name="GetSecretValue",
                        event_source="secretsmanager.amazonaws.com",
                        source_ip=source_ip,
                        user_identity=user_identity,
                        timestamp=burst_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        read_only=True
                    )
                    
                    burst_event["requestParameters"] = {"secretId": secret}
                    burst_event = self.add_tags_to_event(burst_event, usecase_name, description, technique_id)
                    self.logs.append(burst_event)
            else:
                event["requestParameters"] = {"secretId": random.choice(secret_names)}
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                self.logs.append(event)
    
    # Use Case 5.2: Instance Metadata Exploitation
    def generate_imds_exploitation_logs(self, count: int = 100):
        """Generate logs for IMDS credential theft"""
        usecase_name = "Instance Metadata Exploitation - Stealing IAM Credentials"
        description = "Stolen EC2 instance credentials used from external IP"
        technique_id = "T1552.005"
        
        for i in range(count):
            instance_id = random.choice(self.ec2_instances)
            role = random.choice(["EC2-SSM-Role", "EC2-App-Role", "EC2-WebServer-Role"])
            
            # The stolen credentials being used from external IP
            external_ip = self.get_random_ip(use_suspicious=True)
            
            user_identity = {
                "type": "AssumedRole",
                "principalId": f"AROA{random.randint(100000000000, 999999999999)}:{instance_id}",
                "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role}/{instance_id}",
                "accountId": self.account_id,
                "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": f"AROA{random.randint(100000000000, 999999999999)}",
                        "arn": f"arn:aws:iam::{self.account_id}:role/{role}",
                        "accountId": self.account_id,
                        "userName": role
                    },
                    "ec2RoleDelivery": "1.0",
                    "attributes": {
                        "mfaAuthenticated": "false",
                        "creationDate": self.generate_timestamp()
                    }
                }
            }
            
            timestamp = self.generate_timestamp()
            
            # Reconnaissance followed by malicious actions
            actions = [
                ("ListBuckets", "s3.amazonaws.com", True),
                ("DescribeInstances", "ec2.amazonaws.com", True),
                ("GetSecretValue", "secretsmanager.amazonaws.com", True),
                ("CreateUser", "iam.amazonaws.com", False),
                ("PutRolePolicy", "iam.amazonaws.com", False)
            ]
            
            base_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            
            for j, (event_name, event_source, read_only) in enumerate(actions[:random.randint(2, 5)]):
                action_time = base_time + timedelta(minutes=j*2)
                
                event = self.create_base_event(
                    event_name=event_name,
                    event_source=event_source,
                    source_ip=external_ip,  # Key indicator - external IP using instance creds
                    user_identity=user_identity,
                    timestamp=action_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=read_only
                )
                
                if event_name == "GetSecretValue":
                    event["requestParameters"] = {"secretId": "prod/database/credentials"}
                elif event_name == "CreateUser":
                    event["requestParameters"] = {"userName": f"backdoor-{random.randint(100, 999)}"}
                
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                self.logs.append(event)
    
    # Use Case 5.3: Malicious Use of STS Short-Term Access Keys
    def generate_sts_key_abuse_logs(self, count: int = 100):
        """Generate logs for malicious use of STS keys"""
        usecase_name = "Malicious Use of STS Short-Term Access Keys"
        description = "Attacker uses stolen STS credentials (ASIA keys)"
        technique_id = "T1078.004"
        
        for i in range(count):
            # Generate STS key
            access_key = f"ASIA{random.randint(100000000000, 999999999999)}"
            role = random.choice(self.iam_roles)
            session_name = f"stolen-session-{random.randint(10000, 99999)}"
            
            user_identity = {
                "type": "AssumedRole",
                "principalId": f"AROA{random.randint(100000000000, 999999999999)}:{session_name}",
                "arn": f"arn:aws:sts::{self.account_id}:assumed-role/{role}/{session_name}",
                "accountId": self.account_id,
                "accessKeyId": access_key,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": f"AROA{random.randint(100000000000, 999999999999)}",
                        "arn": f"arn:aws:iam::{self.account_id}:role/{role}",
                        "accountId": self.account_id,
                        "userName": role
                    },
                    "attributes": {
                        "mfaAuthenticated": "false",  # Suspicious - no MFA
                        "creationDate": self.generate_timestamp()
                    }
                }
            }
            
            # Use from suspicious IP
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.6,
                                          use_tor=random.random() < 0.2,
                                          use_vpn=random.random() < 0.2)
            
            # High volume of API calls
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            
            # Burst of reconnaissance
            recon_actions = [
                ("ListUsers", "iam.amazonaws.com"),
                ("ListRoles", "iam.amazonaws.com"),
                ("ListBuckets", "s3.amazonaws.com"),
                ("DescribeInstances", "ec2.amazonaws.com"),
                ("ListSecrets", "secretsmanager.amazonaws.com"),
                ("GetAccountAuthorizationDetails", "iam.amazonaws.com")
            ]
            
            for j in range(random.randint(5, 15)):
                event_name, event_source = random.choice(recon_actions)
                action_time = base_time + timedelta(seconds=j*5)
                
                event = self.create_base_event(
                    event_name=event_name,
                    event_source=event_source,
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=action_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=True
                )
                
                # Some fail due to permissions
                if random.random() < 0.2:
                    event["errorCode"] = "AccessDenied"
                
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                self.logs.append(event)
            
            # Follow with malicious action
            if random.random() < 0.7:
                malicious_actions = [
                    ("CreateUser", "iam.amazonaws.com"),
                    ("PutBucketPolicy", "s3.amazonaws.com"),
                    ("RunInstances", "ec2.amazonaws.com")
                ]
                
                mal_event_name, mal_event_source = random.choice(malicious_actions)
                mal_time = base_time + timedelta(minutes=random.randint(5, 20))
                
                mal_event = self.create_base_event(
                    event_name=mal_event_name,
                    event_source=mal_event_source,
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=mal_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=False
                )
                
                mal_event = self.add_tags_to_event(mal_event, usecase_name, description, technique_id)
                self.logs.append(mal_event)
    
    # Use Case 6.1: Reconnaissance of AWS Infrastructure
    def generate_reconnaissance_logs(self, count: int = 100):
        """Generate logs for infrastructure reconnaissance"""
        usecase_name = "Reconnaissance of AWS Infrastructure"
        description = "Broad reconnaissance to understand infrastructure"
        technique_id = "T1580"
        
        discovery_events = [
            ("ListUsers", "iam.amazonaws.com"),
            ("ListRoles", "iam.amazonaws.com"),
            ("ListGroups", "iam.amazonaws.com"),
            ("ListPolicies", "iam.amazonaws.com"),
            ("GetAccountAuthorizationDetails", "iam.amazonaws.com"),
            ("ListBuckets", "s3.amazonaws.com"),
            ("DescribeInstances", "ec2.amazonaws.com"),
            ("DescribeSecurityGroups", "ec2.amazonaws.com"),
            ("DescribeVpcs", "ec2.amazonaws.com"),
            ("DescribeSubnets", "ec2.amazonaws.com"),
            ("DescribeDBInstances", "rds.amazonaws.com"),
            ("ListFunctions", "lambda.amazonaws.com"),
            ("ListSecrets", "secretsmanager.amazonaws.com"),
            ("ListKeys", "kms.amazonaws.com"),
            ("DescribeLoadBalancers", "elasticloadbalancing.amazonaws.com")
        ]
        
        # Generate bursts of reconnaissance
        burst_count = count // 20  # Each burst will have ~20 events
        
        for burst in range(burst_count):
            user = random.choice(self.iam_users)
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.4)
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            # Generate 15-25 discovery calls in rapid succession
            for j in range(random.randint(15, 25)):
                event_name, event_source = random.choice(discovery_events)
                # Rapid fire - seconds apart
                action_time = base_time + timedelta(seconds=j*random.randint(2, 10))
                
                event = self.create_base_event(
                    event_name=event_name,
                    event_source=event_source,
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=action_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=True
                )
                
                # Some fail due to permissions
                if random.random() < 0.15:
                    event["errorCode"] = "AccessDenied"
                
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                self.logs.append(event)
    
    # Use Case 7.1: Creating Snapshots for Data Theft
    def generate_snapshot_exfiltration_logs(self, count: int = 100):
        """Generate logs for snapshot-based data exfiltration"""
        usecase_name = "Creating Snapshots of EBS/RDS for Data Theft"
        description = "Create and share snapshots with external account"
        technique_id = "T1213"
        
        external_accounts = ["999888777666", "111222333444", "555666777888"]
        
        for i in range(count):
            user = random.choice(self.iam_users)
            external_account = random.choice(external_accounts)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.4)
            
            # Alternate between EBS and RDS
            if random.random() < 0.5:
                # EBS Snapshot
                volume_id = f"vol-{random.randint(100000000000, 999999999999):012x}"
                snapshot_id = f"snap-{random.randint(100000000000, 999999999999):012x}"
                
                # CreateSnapshot
                event1 = self.create_base_event(
                    event_name="CreateSnapshot",
                    event_source="ec2.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=False
                )
                
                event1["requestParameters"] = {
                    "volumeId": volume_id,
                    "description": "backup-snapshot"
                }
                
                event1["responseElements"] = {
                    "snapshotId": snapshot_id,
                    "volumeId": volume_id,
                    "status": "pending"
                }
                
                event1 = self.add_tags_to_event(event1, usecase_name, description, technique_id)
                self.logs.append(event1)
                
                # ModifySnapshotAttribute
                event2_time = base_time + timedelta(minutes=random.randint(5, 30))
                event2 = self.create_base_event(
                    event_name="ModifySnapshotAttribute",
                    event_source="ec2.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=event2_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=False
                )
                
                event2["requestParameters"] = {
                    "snapshotId": snapshot_id,
                    "attributeName": "createVolumePermission",
                    "createVolumePermission": {
                        "add": [{"userId": external_account}]
                    }
                }
                
                event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
                self.logs.append(event2)
                
            else:
                # RDS Snapshot
                db_instance = random.choice(self.rds_instances)
                snapshot_id = f"rds:snapshot-{random.randint(100000, 999999)}"
                
                # CreateDBSnapshot
                event1 = self.create_base_event(
                    event_name="CreateDBSnapshot",
                    event_source="rds.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=False
                )
                
                event1["requestParameters"] = {
                    "dBInstanceIdentifier": db_instance,
                    "dBSnapshotIdentifier": snapshot_id
                }
                
                event1 = self.add_tags_to_event(event1, usecase_name, description, technique_id)
                self.logs.append(event1)
                
                # ModifyDBSnapshotAttribute
                event2_time = base_time + timedelta(minutes=random.randint(5, 30))
                event2 = self.create_base_event(
                    event_name="ModifyDBSnapshotAttribute",
                    event_source="rds.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=event2_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=False
                )
                
                event2["requestParameters"] = {
                    "dBSnapshotIdentifier": snapshot_id,
                    "attributeName": "restore",
                    "valuesToAdd": [external_account]
                }
                
                event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
                self.logs.append(event2)
    
    # Use Case 7.2: Publicly Exposing Database Snapshot
    def generate_public_snapshot_logs(self, count: int = 100):
        """Generate logs for making snapshots public"""
        usecase_name = "Publicly Exposing RDS/Database Snapshot"
        description = "Snapshot permissions modified to allow public access"
        technique_id = "T1213"
        
        for i in range(count):
            user = random.choice(self.iam_users)
            db_instance = random.choice(self.rds_instances)
            snapshot_id = f"rds:public-snapshot-{random.randint(100000, 999999)}"
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.5)
            
            event = self.create_base_event(
                event_name="ModifyDBSnapshotAttribute",
                event_source="rds.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=timestamp,
                read_only=False
            )
            
            event["requestParameters"] = {
                "dBSnapshotIdentifier": snapshot_id,
                "attributeName": "restore",
                "valuesToAdd": ["all"]  # Critical - makes it public
            }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 8.1: Making S3 Bucket Public
    def generate_public_s3_bucket_logs(self, count: int = 100):
        """Generate logs for making S3 buckets public"""
        usecase_name = "Making S3 Bucket Public for Data Retrieval"
        description = "S3 bucket policy changed to allow public access"
        technique_id = "T1537"
        
        for i in range(count):
            user = random.choice(self.iam_users)
            bucket = random.choice(self.s3_buckets)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            timestamp = self.generate_timestamp()
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.4)
            
            # Alternate between policy and ACL
            if random.random() < 0.6:
                # PutBucketPolicy
                event = self.create_base_event(
                    event_name="PutBucketPolicy",
                    event_source="s3.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=timestamp,
                    read_only=False
                )
                
                public_policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/*"
                    }]
                }
                
                event["requestParameters"] = {
                    "bucketName": bucket,
                    "bucketPolicy": json.dumps(public_policy)
                }
            else:
                # PutBucketAcl
                event = self.create_base_event(
                    event_name="PutBucketAcl",
                    event_source="s3.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=timestamp,
                    read_only=False
                )
                
                event["requestParameters"] = {
                    "bucketName": bucket,
                    "acl": ["public-read"]
                }
            
            event = self.add_tags_to_event(event, usecase_name, description, technique_id)
            self.logs.append(event)
    
    # Use Case 8.2: Data Exfiltration via EC2 Staging
    def generate_ec2_staging_logs(self, count: int = 100):
        """Generate logs for EC2-based data staging"""
        usecase_name = "Data Exfiltration via EC2 Staging Point"
        description = "EC2 instance used as relay for data exfiltration"
        technique_id = "T1041"
        
        for i in range(count):
            user = random.choice(self.iam_users)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            source_ip = self.get_random_ip()
            
            # RunInstances
            event1 = self.create_base_event(
                event_name="RunInstances",
                event_source="ec2.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            instance_id = f"i-0{random.randint(100000000000, 999999999999):015x}"
            suspicious_region = random.choice(SUSPICIOUS_REGIONS)
            
            event1["awsRegion"] = suspicious_region
            event1["requestParameters"] = {
                "instanceType": "t3.large",
                "maxCount": 1,
                "minCount": 1,
                "instancesSet": {
                    "items": [{
                        "imageId": "ami-12345678",
                        "keyName": "temp-access-key"
                    }]
                }
            }
            
            event1["responseElements"] = {
                "instancesSet": {
                    "items": [{
                        "instanceId": instance_id
                    }]
                }
            }
            
            event1 = self.add_tags_to_event(event1, usecase_name, description, technique_id)
            self.logs.append(event1)
            
            # CreateSecurityGroup
            sg_id = f"sg-{random.randint(100000000000, 999999999999):012x}"
            event2_time = base_time + timedelta(minutes=1)
            
            event2 = self.create_base_event(
                event_name="CreateSecurityGroup",
                event_source="ec2.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=event2_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event2["awsRegion"] = suspicious_region
            event2["requestParameters"] = {
                "groupName": "temp-exfil-sg",
                "groupDescription": "Temporary security group"
            }
            
            event2["responseElements"] = {"groupId": sg_id}
            
            event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
            self.logs.append(event2)
            
            # AuthorizeSecurityGroupEgress
            event3_time = event2_time + timedelta(minutes=1)
            
            event3 = self.create_base_event(
                event_name="AuthorizeSecurityGroupEgress",
                event_source="ec2.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=event3_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            event3["awsRegion"] = suspicious_region
            event3["requestParameters"] = {
                "groupId": sg_id,
                "ipPermissions": {
                    "items": [{
                        "ipProtocol": "tcp",
                        "fromPort": 443,
                        "toPort": 443,
                        "ipRanges": {
                            "items": [{"cidrIp": "0.0.0.0/0"}]  # Permissive egress
                        }
                    }]
                }
            }
            
            event3 = self.add_tags_to_event(event3, usecase_name, description, technique_id)
            self.logs.append(event3)
    
    # Use Case 8.3: Massive S3 Download
    def generate_s3_mass_download_logs(self, count: int = 100):
        """Generate logs for massive S3 data downloads"""
        usecase_name = "Data Exfiltration - Massive S3 Download"
        description = "Large volume of S3 GetObject requests"
        technique_id = "T1048"
        
        # Note: This requires S3 data events to be enabled
        for i in range(count):
            user = random.choice(self.iam_users)
            bucket = random.choice(self.s3_buckets)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            # External IP receiving the data
            source_ip = self.get_random_ip(use_suspicious=True)
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            
            # Generate burst of GetObject events
            num_downloads = random.randint(50, 200)
            for j in range(num_downloads):
                download_time = base_time + timedelta(seconds=j*0.5)  # Rapid downloads
                
                event = self.create_base_event(
                    event_name="GetObject",
                    event_source="s3.amazonaws.com",
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=download_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=True
                )
                
                # S3 data event specific fields
                event["resources"] = [{
                    "type": "AWS::S3::Object",
                    "ARN": f"arn:aws:s3:::{bucket}/sensitive-data/file-{j:04d}.csv"
                }]
                
                event["requestParameters"] = {
                    "bucketName": bucket,
                    "key": f"sensitive-data/file-{j:04d}.csv"
                }
                
                # Add response metadata
                event["additionalEventData"] = {
                    "bytesTransferred": random.randint(1000000, 50000000),  # 1MB to 50MB
                    "x-amz-server-side-encryption": "AES256"
                }
                
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                
                # Sample the logs to avoid too many entries
                if j % 10 == 0:  # Only add every 10th download
                    self.logs.append(event)
    
    # Use Case 9.1: Cryptojacking
    def generate_cryptojacking_logs(self, count: int = 100):
        """Generate logs for cryptomining via unauthorized EC2"""
        usecase_name = "Cryptojacking via Unauthorized EC2 Instances"
        description = "Large number of GPU instances for cryptocurrency mining"
        technique_id = "T1496"
        
        mining_instance_types = ["p3.2xlarge", "p3.8xlarge", "p3.16xlarge", 
                               "g4dn.xlarge", "g4dn.2xlarge", "g4dn.12xlarge"]
        mining_regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
        
        for i in range(count):
            user = random.choice(self.iam_users)
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.5)
            region = random.choice(mining_regions)
            
            # RunInstances - multiple GPU instances
            event1 = self.create_base_event(
                event_name="RunInstances",
                event_source="ec2.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            instance_count = random.randint(5, 20)
            instance_type = random.choice(mining_instance_types)
            
            event1["awsRegion"] = region
            event1["requestParameters"] = {
                "instanceType": instance_type,
                "maxCount": instance_count,
                "minCount": instance_count,
                "instancesSet": {
                    "items": [{
                        "imageId": "ami-mining-optimized",
                        "keyName": "mining-key"
                    }]
                }
            }
            
            event1 = self.add_tags_to_event(event1, usecase_name, description, technique_id)
            self.logs.append(event1)
            
            # AuthorizeSecurityGroupIngress for mining pool
            event2_time = base_time + timedelta(minutes=2)
            
            event2 = self.create_base_event(
                event_name="AuthorizeSecurityGroupIngress",
                event_source="ec2.amazonaws.com",
                source_ip=source_ip,
                user_identity=user_identity,
                timestamp=event2_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                read_only=False
            )
            
            # Common mining pool ports
            mining_ports = [3333, 4444, 5555, 8333, 9999]
            
            event2["awsRegion"] = region
            event2["requestParameters"] = {
                "groupId": f"sg-{random.randint(100000000000, 999999999999):012x}",
                "ipPermissions": {
                    "items": [{
                        "ipProtocol": "tcp",
                        "fromPort": random.choice(mining_ports),
                        "toPort": random.choice(mining_ports),
                        "ipRanges": {
                            "items": [{"cidrIp": "0.0.0.0/0"}]
                        }
                    }]
                }
            }
            
            event2 = self.add_tags_to_event(event2, usecase_name, description, technique_id)
            self.logs.append(event2)
    
    # Use Case 9.2: Destructive Activity
    def generate_destruction_logs(self, count: int = 100):
        """Generate logs for resource deletion attacks"""
        usecase_name = "Destructive Activity - Deleting Resources"
        description = "Mass deletion of critical resources"
        technique_id = "T1485"
        
        destructive_actions = [
            ("TerminateInstances", "ec2.amazonaws.com", 
             {"instancesSet": {"items": [{"instanceId": f"i-{random.randint(100000000000, 999999999999):012x}"}]}}),
            ("DeleteBucket", "s3.amazonaws.com", 
             {"bucketName": random.choice(self.s3_buckets)}),
            ("DeleteDBInstance", "rds.amazonaws.com", 
             {"dBInstanceIdentifier": random.choice(self.rds_instances), "skipFinalSnapshot": True}),
            ("DeleteVolume", "ec2.amazonaws.com", 
             {"volumeId": f"vol-{random.randint(100000000000, 999999999999):012x}"}),
            ("DeleteUser", "iam.amazonaws.com", 
             {"userName": f"user-{random.randint(100, 999)}"}),
            ("DeleteRole", "iam.amazonaws.com", 
             {"roleName": f"role-{random.randint(100, 999)}"}),
            ("DeletePolicy", "iam.amazonaws.com", 
             {"policyArn": f"arn:aws:iam::{self.account_id}:policy/custom-policy-{random.randint(100, 999)}"})
        ]
        
        # Generate bursts of deletions
        burst_count = count // 10
        
        for burst in range(burst_count):
            user = random.choice(self.iam_users)
            base_time = datetime.strptime(self.generate_timestamp(), "%Y-%m-%dT%H:%M:%SZ")
            source_ip = self.get_random_ip(use_suspicious=random.random() < 0.6)
            
            # Check if outside business hours
            hour = base_time.hour
            is_after_hours = hour < 6 or hour > 22
            
            user_identity = {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                "arn": f"arn:aws:iam::{self.account_id}:user/{user}",
                "accountId": self.account_id,
                "userName": user
            }
            
            # Generate 5-15 deletions in rapid succession
            for j in range(random.randint(5, 15)):
                event_name, event_source, params_template = random.choice(destructive_actions)
                action_time = base_time + timedelta(seconds=j*random.randint(5, 30))
                
                event = self.create_base_event(
                    event_name=event_name,
                    event_source=event_source,
                    source_ip=source_ip,
                    user_identity=user_identity,
                    timestamp=action_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    read_only=False
                )
                
                # Generate appropriate parameters
                if isinstance(params_template, dict):
                    event["requestParameters"] = params_template.copy()
                    # Update with fresh values for collections
                    if "bucketName" in params_template:
                        event["requestParameters"]["bucketName"] = random.choice(self.s3_buckets)
                    elif "dBInstanceIdentifier" in params_template:
                        event["requestParameters"]["dBInstanceIdentifier"] = random.choice(self.rds_instances)
                
                # Add metadata about timing
                if is_after_hours:
                    event["additionalEventData"] = {"afterHours": True}
                
                event = self.add_tags_to_event(event, usecase_name, description, technique_id)
                self.logs.append(event)
    
    def generate_all_logs(self):
        """Generate logs for all use cases"""
        print("Generating CloudTrail logs for all use cases...")
        
        # Update todo list
        todo_updates = []
        for i in range(1, 11):
            todo_updates.append({"id": str(i), "content": self.logs[0]["tags"]["usecase"] if i == 1 and self.logs else f"Task {i}", "status": "completed", "priority": "high"})
        
        # Initial Access
        print("1.1 Generating compromised credentials logs...")
        self.generate_compromised_credentials_logs(2500)
        
        print("1.2 Generating geographic anomaly logs...")
        self.generate_geographic_anomaly_logs(2500)
        
        print("1.3 Generating EKS exposure logs...")
        self.generate_eks_exposure_logs(2500)
        
        # Persistence
        print("2.1 Generating backdoor user logs...")
        self.generate_backdoor_user_logs(2500)
        
        print("2.2 Generating trust policy modification logs...")
        self.generate_trust_policy_modification_logs(2500)
        
        print("2.3 Generating low and slow access logs...")
        self.generate_low_slow_access_logs(2500)
        
        # Privilege Escalation
        print("3.1 Generating privilege escalation logs...")
        self.generate_privilege_escalation_logs(2500)
        
        print("3.2 Generating malicious assume role logs...")
        self.generate_malicious_assume_role_logs(2500)
        
        print("3.3 Generating cross-account assumption logs...")
        self.generate_cross_account_assumption_logs(2500)
        
        print("3.4 Generating role chaining logs...")
        self.generate_role_chaining_logs(2500)
        
        # Defense Evasion
        print("4.1 Generating disable logging logs...")
        self.generate_disable_logging_logs(2500)
        
        print("4.2 Generating disable security services logs...")
        self.generate_disable_security_services_logs(2500)
        
        print("4.3 Generating Tor/VPN access logs...")
        self.generate_tor_vpn_access_logs(2500)
        
        # Credential Access
        print("5.1 Generating secrets access logs...")
        self.generate_secrets_access_logs(2500)
        
        print("5.2 Generating IMDS exploitation logs...")
        self.generate_imds_exploitation_logs(2500)
        
        print("5.3 Generating STS key abuse logs...")
        self.generate_sts_key_abuse_logs(2500)
        
        # Discovery
        print("6.1 Generating reconnaissance logs...")
        self.generate_reconnaissance_logs(2500)
        
        # Collection
        print("7.1 Generating snapshot exfiltration logs...")
        self.generate_snapshot_exfiltration_logs(2500)
        
        print("7.2 Generating public snapshot logs...")
        self.generate_public_snapshot_logs(2500)
        
        # Exfiltration
        print("8.1 Generating public S3 bucket logs...")
        self.generate_public_s3_bucket_logs(2500)
        
        print("8.2 Generating EC2 staging logs...")
        self.generate_ec2_staging_logs(2500)
        
        print("8.3 Generating S3 mass download logs...")
        self.generate_s3_mass_download_logs(2500)
        
        # Impact
        print("9.1 Generating cryptojacking logs...")
        self.generate_cryptojacking_logs(2500)
        
        print("9.2 Generating destruction logs...")
        self.generate_destruction_logs(2500)
        
        # Shuffle logs to mix timestamps
        random.shuffle(self.logs)
        
        print(f"\nTotal logs generated: {len(self.logs)}")
        
    def save_logs(self, filename: str = "aws-cloudtrail-logs-based-on-mitre-attack-cloud.log"):
        """Save logs to file, checking size and compressing if needed"""
        print(f"\nSaving logs to {filename}...")
        
        # Write logs line by line (JSON Lines format)
        with open(filename, 'w') as f:
            for log in self.logs:
                f.write(json.dumps(log) + '\n')
        
        # Check file size
        import os
        file_size = os.path.getsize(filename)
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"File size: {file_size_mb:.2f} MB")
        
        if file_size_mb > 500:
            print("File exceeds 500MB limit. Compressing...")
            
            # Compress the file
            with open(filename, 'rb') as f_in:
                with gzip.open(filename + '.gz', 'wb') as f_out:
                    f_out.writelines(f_in)
            
            # Remove original file
            os.remove(filename)
            print(f"Compressed file saved as: {filename}.gz")
            
            compressed_size = os.path.getsize(filename + '.gz') / (1024 * 1024)
            print(f"Compressed file size: {compressed_size:.2f} MB")
        else:
            print(f"Log file saved successfully: {filename}")

def main():
    generator = CloudTrailLogGenerator()
    generator.generate_all_logs()
    generator.save_logs()

if __name__ == "__main__":
    main()