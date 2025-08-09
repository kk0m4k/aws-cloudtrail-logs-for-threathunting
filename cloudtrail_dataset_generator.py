#!/usr/bin/env python3
"""
AWS CloudTrail ML Dataset Generator
Generates synthetic CloudTrail logs for ML-based threat detection training.
50% malicious logs based on MITRE ATT&CK patterns, 50% normal operational logs.
"""

import json
import random
import uuid
import gzip
import os
import sys
import time
import hashlib
import multiprocessing as mp
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import argparse
from tqdm import tqdm
import ipaddress


@dataclass
class LogConfig:
    """Configuration for log generation"""
    total_size_gb: float = 1000.0  # 1TB
    malicious_ratio: float = 0.5
    normal_ratio: float = 0.5
    chunk_size_mb: int = 100
    output_dir: str = "output"
    num_processes: int = mp.cpu_count()
    compress: bool = True
    
    
class IPGenerator:
    """Generate realistic IP addresses for different scenarios"""
    
    # Regional IP ranges (simplified examples)
    REGIONS = {
        'korea': ['223.0.0.0/11', '211.0.0.0/12', '125.128.0.0/11'],
        'usa': ['52.0.0.0/11', '54.0.0.0/10', '35.0.0.0/11'],
        'china': ['223.64.0.0/11', '175.0.0.0/11', '125.64.0.0/12'],
        'russia': ['91.64.0.0/13', '178.0.0.0/12', '2.0.0.0/11'],
        'tor_exit': ['23.129.64.0/24', '162.247.74.0/24', '185.220.101.0/24'],
        'vpn': ['209.58.188.0/24', '45.32.0.0/16', '104.238.0.0/16'],
        'aws_internal': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        'aws_service': ['52.94.0.0/12', '52.219.0.0/14', '54.239.0.0/17']
    }
    
    @classmethod
    def get_ip(cls, region: str = None, is_malicious: bool = False) -> str:
        """Generate IP address based on context"""
        if is_malicious and random.random() < 0.3:
            # 30% chance of Tor/VPN for malicious
            region = random.choice(['tor_exit', 'vpn'])
        elif region is None:
            region = random.choice(['korea', 'usa', 'aws_internal'])
            
        if region in cls.REGIONS:
            network = random.choice(cls.REGIONS[region])
            net = ipaddress.ip_network(network)
            return str(ipaddress.ip_address(net.network_address + random.randint(0, net.num_addresses - 1)))
        return "52.94.228.167"  # Default AWS IP


class UserGenerator:
    """Generate realistic AWS user identities"""
    
    USER_NAMES = {
        'admin': ['admin-user', 'root-admin', 'sysadmin', 'operations-admin'],
        'developer': ['developer-1', 'developer-2', 'dev-team', 'app-developer'],
        'service': ['service-account-1', 'automation-user', 'ci-cd-user', 'lambda-user'],
        'contractor': ['contractor-temp', 'external-user', 'vendor-access', 'third-party'],
        'ops': ['ops-user', 'devops-engineer', 'sre-team', 'monitoring-user'],
        'readonly': ['readonly-user', 'auditor', 'compliance-user', 'viewer']
    }
    
    ROLE_NAMES = [
        'AdminRole', 'DeveloperRole', 'EC2-SSM-Role', 'EC2-App-Role',
        'LambdaExecutionRole', 'ServiceRole', 'CrossAccountRole',
        'SecurityAuditRole', 'EC2-WebServer-Role', 'DataScientistRole'
    ]
    
    @classmethod
    def generate_user_identity(cls, user_type: str = 'IAMUser', is_malicious: bool = False) -> Dict[str, Any]:
        """Generate user identity structure"""
        account_id = "123456789012"
        
        if user_type == 'IAMUser':
            category = random.choice(list(cls.USER_NAMES.keys()))
            user_name = random.choice(cls.USER_NAMES[category])
            principal_id = f"AIDA{random.randint(100000000000, 999999999999)}"
            
            identity = {
                "type": "IAMUser",
                "principalId": principal_id,
                "arn": f"arn:aws:iam::{account_id}:user/{user_name}",
                "accountId": account_id,
                "userName": user_name
            }
            
            if random.random() < 0.3:
                identity["accessKeyId"] = f"AKIA{random.randint(100000000000, 999999999999)}"
                
        elif user_type == 'AssumedRole':
            role_name = random.choice(cls.ROLE_NAMES)
            session_name = f"i-{uuid.uuid4().hex[:16]}" if 'EC2' in role_name else f"session-{random.randint(1000, 99999)}"
            
            if is_malicious and random.random() < 0.6:
                session_name = f"stolen-session-{random.randint(10000, 99999)}"
                
            principal_id = f"AROA{random.randint(100000000000, 999999999999)}:{session_name}"
            access_key_id = f"ASIA{random.randint(100000000000, 999999999999)}"
            
            identity = {
                "type": "AssumedRole",
                "principalId": principal_id,
                "arn": f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}",
                "accountId": account_id,
                "accessKeyId": access_key_id,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": f"AROA{random.randint(100000000000, 999999999999)}",
                        "arn": f"arn:aws:iam::{account_id}:role/{role_name}",
                        "accountId": account_id,
                        "userName": role_name
                    },
                    "attributes": {
                        "mfaAuthenticated": "false" if is_malicious else random.choice(["true", "false"]),
                        "creationDate": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 48))).strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                }
            }
            
            if 'EC2' in role_name:
                identity["sessionContext"]["ec2RoleDelivery"] = "1.0"
                
        return identity


class CloudTrailLogGenerator:
    """Base class for CloudTrail log generation"""
    
    REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-south-1']
    
    USER_AGENTS = [
        "aws-cli/2.13.0 Python/3.11.4 Darwin/22.5.0 exe/x86_64 prompt/off command/s3.ls",
        "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0 exe/x86_64 prompt/off command/iam.list-users",
        "AWS-Console/1.0",
        "Boto3/1.28.57 Python/3.9.7 Linux/5.4.0-42-generic Botocore/1.31.57",
        "aws-sdk-go/1.44.122 (go1.19.3; linux; amd64)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "curl/7.88.1"
    ]
    
    def __init__(self):
        self.ip_gen = IPGenerator()
        self.user_gen = UserGenerator()
        
    def generate_base_log(self, event_name: str, event_source: str, 
                         user_identity: Dict[str, Any], is_malicious: bool = False) -> Dict[str, Any]:
        """Generate base CloudTrail log structure"""
        
        # Generate timestamp - malicious activities might occur at odd hours
        if is_malicious and random.random() < 0.4:
            # 40% chance of odd hours for malicious
            hour = random.choice([2, 3, 4, 5, 22, 23])
        else:
            # Normal business hours
            hour = random.randint(8, 18)
            
        event_time = datetime.now(timezone.utc).replace(
            hour=hour,
            minute=random.randint(0, 59),
            second=random.randint(0, 59)
        ) - timedelta(days=random.randint(0, 180))
        
        log = {
            "eventVersion": "1.08",
            "userIdentity": user_identity,
            "eventTime": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": event_source,
            "eventName": event_name,
            "awsRegion": random.choice(self.REGIONS),
            "sourceIPAddress": self.ip_gen.get_ip(is_malicious=is_malicious),
            "userAgent": random.choice(self.USER_AGENTS),
            "requestID": str(uuid.uuid4()),
            "eventID": str(uuid.uuid4()),
            "readOnly": False,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": user_identity.get("accountId", "123456789012")
        }
        
        return log


class MaliciousLogGenerator(CloudTrailLogGenerator):
    """Generate malicious CloudTrail logs based on MITRE ATT&CK patterns"""
    
    def __init__(self):
        super().__init__()
        
    def generate_initial_access_logs(self) -> List[Dict[str, Any]]:
        """Generate Initial Access tactic logs"""
        logs = []
        
        # 1.1 Compromised IAM User Credentials
        user = self.user_gen.generate_user_identity('IAMUser', is_malicious=True)
        log = self.generate_base_log('ConsoleLogin', 'signin.amazonaws.com', user, is_malicious=True)
        log['sourceIPAddress'] = self.ip_gen.get_ip('china', is_malicious=True)
        log['errorCode'] = random.choice(['Failed authentication', None])
        if log.get('errorCode'):
            log['errorMessage'] = 'An error occurred'
        log['additionalEventData'] = {
            "LoginTo": f"https://console.aws.amazon.com/console/home?region={log['awsRegion']}",
            "MobileVersion": "No",
            "MFAUsed": "No"
        }
        log['tags'] = {
            "usecase": "Valid Accounts - Compromised IAM User Credentials",
            "description": "Attacker uses stolen IAM user credentials for initial access",
            "technique_id": "T1078.004"
        }
        logs.append(log)
        
        # 1.2 Access from Unusual Geographic Locations
        user = self.user_gen.generate_user_identity(random.choice(['IAMUser', 'AssumedRole']), is_malicious=True)
        log = self.generate_base_log('ListBuckets', 's3.amazonaws.com', user, is_malicious=True)
        log['sourceIPAddress'] = self.ip_gen.get_ip(random.choice(['russia', 'china']), is_malicious=True)
        log['tags'] = {
            "usecase": "Access from Unusual Geographic Locations",
            "description": "Access from high-risk countries or unexpected regions",
            "technique_id": "T1078.004"
        }
        logs.append(log)
        
        # 1.3 Exposed EKS Cluster API Endpoint
        user = self.user_gen.generate_user_identity('IAMUser')
        log = self.generate_base_log('UpdateClusterConfig', 'eks.amazonaws.com', user, is_malicious=True)
        log['requestParameters'] = {
            "name": f"dev-cluster",
            "resourcesVpcConfig": {
                "endpointPublicAccess": True,
                "publicAccessCidrs": ["0.0.0.0/0"] if random.random() < 0.7 else ["10.0.0.0/8", "172.16.0.0/12"]
            }
        }
        log['responseElements'] = {
            "update": {
                "id": str(uuid.uuid4()),
                "status": "InProgress",
                "type": "EndpointAccessUpdate"
            }
        }
        log['tags'] = {
            "usecase": "Exposed EKS Cluster API Endpoint",
            "description": "EKS cluster API endpoint changed from private to public",
            "technique_id": "T1190"
        }
        logs.append(log)
        
        return logs
    
    def generate_persistence_logs(self) -> List[Dict[str, Any]]:
        """Generate Persistence tactic logs"""
        logs = []
        
        # 2.1 Create New IAM User for Backdoor Access
        user = self.user_gen.generate_user_identity('IAMUser', is_malicious=True)
        events = ['CreateUser', 'CreateLoginProfile', 'CreateAccessKey', 'AttachUserPolicy']
        
        for event in events:
            log = self.generate_base_log(event, 'iam.amazonaws.com', user, is_malicious=True)
            
            if event == 'CreateUser':
                log['requestParameters'] = {"userName": f"admin-temp-{random.randint(100, 999)}"}
            elif event == 'AttachUserPolicy':
                log['requestParameters'] = {
                    "userName": f"admin-temp-{random.randint(100, 999)}",
                    "policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"
                }
                
            log['tags'] = {
                "usecase": "Create New IAM User for Backdoor Access",
                "description": "Attacker creates new IAM user to maintain access",
                "technique_id": "T1098"
            }
            logs.append(log)
        
        # 2.2 Modify IAM Role Trust Policy
        user = self.user_gen.generate_user_identity('IAMUser')
        log = self.generate_base_log('UpdateAssumeRolePolicy', 'iam.amazonaws.com', user, is_malicious=True)
        log['requestParameters'] = {
            "roleName": random.choice(['EC2-SSM-Role', 'AdminRole', 'DeveloperRole']),
            "policyDocument": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::123456789012:root",
                            f"arn:aws:iam::{random.randint(111111111111, 999999999999)}:root"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }]
            })
        }
        log['tags'] = {
            "usecase": "Modify IAM Role Trust Policy",
            "description": "Attacker modifies role trust policy to allow external account",
            "technique_id": "T1098"
        }
        logs.append(log)
        
        return logs
    
    def generate_privilege_escalation_logs(self) -> List[Dict[str, Any]]:
        """Generate Privilege Escalation tactic logs"""
        logs = []
        
        # 3.2 Malicious Role Assumption via STS
        user = self.user_gen.generate_user_identity('IAMUser')
        log = self.generate_base_log('AssumeRole', 'sts.amazonaws.com', user, is_malicious=True)
        target_role = random.choice(['AdminRole', 'SecurityAuditRole', 'CrossAccountRole'])
        session_name = f"suspicious-session-{random.randint(10000, 99999)}"
        
        log['requestParameters'] = {
            "roleArn": f"arn:aws:iam::123456789012:role/{target_role}",
            "roleSessionName": session_name
        }
        log['responseElements'] = {
            "credentials": {
                "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}",
                "sessionToken": "FQoGZXIvYXdzE...truncated...",
                "expiration": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            "assumedRoleUser": {
                "assumedRoleId": f"AROA{random.randint(100000000000, 999999999999)}:{session_name}",
                "arn": f"arn:aws:sts::123456789012:assumed-role/{target_role}/{session_name}"
            }
        }
        log['tags'] = {
            "usecase": "Malicious Role Assumption via STS",
            "description": "Attacker uses AssumeRole to escalate privileges",
            "technique_id": "T1078.004"
        }
        logs.append(log)
        
        # Follow-up action with assumed role
        assumed_user = self.user_gen.generate_user_identity('AssumedRole', is_malicious=True)
        assumed_user['principalId'] = f"{log['responseElements']['assumedRoleUser']['assumedRoleId']}"
        assumed_user['arn'] = log['responseElements']['assumedRoleUser']['arn']
        
        follow_up = self.generate_base_log(
            random.choice(['CreateUser', 'AttachUserPolicy', 'CreateAccessKey']),
            'iam.amazonaws.com',
            assumed_user,
            is_malicious=True
        )
        follow_up['tags'] = log['tags']
        logs.append(follow_up)
        
        # 3.3 Cross-Account Access
        user = self.user_gen.generate_user_identity('AssumedRole')
        log = self.generate_base_log('AssumeRole', 'sts.amazonaws.com', user, is_malicious=True)
        external_account = random.choice(['555666777888', '999888777666', '111222333444'])
        log['requestParameters'] = {
            "roleArn": f"arn:aws:iam::{external_account}:role/CrossAccountAdminRole",
            "roleSessionName": f"cross-account-{random.randint(10000, 99999)}"
        }
        log['responseElements'] = {
            "credentials": {
                "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}",
                "sessionToken": "FQoGZXIvYXdzE...truncated...",
                "expiration": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            "assumedRoleUser": {
                "assumedRoleId": f"AROA{random.randint(100000000000, 999999999999)}:{log['requestParameters']['roleSessionName']}",
                "arn": f"arn:aws:sts::{external_account}:assumed-role/CrossAccountAdminRole/{log['requestParameters']['roleSessionName']}"
            }
        }
        log['tags'] = {
            "usecase": "Cross-Account Access via Assumed Role Exploitation",
            "description": "Attacker uses role assumption to access different account",
            "technique_id": "T1078.004"
        }
        logs.append(log)
        
        return logs
    
    def generate_defense_evasion_logs(self) -> List[Dict[str, Any]]:
        """Generate Defense Evasion tactic logs"""
        logs = []
        
        # 4.1 Disabling CloudTrail
        user = self.user_gen.generate_user_identity('IAMUser', is_malicious=True)
        events = ['StopLogging', 'DeleteTrail', 'UpdateTrail']
        
        for event in random.sample(events, 1):
            log = self.generate_base_log(event, 'cloudtrail.amazonaws.com', user, is_malicious=True)
            if event == 'UpdateTrail':
                log['requestParameters'] = {
                    "name": "main-trail",
                    "s3BucketName": "attacker-bucket"
                }
            log['tags'] = {
                "usecase": "Disabling or Deleting Security Logs",
                "description": "Attacker stops or deletes CloudTrail logs",
                "technique_id": "T1562.001"
            }
            logs.append(log)
        
        # 4.2 Disabling Security Services
        security_events = [
            ('DisableSecurityHub', 'securityhub.amazonaws.com'),
            ('DeleteDetector', 'guardduty.amazonaws.com'),
            ('StopMonitoringMembers', 'guardduty.amazonaws.com')
        ]
        
        event_name, event_source = random.choice(security_events)
        log = self.generate_base_log(event_name, event_source, user, is_malicious=True)
        log['tags'] = {
            "usecase": "Disabling Security Services",
            "description": "Attacker disables threat detection services",
            "technique_id": "T1562.001"
        }
        logs.append(log)
        
        # 4.3 Access from Tor/VPN
        user = self.user_gen.generate_user_identity(random.choice(['IAMUser', 'AssumedRole']), is_malicious=True)
        log = self.generate_base_log(
            random.choice(['RunInstances', 'CreateUser', 'AssumeRole']),
            random.choice(['ec2.amazonaws.com', 'iam.amazonaws.com', 'sts.amazonaws.com']),
            user,
            is_malicious=True
        )
        log['sourceIPAddress'] = self.ip_gen.get_ip(random.choice(['tor_exit', 'vpn']), is_malicious=True)
        log['tags'] = {
            "usecase": "Access from Anonymizing Services (Tor/VPN)",
            "description": "Attacker uses Tor or VPN to hide true IP",
            "technique_id": "T1090.003"
        }
        logs.append(log)
        
        return logs
    
    def generate_credential_access_logs(self) -> List[Dict[str, Any]]:
        """Generate Credential Access tactic logs"""
        logs = []
        
        # 5.1 Accessing Secrets Manager
        user = self.user_gen.generate_user_identity(random.choice(['IAMUser', 'AssumedRole']), is_malicious=True)
        log = self.generate_base_log('GetSecretValue', 'secretsmanager.amazonaws.com', user, is_malicious=True)
        log['requestParameters'] = {
            "secretId": random.choice([
                "prod/database/credentials",
                "prod/api/external-api-key",
                "prod/infra/ssh-private-key",
                "prod/payment/stripe-api-key"
            ])
        }
        log['tags'] = {
            "usecase": "Accessing Secrets from Secrets Manager",
            "description": "Attacker retrieves sensitive data from Secrets Manager",
            "technique_id": "T1552.005"
        }
        logs.append(log)
        
        # 5.2 Instance Metadata Exploitation
        instance_id = f"i-{uuid.uuid4().hex[:16]}"
        user = self.user_gen.generate_user_identity('AssumedRole', is_malicious=True)
        user['principalId'] = f"{user['principalId'].split(':')[0]}:{instance_id}"
        
        # External IP using stolen instance credentials
        log = self.generate_base_log(
            random.choice(['ListBuckets', 'GetSecretValue', 'DescribeInstances']),
            random.choice(['s3.amazonaws.com', 'secretsmanager.amazonaws.com', 'ec2.amazonaws.com']),
            user,
            is_malicious=True
        )
        log['sourceIPAddress'] = self.ip_gen.get_ip(random.choice(['russia', 'china', 'tor_exit']), is_malicious=True)
        log['tags'] = {
            "usecase": "Instance Metadata Exploitation - Stealing IAM Credentials",
            "description": "Stolen EC2 instance credentials used from external IP",
            "technique_id": "T1552.005"
        }
        logs.append(log)
        
        # 5.3 Malicious Use of STS Short-Term Access Keys
        user = self.user_gen.generate_user_identity('AssumedRole', is_malicious=True)
        log = self.generate_base_log(
            random.choice(['ListUsers', 'GetAccountAuthorizationDetails', 'DescribeInstances', 'ListSecrets']),
            random.choice(['iam.amazonaws.com', 'ec2.amazonaws.com', 'secretsmanager.amazonaws.com']),
            user,
            is_malicious=True
        )
        
        # Add error for suspicious activity
        if random.random() < 0.3:
            log['errorCode'] = 'AccessDenied'
            
        log['tags'] = {
            "usecase": "Malicious Use of STS Short-Term Access Keys",
            "description": "Attacker uses stolen STS credentials (ASIA keys)",
            "technique_id": "T1078.004"
        }
        logs.append(log)
        
        return logs
    
    def generate_discovery_logs(self) -> List[Dict[str, Any]]:
        """Generate Discovery tactic logs"""
        logs = []
        
        # 6.1 Reconnaissance of AWS Infrastructure
        user = self.user_gen.generate_user_identity(random.choice(['IAMUser', 'AssumedRole']), is_malicious=True)
        
        # Generate multiple discovery events
        discovery_events = [
            ('ListUsers', 'iam.amazonaws.com'),
            ('ListRoles', 'iam.amazonaws.com'),
            ('DescribeInstances', 'ec2.amazonaws.com'),
            ('ListBuckets', 's3.amazonaws.com'),
            ('DescribeDBInstances', 'rds.amazonaws.com'),
            ('ListFunctions', 'lambda.amazonaws.com'),
            ('ListSecrets', 'secretsmanager.amazonaws.com')
        ]
        
        # Burst of discovery activity
        base_time = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30))
        for i, (event_name, event_source) in enumerate(random.sample(discovery_events, random.randint(3, 6))):
            log = self.generate_base_log(event_name, event_source, user, is_malicious=True)
            # Events occur within minutes of each other
            log['eventTime'] = (base_time + timedelta(minutes=i*2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            log['readOnly'] = True
            log['tags'] = {
                "usecase": "Reconnaissance of AWS Infrastructure",
                "description": "Broad reconnaissance to understand infrastructure",
                "technique_id": "T1580"
            }
            logs.append(log)
        
        return logs
    
    def generate_collection_logs(self) -> List[Dict[str, Any]]:
        """Generate Collection tactic logs"""
        logs = []
        
        # 7.1 Creating Snapshots for Data Theft
        user = self.user_gen.generate_user_identity('IAMUser', is_malicious=True)
        
        # Create snapshot
        log = self.generate_base_log(
            random.choice(['CreateDBSnapshot', 'CreateSnapshot']),
            random.choice(['rds.amazonaws.com', 'ec2.amazonaws.com']),
            user,
            is_malicious=True
        )
        snapshot_id = f"snap-{uuid.uuid4().hex[:12]}" if 'ec2' in log['eventSource'] else f"rds:snapshot-{uuid.uuid4().hex[:8]}"
        log['requestParameters'] = {"snapshotId": snapshot_id}
        logs.append(log)
        
        # Share snapshot with external account
        share_log = self.generate_base_log(
            'ModifySnapshotAttribute' if 'ec2' in log['eventSource'] else 'ModifyDBSnapshotAttribute',
            log['eventSource'],
            user,
            is_malicious=True
        )
        share_log['requestParameters'] = {
            "snapshotId": snapshot_id,
            "attributeName": "createVolumePermission" if 'ec2' in log['eventSource'] else "restore",
            "createVolumePermission": {
                "add": [{"userId": f"{random.randint(111111111111, 999999999999)}"}]
            }
        }
        share_log['tags'] = {
            "usecase": "Creating Snapshots of EBS/RDS for Data Theft",
            "description": "Create and share snapshots with external account",
            "technique_id": "T1213"
        }
        logs.append(share_log)
        
        # 7.2 Publicly Exposing RDS Snapshot
        if random.random() < 0.3:
            public_log = self.generate_base_log(
                'ModifyDBSnapshotAttribute',
                'rds.amazonaws.com',
                user,
                is_malicious=True
            )
            public_log['requestParameters'] = {
                "dBSnapshotIdentifier": f"rds:snapshot-{uuid.uuid4().hex[:8]}",
                "attributeName": "restore",
                "valuesToAdd": ["all"]  # Public access
            }
            public_log['tags'] = {
                "usecase": "Publicly Exposing RDS/Database Snapshot",
                "description": "RDS snapshot made publicly accessible",
                "technique_id": "T1213"
            }
            logs.append(public_log)
        
        return logs
    
    def generate_exfiltration_logs(self) -> List[Dict[str, Any]]:
        """Generate Exfiltration tactic logs"""
        logs = []
        
        # 8.1 Making S3 Bucket Public
        user = self.user_gen.generate_user_identity('IAMUser', is_malicious=True)
        log = self.generate_base_log(
            random.choice(['PutBucketPolicy', 'PutBucketAcl']),
            's3.amazonaws.com',
            user,
            is_malicious=True
        )
        
        bucket_name = random.choice(['sensitive-documents', 'customer-data', 'financial-records'])
        if log['eventName'] == 'PutBucketPolicy':
            log['requestParameters'] = {
                "bucketName": bucket_name,
                "bucketPolicy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{bucket_name}/*"
                    }]
                })
            }
        else:
            log['requestParameters'] = {
                "bucketName": bucket_name,
                "AccessControlPolicy": {
                    "AccessControlList": {
                        "Grant": [{
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                            },
                            "Permission": "READ"
                        }]
                    }
                }
            }
        
        log['tags'] = {
            "usecase": "Making S3 Bucket Public for Data Retrieval",
            "description": "S3 bucket policy changed to allow public access",
            "technique_id": "T1537"
        }
        logs.append(log)
        
        # 8.2 Data Exfiltration via EC2 Staging Point
        user = self.user_gen.generate_user_identity('IAMUser', is_malicious=True)
        
        # Launch EC2 instance
        launch_log = self.generate_base_log('RunInstances', 'ec2.amazonaws.com', user, is_malicious=True)
        launch_log['requestParameters'] = {
            "instanceType": random.choice(["t3.large", "t3.xlarge", "m5.large"]),
            "maxCount": random.randint(1, 5),
            "minCount": 1
        }
        logs.append(launch_log)
        
        # Modify security group for exfiltration
        sg_log = self.generate_base_log('AuthorizeSecurityGroupEgress', 'ec2.amazonaws.com', user, is_malicious=True)
        sg_log['requestParameters'] = {
            "groupId": f"sg-{uuid.uuid4().hex[:12]}",
            "ipPermissions": {
                "items": [{
                    "ipProtocol": "tcp",
                    "fromPort": random.choice([443, 22, 8080]),
                    "toPort": random.choice([443, 22, 8080]),
                    "ipRanges": {
                        "items": [{"cidrIp": "0.0.0.0/0"}]
                    }
                }]
            }
        }
        sg_log['tags'] = {
            "usecase": "Data Exfiltration via EC2 Staging Point",
            "description": "EC2 instance used as relay for data exfiltration",
            "technique_id": "T1041"
        }
        logs.append(sg_log)
        
        # 8.3 Massive S3 Download
        user = self.user_gen.generate_user_identity(random.choice(['IAMUser', 'AssumedRole']), is_malicious=True)
        
        # Generate multiple GetObject events
        bucket_names = ['backup-files', 'logs-bucket', 'config-bucket', 'sensitive-documents']
        base_time = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30))
        
        for i in range(random.randint(5, 15)):
            log = self.generate_base_log('GetObject', 's3.amazonaws.com', user, is_malicious=True)
            log['eventTime'] = (base_time + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
            bucket = random.choice(bucket_names)
            file_num = random.randint(0, 200)
            
            log['resources'] = [{
                "type": "AWS::S3::Object",
                "ARN": f"arn:aws:s3:::{bucket}/sensitive-data/file-{file_num:04d}.csv"
            }]
            log['requestParameters'] = {
                "bucketName": bucket,
                "key": f"sensitive-data/file-{file_num:04d}.csv"
            }
            log['additionalEventData'] = {
                "bytesTransferred": random.randint(1000000, 50000000),
                "x-amz-server-side-encryption": "AES256"
            }
            log['readOnly'] = True
            log['tags'] = {
                "usecase": "Data Exfiltration - Massive S3 Download",
                "description": "Large volume of S3 GetObject requests",
                "technique_id": "T1048"
            }
            logs.append(log)
        
        return logs
    
    def generate_impact_logs(self) -> List[Dict[str, Any]]:
        """Generate Impact tactic logs"""
        logs = []
        
        # 9.1 Cryptojacking
        user = self.user_gen.generate_user_identity('IAMUser', is_malicious=True)
        
        # Launch multiple GPU instances
        launch_log = self.generate_base_log('RunInstances', 'ec2.amazonaws.com', user, is_malicious=True)
        launch_log['awsRegion'] = random.choice(['us-east-1', 'us-west-2', 'eu-west-1'])  # Cheaper regions
        launch_log['requestParameters'] = {
            "instanceType": random.choice(["g4dn.xlarge", "p3.2xlarge", "c5n.18xlarge"]),
            "maxCount": random.randint(5, 20),
            "minCount": 5
        }
        logs.append(launch_log)
        
        # Open ports for mining pools
        sg_log = self.generate_base_log('AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', user, is_malicious=True)
        sg_log['requestParameters'] = {
            "groupId": f"sg-{uuid.uuid4().hex[:12]}",
            "ipPermissions": {
                "items": [{
                    "ipProtocol": "tcp",
                    "fromPort": random.choice([3333, 4444, 5555]),
                    "toPort": random.choice([8333, 9999, 14444]),
                    "ipRanges": {
                        "items": [{"cidrIp": "0.0.0.0/0"}]
                    }
                }]
            }
        }
        sg_log['tags'] = {
            "usecase": "Cryptojacking via Unauthorized EC2 Instances",
            "description": "Large number of GPU instances for cryptocurrency mining",
            "technique_id": "T1496"
        }
        logs.append(sg_log)
        
        # 9.2 Destructive Activity
        user = self.user_gen.generate_user_identity(random.choice(['IAMUser', 'AssumedRole']), is_malicious=True)
        
        # Mass deletion events
        delete_events = [
            ('TerminateInstances', 'ec2.amazonaws.com', {"instanceIds": [f"i-{uuid.uuid4().hex[:16]}" for _ in range(random.randint(1, 5))]}),
            ('DeleteBucket', 's3.amazonaws.com', {"bucketName": f"important-bucket-{random.randint(1, 100)}"}),
            ('DeleteDBInstance', 'rds.amazonaws.com', {"dBInstanceIdentifier": f"prod-db-{random.randint(1, 10)}"}),
            ('DeleteVolume', 'ec2.amazonaws.com', {"volumeId": f"vol-{uuid.uuid4().hex[:12]}"}),
            ('DeletePolicy', 'iam.amazonaws.com', {"policyArn": f"arn:aws:iam::123456789012:policy/custom-policy-{random.randint(100, 999)}"}),
            ('DeleteUser', 'iam.amazonaws.com', {"userName": f"user-{random.randint(1, 50)}"})
        ]
        
        # Generate multiple deletion events
        for _ in range(random.randint(2, 5)):
            event_name, event_source, params = random.choice(delete_events)
            log = self.generate_base_log(event_name, event_source, user, is_malicious=True)
            log['requestParameters'] = params
            log['tags'] = {
                "usecase": "Destructive Activity - Deleting Resources",
                "description": "Mass deletion of critical resources",
                "technique_id": "T1485"
            }
            logs.append(log)
        
        return logs
    
    def generate_malicious_log(self) -> Dict[str, Any]:
        """Generate a single malicious log from random category"""
        generators = [
            self.generate_initial_access_logs,
            self.generate_persistence_logs,
            self.generate_privilege_escalation_logs,
            self.generate_defense_evasion_logs,
            self.generate_credential_access_logs,
            self.generate_discovery_logs,
            self.generate_collection_logs,
            self.generate_exfiltration_logs,
            self.generate_impact_logs
        ]
        
        logs = random.choice(generators)()
        return random.choice(logs) if logs else None


class NormalLogGenerator(CloudTrailLogGenerator):
    """Generate normal operational CloudTrail logs"""
    
    def __init__(self):
        super().__init__()
        
    def generate_daily_operations_logs(self) -> List[Dict[str, Any]]:
        """Generate daily operational logs"""
        logs = []
        
        # EC2 Instance Management
        user = self.user_gen.generate_user_identity(random.choice(['IAMUser', 'AssumedRole']))
        
        # Start/Stop instances
        for action in ['StartInstances', 'StopInstances', 'DescribeInstances']:
            log = self.generate_base_log(action, 'ec2.amazonaws.com', user)
            if action != 'DescribeInstances':
                log['requestParameters'] = {
                    "instancesSet": {
                        "items": [{"instanceId": f"i-{uuid.uuid4().hex[:16]}"}]
                    }
                }
            log['readOnly'] = (action == 'DescribeInstances')
            logs.append(log)
        
        # S3 Operations
        s3_operations = [
            ('ListBuckets', True, None),
            ('GetObject', True, {
                "bucketName": random.choice(['app-logs', 'config-files', 'static-assets']),
                "key": f"2024/{random.randint(1,12):02d}/{random.randint(1,28):02d}/app.log"
            }),
            ('PutObject', False, {
                "bucketName": random.choice(['app-logs', 'backups', 'uploads']),
                "key": f"uploads/{uuid.uuid4().hex[:8]}.json"
            })
        ]
        
        for op_name, read_only, params in s3_operations:
            log = self.generate_base_log(op_name, 's3.amazonaws.com', user)
            log['readOnly'] = read_only
            if params:
                log['requestParameters'] = params
            logs.append(log)
        
        # CloudWatch Monitoring
        cw_operations = ['PutMetricData', 'GetMetricStatistics', 'DescribeAlarms']
        for op in cw_operations:
            log = self.generate_base_log(op, 'monitoring.amazonaws.com', user)
            log['readOnly'] = (op != 'PutMetricData')
            logs.append(log)
        
        return logs
    
    def generate_development_activity_logs(self) -> List[Dict[str, Any]]:
        """Generate development activity logs"""
        logs = []
        
        user = self.user_gen.generate_user_identity('IAMUser')
        
        # Lambda Development
        lambda_ops = [
            ('CreateFunction', False, {
                "functionName": f"api-handler-{random.choice(['auth', 'data', 'webhook'])}"
            }),
            ('UpdateFunctionCode', False, {
                "functionName": f"api-handler-{random.choice(['auth', 'data', 'webhook'])}"
            }),
            ('GetFunction', True, {
                "functionName": f"api-handler-{random.choice(['auth', 'data', 'webhook'])}"
            })
        ]
        
        for op, read_only, params in lambda_ops:
            log = self.generate_base_log(op, 'lambda.amazonaws.com', user)
            log['readOnly'] = read_only
            log['requestParameters'] = params
            logs.append(log)
        
        # CodeCommit/CodeBuild
        dev_services = [
            ('GitPush', 'codecommit.amazonaws.com', False),
            ('StartBuild', 'codebuild.amazonaws.com', False),
            ('BatchGetBuilds', 'codebuild.amazonaws.com', True)
        ]
        
        for op, source, read_only in dev_services:
            log = self.generate_base_log(op, source, user)
            log['readOnly'] = read_only
            logs.append(log)
        
        # API Gateway
        api_ops = ['CreateRestApi', 'CreateDeployment', 'GetRestApis']
        for op in api_ops:
            log = self.generate_base_log(op, 'apigateway.amazonaws.com', user)
            log['readOnly'] = (op == 'GetRestApis')
            logs.append(log)
        
        return logs
    
    def generate_security_operations_logs(self) -> List[Dict[str, Any]]:
        """Generate security operations logs"""
        logs = []
        
        user = self.user_gen.generate_user_identity('IAMUser')
        user['userName'] = random.choice(['security-auditor', 'compliance-user', 'soc-analyst'])
        
        # GuardDuty Operations
        gd_ops = [
            ('GetFindings', 'guardduty.amazonaws.com', True),
            ('ListDetectors', 'guardduty.amazonaws.com', True),
            ('GetDetector', 'guardduty.amazonaws.com', True)
        ]
        
        for op, source, read_only in gd_ops:
            log = self.generate_base_log(op, source, user)
            log['readOnly'] = read_only
            logs.append(log)
        
        # Security Hub
        sh_ops = ['GetFindings', 'DescribeStandards', 'GetComplianceSummary']
        for op in sh_ops:
            log = self.generate_base_log(op, 'securityhub.amazonaws.com', user)
            log['readOnly'] = True
            logs.append(log)
        
        # IAM Policy Reviews
        iam_ops = [
            ('GetAccountAuthorizationDetails', True),
            ('GetRole', True),
            ('GetRolePolicy', True),
            ('ListAttachedRolePolicies', True)
        ]
        
        for op, read_only in iam_ops:
            log = self.generate_base_log(op, 'iam.amazonaws.com', user)
            log['readOnly'] = read_only
            if op in ['GetRole', 'GetRolePolicy', 'ListAttachedRolePolicies']:
                log['requestParameters'] = {
                    "roleName": random.choice(self.user_gen.ROLE_NAMES)
                }
            logs.append(log)
        
        return logs
    
    def generate_backup_restore_logs(self) -> List[Dict[str, Any]]:
        """Generate backup and restore operation logs"""
        logs = []
        
        user = self.user_gen.generate_user_identity('AssumedRole')
        
        # EBS Snapshots
        snapshot_ops = [
            ('CreateSnapshot', False, {
                "volumeId": f"vol-{uuid.uuid4().hex[:12]}",
                "description": f"Automated backup - {datetime.now().strftime('%Y-%m-%d')}"
            }),
            ('DescribeSnapshots', True, None)
        ]
        
        for op, read_only, params in snapshot_ops:
            log = self.generate_base_log(op, 'ec2.amazonaws.com', user)
            log['readOnly'] = read_only
            if params:
                log['requestParameters'] = params
            logs.append(log)
        
        # RDS Backups
        rds_ops = [
            ('CreateDBSnapshot', False, {
                "dBSnapshotIdentifier": f"backup-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}",
                "dBInstanceIdentifier": f"prod-db-{random.randint(1, 5)}"
            }),
            ('DescribeDBSnapshots', True, None)
        ]
        
        for op, read_only, params in rds_ops:
            log = self.generate_base_log(op, 'rds.amazonaws.com', user)
            log['readOnly'] = read_only
            if params:
                log['requestParameters'] = params
            logs.append(log)
        
        # S3 Backup Operations
        backup_bucket = random.choice(['company-backups', 'disaster-recovery', 'archive-data'])
        log = self.generate_base_log('PutObject', 's3.amazonaws.com', user)
        log['requestParameters'] = {
            "bucketName": backup_bucket,
            "key": f"backups/{datetime.now().strftime('%Y/%m/%d')}/database-backup.sql.gz"
        }
        log['additionalEventData'] = {
            "x-amz-server-side-encryption": "aws:kms",
            "x-amz-server-side-encryption-aws-kms-key-id": f"arn:aws:kms:{log['awsRegion']}:123456789012:key/{uuid.uuid4()}"
        }
        logs.append(log)
        
        return logs
    
    def generate_automation_logs(self) -> List[Dict[str, Any]]:
        """Generate automation and infrastructure management logs"""
        logs = []
        
        # Use service account for automation
        user = self.user_gen.generate_user_identity('IAMUser')
        user['userName'] = random.choice(['automation-user', 'ci-cd-user', 'terraform-user'])
        
        # CloudFormation Operations
        cf_ops = [
            ('CreateStack', False, {
                "stackName": f"{random.choice(['dev', 'staging', 'prod'])}-stack-{random.randint(100, 999)}"
            }),
            ('UpdateStack', False, {
                "stackName": f"{random.choice(['dev', 'staging', 'prod'])}-stack-{random.randint(100, 999)}"
            }),
            ('DescribeStacks', True, None)
        ]
        
        for op, read_only, params in cf_ops:
            log = self.generate_base_log(op, 'cloudformation.amazonaws.com', user)
            log['readOnly'] = read_only
            if params:
                log['requestParameters'] = params
            logs.append(log)
        
        # Systems Manager
        ssm_ops = [
            ('SendCommand', False, {
                "documentName": "AWS-RunShellScript",
                "instanceIds": [f"i-{uuid.uuid4().hex[:16]}" for _ in range(random.randint(1, 3))]
            }),
            ('GetParameter', True, {
                "name": f"/app/{random.choice(['dev', 'prod'])}/{random.choice(['db-host', 'api-key', 'config'])}"
            }),
            ('PutParameter', False, {
                "name": f"/app/{random.choice(['dev', 'prod'])}/{random.choice(['version', 'feature-flag', 'endpoint'])}",
                "type": "String"
            })
        ]
        
        for op, read_only, params in ssm_ops:
            log = self.generate_base_log(op, 'ssm.amazonaws.com', user)
            log['readOnly'] = read_only
            log['requestParameters'] = params
            logs.append(log)
        
        # Auto Scaling
        as_ops = [
            ('UpdateAutoScalingGroup', False, {
                "autoScalingGroupName": f"{random.choice(['web', 'api', 'worker'])}-asg",
                "desiredCapacity": random.randint(2, 10)
            }),
            ('DescribeAutoScalingGroups', True, None)
        ]
        
        for op, read_only, params in as_ops:
            log = self.generate_base_log(op, 'autoscaling.amazonaws.com', user)
            log['readOnly'] = read_only
            if params:
                log['requestParameters'] = params
            logs.append(log)
        
        return logs
    
    def generate_normal_log(self) -> Dict[str, Any]:
        """Generate a single normal operational log"""
        generators = [
            self.generate_daily_operations_logs,
            self.generate_development_activity_logs,
            self.generate_security_operations_logs,
            self.generate_backup_restore_logs,
            self.generate_automation_logs
        ]
        
        # Weight towards daily operations (more common)
        weights = [0.4, 0.2, 0.15, 0.15, 0.1]
        generator = random.choices(generators, weights=weights)[0]
        
        logs = generator()
        return random.choice(logs) if logs else None


class DatasetWriter:
    """Handles efficient writing of dataset to disk"""
    
    def __init__(self, config: LogConfig):
        self.config = config
        self.output_dir = config.output_dir
        self.compress = config.compress
        self.chunk_size_bytes = config.chunk_size_mb * 1024 * 1024
        self.current_size = 0
        self.file_counter = 0
        self.category_counts = defaultdict(int)
        
        # Create output directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'malicious'), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'normal'), exist_ok=True)
        
    def write_chunk(self, logs: List[Dict[str, Any]], category: str = 'mixed'):
        """Write a chunk of logs to file"""
        if not logs:
            return
            
        # Determine directory based on category
        if category in ['malicious', 'normal']:
            dir_path = os.path.join(self.output_dir, category)
        else:
            dir_path = self.output_dir
            
        filename = f"{category}_dataset_{self.category_counts[category]:04d}.json"
        if self.compress:
            filename += '.gz'
            
        filepath = os.path.join(dir_path, filename)
        
        if self.compress:
            with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                for log in logs:
                    f.write(json.dumps(log, separators=(',', ':')) + '\n')
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                for log in logs:
                    f.write(json.dumps(log, separators=(',', ':')) + '\n')
                    
        self.category_counts[category] += 1
        
    def write_statistics(self, stats: Dict[str, Any]):
        """Write dataset statistics"""
        stats_file = os.path.join(self.output_dir, 'dataset_statistics.json')
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)


def generate_dataset_chunk(args: Tuple[int, LogConfig, int]) -> Tuple[int, Dict[str, int], List[Dict], List[Dict]]:
    """Generate a chunk of the dataset (for multiprocessing)"""
    chunk_id, config, total_logs = args
    
    malicious_gen = MaliciousLogGenerator()
    normal_gen = NormalLogGenerator()
    
    malicious_logs = []
    normal_logs = []
    stats = defaultdict(int)
    
    # Calculate logs for this chunk
    logs_per_chunk = total_logs // config.num_processes
    if chunk_id == config.num_processes - 1:
        # Last process handles remainder
        logs_per_chunk += total_logs % config.num_processes
    
    malicious_count = int(logs_per_chunk * config.malicious_ratio)
    normal_count = logs_per_chunk - malicious_count
    
    # Generate malicious logs
    for _ in range(malicious_count):
        log = malicious_gen.generate_malicious_log()
        if log:
            malicious_logs.append(log)
            stats['malicious'] += 1
            if 'tags' in log:
                stats[f"malicious_{log['tags']['technique_id']}"] += 1
    
    # Generate normal logs
    for _ in range(normal_count):
        log = normal_gen.generate_normal_log()
        if log:
            normal_logs.append(log)
            stats['normal'] += 1
    
    return chunk_id, stats, malicious_logs, normal_logs


def main():
    """Main function to orchestrate dataset generation"""
    parser = argparse.ArgumentParser(description='Generate CloudTrail ML training dataset')
    parser.add_argument('--size-gb', type=float, default=1000.0, help='Target dataset size in GB (default: 1000)')
    parser.add_argument('--malicious-ratio', type=float, default=0.5, help='Ratio of malicious logs (default: 0.5)')
    parser.add_argument('--output-dir', type=str, default='output', help='Output directory (default: output)')
    parser.add_argument('--processes', type=int, default=mp.cpu_count(), help='Number of processes')
    parser.add_argument('--no-compress', action='store_true', help='Disable gzip compression')
    parser.add_argument('--chunk-size-mb', type=int, default=100, help='Chunk size in MB (default: 100)')
    
    args = parser.parse_args()
    
    config = LogConfig(
        total_size_gb=args.size_gb,
        malicious_ratio=args.malicious_ratio,
        normal_ratio=1 - args.malicious_ratio,
        chunk_size_mb=args.chunk_size_mb,
        output_dir=args.output_dir,
        num_processes=args.processes,
        compress=not args.no_compress
    )
    
    print(f"Generating {config.total_size_gb}GB CloudTrail dataset...")
    print(f"Configuration:")
    print(f"  - Malicious logs: {config.malicious_ratio * 100}%")
    print(f"  - Normal logs: {config.normal_ratio * 100}%")
    print(f"  - Output directory: {config.output_dir}")
    print(f"  - Processes: {config.num_processes}")
    print(f"  - Compression: {'Enabled' if config.compress else 'Disabled'}")
    
    # Estimate number of logs needed
    # Average CloudTrail log size: ~1-2KB per log
    avg_log_size = 1500  # bytes
    total_bytes = config.total_size_gb * 1024 * 1024 * 1024
    estimated_logs = int(total_bytes / avg_log_size)
    
    print(f"\nEstimated total logs: {estimated_logs:,}")
    
    # Create writer
    writer = DatasetWriter(config)
    
    # Prepare multiprocessing arguments
    mp_args = [(i, config, estimated_logs) for i in range(config.num_processes)]
    
    # Generate dataset using multiprocessing
    print("\nGenerating logs...")
    all_stats = defaultdict(int)
    
    with mp.Pool(processes=config.num_processes) as pool:
        with tqdm(total=estimated_logs, desc="Logs generated") as pbar:
            for chunk_id, stats, malicious_logs, normal_logs in pool.imap_unordered(generate_dataset_chunk, mp_args):
                # Write logs to appropriate directories
                if malicious_logs:
                    writer.write_chunk(malicious_logs, 'malicious')
                if normal_logs:
                    writer.write_chunk(normal_logs, 'normal')
                
                # Update statistics
                for key, value in stats.items():
                    all_stats[key] += value
                
                # Update progress
                pbar.update(sum(stats.values()))
    
    # Write final statistics
    final_stats = {
        'total_logs': sum(all_stats.values()),
        'malicious_logs': all_stats['malicious'],
        'normal_logs': all_stats['normal'],
        'malicious_breakdown': {
            k: v for k, v in all_stats.items() 
            if k.startswith('malicious_') and k != 'malicious'
        },
        'configuration': {
            'target_size_gb': config.total_size_gb,
            'malicious_ratio': config.malicious_ratio,
            'normal_ratio': config.normal_ratio,
            'compression': config.compress
        },
        'generation_time': datetime.now().isoformat()
    }
    
    writer.write_statistics(final_stats)
    
    print(f"\nDataset generation complete!")
    print(f"Total logs generated: {final_stats['total_logs']:,}")
    print(f"Malicious logs: {final_stats['malicious_logs']:,}")
    print(f"Normal logs: {final_stats['normal_logs']:,}")
    print(f"\nStatistics saved to: {os.path.join(config.output_dir, 'dataset_statistics.json')}")


if __name__ == "__main__":
    main()