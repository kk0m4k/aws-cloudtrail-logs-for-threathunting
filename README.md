# AWS CloudTrail ML Dataset Generator

## Overview

A high-performance synthetic CloudTrail log generator for ML-based threat detection training. This tool generates realistic AWS CloudTrail logs with a configurable mix of malicious (based on MITRE ATT&CK patterns) and normal operational activities.

## Key Features

- **Large-scale Dataset Generation**: Capable of generating TB-scale datasets efficiently using multiprocessing
- **50/50 Split**: Default configuration generates 50% malicious logs and 50% normal operational logs
- **MITRE ATT&CK Mapping**: All malicious events are mapped to specific MITRE ATT&CK techniques
- **Realistic Log Structure**: Generates logs that closely match real AWS CloudTrail format
- **ML-Ready**: Designed specifically for training machine learning models for threat detection
- **High Performance**: Utilizes multiprocessing to maximize generation speed
- **Compression Support**: Optional gzip compression to reduce storage requirements

## File Structure

```
aws-cloudtrail-logs-for-threathunting/
├── cloudtrail_dataset_generator.py  # Main dataset generator script
├── output/                          # Default output directory for generated datasets
│   ├── malicious/                   # Malicious log samples
│   ├── normal/                      # Normal log samples
│   └── dataset_statistics.json      # Generation statistics
└── requirements.txt                 # Python dependencies
```

## Supported Attack Scenarios (Malicious Logs)

### 1. Initial Access
- **1.1 Compromised IAM User Credentials** (T1078.004)
  - Failed authentication attempts followed by successful login
  - Access from suspicious geographic locations (China, Russia)
  - Unusual access times (2-5 AM, 10-11 PM)
  
- **1.2 Access from Unusual Geographic Locations** (T1078.004)
  - Tor exit nodes and VPN IP addresses
  - High-risk countries
  
- **1.3 Exposed EKS Cluster API Endpoint** (T1190)
  - Public endpoint configuration
  - Overly permissive CIDR settings (0.0.0.0/0)

### 2. Persistence
- **2.1 Create New IAM User for Backdoor Access** (T1098)
  - Suspicious naming patterns (admin-temp-XXX)
  - Administrator policy attachment
  - Sequential events: CreateUser → CreateLoginProfile → CreateAccessKey → AttachUserPolicy
  
- **2.2 Modify IAM Role Trust Policy** (T1098)
  - Adding external AWS accounts to trust relationships
  - Cross-account role assumption setup

### 3. Privilege Escalation  
- **3.1 Malicious Role Assumption via STS** (T1078.004)
  - AssumeRole to high-privilege roles (AdminRole, SecurityAuditRole)
  - Suspicious session names
  - Follow-up privileged actions
  
- **3.2 Cross-Account Access** (T1078.004)
  - Role assumption across different AWS accounts
  - External account ID patterns

### 4. Defense Evasion
- **4.1 Disabling or Deleting Security Logs** (T1562.001)
  - StopLogging, DeleteTrail, UpdateTrail events
  - Redirecting logs to attacker-controlled buckets
  
- **4.2 Disabling Security Services** (T1562.001)
  - DisableSecurityHub
  - DeleteDetector (GuardDuty)
  - StopMonitoringMembers
  
- **4.3 Access from Anonymizing Services** (T1090.003)
  - Tor exit node IPs
  - VPN service IPs

### 5. Credential Access
- **5.1 Accessing Secrets Manager** (T1552.005)
  - GetSecretValue for sensitive secrets
  - Database credentials, API keys, SSH keys
  
- **5.2 Instance Metadata Exploitation** (T1552.005)
  - Stolen EC2 instance credentials used from external IPs
  - ASIA keys from unexpected locations
  
- **5.3 Malicious Use of STS Short-Term Access Keys** (T1078.004)
  - Suspicious activities with temporary credentials
  - AccessDenied errors indicating privilege probing

### 6. Discovery
- **6.1 Reconnaissance of AWS Infrastructure** (T1580)
  - Burst of List/Describe API calls
  - Multiple services enumerated within minutes
  - Common pattern: ListUsers → ListRoles → DescribeInstances → ListBuckets

### 7. Collection
- **7.1 Creating Snapshots for Data Theft** (T1213)
  - CreateDBSnapshot/CreateSnapshot
  - ModifySnapshotAttribute to share with external accounts
  
- **7.2 Publicly Exposing RDS Snapshot** (T1213)
  - Setting restore permissions to "all" (public)

### 8. Exfiltration
- **8.1 Making S3 Bucket Public** (T1537)
  - PutBucketPolicy/PutBucketAcl with public permissions
  - Targeting sensitive buckets
  
- **8.2 Data Exfiltration via EC2** (T1041)
  - RunInstances in unusual regions
  - AuthorizeSecurityGroupEgress with 0.0.0.0/0
  
- **8.3 Massive S3 Download** (T1048)
  - Multiple GetObject events in rapid succession
  - Large bytesTransferred values
  - Sensitive file patterns

### 9. Impact
- **9.1 Cryptojacking** (T1496)
  - Large-scale GPU instance launches
  - Mining pool ports (3333, 4444, 8333)
  - Instance types: g4dn.xlarge, p3.2xlarge
  
- **9.2 Destructive Activity** (T1485)
  - Mass deletion events
  - TerminateInstances, DeleteBucket, DeleteDBInstance

## Normal Operational Activities (Normal Logs)

### 1. Daily Operations
- EC2 instance management (Start/Stop/Describe)
- S3 operations (List/Get/Put objects)
- CloudWatch monitoring (PutMetricData, GetMetricStatistics)

### 2. Development Activities
- Lambda function management
- CodeCommit/CodeBuild operations
- API Gateway deployments

### 3. Security Operations
- GuardDuty findings review
- Security Hub compliance checks
- IAM policy reviews

### 4. Backup and Restore
- EBS/RDS snapshot creation
- S3 backup operations with KMS encryption
- Automated backup patterns

### 5. Automation and Infrastructure
- CloudFormation stack operations
- Systems Manager parameter management
- Auto Scaling group updates

## Requirements

```bash
pip install -r requirements.txt
```

Dependencies:
- Python 3.7+
- tqdm (for progress bars)
- Standard library modules: json, multiprocessing, gzip

## Usage

### Basic Usage

```bash
# Generate 1TB dataset with default settings (50% malicious, 50% normal)
python cloudtrail_dataset_generator.py
```

### Advanced Options

```bash
# Generate 100GB dataset
python cloudtrail_dataset_generator.py --size-gb 100

# Adjust malicious/normal ratio (70% malicious, 30% normal)
python cloudtrail_dataset_generator.py --malicious-ratio 0.7

# Specify output directory
python cloudtrail_dataset_generator.py --output-dir /path/to/output

# Use specific number of processes
python cloudtrail_dataset_generator.py --processes 8

# Disable compression
python cloudtrail_dataset_generator.py --no-compress

# Set chunk size (default 100MB)
python cloudtrail_dataset_generator.py --chunk-size-mb 200
```

### Command Line Arguments

- `--size-gb`: Target dataset size in GB (default: 1000)
- `--malicious-ratio`: Ratio of malicious logs 0-1 (default: 0.5)
- `--output-dir`: Output directory path (default: output)
- `--processes`: Number of parallel processes (default: CPU count)
- `--no-compress`: Disable gzip compression
- `--chunk-size-mb`: Size of each output chunk in MB (default: 100)

## Log Structure

Each CloudTrail log event follows the standard AWS CloudTrail format:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA123456789012",
    "arn": "arn:aws:iam::123456789012:user/developer-1",
    "accountId": "123456789012",
    "userName": "developer-1",
    "accessKeyId": "AKIA123456789012"
  },
  "eventTime": "2024-01-15T10:30:45Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "52.94.228.167",
  "userAgent": "aws-cli/2.13.0 Python/3.11.4 Darwin/22.5.0",
  "requestID": "12345678-1234-1234-1234-123456789012",
  "eventID": "87654321-4321-4321-4321-210987654321",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "requestParameters": {
    "userName": "admin-temp-123"
  },
  "tags": {
    "usecase": "Create New IAM User for Backdoor Access",
    "description": "Attacker creates new IAM user to maintain access",
    "technique_id": "T1098"
  }
}
```

### Key Features of Generated Logs

1. **Realistic User Identities**
   - IAMUser and AssumedRole types
   - Proper ARN formatting
   - Realistic principal IDs and access keys

2. **IP Address Generation**
   - Regional IP ranges (Korea, USA, China, Russia)
   - Tor exit nodes and VPN IPs for malicious activities
   - AWS internal and service IPs

3. **Temporal Patterns**
   - Normal logs during business hours (8 AM - 6 PM)
   - Malicious logs often at unusual hours (2-5 AM, 10-11 PM)
   - Events spread across 180 days

4. **MITRE ATT&CK Tags** (Malicious logs only)
   - `usecase`: Descriptive name of the attack pattern
   - `description`: Detailed explanation
   - `technique_id`: MITRE ATT&CK technique identifier

## Output Structure

```
output/
├── mixed_dataset_0000.json.gz
├── mixed_dataset_0001.json.gz
├── ...
└── dataset_statistics.json
```

### Dataset Statistics

The `dataset_statistics.json` file contains:

```json
{
  "total_logs": 666666667,
  "malicious_logs": 333333334,
  "normal_logs": 333333333,
  "malicious_breakdown": {
    "malicious_T1078.004": 45678,
    "malicious_T1098": 34567,
    "malicious_T1562.001": 23456,
    ...
  },
  "configuration": {
    "target_size_gb": 1000.0,
    "malicious_ratio": 0.5,
    "normal_ratio": 0.5,
    "compression": true
  },
  "generation_time": "2024-01-15T10:30:45.123456"
}
```

## Performance Considerations

- **Multiprocessing**: Utilizes all available CPU cores by default
- **Memory Efficient**: Processes logs in chunks to avoid memory issues
- **Compression**: Gzip compression reduces storage by ~80%
- **Generation Speed**: ~10-20 GB/minute on modern hardware

## Use Cases

1. **ML Model Training**: Train classification models to detect malicious CloudTrail events
2. **Threat Detection Rule Development**: Develop and test SIEM rules
3. **Security Tool Evaluation**: Benchmark detection capabilities
4. **Security Training**: Understand real attack patterns
5. **Research**: Analyze attack techniques and patterns

## Important Notes

- This tool generates **synthetic data** for research and training purposes only
- Generated logs are not from real AWS environments
- Do not use in production environments
- Ensure compliance with your organization's data policies
- Large datasets require significant disk space (1TB uncompressed ≈ 200GB compressed)

## Architecture Details

### Class Structure

1. **CloudTrailLogGenerator**: Base class for log generation
   - Handles base log structure
   - Manages user identity generation
   - Controls temporal patterns

2. **MaliciousLogGenerator**: Generates attack pattern logs
   - 9 different attack categories
   - Each mapped to MITRE ATT&CK techniques
   - Realistic attack sequences

3. **NormalLogGenerator**: Generates operational logs
   - 5 categories of normal activities
   - Weighted distribution (40% daily ops, 20% dev, etc.)
   - Business hour patterns

4. **DatasetWriter**: Handles efficient file I/O
   - Chunk-based writing
   - Optional compression
   - Statistics tracking

### Generation Process

1. Calculates total logs needed based on target size
2. Distributes work across multiple processes
3. Each process generates its portion of logs
4. Logs are shuffled to mix malicious and normal
5. Written to disk in compressed chunks
6. Statistics aggregated and saved

## Contributing

Contributions are welcome! Areas for improvement:

1. Additional attack scenarios
2. More normal activity patterns
3. Performance optimizations
4. Additional output formats
5. Configuration templates

## License

This project is provided for educational and research purposes. For commercial use, please contact the maintainers.

## References

- [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [CloudTrail Log File Examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)