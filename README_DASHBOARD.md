# AWS CloudTrail Threat Hunting Dashboard

A comprehensive dashboard for analyzing AWS CloudTrail logs with a focus on threat detection using the MITRE ATT&CK framework.

## 🚀 Features

- **Multi-page Streamlit Dashboard**: Interactive web interface for log analysis
- **FastAPI Backend**: High-performance API for data processing
- **MITRE ATT&CK Mapping**: All threats mapped to specific techniques
- **ML-Powered Analytics**: Anomaly detection and behavioral analysis
- **Real-time Filtering**: Advanced search and filter capabilities
- **Interactive Visualizations**: Charts, graphs, and heatmaps for insights

## 📋 Prerequisites

- Python 3.11+
- Docker and Docker Compose (optional)
- Generated CloudTrail logs (using `cloudtrail_dataset_generator.py`)

## 🛠️ Installation

### Option 1: Local Installation

1. **Install Backend Dependencies**
```bash
cd backend
pip install -r requirements.txt
```

2. **Install Frontend Dependencies**
```bash
cd frontend
pip install -r requirements.txt
```

### Option 2: Docker Installation

```bash
docker-compose up -d
```

## 🚀 Running the Dashboard

### Local Development

1. **Start the Backend API**
```bash
cd backend
python -m uvicorn main:app --reload
```

2. **Start the Frontend Dashboard**
```bash
cd frontend
streamlit run app.py
```

3. **Access the Dashboard**
- Frontend: http://localhost:8501
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

### Docker Deployment

```bash
docker-compose up
```

## 📊 Dashboard Pages

### 1. Overview
- Key metrics and statistics
- Event timeline
- Top MITRE ATT&CK techniques
- Recent anomalies

### 2. Tactic Pages
- **Initial Access**: T1078.004, T1190
- **Persistence**: T1098
- **Privilege Escalation**: T1078.004 (STS)
- **Defense Evasion**: T1562.001, T1090.003
- **Credential Access**: T1552.005
- **Discovery**: T1580
- **Collection**: T1213
- **Exfiltration**: T1537, T1041, T1048
- **Impact**: T1496, T1485

### 3. Log Explorer
- Advanced search and filtering
- Pagination support
- Export functionality
- Detailed log viewer

### 4. ML Analytics
- Anomaly detection
- Behavioral analysis
- Pattern discovery
- Risk assessment

## 🔧 Configuration

### Backend Configuration

Edit `backend/config.py` or use environment variables:

```bash
CLOUDTRAIL_HOST=0.0.0.0
CLOUDTRAIL_PORT=8000
CLOUDTRAIL_DATA_DIR=/path/to/output
CLOUDTRAIL_CACHE_TTL=300
CLOUDTRAIL_ENABLE_CACHE=true
```

### Frontend Configuration

Set the API URL:

```bash
CLOUDTRAIL_API_URL=http://localhost:8000
```

## 📚 API Endpoints

### Core Endpoints

- `GET /api/logs` - Retrieve logs with filters
- `GET /api/statistics` - Get overall statistics
- `GET /api/techniques` - List all techniques
- `GET /api/techniques/{technique_id}/analytics` - Get technique analytics
- `GET /api/techniques/{technique_id}/logs` - Get logs for a technique
- `GET /api/anomalies` - Get detected anomalies
- `GET /api/timeseries` - Get time series data

### Query Parameters

- `start_time`, `end_time` - Time range filters
- `event_names[]` - Filter by event names
- `event_sources[]` - Filter by event sources
- `user_names[]` - Filter by users
- `source_ips[]` - Filter by IPs
- `regions[]` - Filter by AWS regions
- `technique_ids[]` - Filter by MITRE techniques
- `is_malicious` - Filter malicious/normal logs
- `limit`, `offset` - Pagination

## 🎯 Use Cases

### Threat Hunting
1. Navigate to specific tactic pages
2. Review risk scores and analytics
3. Examine sample logs
4. Follow security recommendations

### Incident Investigation
1. Use Log Explorer for detailed searches
2. Filter by time range and indicators
3. Export relevant logs
4. Check Analytics for anomalies

### Security Monitoring
1. Monitor Overview dashboard
2. Check anomaly detection regularly
3. Review user behavior patterns
4. Track technique trends

## 🔍 Key Features

### Anomaly Detection
- Unusual access patterns
- Privilege escalation chains
- Data exfiltration patterns
- Defense evasion activities

### Behavioral Analysis
- User activity patterns
- IP diversity analysis
- Time-based activity heatmaps
- Access pattern correlation

### Risk Assessment
- Real-time risk scoring
- Factor-based analysis
- Actionable recommendations
- Severity classification

## 🐛 Troubleshooting

### Common Issues

1. **API Connection Failed**
   - Ensure backend is running on port 8000
   - Check firewall settings
   - Verify CLOUDTRAIL_API_URL

2. **No Data Displayed**
   - Verify logs exist in output directory
   - Check file permissions
   - Ensure proper log format

3. **Performance Issues**
   - Enable caching in backend
   - Reduce query limits
   - Use time filters

### Debug Mode

Enable debug logging:
```bash
CLOUDTRAIL_DEBUG=true
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- AWS CloudTrail Documentation
- Streamlit Community
- FastAPI Team