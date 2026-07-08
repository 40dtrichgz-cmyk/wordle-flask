# 🛡️ Advanced EDR Security Monitoring System

A comprehensive, real-time Endpoint Detection & Response (EDR) system built with Python Flask and a modern cybersecurity-themed dashboard. This system monitors processes, network connections, startup programs, and detects suspicious activity with high accuracy.

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Threat Detection Logic](#threat-detection-logic)
- [Dashboard Guide](#dashboard-guide)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Security Features](#security-features)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## ✨ Features

### 🔍 Core Monitoring Capabilities

#### 1. **Process Monitoring**
- Real-time process enumeration with resource metrics (CPU, Memory)
- Malware pattern detection using threat intelligence database
- Suspicious path detection (temp folders, AppData, etc.)
- Resource anomaly detection (CPU spikes, memory leaks)
- Hidden/random process name detection
- One-click process termination with safety checks
- Process risk scoring (CRITICAL, HIGH, MEDIUM, LOW)

#### 2. **Network Connection Monitoring**
- Real-time active connection tracking
- Local and remote IP/port information
- Connection status monitoring (ESTABLISHED, LISTENING, etc.)
- Suspicious port detection (C2, botnet, remote access tools)
- Beaconing pattern detection (repeated connections to same IP)
- Private IP range detection for internal reconnaissance
- High-numbered port flag detection

#### 3. **Startup & Persistence Detection**
- Registry autorun entry scanning (Windows)
- Suspicious startup location detection
- Malicious persistence mechanism identification
- Risk assessment for auto-start programs
- Full command line visibility

#### 4. **System Health Monitoring**
- Real-time CPU, Memory, and Disk usage tracking
- Baseline anomaly detection
- System resource spike alerts
- Boot time and process count tracking
- Anomaly comparison against baseline metrics

#### 5. **User Session Monitoring**
- Logged-in user detection
- Multiple session alerts
- Remote session identification
- Session status tracking (Windows)

#### 6. **Alert System**
- Real-time security alerts with severity levels
- Smart alert deduplication (60-second window)
- Persistent alert logging to file
- Alert export functionality (JSON format)
- Critical alert notifications with sound
- Alert history tracking (last 100 alerts)

---

## 🏗️ Architecture

```
EDR System/
├── app.py                      # Flask backend (threat detection engine)
├── security_monitor.py         # Advanced security monitoring module
├── requirements.txt            # Python dependencies
├── templates/
│   └── index.html             # Web dashboard HTML
└── static/
    ├── app.js                 # Dashboard JavaScript (API calls, UI logic)
    └── style.css              # Cybersecurity-themed styling
```

### Backend Components

**app.py** - Main Flask Application
- REST API endpoints for data collection
- Threat detection engine
- Process/Network monitoring
- Alert management

**security_monitor.py** - Advanced Detection Module
- Malware pattern matching
- Heuristic-based risk assessment
- Anomaly detection algorithms
- Windows registry scanning
- Remote access tool detection

### Frontend Components

**index.html** - Responsive Dashboard
- 5 main sections (Overview, Processes, Network, Startup, Alerts)
- Real-time metric updates
- Interactive data tables
- Search and filtering capabilities

**app.js** - Frontend Logic
- Auto-refresh every 5 seconds
- API integration
- Tab navigation
- Table filtering and search
- Process termination
- Alert export

**style.css** - Cybersecurity Theme
- Dark theme with neon green accents
- Professional dashboard UI
- Color-coded risk levels
- Responsive mobile design

---

## 📦 Installation

### Prerequisites

- **Python 3.8+**
- **Windows, macOS, or Linux**
- **Administrator/root privileges** (for full monitoring capabilities)
- **Modern web browser** (Chrome, Firefox, Edge, Safari)

### Step 1: Clone/Download Repository

```bash
git clone https://github.com/40dtrichgz-cmyk/wordle-flask.git
cd wordle-flask/edr_system
```

### Step 2: Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

### Step 3: Run the Application

```bash
python app.py
```

Expected output:
```
============================================================
   SECURITY MONITORING SYSTEM - EDR Dashboard
============================================================

✓ Starting Flask server...
✓ Navigate to: http://localhost:5000
✓ Press CTRL+C to stop
```

### Step 4: Access Dashboard

Open your browser and navigate to:
```
http://localhost:5000
```

---

## ⚡ Quick Start

### 5-Minute Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the server:**
   ```bash
   python app.py
   ```

3. **Open dashboard:**
   ```
   http://localhost:5000
   ```

4. **Set baseline (recommended):**
   - Click "Overview" tab
   - Click "Set Baseline" button
   - This establishes normal system metrics for anomaly detection

5. **Review threats:**
   - Check "Alerts" tab for detected security issues
   - Review suspicious processes in "Processes" tab
   - Investigate network connections in "Network" tab

---

## ⚙️ Configuration

### Environment Configuration

Create `.env` file in `edr_system/` directory:

```env
# Server Configuration
FLASK_ENV=development
FLASK_DEBUG=False
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# Monitoring Configuration
SCAN_INTERVAL=5
MAX_PROCESSES=200
MAX_CONNECTIONS=100
MAX_ALERTS=100

# Feature Flags
ENABLE_SOUND_ALERTS=True
ENABLE_LOGGING=True
```

### Threat Intelligence Database

Edit malware patterns in `app.py`:

```python
MALWARE_PATTERNS = {
    'CustomMalware': ['pattern1', 'pattern2'],
    # Add more patterns...
}

SUSPICIOUS_PORTS = {
    9999: 'Custom C2 Port',
    # Add more ports...
}
```

### Baseline Metrics

Set baseline for anomaly detection:
- Click "Set Baseline" button
- System stores current CPU/Memory metrics
- Future spikes are compared against baseline

---

## 📡 API Documentation

### System Overview

**GET** `/api/system`

Returns system health metrics:
```json
{
    "timestamp": "2026-07-08T17:00:00",
    "cpu_percent": 25.5,
    "memory": {
        "total_mb": 16384,
        "used_mb": 8192,
        "percent": 50.0
    },
    "disk": {
        "total_mb": 512000,
        "used_mb": 256000,
        "percent": 50.0
    },
    "process_count": 248,
    "boot_time": "2026-07-08T10:30:00",
    "anomalies": []
}
```

### Process List

**GET** `/api/processes`

Returns all processes with threat assessment:
```json
{
    "count": 248,
    "critical": 2,
    "high": 5,
    "processes": [
        {
            "pid": 1234,
            "name": "suspicious.exe",
            "status": "running",
            "path": "C:\\Temp\\suspicious.exe",
            "cpu_percent": 45.2,
            "memory_mb": 256.5,
            "risk_level": "HIGH",
            "risk_score": 55,
            "factors": ["Running from suspicious path: temp", "High memory consumption"]
        }
    ]
}
```

### Network Connections

**GET** `/api/network`

Returns active network connections:
```json
{
    "stats": {
        "total": 52,
        "established": 28,
        "listening": 12,
        "suspicious": 3
    },
    "connections": [
        {
            "local_ip": "192.168.1.100",
            "local_port": 54321,
            "remote_ip": "203.0.113.42",
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "process": "malware.exe",
            "pid": 5678,
            "risk_level": "HIGH",
            "factors": ["Suspicious port: 4444 (Metasploit/C2)"]
        }
    ]
}
```

### Startup Programs

**GET** `/api/startup`

Returns registry autorun entries:
```json
{
    "count": 15,
    "high_risk": 2,
    "items": [
        {
            "name": "MaliciousApp",
            "path": "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe",
            "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "risk": "HIGH"
        }
    ]
}
```

### Security Alerts

**GET** `/api/alerts`

Returns recent security alerts:
```json
{
    "count": 15,
    "critical": 1,
    "high": 3,
    "alerts": [
        {
            "timestamp": "2026-07-08T17:05:32",
            "severity": "CRITICAL",
            "title": "Suspicious Process: malware.exe",
            "description": "PID 1234: Known malware: Mirai, Running from suspicious path: temp",
            "recommendation": "Review process at C:\\Temp\\malware.exe and terminate if unauthorized"
        }
    ]
}
```

### Process Termination

**POST** `/api/process/<pid>/kill`

Terminates a process:
```bash
curl -X POST http://localhost:5000/api/process/1234/kill
```

Response:
```json
{
    "success": true,
    "message": "Process malware.exe terminated"
}
```

### Set Baseline

**POST** `/api/baseline`

Establishes baseline metrics for anomaly detection:
```bash
curl -X POST http://localhost:5000/api/baseline
```

### Export Alerts

**GET** `/api/export/alerts`

Exports all alerts as JSON:
```bash
curl http://localhost:5000/api/export/alerts > alerts.json
```

---

## 🧠 Threat Detection Logic

### Process Risk Assessment

**Scoring System:**
```
Malware Pattern Match        → +40 points
Suspicious Location          → +25 points
Short/Random Name           → +15 points
Excessive CPU (>85%)        → +20 points
High Memory (>1GB)          → +15 points

Risk Level:
- 60+ points: CRITICAL
- 40-59 points: HIGH
- 20-39 points: MEDIUM
- 0-19 points: LOW
```

**Detection Patterns:**
- Known malware signatures (RATs, trojans, worms, cryptominers)
- Suspicious execution paths (temp, appdata, recycle bin)
- Suspicious process names (single letters, all numeric, random)
- Resource anomalies (sustained high CPU/memory)

### Network Risk Assessment

**Scoring System:**
```
Suspicious Port Connection   → +35 points
High-Numbered Port          → +20 points
Repeated Connections        → +25 points

Risk Level:
- 50+ points: HIGH
- 30-49 points: MEDIUM
- 0-29 points: LOW
```

**Detection Methods:**
- Malicious port database (C2, botnet, remote access)
- Beaconing pattern detection (>30 connections to same IP)
- High-numbered port flagging (>40000)
- Private IP range exclusion (internal traffic)

### Startup Risk Assessment

**Indicators:**
- Execution from temp directories
- Batch/PowerShell script execution
- AppData/ProgramData references
- VBS script files

### Anomaly Detection

**Baseline Comparison:**
```
If (Current CPU - Baseline CPU) > 40%  → Medium Alert
If (Current Memory - Baseline Memory) > 30% → Medium Alert
```

---

## 📊 Dashboard Guide

### Overview Tab

**System Status Card:**
- CPU, Memory, Disk usage with visual bars
- Real-time metric updates
- Color-coded alert levels

**Security Status Card:**
- Threat count (critical processes)
- Active processes
- Network connections
- Total alerts

**Top Processes:**
- Highest CPU consumers
- Risk level indicators
- Quick access to detailed view

### Processes Tab

**Features:**
- Full process list with threat assessment
- Filter by process name (real-time search)
- Filter by risk level (CRITICAL, HIGH, MEDIUM, LOW)
- CPU and memory metrics
- Risk factors explanation
- One-click process termination

**Color Coding:**
- 🔴 CRITICAL: Immediate threat
- 🟠 HIGH: Suspicious activity
- 🟡 MEDIUM: Monitor closely
- 🟢 LOW: Safe

### Network Tab

**Connection Statistics:**
- Total active connections
- Established connections
- Listening ports
- Suspicious connections count

**Filters:**
- Show suspicious connections only
- Established connections only
- Real-time filtering

**Connection Details:**
- Process name and PID
- Local and remote IP:Port
- Connection status
- Risk assessment
- Threat factors

### Startup Tab

**Registry Analysis:**
- Auto-start program names
- Full execution paths
- Registry location
- Risk assessment
- Suspicious location detection

### Alerts Tab

**Alert Details:**
- Timestamp and severity level
- Alert title and description
- Security recommendation
- Color-coded severity

**Severity Levels:**
- 🔴 CRITICAL: Immediate action required
- 🟠 HIGH: Urgent review needed
- 🟡 MEDIUM: Monitor and investigate
- 🟢 INFO: System events

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + R` | Refresh all data |
| `Ctrl + B` | Set baseline metrics |
| `Ctrl + E` | Export alerts to JSON |

---

## 🔒 Security Features

### Data Protection

- **No data transmission:** All monitoring happens locally
- **No cloud connectivity:** Purely offline operation
- **Secure process termination:** Critical process protection
- **Access logging:** All alert events logged to file

### Threat Intelligence

- **Malware database:** 15+ known malware families
- **Port signatures:** 20+ suspicious ports identified
- **Heuristic detection:** Multi-factor risk scoring
- **Anomaly detection:** Baseline comparison

### Safety Mechanisms

- **Critical process protection:** Windows system processes cannot be terminated
- **Alert deduplication:** Prevents alert spam
- **Graceful degradation:** Continues operation if individual features fail
- **Rate limiting:** Maximum 100 alerts retained

---

## 🔧 Troubleshooting

### Common Issues

#### 1. **"Permission Denied" errors**

**Problem:** Cannot access certain processes or registry

**Solution:**
```bash
# Windows: Run as Administrator
# macOS/Linux: Use sudo
sudo python app.py
```

#### 2. **Port 5000 already in use**

**Problem:** Flask server won't start

**Solution:**
```bash
# Change port in app.py
app.run(host='0.0.0.0', port=8000)
```

#### 3. **Dashboard loads but no data**

**Problem:** API endpoints return empty data

**Solution:**
- Check Flask server console for errors
- Verify psutil is installed: `pip list | grep psutil`
- Restart the application

#### 4. **High CPU usage from monitoring**

**Problem:** System becomes slow

**Solution:**
- Increase refresh interval in `app.js`:
  ```javascript
  const CONFIG = {
      refreshInterval: 10000  // 10 seconds instead of 5
  };
  ```

#### 5. **Windows: Cannot detect autorun entries**

**Problem:** Startup tab shows no programs

**Solution:**
- Run as Administrator
- Ensure `winreg` module is available
- Check registry paths have correct permissions

#### 6. **Browser console shows CORS errors**

**Problem:** JavaScript cannot reach API

**Solution:**
- Verify Flask-CORS is installed: `pip install Flask-CORS`
- Check server is running on `http://localhost:5000`
- Clear browser cache

#### 7. **Alert sound not working**

**Problem:** No audio feedback

**Solution:**
- Check browser volume settings
- Verify speaker hardware
- Check browser console for Web Audio API errors

---

## 📈 Performance Considerations

### Resource Impact

- **CPU:** 1-3% (minimal)
- **Memory:** 50-150MB
- **Disk I/O:** Minimal
- **Network:** None (local only)

### Optimization Tips

1. **Increase refresh interval** for lower resource usage
2. **Reduce max processes/connections** to display
3. **Disable sound alerts** for lower CPU
4. **Close browser tab** if not actively monitoring

---

## 🚀 Advanced Usage

### Custom Malware Patterns

Add new patterns to `app.py`:

```python
MALWARE_PATTERNS = {
    'CustomRAT': ['custom_pattern', 'another_name'],
    'Existing': ['pattern1', 'pattern2']
}
```

### Custom Suspicious Ports

```python
SUSPICIOUS_PORTS = {
    8080: 'Custom Port',
    9090: 'Another Port'
}
```

### API Integration

Integrate EDR data into other systems:

```bash
# Get current threats
curl http://localhost:5000/api/processes | jq '.processes[] | select(.risk_level == "CRITICAL")'

# Export alerts periodically
curl http://localhost:5000/api/export/alerts > alerts_$(date +%s).json
```

---

## 📚 Learning Resources

### Understanding the Detection Logic

1. **Process Risk Scoring:** See `ThreatDetector.assess_process_risk()` in `app.py`
2. **Network Risk Scoring:** See `ThreatDetector.assess_connection_risk()` in `app.py`
3. **Startup Analysis:** See `SecurityMonitor.get_startup_programs()` in `app.py`

### Cybersecurity Concepts

- **EDR (Endpoint Detection & Response):** Real-time threat detection on endpoints
- **Beaconing:** Repeated connections indicating command & control (C2)
- **Anomaly Detection:** Statistical deviation from baseline
- **Process Hollowing:** Malware technique using legitimate process images
- **Living off the Land:** Using system tools for malicious purposes

---

## 📝 Logging

### Alert Log File

Location: `security_alerts.log`

Contains all security events with timestamps:

```
2026-07-08 17:05:32,123 - WARNING - [HIGH] Suspicious Process: malware.exe
2026-07-08 17:06:15,456 - WARNING - [HIGH] Suspicious Network Connection
```

### Enabling Debug Logging

In `app.py`:
```python
logging.basicConfig(level=logging.DEBUG)  # More verbose output
```

---

## 🐛 Bug Reports & Features

Report issues or request features on GitHub:
- **Issues:** https://github.com/40dtrichgz-cmyk/wordle-flask/issues
- **Pull Requests:** Welcome!

---

## ⚖️ Legal & Ethical Use

This system is designed for:
✅ **Defensive security monitoring**
✅ **System administration**
✅ **Threat detection & response**
✅ **Educational purposes**
✅ **Corporate security operations**

**NOT for:**
❌ Unauthorized system access
❌ Malicious activity
❌ Privacy violations
❌ Illegal monitoring

---

## 📄 License

This project is provided as-is for educational and defensive security purposes.

---

## 👨‍💻 Author

**40dtrichgz-cmyk** - GitHub Security Enthusiast

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create Pull Request

---

## ⚡ Quick Commands Reference

```bash
# Install
pip install -r requirements.txt

# Run
python app.py

# With admin privileges (Windows)
python -m app.py  # Run as Admin in PowerShell

# Debug mode
set FLASK_DEBUG=1
python app.py

# Access dashboard
http://localhost:5000

# Export alerts
curl http://localhost:5000/api/export/alerts > alerts.json

# Check processes
curl http://localhost:5000/api/processes | python -m json.tool

# Check network
curl http://localhost:5000/api/network | python -m json.tool
```

---

## 📞 Support

For issues or questions:
1. Check troubleshooting section above
2. Review Flask/psutil documentation
3. Check GitHub issues
4. Open new issue with details

---

**Last Updated:** July 8, 2026
**Version:** 1.0.0
**Status:** ✅ Production Ready
