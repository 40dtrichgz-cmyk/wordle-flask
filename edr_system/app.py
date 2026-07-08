"""
Advanced EDR-like Security Monitoring System
Flask Backend for Real-time Threat Detection and System Monitoring
"""

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import psutil
import socket
import json
import os
import threading
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess
import hashlib
from pathlib import Path

# ==================== CONFIGURATION ====================

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_alerts.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Threat intelligence
MALWARE_PATTERNS = {
    'AsyncRAT': ['asyncrat', 'asyncremote', 'acrly'],
    'Agent Tesla': ['agenttesla', 'agentt', 'tesla'],
    'Poison Ivy': ['poisonivy', 'pvivy', 'ivy'],
    'njRAT': ['njrat', 'nj_rat'],
    'Mirai': ['mirai', 'botnet', 'mirai_'],
    'Mimikatz': ['mimikatz', 'mimi', 'sekurlsa'],
    'Metasploit': ['meterpreter', 'metasploit', 'meterp'],
    'Cobalt Strike': ['beacon', 'cobalt', 'cobaltstrike'],
    'Emotet': ['emotet', 'heodo'],
    'TrickBot': ['trickbot', 'trick_'],
    'ZeroAccess': ['zeroaccess', 'sirefef'],
    'Cryptominer': ['stratum', 'xmrig', 'cpuminer', 'mining'],
}

SUSPICIOUS_PORTS = {
    4444: 'Metasploit/C2',
    5555: 'Remote Shell',
    6666: 'IRC/Botnet',
    7777: 'Remote Access',
    8888: 'Proxy/Tunnel',
    9999: 'Remote Tool',
    1337: 'Elite Port',
    5900: 'VNC',
}

WINDOWS_CRITICAL_PROCESSES = {
    'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe',
    'lsass.exe', 'services.exe', 'smss.exe', 'system', 'conhost.exe',
}

# Global state
threat_detector = None
monitoring_active = False
alerts_history = []
baseline_metrics = None

# ==================== THREAT DETECTION ENGINE ====================

class ThreatDetector:
    def __init__(self):
        self.alerts = []
        self.connection_history = defaultdict(int)
        self.process_history = {}
        self.last_alert_time = {}
        self.baseline = {
            'cpu': 30,
            'memory': 50,
            'connections': 50
        }
        
    def assess_process_risk(self, proc_info):
        """Comprehensive process risk assessment"""
        risk_score = 0
        risk_factors = []
        
        proc_name = proc_info['name'].lower()
        proc_path = proc_info.get('path', '').lower()
        cpu = proc_info.get('cpu_percent', 0)
        memory = proc_info.get('memory_mb', 0)
        
        # 1. Check malware patterns
        for malware, patterns in MALWARE_PATTERNS.items():
            for pattern in patterns:
                if pattern in proc_name:
                    risk_score += 40
                    risk_factors.append(f'Known malware: {malware}')
                    break
        
        # 2. Check process location (suspicious paths)
        suspicious_paths = ['temp', 'appdata', 'programdata', 'recycle', 'downloads', 'user\\temp']
        for suspicious in suspicious_paths:
            if suspicious in proc_path:
                risk_score += 25
                risk_factors.append(f'Running from suspicious path: {suspicious}')
                break
        
        # 3. Check for hidden/random process names
        if len(proc_name) <= 2 or (len(proc_name) > 3 and proc_name.isdigit()):
            risk_score += 15
            risk_factors.append('Suspicious process name (short/random)')
        
        # 4. Resource anomalies
        if cpu > 85:
            risk_score += 20
            risk_factors.append(f'Excessive CPU usage: {cpu:.1f}%')
        
        if memory > 1024 and 'chrome' not in proc_name and 'firefox' not in proc_name:
            risk_score += 15
            risk_factors.append(f'High memory consumption: {memory:.0f}MB')
        
        # 5. Network behavior (checked separately)
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = 'CRITICAL'
        elif risk_score >= 40:
            risk_level = 'HIGH'
        elif risk_score >= 20:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'factors': risk_factors
        }
    
    def assess_connection_risk(self, conn_info):
        """Assess network connection risk"""
        risk_score = 0
        risk_factors = []
        
        remote_ip = conn_info.get('remote_ip', '')
        remote_port = conn_info.get('remote_port', 0)
        status = conn_info.get('status', '')
        
        # Skip internal connections
        if self._is_private_ip(remote_ip):
            return {'risk_level': 'LOW', 'risk_score': 0, 'factors': []}
        
        # 1. Suspicious ports
        if remote_port in SUSPICIOUS_PORTS:
            risk_score += 35
            risk_factors.append(f'Suspicious port: {remote_port} ({SUSPICIOUS_PORTS[remote_port]})')
        
        # 2. High-numbered ports
        if remote_port > 40000 and status == 'ESTABLISHED':
            risk_score += 20
            risk_factors.append(f'High-numbered port: {remote_port}')
        
        # 3. Repeated connections (beaconing pattern)
        self.connection_history[remote_ip] += 1
        if self.connection_history[remote_ip] > 30:
            risk_score += 25
            risk_factors.append(f'Repeated connections to {remote_ip}')
        
        if risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'factors': risk_factors
        }
    
    @staticmethod
    def _is_private_ip(ip):
        """Check if IP is in private range"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            if first == 10:
                return True
            if first == 172 and 16 <= int(parts[1]) <= 31:
                return True
            if first == 192 and int(parts[1]) == 168:
                return True
            if first == 127:
                return True
            return False
        except:
            return False
    
    def add_alert(self, severity, title, description, recommendation):
        """Add alert with deduplication"""
        alert_key = f"{severity}_{title}"
        
        # Deduplication: skip if same alert within 60 seconds
        if alert_key in self.last_alert_time:
            if datetime.now() - self.last_alert_time[alert_key] < timedelta(seconds=60):
                return
        
        self.last_alert_time[alert_key] = datetime.now()
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation
        }
        
        self.alerts.append(alert)
        
        # Keep last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        
        # Log to file
        logger.warning(f"[{severity}] {title}: {description}")


# ==================== DATA COLLECTION ====================

class SecurityMonitor:
    def __init__(self):
        self.detector = ThreatDetector()
        self.last_scan_time = None
        
    def get_processes(self):
        """Get all processes with threat assessment"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'status', 'create_time']):
                try:
                    # Get process info
                    pinfo = proc.as_dict()
                    
                    # Get path
                    try:
                        path = proc.exe()
                    except:
                        path = 'N/A'
                    
                    # Get resources
                    try:
                        cpu_percent = proc.cpu_percent(interval=0.01)
                        memory_info = proc.memory_info()
                        memory_mb = memory_info.rss / (1024 * 1024)
                    except:
                        cpu_percent = 0
                        memory_mb = 0
                    
                    proc_info = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'status': pinfo['status'],
                        'path': path,
                        'cpu_percent': cpu_percent,
                        'memory_mb': memory_mb,
                        'ppid': pinfo.get('ppid', 0),
                        'create_time': pinfo.get('create_time', 0)
                    }
                    
                    # Assess risk
                    risk_assessment = self.detector.assess_process_risk(proc_info)
                    proc_info.update(risk_assessment)
                    
                    # Alert if critical
                    if risk_assessment['risk_level'] in ['CRITICAL', 'HIGH']:
                        self.detector.add_alert(
                            risk_assessment['risk_level'],
                            f'Suspicious Process: {pinfo["name"]}',
                            f'PID {pinfo["pid"]}: {", ".join(risk_assessment["factors"])}',
                            f'Review process at {path} and terminate if unauthorized'
                        )
                    
                    processes.append(proc_info)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        
        except Exception as e:
            logger.error(f"Error getting processes: {e}")
        
        return processes
    
    def get_network_connections(self):
        """Get active network connections"""
        connections = []
        stats = {'total': 0, 'established': 0, 'listening': 0, 'suspicious': 0}
        
        try:
            for conn in psutil.net_connections():
                try:
                    # Skip localhost noise
                    if conn.raddr and conn.raddr.ip == '127.0.0.1':
                        continue
                    
                    remote_ip = conn.raddr.ip if conn.raddr else 'N/A'
                    remote_port = conn.raddr.port if conn.raddr else 'N/A'
                    local_ip = conn.laddr.ip if conn.laddr else 'N/A'
                    local_port = conn.laddr.port if conn.laddr else 'N/A'
                    
                    conn_info = {
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'status': conn.status,
                        'pid': conn.pid,
                    }
                    
                    # Get process name
                    try:
                        proc = psutil.Process(conn.pid)
                        conn_info['process'] = proc.name()
                    except:
                        conn_info['process'] = 'Unknown'
                    
                    # Assess risk
                    risk_assessment = self.detector.assess_connection_risk(conn_info)
                    conn_info.update(risk_assessment)
                    
                    # Alert if suspicious
                    if risk_assessment['risk_level'] in ['HIGH', 'MEDIUM']:
                        self.detector.add_alert(
                            risk_assessment['risk_level'],
                            f'Suspicious Network Connection',
                            f'{conn_info["process"]} → {remote_ip}:{remote_port}: {", ".join(risk_assessment["factors"])}',
                            f'Investigate connection to {remote_ip} from {conn_info["process"]}'
                        )
                    
                    connections.append(conn_info)
                    
                    stats['total'] += 1
                    if conn.status == 'ESTABLISHED':
                        stats['established'] += 1
                    elif conn.status == 'LISTEN':
                        stats['listening'] += 1
                    
                    if risk_assessment['risk_level'] in ['HIGH', 'MEDIUM']:
                        stats['suspicious'] += 1
                
                except Exception:
                    pass
        
        except Exception as e:
            logger.error(f"Error getting network connections: {e}")
        
        return {'connections': connections, 'stats': stats}
    
    def get_system_status(self):
        """Get system health metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Anomaly detection: check against baseline
            anomalies = []
            if baseline_metrics:
                if cpu_percent > baseline_metrics['cpu_percent'] + 40:
                    anomalies.append(f'CPU spike: {cpu_percent:.1f}%')
                if memory.percent > baseline_metrics['memory']['percent'] + 30:
                    anomalies.append(f'Memory spike: {memory.percent:.1f}%')
            
            if anomalies:
                self.detector.add_alert(
                    'MEDIUM',
                    'System Resource Anomaly',
                    ', '.join(anomalies),
                    'Check for resource-intensive or malicious processes'
                )
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory': {
                    'total_mb': memory.total / (1024**2),
                    'used_mb': memory.used / (1024**2),
                    'percent': memory.percent
                },
                'disk': {
                    'total_mb': disk.total / (1024**2),
                    'used_mb': disk.used / (1024**2),
                    'percent': disk.percent
                },
                'process_count': len(psutil.pids()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'anomalies': anomalies
            }
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return None
    
    def get_startup_programs(self):
        """Get auto-start programs"""
        startup_items = []
        
        if os.name == 'nt':  # Windows
            try:
                import winreg
                
                autorun_paths = [
                    r'Software\Microsoft\Windows\CurrentVersion\Run',
                    r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                    r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                ]
                
                for autorun_path in autorun_paths:
                    try:
                        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, autorun_path)
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(reg_key, i)
                                
                                # Check for suspicious locations
                                risk = 'LOW'
                                if any(x in value.lower() for x in ['temp', 'appdata', 'programdata', '.tmp', '.vbs', '.bat', '.ps1']):
                                    risk = 'HIGH'
                                    self.detector.add_alert(
                                        'HIGH',
                                        'Suspicious Autorun Entry',
                                        f'{name}: {value}',
                                        'Remove this entry or verify its legitimacy'
                                    )
                                
                                startup_items.append({
                                    'name': name,
                                    'path': value,
                                    'registry_path': autorun_path,
                                    'risk': risk
                                })
                                
                                i += 1
                            except OSError:
                                break
                        
                        winreg.CloseKey(reg_key)
                    except:
                        pass
            except ImportError:
                logger.warning("winreg not available (not on Windows)")
        
        return startup_items
    
    def get_user_sessions(self):
        """Get logged-in users"""
        sessions = []
        
        if os.name == 'nt':  # Windows
            try:
                result = subprocess.run(
                    ['query', 'user'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        sessions.append({
                            'username': parts[0],
                            'session_name': parts[1] if len(parts) > 1 else 'N/A',
                            'session_id': parts[2] if len(parts) > 2 else 'N/A',
                            'status': parts[3] if len(parts) > 3 else 'N/A'
                        })
                
                # Alert on multiple sessions
                if len(sessions) > 2:
                    self.detector.add_alert(
                        'MEDIUM',
                        f'Multiple User Sessions Detected',
                        f'{len(sessions)} sessions active',
                        'Verify all sessions are authorized'
                    )
            except Exception as e:
                logger.error(f"Error getting user sessions: {e}")
        
        return sessions
    
    def terminate_process(self, pid):
        """Safely terminate a process"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Protect critical processes
            if proc_name.lower() in WINDOWS_CRITICAL_PROCESSES:
                return {
                    'success': False,
                    'error': f'Cannot terminate critical process: {proc_name}'
                }
            
            logger.warning(f"Terminating process: {proc_name} (PID {pid})")
            proc.terminate()
            
            time.sleep(1)
            if proc.is_running():
                proc.kill()
            
            self.detector.add_alert(
                'INFO',
                f'Process Terminated',
                f'{proc_name} (PID {pid}) was terminated',
                'Process removed from system'
            )
            
            return {
                'success': True,
                'message': f'Process {proc_name} terminated'
            }
        
        except psutil.NoSuchProcess:
            return {'success': False, 'error': 'Process not found'}
        except psutil.AccessDenied:
            return {'success': False, 'error': 'Access denied'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


# ==================== INITIALIZE ====================

monitor = SecurityMonitor()
threat_detector = monitor.detector


# ==================== FLASK ROUTES ====================

@app.route('/')
def index():
    """Serve dashboard"""
    return render_template('index.html')


@app.route('/api/system', methods=['GET'])
def api_system():
    """Get system overview"""
    status = monitor.get_system_status()
    return jsonify(status)


@app.route('/api/processes', methods=['GET'])
def api_processes():
    """Get all processes"""
    processes = monitor.get_processes()
    
    # Sort by risk level
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    processes.sort(key=lambda x: (risk_order.get(x['risk_level'], 4), -x['cpu_percent']))
    
    return jsonify({
        'count': len(processes),
        'critical': len([p for p in processes if p['risk_level'] == 'CRITICAL']),
        'high': len([p for p in processes if p['risk_level'] == 'HIGH']),
        'processes': processes[:200]  # Limit to top 200
    })


@app.route('/api/network', methods=['GET'])
def api_network():
    """Get network connections"""
    network_info = monitor.get_network_connections()
    
    # Sort by risk
    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    conns = network_info['connections']
    conns.sort(key=lambda x: risk_order.get(x['risk_level'], 3))
    
    return jsonify({
        'stats': network_info['stats'],
        'connections': conns[:100]  # Limit to top 100
    })


@app.route('/api/startup', methods=['GET'])
def api_startup():
    """Get startup programs"""
    startup = monitor.get_startup_programs()
    
    # Sort by risk
    startup.sort(key=lambda x: (x['risk'] == 'LOW', x['name']))
    
    return jsonify({
        'count': len(startup),
        'high_risk': len([s for s in startup if s['risk'] == 'HIGH']),
        'items': startup
    })


@app.route('/api/sessions', methods=['GET'])
def api_sessions():
    """Get user sessions"""
    sessions = monitor.get_user_sessions()
    return jsonify({'sessions': sessions})


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get security alerts"""
    alerts = threat_detector.alerts[-50:]  # Last 50 alerts
    return jsonify({
        'count': len(alerts),
        'critical': len([a for a in alerts if a['severity'] == 'CRITICAL']),
        'high': len([a for a in alerts if a['severity'] == 'HIGH']),
        'alerts': alerts
    })


@app.route('/api/process/<int:pid>/kill', methods=['POST'])
def api_kill_process(pid):
    """Terminate a process"""
    result = monitor.terminate_process(pid)
    return jsonify(result)


@app.route('/api/baseline', methods=['POST'])
def api_set_baseline():
    """Set baseline metrics for anomaly detection"""
    global baseline_metrics
    baseline_metrics = monitor.get_system_status()
    return jsonify({
        'success': True,
        'message': 'Baseline metrics set',
        'baseline': baseline_metrics
    })


@app.route('/api/export/alerts', methods=['GET'])
def api_export_alerts():
    """Export alerts as JSON"""
    return jsonify({
        'export_time': datetime.now().isoformat(),
        'alerts': threat_detector.alerts
    })


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500


# ==================== ENTRY POINT ====================

if __name__ == '__main__':
    logger.info("Starting Security Monitoring System...")
    print("\n" + "="*60)
    print("   SECURITY MONITORING SYSTEM - EDR Dashboard")
    print("="*60)
    print("\n✓ Starting Flask server...")
    print("✓ Navigate to: http://localhost:5000")
    print("✓ Press CTRL+C to stop\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
