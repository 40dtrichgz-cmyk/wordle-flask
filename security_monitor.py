"""
Advanced Security Monitoring System for Windows
Detects: Malware, Unauthorized Access, Remote Tools, Suspicious Activity
"""

import os
import sys
import json
import psutil
import socket
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any
import re

try:
    import winreg
    WINDOWS = True
except ImportError:
    WINDOWS = False

# ==================== THREAT INTELLIGENCE DATABASE ====================

MALWARE_PATTERNS = {
    # Remote Access Tools (RATs)
    'AsyncRAT': ['asyncrat', 'asyncremote'],
    'Agent Tesla': ['agenttesla', 'agentt'],
    'Poison Ivy': ['poisonivy', 'pvivy'],
    'DarkComet': ['darkcomet', 'dc_client'],
    'njRAT': ['njrat', 'nj_'],
    'Mirai': ['mirai', 'botnet'],
    
    # Legit Remote Tools (Alert if unexpected)
    'RDP': ['rdpclip', 'mstsc'],
    'TeamViewer': ['teamviewer'],
    'AnyDesk': ['anydesk'],
    'VNC': ['vnc', 'uvnc'],
    
    # Hacking Tools
    'Mimikatz': ['mimikatz', 'mimi', 'sekurlsa'],
    'Metasploit': ['meterpreter', 'metasploit'],
    'Cobalt Strike': ['beacon', 'cobalt'],
    'Psexec': ['psexec', 'psexesvc'],
    'WinRAR': ['winrar', 'rar'],  # Often used to hide payloads
    
    # Rootkits & Persistence
    'ZeroAccess': ['zeroaccess', 'sirefef'],
    'Conficker': ['conficker', 'confickerWorm'],
    'TDL': ['tdl4', 'tdl3'],
    
    # Cryptominers
    'Cryptominer': ['stratum', 'pool.mining', 'xmrig', 'cpuminer'],
    'Monero Miner': ['monero', 'xmr'],
    
    # Keyloggers/Spyware
    'Keylogger': ['keylog', 'keystroke', 'hook'],
    'Spyware': ['spy', 'infostealer'],
    
    # Downloaders
    'Downloader': ['download', 'fetch', 'retrieve'],
    'Dropper': ['dropper', 'payload'],
}

SUSPICIOUS_PORTS = {
    # Command & Control
    4444: 'Metasploit/C2',
    5555: 'Remote Shell/ADB',
    6666: 'IRC/Botnet',
    7777: 'Remote Access',
    8888: 'Proxy/Bypass',
    9999: 'Remote Tool',
    1337: 'Elite/Hacker',
    1433: 'SQL Server (unexpected)',
    3389: 'RDP (unexpected)',
    5900: 'VNC',
    5985: 'WinRM',
    5986: 'WinRM (SSL)',
}

SUSPICIOUS_IPS = {
    # Common C2/Botnet servers (example - in production, use threat intel feeds)
}

SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl',  # URL shorteners (obfuscation)
    'pastebin.com', 'hastebin.com',  # Payload hosting
    'no-ip.com', 'dyn.com',  # Dynamic DNS (often used by malware)
]

WINDOWS_CRITICAL_PROCESSES = {
    'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe',
    'lsass.exe', 'services.exe', 'smss.exe', 'system',
}

# ==================== DETECTION LOGIC ====================

class ThreatDetector:
    def __init__(self):
        self.alerts = []
        self.connection_history = defaultdict(int)
        self.process_history = {}
        self.last_alert_time = {}
        
    def check_process_name(self, process_name: str) -> Dict[str, Any]:
        """Detect malicious process names"""
        result = {'risk': 'LOW', 'reason': '', 'malware_type': ''}
        
        name_lower = process_name.lower()
        
        # Check against malware patterns
        for malware_type, patterns in MALWARE_PATTERNS.items():
            for pattern in patterns:
                if pattern in name_lower:
                    result['risk'] = 'HIGH'
                    result['malware_type'] = malware_type
                    result['reason'] = f'Known malware pattern: {malware_type}'
                    return result
        
        # Suspicious naming patterns
        suspicious_patterns = [
            (r'^[a-z]{1,3}\.exe$', 'Suspiciously short executable name'),
            (r'^\d+\.exe$', 'Numeric executable (suspicious obfuscation)'),
            (r'.*\s+\(\d+\)\.exe$', 'Process with run count suffix'),
        ]
        
        for pattern, reason in suspicious_patterns:
            if re.match(pattern, name_lower):
                result['risk'] = 'MEDIUM'
                result['reason'] = reason
                return result
        
        return result
    
    def check_resource_anomaly(self, process: psutil.Process) -> Dict[str, Any]:
        """Detect abnormal CPU/Memory usage"""
        result = {'risk': 'LOW', 'reason': ''}
        
        try:
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            
            # System processes should be low
            if process.name().lower() not in WINDOWS_CRITICAL_PROCESSES:
                # Non-system process using >90% CPU sustained
                if cpu_percent > 90:
                    result['risk'] = 'HIGH'
                    result['reason'] = f'Excessive CPU usage: {cpu_percent:.1f}%'
                    return result
                
                # Consuming >1GB RAM (excluding browsers/IDEs)
                if memory_mb > 1024 and 'chrome' not in process.name().lower() and 'firefox' not in process.name().lower():
                    if cpu_percent > 50:  # Combined with CPU usage
                        result['risk'] = 'MEDIUM'
                        result['reason'] = f'High memory ({memory_mb:.0f}MB) + CPU ({cpu_percent:.1f}%)'
                        return result
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        return result
    
    def check_network_anomaly(self, connection) -> Dict[str, Any]:
        """Detect suspicious network connections"""
        result = {'risk': 'LOW', 'reason': ''}
        
        try:
            remote_ip = connection.raddr.ip if connection.raddr else None
            remote_port = connection.raddr.port if connection.raddr else None
            
            if not remote_ip or remote_ip == '0.0.0.0':
                return result
            
            # Suspicious port?
            if remote_port in SUSPICIOUS_PORTS:
                result['risk'] = 'HIGH'
                result['reason'] = f'Connection to suspicious port: {remote_port} ({SUSPICIOUS_PORTS[remote_port]})'
                return result
            
            # High-numbered ports (often used by malware for C2)
            if remote_port and remote_port > 40000:
                if connection.status == 'ESTABLISHED':
                    result['risk'] = 'MEDIUM'
                    result['reason'] = f'Established connection to high-numbered port: {remote_port}'
                    return result
            
            # Private IP ranges (internal reconnaissance)
            if self._is_private_ip(remote_ip):
                if connection.status == 'ESTABLISHED':
                    self.connection_history[remote_ip] += 1
                    if self.connection_history[remote_ip] > 20:
                        result['risk'] = 'MEDIUM'
                        result['reason'] = f'Repeated connections to internal IP {remote_ip}'
                        return result
            
            # Check for beaconing pattern (same remote IP multiple times)
            if connection.status == 'ESTABLISHED':
                self.connection_history[remote_ip] += 1
        
        except Exception:
            pass
        
        return result
    
    def check_remote_access_tools(self) -> List[Dict[str, Any]]:
        """Detect active remote access tools"""
        findings = []
        
        tools_to_check = {
            'mstsc.exe': 'RDP',
            'teamviewer.exe': 'TeamViewer',
            'anydesk.exe': 'AnyDesk',
            'vnc.exe': 'VNC',
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'status']):
                proc_name = proc.name().lower()
                
                for exe, tool_name in tools_to_check.items():
                    if exe in proc_name:
                        findings.append({
                            'tool': tool_name,
                            'process': proc.name(),
                            'pid': proc.pid,
                            'risk': 'MEDIUM',  # Could be legitimate or not
                            'reason': f'Remote access tool detected: {tool_name}'
                        })
        except Exception:
            pass
        
        return findings
    
    def check_persistence_mechanisms(self) -> List[Dict[str, Any]]:
        """Check for persistence (autorun entries, scheduled tasks)"""
        findings = []
        
        if not WINDOWS:
            return findings
        
        # Check Windows registry autorun keys
        autorun_paths = [
            r'Software\Microsoft\Windows\CurrentVersion\Run',
            r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
            r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        ]
        
        try:
            for autorun_path in autorun_paths:
                try:
                    reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, autorun_path)
                    i = 0
                    while True:
                        try:
                            name, value, reg_type = winreg.EnumValue(reg_key, i)
                            
                            # Check for suspicious autorun entries
                            if any(pattern in value.lower() for pattern in ['temp', 'appdata', 'programdata', '.tmp', '.bat', '.vbs']):
                                findings.append({
                                    'type': 'Registry Autorun',
                                    'key': name,
                                    'value': value,
                                    'risk': 'HIGH',
                                    'reason': 'Suspicious autorun entry pointing to temp/suspicious location'
                                })
                            
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(reg_key)
                except Exception:
                    pass
        except Exception:
            pass
        
        return findings
    
    def check_open_ports(self) -> List[Dict[str, Any]]:
        """Detect unusual open ports"""
        findings = []
        
        try:
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    
                    # Known suspicious listening port
                    if port in SUSPICIOUS_PORTS:
                        findings.append({
                            'port': port,
                            'protocol': 'TCP',
                            'risk': 'HIGH',
                            'reason': f'Suspicious port listening: {SUSPICIOUS_PORTS[port]}'
                        })
                    
                    # Unusual port ranges
                    elif port > 40000:
                        findings.append({
                            'port': port,
                            'protocol': 'TCP',
                            'risk': 'MEDIUM',
                            'reason': 'High-numbered port listening'
                        })
        except Exception:
            pass
        
        return findings
    
    def check_user_sessions(self) -> List[Dict[str, Any]]:
        """Detect multiple users or remote sessions"""
        findings = []
        
        if not WINDOWS:
            return findings
        
        try:
            # This requires WMI on Windows
            result = subprocess.run(
                ['query', 'session'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            sessions = result.stdout.strip().split('\n')[1:]
            if len(sessions) > 2:  # More than just console and disconnect
                findings.append({
                    'type': 'Multiple User Sessions',
                    'count': len(sessions),
                    'risk': 'MEDIUM',
                    'reason': f'Multiple active sessions detected: {len(sessions)}'
                })
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private range"""
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
        except:
            pass
        
        return False
    
    def generate_alert(self, severity: str, title: str, description: str, recommendation: str):
        """Create a new alert"""
        # Deduplication: don't alert for same issue within 60 seconds
        alert_key = f"{severity}_{title}"
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
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]


# ==================== MONITORING COLLECTOR ====================

class SecurityMonitor:
    def __init__(self):
        self.detector = ThreatDetector()
        self.scan_interval = 5  # seconds
        self.is_running = False
    
    def get_processes_info(self) -> List[Dict[str, Any]]:
        """Get all processes with threat assessment"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'status', 'create_time']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'status', 'create_time', 'ppid'])
                    
                    # Threat assessment
                    name_check = self.detector.check_process_name(pinfo['name'])
                    resource_check = self.detector.check_resource_anomaly(proc)
                    
                    risk = name_check['risk']
                    reason = name_check['reason'] or resource_check['reason']
                    malware_type = name_check.get('malware_type', '')
                    
                    # Escalate risk if multiple signals
                    if name_check['reason'] and resource_check['reason']:
                        risk = 'HIGH'
                    
                    try:
                        cpu_percent = proc.cpu_percent(interval=0.05)
                        memory_mb = proc.memory_info().rss / (1024 * 1024)
                    except:
                        cpu_percent = 0
                        memory_mb = 0
                    
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'status': pinfo['status'],
                        'cpu_percent': cpu_percent,
                        'memory_mb': memory_mb,
                        'risk': risk,
                        'reason': reason,
                        'malware_type': malware_type,
                        'create_time': pinfo['create_time'],
                        'ppid': pinfo['ppid']
                    })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        
        except Exception as e:
            print(f"Error getting processes: {e}")
        
        return processes
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get network connections with threat assessment"""
        connections = []
        stats = {'total': 0, 'established': 0, 'listening': 0, 'suspicious': 0}
        
        try:
            for conn in psutil.net_connections():
                try:
                    # Skip localhost internal noise
                    if conn.raddr and conn.raddr.ip == '127.0.0.1':
                        continue
                    
                    threat_check = self.detector.check_network_anomaly(conn)
                    
                    local_ip = conn.laddr.ip if conn.laddr else 'N/A'
                    local_port = conn.laddr.port if conn.laddr else 'N/A'
                    remote_ip = conn.raddr.ip if conn.raddr else 'N/A'
                    remote_port = conn.raddr.port if conn.raddr else 'N/A'
                    
                    connection_info = {
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'status': conn.status,
                        'pid': conn.pid,
                        'risk': threat_check['risk'],
                        'reason': threat_check['reason']
                    }
                    
                    # Get process name
                    try:
                        proc = psutil.Process(conn.pid)
                        connection_info['process'] = proc.name()
                    except:
                        connection_info['process'] = 'Unknown'
                    
                    connections.append(connection_info)
                    
                    stats['total'] += 1
                    if conn.status == 'ESTABLISHED':
                        stats['established'] += 1
                    elif conn.status == 'LISTEN':
                        stats['listening'] += 1
                    
                    if threat_check['risk'] in ['HIGH', 'MEDIUM']:
                        stats['suspicious'] += 1
                
                except Exception:
                    pass
        
        except Exception as e:
            print(f"Error getting network info: {e}")
        
        return {'connections': connections, 'stats': stats}
    
    def get_system_overview(self) -> Dict[str, Any]:
        """Get system health overview"""
        overview = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total_mb': psutil.virtual_memory().total / (1024**2),
                'used_mb': psutil.virtual_memory().used / (1024**2),
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total_mb': psutil.disk_usage('/').total / (1024**2),
                'used_mb': psutil.disk_usage('/').used / (1024**2),
                'percent': psutil.disk_usage('/').percent
            },
            'total_processes': len(psutil.pids()),
            'threats_detected': sum(1 for p in self.get_processes_info() if p['risk'] in ['HIGH', 'MEDIUM']),
            'alerts_count': len(self.detector.alerts)
        }
        
        return overview
    
    def full_security_scan(self) -> Dict[str, Any]:
        """Comprehensive security scan"""
        scan_result = {
            'timestamp': datetime.now().isoformat(),
            'overview': self.get_system_overview(),
            'processes': self.get_processes_info(),
            'network': self.get_network_info(),
            'open_ports': self.detector.check_open_ports(),
            'remote_tools': self.detector.check_remote_access_tools(),
            'persistence': self.detector.check_persistence_mechanisms(),
            'user_sessions': self.detector.check_user_sessions(),
            'alerts': self.detector.alerts
        }
        
        return scan_result
    
    def terminate_process(self, pid: int) -> Dict[str, Any]:
        """Safely terminate a process"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Prevent terminating critical processes
            if proc_name.lower() in WINDOWS_CRITICAL_PROCESSES:
                return {'success': False, 'error': f'Cannot terminate critical process: {proc_name}'}
            
            proc.terminate()
            time.sleep(1)
            
            if proc.is_running():
                proc.kill()  # Force kill if terminate didn't work
            
            return {'success': True, 'message': f'Process {proc_name} ({pid}) terminated'}
        
        except psutil.NoSuchProcess:
            return {'success': False, 'error': f'Process {pid} not found'}
        except psutil.AccessDenied:
            return {'success': False, 'error': f'Access denied to terminate process {pid}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


# ==================== FLASK APP ====================

if __name__ == '__main__':
    monitor = SecurityMonitor()
    
    # Quick test
    print("=" * 60)
    print("SECURITY MONITORING SYSTEM - Initial Scan")
    print("=" * 60)
    
    scan = monitor.full_security_scan()
    
    print(f"\nSystem Overview:")
    print(f"  CPU: {scan['overview']['cpu_percent']:.1f}%")
    print(f"  Memory: {scan['overview']['memory']['percent']:.1f}%")
    print(f"  Total Processes: {scan['overview']['total_processes']}")
    print(f"  Threats Detected: {scan['overview']['threats_detected']}")
    
    print(f"\nNetwork Stats:")
    print(f"  Total Connections: {scan['network']['stats']['total']}")
    print(f"  Established: {scan['network']['stats']['established']}")
    print(f"  Listening: {scan['network']['stats']['listening']}")
    print(f"  Suspicious: {scan['network']['stats']['suspicious']}")
    
    print(f"\nOpen Ports: {len(scan['open_ports'])}")
    print(f"Remote Tools: {len(scan['remote_tools'])}")
    print(f"Alerts: {len(scan['alerts'])}")
