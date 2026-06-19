#!/usr/bin/env python3
"""
Comprehensive MITRE ATT&CK Coverage Analysis Report Generator

Generates professional HTML and PDF reports with:
- Decorated visuals and charts
- Assessment scores by tactic and technique
- Coverage heatmap
- Detailed statistics and graphs
- Recommended rules to close coverage gaps
- Executive summary and key findings
"""

import json
from datetime import datetime
from pathlib import Path
import base64
from typing import Dict, List, Tuple
import statistics

# ============================================================================
# MITRE FRAMEWORK DATA
# ============================================================================

MITRE_TACTICS = [
    ("TA0001", "Initial Access", "#FF6B6B"),
    ("TA0002", "Execution", "#FFA500"),
    ("TA0003", "Persistence", "#FFD700"),
    ("TA0004", "Privilege Escalation", "#ADFF2F"),
    ("TA0005", "Defense Evasion", "#90EE90"),
    ("TA0006", "Credential Access", "#00CED1"),
    ("TA0007", "Discovery", "#1E90FF"),
    ("TA0008", "Lateral Movement", "#4169E1"),
    ("TA0009", "Collection", "#8B008B"),
    ("TA0010", "Exfiltration", "#FF1493"),
    ("TA0011", "Command and Control", "#DC143C"),
    ("TA0040", "Impact", "#8B0000"),
]

MITRE_COVERAGE_DATA = {
    "TA0001": {
        "name": "Initial Access",
        "coverage": 95,
        "incidents": 2562,
        "techniques": 9,
        "covered_techniques": 8,
        "techniques_list": [
            ("T1200", "Hardware Additions", True, 100),
            ("T1566", "Phishing", True, 100),
            ("T1091", "Replication Through Removable Media", False, 0),
            ("T1195", "Supply Chain Compromise", True, 85),
            ("T1199", "Trusted Relationship", True, 92),
            ("T1566.002", "Phishing: Spearphishing Link", True, 100),
            ("T1566.001", "Phishing: Spearphishing Attachment", True, 95),
            ("T1598", "Phishing for Information", True, 88),
            ("T1091", "Replication Through Removable Media", False, 0),
        ]
    },
    "TA0002": {
        "name": "Execution",
        "coverage": 45,
        "incidents": 342,
        "techniques": 14,
        "covered_techniques": 6,
        "techniques_list": [
            ("T1059", "Command and Scripting Interpreter", True, 78),
            ("T1203", "Exploitation for Client Execution", True, 65),
            ("T1559", "Inter-Process Communication", True, 52),
            ("T1559.001", "Component Object Model", True, 58),
            ("T1648", "Serverless Execution", False, 0),
            ("T1204", "User Execution", True, 82),
            ("T1559.002", "Dynamic Data Exchange", False, 0),
            ("T1559.003", "WMI Event Subscription", True, 48),
            ("T1112", "Modify Registry", False, 0),
            ("T1053", "Scheduled Task/Job", True, 72),
            ("T1129", "Shared Modules", False, 0),
            ("T1072", "Software Deployment Tools", False, 0),
            ("T1648", "Execution via API", False, 0),
            ("T1547.014", "Run Registry Modified", False, 0),
        ]
    },
    "TA0003": {
        "name": "Persistence",
        "coverage": 38,
        "incidents": 268,
        "techniques": 19,
        "covered_techniques": 7,
        "techniques_list": [
            ("T1098", "Account Manipulation", True, 75),
            ("T1547", "Boot or Logon Autostart Execution", True, 62),
            ("T1547.001", "Registry Run Keys / Start Folder", False, 0),
            ("T1547.014", "Active Setup", False, 0),
            ("T1547.013", "Logon Hook", False, 0),
            ("T1547.008", "LSASS Driver", False, 0),
            ("T1547.007", "Re-opened Applications", False, 0),
            ("T1547.001", "Registry Run Keys / Start Folder", True, 58),
            ("T1547.014", "Active Setup", False, 0),
            ("T1547.015", "Login Items", False, 0),
            ("T1547.013", "Logon Hook", False, 0),
            ("T1547.009", "Shortcut Modification", False, 0),
            ("T1547.003", "Network Logon Script", False, 0),
            ("T1547.011", "Plist Modification", False, 0),
            ("T1547.008", "LSASS Driver", False, 0),
            ("T1547.006", "Kernel Modules and Extensions", False, 0),
            ("T1547.002", "Browser Extensions", False, 0),
            ("T1547.004", "Winlogon Helper DLL", False, 0),
            ("T1547.010", "Port Monitors", False, 0),
        ]
    },
    "TA0004": {
        "name": "Privilege Escalation",
        "coverage": 32,
        "incidents": 156,
        "techniques": 17,
        "covered_techniques": 5,
        "techniques_list": [
            ("T1548", "Abuse Elevation Control Mechanism", True, 68),
            ("T1548.002", "Bypass User Access Control", True, 72),
            ("T1548.003", "Sudo and Sudo Caching", False, 0),
            ("T1548.001", "Setuid and Setgid", False, 0),
            ("T1548.004", "Elevated Execution with Prompt", False, 0),
            ("T1547.001", "Registry Run Keys / Start Folder", True, 55),
            ("T1547.004", "Winlogon Helper DLL", False, 0),
            ("T1547.008", "LSASS Driver", False, 0),
            ("T1547.009", "Shortcut Modification", False, 0),
            ("T1547.003", "Network Logon Script", False, 0),
            ("T1547.013", "Logon Hook", False, 0),
            ("T1547.006", "Kernel Modules and Extensions", False, 0),
            ("T1547.007", "Re-opened Applications", False, 0),
            ("T1547.010", "Port Monitors", False, 0),
            ("T1547.014", "Active Setup", False, 0),
            ("T1098", "Account Manipulation", True, 62),
            ("T1134", "Access Token Manipulation", False, 0),
        ]
    },
    "TA0005": {
        "name": "Defense Evasion",
        "coverage": 28,
        "incidents": 124,
        "techniques": 34,
        "covered_techniques": 9,
        "techniques_list": [
            ("T1548", "Abuse Elevation Control Mechanism", True, 65),
            ("T1548.002", "Bypass User Access Control", True, 68),
            ("T1548.003", "Sudo and Sudo Caching", False, 0),
            ("T1548.004", "Elevated Execution with Prompt", False, 0),
            ("T1548.001", "Setuid and Setgid", False, 0),
            ("T1548.005", "Temporary Elevated Cloud Access", False, 0),
            ("T1197", "BITS Jobs", False, 0),
            ("T1612", "Build Image on Host", False, 0),
            ("T1140", "Deobfuscate/Decode Files or Information", True, 58),
            ("T1222", "File and Directory Permissions Modification", False, 0),
            ("T1202", "Indirect Command Execution", False, 0),
            ("T1036", "Masquerading", True, 72),
            ("T1036.005", "Match Legitimate Name or Location", True, 68),
            ("T1036.003", "Rename System Utilities", False, 0),
            ("T1036.006", "Space after Filename", False, 0),
            ("T1036.002", "Space after Filename", False, 0),
            ("T1036.004", "Masquerade Task Scheduler Task", False, 0),
            ("T1036.001", "Invalid Code Signature", False, 0),
            ("T1036.007", "Double File Extension", False, 0),
            ("T1036.008", "Masquerading as System File or Directory", False, 0),
            ("T1207", "Rogue Domain Controller", False, 0),
            ("T1578", "Modify Cloud Compute Infrastructure", False, 0),
            ("T1578.001", "Create Snapshot", False, 0),
            ("T1578.002", "Create Cloud Instance", False, 0),
            ("T1578.003", "Delete Cloud Instance", False, 0),
            ("T1578.004", "Revert Cloud Instance", False, 0),
            ("T1110", "Brute Force", True, 62),
            ("T1110.001", "Password Guessing", True, 65),
            ("T1110.004", "Credential Stuffing", True, 58),
            ("T1110.002", "Password Cracking", False, 0),
            ("T1110.003", "Password Spraying", False, 0),
            ("T1578.005", "Modify Cloud Compute Infrastructure", False, 0),
            ("T1112", "Modify Registry", False, 0),
            ("T1601", "Modify System Image", False, 0),
        ]
    },
    "TA0006": {
        "name": "Credential Access",
        "coverage": 52,
        "incidents": 428,
        "techniques": 18,
        "covered_techniques": 9,
        "techniques_list": [
            ("T1110", "Brute Force", True, 78),
            ("T1110.001", "Password Guessing", True, 82),
            ("T1110.003", "Password Spraying", True, 85),
            ("T1110.004", "Credential Stuffing", True, 72),
            ("T1110.002", "Password Cracking", False, 0),
            ("T1555", "Credentials from Password Stores", True, 68),
            ("T1056", "Input Capture", True, 45),
            ("T1056.001", "Keylogging", True, 52),
            ("T1056.002", "GUI Input Capture", False, 0),
            ("T1056.003", "Web Portal Capture", False, 0),
            ("T1056.004", "Credential API Hooking", False, 0),
            ("T1187", "Forced Phishing", False, 0),
            ("T1040", "Network Sniffing", False, 0),
            ("T1111", "Multi-Factor Authentication Interception", True, 35),
            ("T1621", "Multi-Factor Authentication Interception", True, 42),
            ("T1040", "Network Sniffing", False, 0),
            ("T1003", "OS Credential Dumping", False, 0),
            ("T1528", "Steal Application Access Token", False, 0),
        ]
    },
    "TA0007": {
        "name": "Discovery",
        "coverage": 35,
        "incidents": 187,
        "techniques": 30,
        "covered_techniques": 10,
        "techniques_list": [
            ("T1087", "Account Discovery", True, 72),
            ("T1010", "Application Window Discovery", True, 52),
            ("T1217", "Browser Bookmark Discovery", False, 0),
            ("T1580", "Cloud Infrastructure Discovery", True, 65),
            ("T1526", "Enumerate Cloud Resources", True, 68),
            ("T1538", "Cloud Service Dashboard", True, 48),
            ("T1526", "Enumerate Cloud Resources", True, 68),
            ("T1619", "Cloud Storage Object Discovery", True, 55),
            ("T1622", "Debugger Evasion", False, 0),
            ("T1538", "Cloud Service Dashboard", True, 48),
            ("T1526", "Enumerate Cloud Resources", True, 68),
            ("T1087", "Account Discovery", True, 72),
            ("T1087.004", "Cloud Account Discovery", True, 75),
            ("T1087.001", "Local Account Discovery", False, 0),
            ("T1087.002", "Domain Account Discovery", False, 0),
            ("T1087.003", "Email Account Discovery", True, 68),
            ("T1087.004", "Cloud Account Discovery", True, 75),
            ("T1010", "Application Window Discovery", True, 52),
            ("T1538", "Cloud Service Dashboard", True, 48),
            ("T1217", "Browser Bookmark Discovery", False, 0),
            ("T1580", "Cloud Infrastructure Discovery", True, 65),
            ("T1538", "Cloud Service Dashboard", True, 48),
            ("T1526", "Enumerate Cloud Resources", True, 68),
            ("T1619", "Cloud Storage Object Discovery", True, 55),
            ("T1538", "Cloud Service Dashboard", True, 48),
            ("T1087", "Account Discovery", True, 72),
            ("T1087.001", "Local Account Discovery", False, 0),
            ("T1087.002", "Domain Account Discovery", False, 0),
            ("T1087.003", "Email Account Discovery", True, 68),
            ("T1087.004", "Cloud Account Discovery", True, 75),
        ]
    },
    "TA0008": {
        "name": "Lateral Movement",
        "coverage": 0,
        "incidents": 0,
        "techniques": 9,
        "covered_techniques": 0,
        "techniques_list": [
            ("T1570", "Lateral Tool Transfer", False, 0),
            ("T1570", "Lateral Tool Transfer", False, 0),
            ("T1021", "Remote Service Session Initiation", False, 0),
            ("T1021.001", "Remote Desktop Protocol", False, 0),
            ("T1021.002", "SSH", False, 0),
            ("T1021.003", "Distributed Component Object Model", False, 0),
            ("T1021.004", "SSH", False, 0),
            ("T1021.005", "Windows Remote Management", False, 0),
            ("T1021.006", "Windows Management Instrumentation", False, 0),
            ("T1021.007", "Secure Shell", False, 0),
        ]
    },
    "TA0009": {
        "name": "Collection",
        "coverage": 22,
        "incidents": 89,
        "techniques": 20,
        "covered_techniques": 4,
        "techniques_list": [
            ("T1557", "Adversary-in-the-Middle", True, 45),
            ("T1557.002", "ARP Cache Poisoning", False, 0),
            ("T1557.003", "DHCP Spoofing", False, 0),
            ("T1557.001", "LLMNR/NBT-NS Poisoning and Relay", False, 0),
            ("T1123", "Audio Capture", False, 0),
            ("T1119", "Automated Exfiltration", False, 0),
            ("T1115", "Clipboard Data", True, 38),
            ("T1530", "Data from Cloud Storage Object", True, 52),
            ("T1602", "Data from Network Device Config Repository", False, 0),
            ("T1213", "Data from Information Repositories", True, 48),
            ("T1005", "Data from Local System", True, 42),
            ("T1039", "Data from Network Shared Drive", True, 35),
            ("T1025", "Data Staged", True, 28),
            ("T1056", "Input Capture", True, 45),
            ("T1113", "Screen Capture", True, 52),
            ("T1123", "Audio Capture", False, 0),
            ("T1119", "Automated Exfiltration", False, 0),
            ("T1123", "Audio Capture", False, 0),
            ("T1119", "Automated Exfiltration", False, 0),
            ("T1123", "Audio Capture", False, 0),
        ]
    },
    "TA0010": {
        "name": "Exfiltration",
        "coverage": 8,
        "incidents": 22,
        "techniques": 13,
        "covered_techniques": 1,
        "techniques_list": [
            ("T1020", "Automated Exfiltration", True, 35),
            ("T1030", "Data Transfer Size Limits", False, 0),
            ("T1048", "Exfiltration Over Alternative Protocol", False, 0),
            ("T1048.001", "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol", False, 0),
            ("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", False, 0),
            ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", False, 0),
            ("T1041", "Exfiltration Over C2 Channel", False, 0),
            ("T1011", "Exfiltration Over Other Network Medium", False, 0),
            ("T1052", "Exfiltration Over Physical Medium", False, 0),
            ("T1048", "Exfiltration Over Alternative Protocol", False, 0),
            ("T1020", "Automated Exfiltration", True, 35),
            ("T1030", "Data Transfer Size Limits", False, 0),
            ("T1537", "Transfer Data to Cloud Account", False, 0),
        ]
    },
    "TA0011": {
        "name": "Command and Control",
        "coverage": 5,
        "incidents": 8,
        "techniques": 17,
        "covered_techniques": 1,
        "techniques_list": [
            ("T1071", "Application Layer Protocol", False, 0),
            ("T1071.001", "Web Protocols", True, 28),
            ("T1071.002", "File Transfer Protocols", False, 0),
            ("T1071.003", "Mail Protocols", False, 0),
            ("T1071.004", "DNS", False, 0),
            ("T1092", "Communication Through Removable Media", False, 0),
            ("T1008", "Fallback Channels", False, 0),
            ("T1105", "Ingress Tool Transfer", False, 0),
            ("T1571", "Non-Standard Port", False, 0),
            ("T1572", "Protocol Tunneling", False, 0),
            ("T1008", "Fallback Channels", False, 0),
            ("T1105", "Ingress Tool Transfer", False, 0),
            ("T1571", "Non-Standard Port", False, 0),
            ("T1572", "Protocol Tunneling", False, 0),
            ("T1008", "Fallback Channels", False, 0),
            ("T1105", "Ingress Tool Transfer", False, 0),
            ("T1571", "Non-Standard Port", False, 0),
        ]
    },
    "TA0040": {
        "name": "Impact",
        "coverage": 12,
        "incidents": 45,
        "techniques": 16,
        "covered_techniques": 2,
        "techniques_list": [
            ("T1531", "Account Access Removal", False, 0),
            ("T1485", "Data Destruction", False, 0),
            ("T1491", "Defacement", True, 32),
            ("T1491.001", "Internal Defacement", True, 38),
            ("T1491.002", "External Defacement", False, 0),
            ("T1561", "Disk Wipe", False, 0),
            ("T1561.001", "Disk Structure Wipe", False, 0),
            ("T1561.002", "Disk Content Wipe", False, 0),
            ("T1499", "Endpoint Denial of Service", False, 0),
            ("T1561", "Disk Wipe", False, 0),
            ("T1499.001", "OS Exhaustion Flood", False, 0),
            ("T1499.002", "Service Exhaustion Flood", False, 0),
            ("T1499.003", "Application Exhaustion Flood", False, 0),
            ("T1561", "Disk Wipe", False, 0),
            ("T1529", "System Shutdown/Reboot", True, 25),
            ("T1561", "Disk Wipe", False, 0),
        ]
    },
}

RECOMMENDED_RULES = [
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    {
        "id": 1,
        "tactic": "TA0008", "tactic_name": "Lateral Movement",
        "technique": "T1021.001", "technique_name": "Remote Desktop Protocol",
        "priority": "CRITICAL",
        "description": "Detect RDP lateral movement via EventID 4648/4624 LogonType 10. Alert on RDP from non-admin workstations, connections to multiple hosts within short windows, and off-hours logins.",
        "mitre_data_source": "Windows Security Event Logs",
        "estimated_incidents": 450,
        "detection_method": "Behavioral: same account RDP-ing to 3+ unique hosts within 1 hour; logons outside business hours; source IP not in approved admin workstation list",
        "implementation_effort": "Medium",
        "rule_template": """SecurityEvent
| where EventID in (4648, 4624, 4625) and LogonType == 10
| where AccountName !endswith '$'
| summarize Count=count(), Hosts=dcount(Computer)
    by Account, IpAddress, bin(TimeGenerated, 1h)
| where Hosts > 3 or Count > 20
| extend RiskScore = iff(Hosts > 5, "Critical", "High")"""
    },
    {
        "id": 2,
        "tactic": "TA0008", "tactic_name": "Lateral Movement",
        "technique": "T1021.005", "technique_name": "Windows Remote Management (WinRM)",
        "priority": "CRITICAL",
        "description": "Monitor WinRM (port 5985/5986) session initiations and correlate with PowerShell execution on remote host. WinRM is frequently abused for fileless lateral spread.",
        "mitre_data_source": "Network Events, Windows Event Logs",
        "estimated_incidents": 280,
        "detection_method": "Alert on port 5985/5986 connections from non-admin accounts; WinRM sessions correlated with PowerShell -EncodedCommand on remote host",
        "implementation_effort": "Medium",
        "rule_template": """DeviceNetworkEvents
| where RemotePort in (5985, 5986)
| where InitiatingProcessAccountName !endswith '-adm'
| join kind=inner (
    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine contains "EncodedCommand"
) on DeviceName
| summarize count() by DeviceName, RemoteIp, InitiatingProcessAccountName"""
    },
    {
        "id": 3,
        "tactic": "TA0008", "tactic_name": "Lateral Movement",
        "technique": "T1550.002", "technique_name": "Pass-the-Hash",
        "priority": "CRITICAL",
        "description": "Detect Pass-the-Hash via NTLM LogonType 3 anomalies: same hash authenticating to multiple hosts rapidly, or NTLM auth from hosts where the account has never logged on before.",
        "mitre_data_source": "Windows Security Event Logs",
        "estimated_incidents": 380,
        "detection_method": "Correlate NTLM LogonType 3 with NtLmSsp auth package; alert on same account authenticating to 3+ unique hosts within 15 minutes",
        "implementation_effort": "Medium",
        "rule_template": """SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName =~ "NTLM"
| where AccountName !endswith '$'
| summarize TargetHosts=dcount(Computer), Count=count()
    by Account, IpAddress, bin(TimeGenerated, 15m)
| where TargetHosts >= 3
| extend Severity = iff(TargetHosts >= 5, "High", "Medium")"""
    },
    {
        "id": 4,
        "tactic": "TA0006", "tactic_name": "Credential Access",
        "technique": "T1003.001", "technique_name": "LSASS Memory Dump",
        "priority": "CRITICAL",
        "description": "Detect LSASS process memory access via MDE DeviceProcessEvents for Mimikatz, procdump, and similar tools. LSASS dumps are the primary path to domain-wide credential harvesting.",
        "mitre_data_source": "Sysmon Event 10, MDE DeviceProcessEvents",
        "estimated_incidents": 320,
        "detection_method": "Alert on: procdump/mimikatz/nanodump by name; processes opening lsass.exe with PROCESS_VM_READ (AccessMask 0x1010/0x1410); sqldumper targeting lsass",
        "implementation_effort": "Low",
        "rule_template": """DeviceProcessEvents
| where FileName has_any ("procdump", "mimikatz", "lsassy", "nanodump", "pypykatz")
    or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("dump", "minidump"))
| union (
    SecurityEvent
    | where EventID == 4656 and ObjectName =~ "lsass.exe"
    | where AccessMask in ("0x1010", "0x1410", "0x40")
)
| project TimeGenerated, DeviceName, Computer, InitiatingProcessAccountName, ProcessCommandLine"""
    },
    {
        "id": 5,
        "tactic": "TA0040", "tactic_name": "Impact",
        "technique": "T1486", "technique_name": "Data Encrypted for Impact (Ransomware)",
        "priority": "CRITICAL",
        "description": "Detect ransomware activity: shadow copy deletion (vssadmin delete shadows), mass file renames to unknown extensions, and bcdedit disabling recovery.",
        "mitre_data_source": "MDE File Events, Process Events, Windows Event Logs",
        "estimated_incidents": 85,
        "detection_method": "Alert on vssadmin/wmic delete shadow copies; mass file renames (>100 files/5min) to unknown extensions; ransom note creation; bcdedit /set recoveryenabled no",
        "implementation_effort": "Medium",
        "rule_template": """DeviceProcessEvents
| where ProcessCommandLine has_any (
    "vssadmin delete shadows", "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no"
)
| union (
    DeviceFileEvents
    | where ActionType == "FileRenamed"
    | summarize FileCount=count(), ExtChanges=dcount(FileName)
        by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 5m)
    | where FileCount > 100 and ExtChanges > 50
)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine"""
    },
    # ── HIGH ──────────────────────────────────────────────────────────────────
    {
        "id": 6,
        "tactic": "TA0008", "tactic_name": "Lateral Movement",
        "technique": "T1021.003", "technique_name": "Distributed Component Object Model (DCOM)",
        "priority": "HIGH",
        "description": "Detect DCOM lateral movement: wmiprvse.exe/svchost.exe spawning cmd/powershell, MMC20/ShellWindows DCOM object activation to remote hosts.",
        "mitre_data_source": "Windows Event Logs (5857/5858), MDE Process Events",
        "estimated_incidents": 320,
        "detection_method": "Monitor wmiprvse.exe or svchost.exe spawning cmd/powershell/wscript with a remote network context; WMI event 5857/5858 for remote DCOM activations",
        "implementation_effort": "High",
        "rule_template": """DeviceProcessEvents
| where InitiatingProcessFileName in~ ("svchost.exe", "wmiprvse.exe")
    and FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| where isnotempty(InitiatingProcessRemoteUrl)
    or InitiatingProcessAccountName has "NETWORK"
| summarize count() by DeviceName, FileName, InitiatingProcessFileName, bin(TimeGenerated, 1h)"""
    },
    {
        "id": 7,
        "tactic": "TA0008", "tactic_name": "Lateral Movement",
        "technique": "T1021.004", "technique_name": "SSH Lateral Movement",
        "priority": "HIGH",
        "description": "Detect SSH-based lateral movement within the corporate network: connections between internal hosts not via approved bastion, new SSH key use, and SSH tunneling for port forwarding.",
        "mitre_data_source": "Linux Syslog (auth), Network Events, MDE",
        "estimated_incidents": 95,
        "detection_method": "Alert on SSH connections from workstations to servers not in bastion allowlist; ProxyJump chains; ssh.exe spawned from unusual parent processes on Windows hosts",
        "implementation_effort": "Medium",
        "rule_template": """Syslog
| where Facility =~ "auth" and SyslogMessage has "sshd" and SyslogMessage has "Accepted"
| parse SyslogMessage with * "from " SourceIP " port " * " ssh2" *
| join kind=inner (
    Syslog
    | where SyslogMessage has "sshd" and SyslogMessage has "Invalid user"
    | summarize FailedAttempts=count() by Computer, bin(TimeGenerated, 30m)
    | where FailedAttempts > 5
) on Computer
| project TimeGenerated, Computer, SourceIP, SyslogMessage"""
    },
    {
        "id": 8,
        "tactic": "TA0011", "tactic_name": "Command and Control",
        "technique": "T1571", "technique_name": "Non-Standard Port C2",
        "priority": "HIGH",
        "description": "Detect C2 over non-standard ports (>5000, excluding known app ports) from non-browser/svchost processes. Covers beaconing to rare external IPs on unusual ports.",
        "mitre_data_source": "Network Traffic, Firewall Logs, MDE Network Events",
        "estimated_incidents": 180,
        "detection_method": "Outbound connections to rare ports from processes that don't normally make network connections; regular interval beaconing; connections to newly registered domains",
        "implementation_effort": "Medium",
        "rule_template": """DeviceNetworkEvents
| where RemotePort > 5000
    and RemotePort !in (8080, 8443, 5985, 5986, 5432, 3306, 6379, 9200, 27017)
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe", "services.exe")
| summarize count(), dcount(RemoteIp)
    by DeviceName, RemotePort, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| where count_ > 10"""
    },
    {
        "id": 9,
        "tactic": "TA0011", "tactic_name": "Command and Control",
        "technique": "T1071.004", "technique_name": "DNS Tunneling / C2 over DNS",
        "priority": "HIGH",
        "description": "Detect C2 over DNS: unusually long subdomain queries (>52 chars), high DNS query volume to a single domain, TXT record queries for data exfil, and DGA domain patterns.",
        "mitre_data_source": "DNS Server Logs, Azure Firewall DNS Proxy, DnsEvents",
        "estimated_incidents": 165,
        "detection_method": "Alert on subdomain length >52 chars; TXT record queries; single host querying same domain >100 times/hour; high-entropy domain names (DGA); DNS responses with large TXT payloads",
        "implementation_effort": "Medium",
        "rule_template": """DnsEvents
| where SubType =~ "LookupQuery"
| extend SubdomainLength = strlen(extract("^([^.]+)", 1, Name))
| where SubdomainLength > 52 or QueryType =~ "TXT"
| summarize QueryCount=count(), UniqueSubdomains=dcount(Name)
    by ClientIP, bin(TimeGenerated, 1h)
| where QueryCount > 100 or UniqueSubdomains > 50
| extend Suspicion = iff(QueryCount > 500, "High DNS C2", "Suspicious DNS")"""
    },
    {
        "id": 10,
        "tactic": "TA0011", "tactic_name": "Command and Control",
        "technique": "T1572", "technique_name": "Protocol Tunneling",
        "priority": "HIGH",
        "description": "Detect ICMP/HTTP/HTTPS protocol tunneling: unusual payload sizes in ICMP, HTTP POST with binary content to rare domains, large sustained outbound transfers from non-browser processes.",
        "mitre_data_source": "Network Traffic, Azure Firewall Logs, MDE Network Events",
        "estimated_incidents": 140,
        "detection_method": "Alert on ICMP packets >128 bytes; HTTP POST >1MB to new domains; connections to Tor exit nodes; >10MB/hour from a single non-browser process to one external IP",
        "implementation_effort": "High",
        "rule_template": """DeviceNetworkEvents
| where RemotePort in (80, 443, 8080, 8443)
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "svchost.exe", "OneDrive.exe"
)
| summarize BytesSent=sum(SentBytes), Connections=count()
    by DeviceName, RemoteIp, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| where BytesSent > 10485760 or (Connections > 200 and dcount(RemoteIp) < 3)
| extend Severity = iff(BytesSent > 52428800, "High", "Medium")"""
    },
    {
        "id": 11,
        "tactic": "TA0011", "tactic_name": "Command and Control",
        "technique": "T1105", "technique_name": "Ingress Tool Transfer",
        "priority": "HIGH",
        "description": "Detect tool download and staging: certutil/bitsadmin used as downloader, mshta/regsvr32 fetching remote payloads, and PE files dropped to %TEMP%/%Public% via HTTP.",
        "mitre_data_source": "MDE Process Events, Network Events, File Events",
        "estimated_incidents": 170,
        "detection_method": "Alert on certutil -urlcache/-decode; mshta with http:// URL; regsvr32 scrobj.dll; Temp/Public folder PE files created after a network connection by the same process",
        "implementation_effort": "Medium",
        "rule_template": """DeviceProcessEvents
| where FileName has_any ("certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("http://", "https://", "ftp://", "-urlcache", "-decode", "scrobj.dll")
| union (
    DeviceFileEvents
    | where FolderPath has_any ("\\Temp\\", "\\Public\\", "\\AppData\\Local\\Temp\\")
    | where ActionType == "FileCreated"
    | where FileName has_any (".exe", ".dll", ".ps1", ".bat", ".vbs")
)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath"""
    },
    {
        "id": 12,
        "tactic": "TA0005", "tactic_name": "Defense Evasion",
        "technique": "T1070.001", "technique_name": "Clear Windows Event Logs",
        "priority": "HIGH",
        "description": "Detect clearing of Windows Security/System Event Logs (EventID 1102 and 104) outside maintenance windows. Attackers clear logs to remove forensic evidence after compromise.",
        "mitre_data_source": "Windows Security Event Logs",
        "estimated_incidents": 95,
        "detection_method": "Alert on EventID 1102 (Security log cleared) or 104 (System log cleared) from non-SYSTEM accounts outside approved maintenance windows",
        "implementation_effort": "Low",
        "rule_template": """SecurityEvent
| where EventID in (1102, 104)
| where SubjectUserName !has "SYSTEM" and SubjectUserName !has "backup-svc"
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, EventID
| extend Description = iff(EventID == 1102,
    "Security Audit Log Cleared", "System Event Log Cleared")"""
    },
    {
        "id": 13,
        "tactic": "TA0005", "tactic_name": "Defense Evasion",
        "technique": "T1197", "technique_name": "BITS Jobs Abuse",
        "priority": "HIGH",
        "description": "Detect BITS abuse for payload download and persistence: bitsadmin.exe /transfer, PowerShell Start-BitsTransfer to non-Microsoft URLs, and long-running BITS jobs.",
        "mitre_data_source": "Windows Event Logs (Microsoft-Windows-Bits-Client), MDE Process Events",
        "estimated_incidents": 110,
        "detection_method": "Alert on bitsadmin.exe with /transfer to external URLs; PowerShell New-BitsTransfer/Start-BitsTransfer to non-windowsupdate/microsoft.com domains",
        "implementation_effort": "Low",
        "rule_template": """DeviceProcessEvents
| where FileName =~ "bitsadmin.exe" and ProcessCommandLine has "/transfer"
| union (
    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any ("Start-BitsTransfer", "New-BitsTransfer")
    | where ProcessCommandLine !has "windowsupdate"
        and ProcessCommandLine !has "microsoft.com"
)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine"""
    },
    {
        "id": 14,
        "tactic": "TA0005", "tactic_name": "Defense Evasion",
        "technique": "T1112", "technique_name": "Modify Registry (Security Controls)",
        "priority": "HIGH",
        "description": "Detect registry modifications targeting security tool configurations, UAC bypass keys, and Run persistence keys by non-deployment processes.",
        "mitre_data_source": "Sysmon Events 12/13, MDE DeviceRegistryEvents",
        "estimated_incidents": 175,
        "detection_method": "Monitor HKCU/HKLM Run* keys; DisableAntiSpyware/DisableRealtimeMonitoring values; CurrentControlSet\\Services for new services by non-SYSTEM processes",
        "implementation_effort": "Medium",
        "rule_template": """DeviceRegistryEvents
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    "\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce",
    "\\DisableAntiSpyware", "\\DisableRealtimeMonitoring",
    "\\CurrentControlSet\\Services\\", "\\Winlogon\\Shell"
)
| where InitiatingProcessFileName !in~ (
    "svchost.exe", "TrustedInstaller.exe", "msiexec.exe", "MicrosoftEdgeUpdate.exe"
)
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName"""
    },
    {
        "id": 15,
        "tactic": "TA0010", "tactic_name": "Exfiltration",
        "technique": "T1537", "technique_name": "Transfer Data to Cloud Account",
        "priority": "HIGH",
        "description": "Detect mass uploads to unauthorized Azure Storage, OneDrive, or other cloud accounts: AzCopy to non-corporate storage, bulk SharePoint downloads, or new external storage containers.",
        "mitre_data_source": "AzureActivity, OfficeActivity, Defender for Cloud Apps",
        "estimated_incidents": 195,
        "detection_method": "Alert on AzCopy uploads to non-corporate storage accounts; >500 file downloads/hour from SharePoint/OneDrive; new Azure Blob containers created by non-automation identities",
        "implementation_effort": "Medium",
        "rule_template": """OfficeActivity
| where Operation in ("FileSyncDownloadedFull", "FileDownloaded", "FileCopied")
| summarize FileCount=count(), TotalSizeMB=sum(SourceFileSize)/1048576
    by UserId, ClientIP, bin(TimeGenerated, 1h)
| where FileCount > 500 or TotalSizeMB > 1024
| union (
    AzureActivity
    | where OperationNameValue has "STORAGEACCOUNTS" and OperationNameValue has "WRITE"
    | where ActivityStatusValue =~ "Success"
    | summarize UploadCount=count() by Caller, ResourceGroup, bin(TimeGenerated, 1h)
    | where UploadCount > 100
)"""
    },
    {
        "id": 16,
        "tactic": "TA0010", "tactic_name": "Exfiltration",
        "technique": "T1048.003", "technique_name": "Exfiltration Over Unencrypted Protocol",
        "priority": "HIGH",
        "description": "Detect large data transfers over HTTP/FTP to external destinations, bulk email attachments with sensitive file types sent externally, and FTP uploads from endpoints.",
        "mitre_data_source": "Email logs, Network Traffic, Cloud Activity logs",
        "estimated_incidents": 220,
        "detection_method": "Alert on >500MB over unencrypted protocols; email with .pst/.csv/.xlsx/.zip attachments >20MB to external domains; FTP connections from workstations to external IPs",
        "implementation_effort": "High",
        "rule_template": """EmailEvents
| where EmailDirection == "Outbound"
| where AttachmentCount > 3 and TotalEmailSize > 20971520
| where RecipientEmailAddress !endswith "@company.com"
| where AttachmentFileExtension has_any (".zip", ".pst", ".csv", ".xlsx", ".sql", ".bak")
| summarize count() by Subject, SenderMailFromAddress, RecipientEmailAddress, bin(TimeGenerated, 1h)"""
    },
    {
        "id": 17,
        "tactic": "TA0010", "tactic_name": "Exfiltration",
        "technique": "T1041", "technique_name": "Exfiltration Over C2 Channel",
        "priority": "HIGH",
        "description": "Detect data exfiltration via the established C2 channel: large outbound HTTP POST bodies, base64 patterns in URL query strings, and sustained large transfers at regular intervals to the same IP.",
        "mitre_data_source": "Network Traffic, Azure Firewall Logs, Proxy Logs",
        "estimated_incidents": 85,
        "detection_method": "Alert on HTTP POST >10MB to rare external destinations from non-browser processes; base64 in URL query strings; >10MB/hour consistently to single external IP over days",
        "implementation_effort": "High",
        "rule_template": """DeviceNetworkEvents
| where ActionType == "ConnectionSuccess" and RemoteIPType =~ "Public"
| summarize BytesSent=sum(SentBytes), Connections=count()
    by DeviceName, RemoteIp, RemotePort, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| where BytesSent > 10485760
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "OneDrive.exe"
)
| extend Severity = iff(BytesSent > 104857600, "High", "Medium")"""
    },
    {
        "id": 18,
        "tactic": "TA0006", "tactic_name": "Credential Access",
        "technique": "T1558.003", "technique_name": "Kerberoasting",
        "priority": "HIGH",
        "description": "Detect Kerberoasting via EventID 4769 (TGS request) with RC4 encryption (0x17). Attackers request service tickets with weak encryption to crack offline.",
        "mitre_data_source": "Windows Security Event Logs (Domain Controllers)",
        "estimated_incidents": 245,
        "detection_method": "Alert on EventID 4769 with TicketEncryptionType=0x17 from user accounts; single account requesting TGS for multiple services within 1 hour; requests from unusual workstations",
        "implementation_effort": "Low",
        "rule_template": """SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName !startswith "krbtgt"
| where AccountName !endswith "$"
| summarize RequestCount=count(), UniqueServices=dcount(ServiceName)
    by AccountName, IpAddress, bin(TimeGenerated, 1h)
| where UniqueServices > 3 or RequestCount > 10
| extend Severity = iff(UniqueServices > 5, "High", "Medium")"""
    },
    {
        "id": 19,
        "tactic": "TA0004", "tactic_name": "Privilege Escalation",
        "technique": "T1055", "technique_name": "Process Injection",
        "priority": "HIGH",
        "description": "Detect process injection: Office apps spawning cmd/PowerShell (macro-based injection), remote thread creation in sensitive processes, and unusual parent-child process chains.",
        "mitre_data_source": "Sysmon Event 8, MDE DeviceProcessEvents",
        "estimated_incidents": 185,
        "detection_method": "Alert on winword/excel/outlook/acrobat spawning cmd or powershell; processes with no visible window making network connections; remote thread creation in lsass/svchost",
        "implementation_effort": "High",
        "rule_template": """DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "outlook.exe", "acrobat.exe", "acrord32.exe"
)
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessAccountName"""
    },
    {
        "id": 20,
        "tactic": "TA0007", "tactic_name": "Discovery",
        "technique": "T1046", "technique_name": "Network Service Scanning",
        "priority": "HIGH",
        "description": "Detect internal network port scanning before lateral movement: single host connecting to many internal IPs on common lateral-movement ports within a short time window.",
        "mitre_data_source": "MDE Network Events, Azure Firewall Logs, NSG Flow Logs",
        "estimated_incidents": 160,
        "detection_method": "Alert on single host connecting to >15 unique internal IPs within 5 minutes on ports 22/445/135/3389/5985; nmap/masscan/zmap process execution",
        "implementation_effort": "Medium",
        "rule_template": """DeviceNetworkEvents
| where RemotePort in (22, 23, 25, 445, 135, 139, 3389, 5985, 5986)
| summarize TargetIPs=dcount(RemoteIp), ConnectionCount=count()
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 5m)
| where TargetIPs > 15
| union (
    DeviceProcessEvents
    | where FileName has_any ("nmap", "masscan", "zmap", "netscan", "portscan")
)
| extend Severity = iff(TargetIPs > 30, "High", "Medium")"""
    },
    {
        "id": 21,
        "tactic": "TA0009", "tactic_name": "Collection",
        "technique": "T1119", "technique_name": "Automated Collection",
        "priority": "HIGH",
        "description": "Detect automated data collection scripts: PowerShell enumerating and copying sensitive files at scale, robocopy/xcopy mass operations on network shares, or scripts reading >1000 files in 10 minutes.",
        "mitre_data_source": "MDE File Events, Process Events",
        "estimated_incidents": 150,
        "detection_method": "Alert on PowerShell Get-ChildItem -Recurse on sensitive paths followed by file copy; >1000 FileRead events in 10 min from same process; archiver (7z/WinRAR) targeting sensitive directories",
        "implementation_effort": "Medium",
        "rule_template": """DeviceFileEvents
| where ActionType == "FileRead"
| summarize FileReadCount=count(), UniquePaths=dcount(FolderPath)
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 10m)
| where FileReadCount > 1000 and UniquePaths > 20
| where InitiatingProcessFileName !in~ ("SearchIndexer.exe", "MsMpEng.exe", "svchost.exe")
| extend Severity = iff(FileReadCount > 5000, "High", "Medium")"""
    },
    {
        "id": 22,
        "tactic": "TA0009", "tactic_name": "Collection",
        "technique": "T1530", "technique_name": "Data from Cloud Storage Object",
        "priority": "HIGH",
        "description": "Detect unauthorized mass access to Azure Blob Storage or SharePoint: anonymous container access, service principal bulk downloads, and unusual storage enumeration.",
        "mitre_data_source": "AzureActivity, StorageBlobLogs, OfficeActivity",
        "estimated_incidents": 125,
        "detection_method": "Alert on anonymous/SAS-token access to storage with >200 GetBlob calls in 1 hour; bulk OneDrive/SharePoint file downloads (>300 files/hour) from a single identity",
        "implementation_effort": "Medium",
        "rule_template": """StorageBlobLogs
| where OperationName in ("GetBlob", "ListBlobs")
| where AuthenticationType =~ "Anonymous" or isnotempty(SasToken)
| summarize AccessCount=count() by CallerIpAddress, bin(TimeGenerated, 1h)
| where AccessCount > 200
| union (
    OfficeActivity
    | where Operation =~ "FileDownloaded"
    | summarize count() by UserId, ClientIP, bin(TimeGenerated, 1h)
    | where count_ > 300
)"""
    },
    {
        "id": 23,
        "tactic": "TA0040", "tactic_name": "Impact",
        "technique": "T1485", "technique_name": "Data Destruction",
        "priority": "HIGH",
        "description": "Detect mass file deletion, database wipe, or Azure resource deletion: >500 file deletes in 5 minutes, SQL DROP/TRUNCATE on production, or storage account deletion outside change windows.",
        "mitre_data_source": "MDE File Events, Azure Activity Logs, SQL Audit Logs",
        "estimated_incidents": 65,
        "detection_method": "Alert on >500 FileDeleted events in 5 min; SQL DROP TABLE on production databases; Azure storage account deletion; AzureActivity resource group deletion",
        "implementation_effort": "Medium",
        "rule_template": """DeviceFileEvents
| where ActionType == "FileDeleted"
| summarize DeleteCount=count()
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 5m)
| where DeleteCount > 500
| union (
    AzureActivity
    | where OperationNameValue has "DELETE"
    | where ResourceGroup has_any ("prod", "production", "critical")
    | where ActivityStatusValue =~ "Success"
)"""
    },
    {
        "id": 24,
        "tactic": "TA0040", "tactic_name": "Impact",
        "technique": "T1529", "technique_name": "System Shutdown / Reboot",
        "priority": "HIGH",
        "description": "Detect unauthorized system shutdowns: EventID 1074 outside maintenance windows, shutdown.exe /f from non-admin accounts, and Azure VM stop/deallocate operations from unexpected identities.",
        "mitre_data_source": "Windows System Event Logs, Azure Activity Logs",
        "estimated_incidents": 55,
        "detection_method": "Alert on EventID 1074 outside maintenance windows (01:00–05:00); shutdown.exe with /f flag; Azure VM PowerOff/Deallocate by non-automation service principals",
        "implementation_effort": "Low",
        "rule_template": """Event
| where EventID == 1074 and EventLog =~ "System" and Source =~ "User32"
| where TimeGenerated !between (datetime(01:00) .. datetime(05:00))
| project TimeGenerated, Computer, RenderedDescription
| union (
    AzureActivity
    | where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/POWEROFF/ACTION"
    | where ActivityStatusValue =~ "Success"
    | project TimeGenerated, Caller, ResourceGroup
)"""
    },
    {
        "id": 25,
        "tactic": "TA0003", "tactic_name": "Persistence",
        "technique": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder",
        "priority": "HIGH",
        "description": "Detect persistence via Run/RunOnce registry keys and Startup folder modifications by non-deployment processes. Covers both HKCU and HKLM hives.",
        "mitre_data_source": "Sysmon Events 11/12/13, MDE DeviceRegistryEvents + DeviceFileEvents",
        "estimated_incidents": 165,
        "detection_method": "Alert on new values in Run/RunOnce keys outside software deployment; PE files dropped to %AppData%\\Startup folder by non-installer processes",
        "implementation_effort": "Low",
        "rule_template": """DeviceRegistryEvents
| where RegistryKey has_any ("\\CurrentVersion\\Run\\", "\\CurrentVersion\\RunOnce\\")
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName !in~ (
    "msiexec.exe", "setup.exe", "install.exe", "MicrosoftEdgeUpdate.exe"
)
| union (
    DeviceFileEvents
    | where FolderPath has "Start Menu\\Programs\\Startup"
    | where ActionType == "FileCreated"
    | where FileName has_any (".exe", ".vbs", ".bat", ".ps1", ".lnk")
)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueData"""
    },
    {
        "id": 26,
        "tactic": "TA0003", "tactic_name": "Persistence",
        "technique": "T1098", "technique_name": "Account Manipulation / Mailbox Forwarding",
        "priority": "HIGH",
        "description": "Monitor for unauthorized mailbox forwarding rules, OAuth app consent abuse, and password changes on service accounts. Attackers create silent forwarding rules to copy all email.",
        "mitre_data_source": "Office Activity Logs, Azure AD Audit Logs",
        "estimated_incidents": 195,
        "detection_method": "Detect new Exchange inbox rules with ForwardTo/RedirectTo; risky OAuth grants (Mail.Read.All, Files.ReadWrite.All); ownership transfers on privileged groups",
        "implementation_effort": "Medium",
        "rule_template": """OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| union (
    AuditLogs
    | where OperationName =~ "Add app role assignment to service principal"
    | where TargetResources has_any ("Mail.Read", "Files.ReadWrite.All", "User.ReadWrite.All")
)"""
    },
    {
        "id": 27,
        "tactic": "TA0002", "tactic_name": "Execution",
        "technique": "T1059.001", "technique_name": "PowerShell Encoded Commands",
        "priority": "HIGH",
        "description": "Detect obfuscated PowerShell: -EncodedCommand/-enc flags, download cradles (IEX/Invoke-Expression/DownloadString), and PowerShell spawned from Office/script hosts.",
        "mitre_data_source": "PowerShell Script Block Logs (Event 4104), MDE Process Events",
        "estimated_incidents": 205,
        "detection_method": "Alert on PowerShell with -EncodedCommand or -enc; IEX(New-Object Net.WebClient).DownloadString; PowerShell spawned from winword/excel/wscript; Empire/Cobalt Strike stager patterns",
        "implementation_effort": "Low",
        "rule_template": """DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "-EncodedCommand", "-enc ", "IEX", "Invoke-Expression",
    "DownloadString", "DownloadFile", "FromBase64String", "WebClient"
)
| where InitiatingProcessFileName !in~ ("explorer.exe", "taskmgr.exe", "Code.exe")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
    ProcessCommandLine, InitiatingProcessFileName"""
    },
    {
        "id": 28,
        "tactic": "TA0002", "tactic_name": "Execution",
        "technique": "T1047", "technique_name": "WMI Remote Execution",
        "priority": "MEDIUM",
        "description": "Detect WMI-based remote code execution: wmic.exe /node: parameter, wmiprvse.exe spawning shells, and WMI event subscription creation (T1546.003).",
        "mitre_data_source": "Windows Event Logs (5857/5861), MDE Process Events",
        "estimated_incidents": 120,
        "detection_method": "Alert on wmic.exe with /node:; wmiprvse.exe spawning cmd/powershell/cscript; WMI event subscription creation (EventID 5861) for persistence",
        "implementation_effort": "Medium",
        "rule_template": """DeviceProcessEvents
| where FileName =~ "wmic.exe" and ProcessCommandLine has "/node:"
| union (
    DeviceProcessEvents
    | where InitiatingProcessFileName =~ "wmiprvse.exe"
    | where FileName in~ ("cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe")
)
| union (
    Event
    | where EventID == 5861
    | where RenderedDescription has "EventConsumer"
)"""
    },
    {
        "id": 29,
        "tactic": "TA0003", "tactic_name": "Persistence",
        "technique": "T1053.005", "technique_name": "Scheduled Task for Persistence",
        "priority": "MEDIUM",
        "description": "Detect malicious scheduled task creation outside software deployment windows, especially tasks executing from Temp/AppData or running PowerShell with encoded commands.",
        "mitre_data_source": "Windows Security Events (4698/4699/4702), MDE Process Events",
        "estimated_incidents": 140,
        "detection_method": "Alert on tasks created (EventID 4698) executing from %TEMP%/%AppData%; schtasks.exe /create with PowerShell or cmd payloads; tasks with RandomDelay to evade detection",
        "implementation_effort": "Low",
        "rule_template": """SecurityEvent
| where EventID in (4698, 4699, 4702)
| where SubjectUserName !has "SYSTEM" and SubjectUserName !endswith "$"
| extend TaskXML = tostring(EventData)
| where TaskXML has_any ("Temp", "AppData", "EncodedCommand", "DownloadString")
| union (
    DeviceProcessEvents
    | where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
    | where ProcessCommandLine has_any ("Temp", "AppData", "powershell", "cmd /c")
)"""
    },
    # ── MEDIUM ────────────────────────────────────────────────────────────────
    {
        "id": 30,
        "tactic": "TA0006", "tactic_name": "Credential Access",
        "technique": "T1187", "technique_name": "Forced Authentication / NTLM Relay",
        "priority": "MEDIUM",
        "description": "Detect forced NTLM authentication (Responder/LLMNR poisoning) and NTLM relay attacks: unusual NTLM authentications to non-DC servers, multiple auth failures followed by success from same source.",
        "mitre_data_source": "Windows Security Event Logs, Network Logs",
        "estimated_incidents": 130,
        "detection_method": "Alert on NTLM auth to servers that normally use Kerberos; LLMNR/NetBIOS query responses from unusual hosts; NTLM relay indicators (auth from server to server)",
        "implementation_effort": "High",
        "rule_template": """SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName =~ "NTLM"
| where TargetServerName !endswith ".domain.local" and TargetServerName != "localhost"
| summarize NTLMCount=count() by IpAddress, TargetServerName, bin(TimeGenerated, 15m)
| where NTLMCount > 10
| extend Suspicion = "Potential NTLM Relay or Forced Auth"
| project TimeGenerated, IpAddress, TargetServerName, NTLMCount, Suspicion"""
    },
    {
        "id": 31,
        "tactic": "TA0004", "tactic_name": "Privilege Escalation",
        "technique": "T1134.002", "technique_name": "Token Impersonation (Potato Attacks)",
        "priority": "MEDIUM",
        "description": "Detect token impersonation via SeImpersonatePrivilege abuse (PrintSpoofer, RoguePotato, JuicyPotato). Alert on EventID 4672 for non-admin accounts gaining privileged tokens.",
        "mitre_data_source": "Windows Security Event Logs (4672/4673), MDE Process Events",
        "estimated_incidents": 95,
        "detection_method": "Alert on EventID 4672 with SeImpersonatePrivilege/SeDebugPrivilege for non-admin accounts; named pipe impersonation tool signatures; process token privilege escalation chains",
        "implementation_effort": "High",
        "rule_template": """SecurityEvent
| where EventID == 4672
| where SubjectUserName !endswith "$" and SubjectUserName !has "SYSTEM"
| where PrivilegeList has_any (
    "SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege"
)
| join kind=leftouter (
    DeviceProcessEvents
    | where FileName has_any ("PrintSpoofer", "RoguePotato", "JuicyPotato", "SweetPotato")
) on $left.SubjectUserName == $right.InitiatingProcessAccountName
| project TimeGenerated, SubjectUserName, PrivilegeList, FileName"""
    },
    {
        "id": 32,
        "tactic": "TA0007", "tactic_name": "Discovery",
        "technique": "T1087.002", "technique_name": "Domain Account Discovery",
        "priority": "MEDIUM",
        "description": "Detect LDAP-based AD reconnaissance: net.exe domain enumeration, PowerShell AD module queries, and BloodHound/SharpHound collection activity.",
        "mitre_data_source": "Windows Security Events (4661/4662), MDE Process Events",
        "estimated_incidents": 110,
        "detection_method": "Alert on net user/group /domain from workstations; PowerShell Get-ADUser -Filter *; LDAP queries for all user objects from non-admin systems; SharpHound/BloodHound process names",
        "implementation_effort": "Medium",
        "rule_template": """DeviceProcessEvents
| where (FileName =~ "net.exe" or FileName =~ "net1.exe")
    and ProcessCommandLine has_any ("user /domain", "group /domain", "accounts /domain")
| union (
    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any (
        "Get-ADUser", "Get-ADGroup", "Get-ADComputer", "Get-ADObject"
    )
)
| union (
    DeviceProcessEvents
    | where FileName has_any ("SharpHound", "BloodHound", "ADRecon")
)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine"""
    },
    {
        "id": 33,
        "tactic": "TA0005", "tactic_name": "Defense Evasion",
        "technique": "T1036", "technique_name": "Masquerading",
        "priority": "MEDIUM",
        "description": "Detect executables masquerading as documents (.exe named as .pdf), renamed system utilities, and LOLBins launched from non-standard directories (Temp, AppData, Downloads).",
        "mitre_data_source": "MDE File Events, Process Events",
        "estimated_incidents": 145,
        "detection_method": "Monitor executables with double extensions; svchost/explorer launched from outside C:\\Windows; processes with OriginalFileName mismatching actual filename",
        "implementation_effort": "Medium",
        "rule_template": """DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName has_any (".exe.", ".scr.", ".vbs.", ".ps1.")
| union (
    DeviceProcessEvents
    | where FileName in~ ("svchost.exe", "explorer.exe", "lsass.exe")
    | where FolderPath !has "C:\\Windows\\"
)
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessAccountName"""
    },
]

# ============================================================================
# MISSING LOG SOURCES — data sources absent from the environment that are
# required for comprehensive MITRE ATT&CK coverage
# ============================================================================

MISSING_LOG_SOURCES = [
    {
        "id": 1,
        "source_name": "Sysmon (System Monitor)",
        "category": "Endpoint",
        "status": "ABSENT",
        "priority": "CRITICAL",
        "sentinel_table": "Event (EventID 1/3/7/8/10/11/12/13 from Microsoft-Windows-Sysmon/Operational)",
        "tactics_affected": ["Execution", "Persistence", "Defense Evasion", "Lateral Movement", "Command and Control"],
        "techniques_covered": ["T1059", "T1547", "T1036", "T1021", "T1055", "T1003", "T1071"],
        "technique_count": 7,
        "description": "Sysmon provides process creation (Event 1), network connections (Event 3), driver loads (Event 6), remote thread creation (Event 8), process access on lsass (Event 10), file creation (Event 11), and registry modifications (Events 12/13). Without Sysmon, living-off-the-land (LOLBin) and fileless attacks are nearly undetectable.",
        "implementation": "Deploy via GPO or Intune using SwiftOnSecurity/sysmon-config or Florian Roth sysmon-config baseline. Connect to Sentinel via Azure Monitor Agent (AMA) with a Data Collection Rule targeting the Sysmon Operational channel.",
        "estimated_coverage_gain": 18
    },
    {
        "id": 2,
        "source_name": "Windows Security Event Logs — Full Audit Policy",
        "category": "Authentication / Process",
        "status": "PARTIAL",
        "priority": "CRITICAL",
        "sentinel_table": "SecurityEvent",
        "tactics_affected": ["Credential Access", "Lateral Movement", "Privilege Escalation", "Execution", "Persistence"],
        "techniques_covered": ["T1021.001", "T1550.002", "T1558.003", "T1003", "T1078", "T1134"],
        "technique_count": 6,
        "description": "Full Security Audit Policy coverage is missing. Critical events absent include 4688 (process creation with full command line), 4769 (Kerberos TGS — Kerberoasting), 4648/4624/4625 logon events on all DCs and servers, and 4656 (object access on lsass). Without these, Pass-the-Hash, Kerberoasting, and LSASS dump detection are blind.",
        "implementation": "Enable Advanced Audit Policy via GPO: Audit Process Creation with command line, Audit Logon Events, Audit Account Logon, Audit Privilege Use. Ensure all Domain Controllers forward Security events to Sentinel workspace via AMA.",
        "estimated_coverage_gain": 12
    },
    {
        "id": 3,
        "source_name": "DNS Server / Resolver Logs",
        "category": "Network",
        "status": "ABSENT",
        "priority": "HIGH",
        "sentinel_table": "DnsEvents (Microsoft DNS Server connector) or AzureDiagnostics (Azure DNS)",
        "tactics_affected": ["Command and Control", "Exfiltration", "Discovery"],
        "techniques_covered": ["T1071.004", "T1568", "T1048.002", "T1087", "T1590"],
        "technique_count": 5,
        "description": "DNS logs enable detection of DNS tunneling (T1071.004), C2 beaconing via DNS (T1568), DGA domain resolution, and data exfiltration via DNS TXT records. Currently C&C coverage is only 5% — DNS logging is the primary gap. Without DNS data, an attacker can maintain C2 communications indefinitely.",
        "implementation": "Enable DNS analytical logging on all Windows DNS servers via dnscmd /config /logLevel 0x8100. Deploy the Sentinel DNS connector or send DNS events via CEF/Syslog. For Azure-hosted DNS, enable Azure Firewall DNS proxy logging.",
        "estimated_coverage_gain": 8
    },
    {
        "id": 4,
        "source_name": "Network Flow Logs (NSG Flow / Azure Firewall / NTA)",
        "category": "Network",
        "status": "ABSENT",
        "priority": "HIGH",
        "sentinel_table": "AzureNetworkAnalytics_CL or AzureDiagnostics (AzureFirewall category)",
        "tactics_affected": ["Command and Control", "Exfiltration", "Lateral Movement", "Discovery"],
        "techniques_covered": ["T1046", "T1048", "T1571", "T1021", "T1008", "T1572"],
        "technique_count": 6,
        "description": "Network flow data provides east-west traffic visibility for lateral movement detection, C2 beaconing patterns (regular-interval outbound connections), port scanning, and data exfiltration over unusual protocols. Without NetFlow/NSG flow logs, lateral movement between internal subnets is invisible to Sentinel.",
        "implementation": "Enable NSG Flow Logs v2 on all NSGs and send to Sentinel workspace via Traffic Analytics. Enable Azure Firewall diagnostic logs (AzureFirewallNetworkRule + AzureFirewallApplicationRule categories). Consider Microsoft Defender for IoT for OT/IoT segments.",
        "estimated_coverage_gain": 10
    },
    {
        "id": 5,
        "source_name": "Microsoft Defender for Endpoint (MDE) — Full Deployment",
        "category": "Endpoint",
        "status": "PARTIAL",
        "priority": "CRITICAL",
        "sentinel_table": "DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents",
        "tactics_affected": ["Execution", "Persistence", "Defense Evasion", "Lateral Movement", "Collection", "Exfiltration"],
        "techniques_covered": ["T1059", "T1547", "T1036", "T1021", "T1005", "T1048", "T1070", "T1055"],
        "technique_count": 8,
        "description": "MDE Advanced Hunting tables are partially available but not all endpoints are enrolled. Servers, Linux endpoints, and macOS devices may be missing. Without full MDE coverage, the DeviceProcessEvents/DeviceNetworkEvents tables only reflect a fraction of the estate — leaving significant blind spots.",
        "implementation": "Ensure 100% device enrollment in MDE across Windows, Linux, macOS, and servers. Enable EDR in block mode, network protection, and tamper protection. Stream all Advanced Hunting tables to Sentinel via the Microsoft 365 Defender connector.",
        "estimated_coverage_gain": 15
    },
    {
        "id": 6,
        "source_name": "PowerShell Script Block Logging (Event 4104)",
        "category": "Endpoint",
        "status": "ABSENT",
        "priority": "HIGH",
        "sentinel_table": "Event (EventID 4104 from Microsoft-Windows-PowerShell/Operational)",
        "tactics_affected": ["Execution", "Defense Evasion", "Collection", "Command and Control"],
        "techniques_covered": ["T1059.001", "T1140", "T1119", "T1105"],
        "technique_count": 4,
        "description": "PowerShell Script Block Logging (Event 4104) captures all PowerShell code *before* de-obfuscation, enabling detection of encoded payloads, download cradles, and AMSI-bypass attempts. Without it, obfuscated PowerShell attacks (Empire, Cobalt Strike PS stagers) are invisible even with process creation logging.",
        "implementation": "Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging. Forward events to Sentinel workspace via AMA with the PowerShell Operational channel in the DCR.",
        "estimated_coverage_gain": 6
    },
    {
        "id": 7,
        "source_name": "Azure Activity Logs — All Subscriptions",
        "category": "Cloud",
        "status": "PARTIAL",
        "priority": "HIGH",
        "sentinel_table": "AzureActivity",
        "tactics_affected": ["Defense Evasion", "Impact", "Persistence", "Privilege Escalation"],
        "techniques_covered": ["T1578", "T1531", "T1485", "T1098.001", "T1136.003"],
        "technique_count": 5,
        "description": "Azure Activity logs capture control-plane operations: VM creation/deletion (T1578), role assignment changes (T1098.001), storage account deletion (T1485), and new user/service principal creation (T1136.003). Currently only some subscriptions are forwarding Activity Logs — activity in non-monitored subscriptions is invisible.",
        "implementation": "Enable Diagnostic Settings on all Azure subscriptions to stream Activity Logs to the Sentinel workspace. Automate via Azure Policy (built-in initiative: 'Configure Azure Activity log to stream to specified Log Analytics workspace').",
        "estimated_coverage_gain": 7
    },
    {
        "id": 8,
        "source_name": "Microsoft Purview / Data Loss Prevention (DLP) Logs",
        "category": "Data Loss Prevention",
        "status": "ABSENT",
        "priority": "HIGH",
        "sentinel_table": "MicrosoftPurviewInformationProtection or DLPAllLogs_CL",
        "tactics_affected": ["Exfiltration", "Collection"],
        "techniques_covered": ["T1048", "T1567", "T1213", "T1530"],
        "technique_count": 4,
        "description": "DLP telemetry detects sensitive data being moved to USB, email, or cloud storage. Without Purview DLP, exfiltration of PII/financial data is detectable only through network heuristics. DLP provides label-aware detection that network logs cannot.",
        "implementation": "Enable Microsoft Purview DLP policies in audit mode first, then switch to protection. Configure the Purview Information Protection connector in Sentinel. Tune policies for sensitivity labels (Confidential, Highly Confidential) relevant to your data classification.",
        "estimated_coverage_gain": 5
    },
    {
        "id": 9,
        "source_name": "Active Directory Domain Controller Security Events",
        "category": "Identity",
        "status": "PARTIAL",
        "priority": "CRITICAL",
        "sentinel_table": "SecurityEvent (from all Domain Controllers)",
        "tactics_affected": ["Credential Access", "Privilege Escalation", "Lateral Movement", "Discovery", "Persistence"],
        "techniques_covered": ["T1003.003", "T1558.001", "T1558.003", "T1087.002", "T1484", "T1207"],
        "technique_count": 6,
        "description": "Only some Domain Controllers are forwarding Security events to Sentinel. Events from unmonitored DCs include 4769 (Kerberoasting), 4768 (AS-REP roasting), 4672 (privileged logon), 4742/4743 (computer account changes), and replication operations (T1003.003 — DCSync). This creates a critical blind spot for AD-based attacks.",
        "implementation": "Ensure ALL Domain Controllers have the Azure Monitor Agent (AMA) installed and a DCR configured to forward Windows Security events (minimum: 4624, 4625, 4648, 4662, 4672, 4720, 4728, 4732, 4756, 4769). Verify coverage with a KQL query counting unique DCs in SecurityEvent.",
        "estimated_coverage_gain": 9
    },
    {
        "id": 10,
        "source_name": "Proxy / Web Filter Logs (Zscaler, Defender for Cloud Apps, Squid)",
        "category": "Network / Web",
        "status": "ABSENT",
        "priority": "MEDIUM",
        "sentinel_table": "ZscalerHTTP_CL or McasShadowItReporting or CommonSecurityLog (CEF)",
        "tactics_affected": ["Command and Control", "Exfiltration", "Initial Access"],
        "techniques_covered": ["T1071.001", "T1566.002", "T1048.003", "T1189", "T1190"],
        "technique_count": 5,
        "description": "Web proxy logs enable detection of C2 HTTP/HTTPS beaconing (T1071.001), spearphishing link clicks (T1566.002), and data exfiltration via web uploads. Defender for Cloud Apps provides additional shadow IT detection for unsanctioned cloud services used for exfiltration.",
        "implementation": "Deploy Zscaler Internet Access or equivalent web proxy with Sentinel integration via CEF connector. Alternatively, enable Microsoft Defender for Cloud Apps (MCAS) connector in Sentinel for O365/Azure shadow IT visibility. Configure web proxy to log full URL, user agent, and bytes transferred.",
        "estimated_coverage_gain": 8
    },
    {
        "id": 11,
        "source_name": "VPN / Remote Access Gateway Logs",
        "category": "Network / Authentication",
        "status": "ABSENT",
        "priority": "MEDIUM",
        "sentinel_table": "CommonSecurityLog (CEF/Syslog from VPN appliance)",
        "tactics_affected": ["Initial Access", "Lateral Movement", "Persistence"],
        "techniques_covered": ["T1133", "T1078", "T1021"],
        "technique_count": 3,
        "description": "VPN logs enable detection of unauthorized remote access (T1133), credential stuffing on VPN endpoints, impossible travel scenarios (T1078), and unusual connection patterns (off-hours, new geo locations). Without VPN logs, remote-access-based initial access is only partially visible through Azure AD Sign-In logs.",
        "implementation": "Configure VPN appliance (Cisco ASA, Palo Alto GlobalProtect, Fortinet FortiGate) to send CEF or Syslog to the Sentinel workspace via the Common Event Format connector. Map source IP and username fields for correlation with Azure AD sign-in events.",
        "estimated_coverage_gain": 5
    },
    {
        "id": 12,
        "source_name": "Container / Kubernetes Audit Logs (AKS)",
        "category": "Cloud / Container",
        "status": "ABSENT",
        "priority": "MEDIUM",
        "sentinel_table": "AzureDiagnostics (Category: kube-audit) or ContainerLog",
        "tactics_affected": ["Execution", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "techniques_covered": ["T1610", "T1613", "T1611", "T1525", "T1609"],
        "technique_count": 5,
        "description": "Kubernetes audit logs capture API server actions: privileged pod creation (T1610), container escape attempts (T1611), implanted container images (T1525), and exec into running containers (T1609). If containerised workloads are present, this is a critical gap in runtime security visibility.",
        "implementation": "Enable AKS diagnostic settings (kube-audit, kube-audit-admin categories) to stream to Sentinel workspace. Deploy Microsoft Defender for Containers for real-time admission control and runtime threat protection. Consider Falco for open-source runtime alerting.",
        "estimated_coverage_gain": 4
    },
]

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

def generate_html_report() -> str:
    """Generate comprehensive HTML report with all sections."""
    
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MITRE ATT&CK Coverage Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f1e 0%, #1a1a2e 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 40px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .meta {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            font-size: 0.95em;
        }
        
        .meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .meta-icon {
            font-size: 1.2em;
        }
        
        .section {
            background: #1a1a2e;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        }
        
        .section h2 {
            font-size: 1.8em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .kpi-card {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2);
        }
        
        .kpi-card.high {
            border-left-color: #ef4444;
            background: linear-gradient(135deg, #7f1d1d 0%, #dc2626 100%);
        }
        
        .kpi-card.medium {
            border-left-color: #f59e0b;
            background: linear-gradient(135deg, #78350f 0%, #f59e0b 100%);
        }
        
        .kpi-card.low {
            border-left-color: #10b981;
            background: linear-gradient(135deg, #064e3b 0%, #10b981 100%);
        }
        
        .kpi-label {
            font-size: 0.9em;
            color: rgba(255,255,255,0.7);
            margin-bottom: 5px;
        }
        
        .kpi-value {
            font-size: 2em;
            font-weight: bold;
            color: white;
        }
        
        .kpi-detail {
            font-size: 0.85em;
            color: rgba(255,255,255,0.6);
            margin-top: 5px;
        }
        
        .chart-container {
            background: #0f0f1e;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border: 1px solid #333;
        }
        
        .chart-title {
            font-size: 1.2em;
            color: #667eea;
            margin-bottom: 15px;
            font-weight: 600;
        }
        
        .bar-chart {
            display: flex;
            align-items: flex-end;
            height: 300px;
            gap: 15px;
            margin: 30px 0;
        }
        
        .bar {
            flex: 1;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
            border-radius: 4px 4px 0 0;
            position: relative;
            min-height: 30px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .bar:hover {
            filter: brightness(1.2);
        }
        
        .bar.high { background: linear-gradient(180deg, #10b981 0%, #059669 100%); }
        .bar.medium { background: linear-gradient(180deg, #f59e0b 0%, #d97706 100%); }
        .bar.low { background: linear-gradient(180deg, #ef4444 0%, #dc2626 100%); }
        
        .bar-label {
            position: absolute;
            bottom: -25px;
            left: 0;
            right: 0;
            text-align: center;
            font-size: 0.85em;
            color: #999;
        }
        
        .bar-value {
            position: absolute;
            top: -25px;
            left: 0;
            right: 0;
            text-align: center;
            font-weight: bold;
            color: white;
        }
        
        .heatmap-container {
            overflow-x: auto;
            margin: 20px 0;
        }
        
        .heatmap {
            display: inline-grid;
            gap: 4px;
            padding: 10px;
            background: #0f0f1e;
            border-radius: 8px;
        }
        
        .heatmap-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
            gap: 4px;
        }
        
        .heatmap-cell {
            padding: 15px;
            border-radius: 4px;
            text-align: center;
            font-weight: bold;
            color: white;
            cursor: pointer;
            transition: all 0.2s ease;
            min-height: 60px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            font-size: 0.9em;
        }
        
        .heatmap-cell:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        
        .heatmap-cell.cold { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
        .heatmap-cell.warm { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
        .heatmap-cell.hot { background: linear-gradient(135deg, #10b981 0%, #059669 100%); }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #333;
        }
        
        tr:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge.critical {
            background: #ef4444;
            color: white;
        }
        
        .badge.high {
            background: #f59e0b;
            color: white;
        }
        
        .badge.medium {
            background: #3b82f6;
            color: white;
        }
        
        .badge.low {
            background: #10b981;
            color: white;
        }
        
        .finding {
            background: rgba(102, 126, 234, 0.1);
            border-left: 4px solid #667eea;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        
        .finding.critical {
            border-left-color: #ef4444;
            background: rgba(239, 68, 68, 0.1);
        }
        
        .finding.high {
            border-left-color: #f59e0b;
            background: rgba(245, 158, 11, 0.1);
        }
        
        .finding.positive {
            border-left-color: #10b981;
            background: rgba(16, 185, 129, 0.1);
        }
        
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 20px 0;
        }
        
        .technique-table {
            font-size: 0.95em;
        }
        
        .technique-table th {
            font-size: 0.9em;
        }
        
        .coverage-indicator {
            display: inline-block;
            width: 100%;
            height: 8px;
            background: #333;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .coverage-fill {
            height: 100%;
            background: linear-gradient(90deg, #10b981, #667eea);
            border-radius: 4px;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #999;
            border-top: 1px solid #333;
            margin-top: 40px;
        }
        
        .assessment-score {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .score-box {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
        }
        
        .score-box.critical {
            background: linear-gradient(135deg, #7f1d1d 0%, #dc2626 100%);
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.2);
        }
        
        .score-number {
            font-size: 2.5em;
            font-weight: bold;
            color: white;
            margin: 10px 0;
        }
        
        .score-label {
            font-size: 0.9em;
            color: rgba(255,255,255,0.8);
        }
        
        .page-break {
            page-break-after: always;
            margin: 40px 0;
            padding: 20px 0;
            border-top: 2px dashed #667eea;
        }
        
        @media print {
            body {
                background: white;
                color: #000;
            }
            .section {
                background: white;
                border: 1px solid #ccc;
                box-shadow: none;
            }
            .page-break {
                page-break-after: always;
            }
        }
    </style>
</head>
<body>
    <div class="container">
"""
    
    # Header Section
    html_content += f"""
        <div class="header">
            <h1>🛡️ MITRE ATT&CK Coverage Analysis Report</h1>
            <div class="meta">
                <div class="meta-item">
                    <span class="meta-icon">📊</span>
                    <span><strong>Workspace:</strong> Infosec-Sentinel-LAW</span>
                </div>
                <div class="meta-item">
                    <span class="meta-icon">📅</span>
                    <span><strong>Generated:</strong> April 18, 2026</span>
                </div>
                <div class="meta-item">
                    <span class="meta-icon">📈</span>
                    <span><strong>Analysis Period:</strong> Last 90 Days</span>
                </div>
                <div class="meta-item">
                    <span class="meta-icon">🎯</span>
                    <span><strong>Incidents Analyzed:</strong> 3,640</span>
                </div>
            </div>
        </div>
"""
    
    # Executive Summary
    html_content += """
        <div class="section">
            <h2>📋 Executive Summary</h2>
            <div class="kpi-grid">
                <div class="kpi-card medium">
                    <div class="kpi-label">Overall Coverage</div>
                    <div class="kpi-value">38%</div>
                    <div class="kpi-detail">14 of 36 tactics covered</div>
                </div>
                <div class="kpi-card low">
                    <div class="kpi-label">Critical Gaps</div>
                    <div class="kpi-value">5</div>
                    <div class="kpi-detail">Lateral Movement, C2, Exfiltration</div>
                </div>
                <div class="kpi-card high">
                    <div class="kpi-label">Recommended Rules</div>
                    <div class="kpi-value">8</div>
                    <div class="kpi-detail">To reach 70% coverage</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Incidents Detected</div>
                    <div class="kpi-value">3,640</div>
                    <div class="kpi-detail">Over 90-day period</div>
                </div>
            </div>
            
            <div class="finding critical">
                <strong>⚠️ CRITICAL RISK:</strong> Zero detection coverage for Lateral Movement (TA0008). Once attackers gain initial access, they can move undetected within your network.
            </div>
            
            <div class="finding high">
                <strong>🔴 HIGH PRIORITY:</strong> Command & Control (5% coverage) and Exfiltration (8% coverage) are severely under-monitored. Attackers can establish persistence and exfiltrate data without detection.
            </div>
            
            <div class="finding positive">
                <strong>✅ STRENGTH:</strong> Excellent Initial Access detection (95% coverage with 2,562 incidents). Your organization has strong credential and phishing monitoring.
            </div>
        </div>
"""
    
    # Coverage by Tactic
    html_content += """
        <div class="section">
            <h2>📊 Coverage by Tactic</h2>
            <div class="chart-container">
                <div class="chart-title">MITRE Tactic Coverage Breakdown</div>
                <div class="bar-chart">
"""
    
    for tactic_id, tactic_name, color in MITRE_TACTICS:
        data = MITRE_COVERAGE_DATA.get(tactic_id, {})
        coverage = data.get('coverage', 0)
        incidents = data.get('incidents', 0)
        
        # Determine height (max 100%)
        height = max(5, coverage)  # Minimum 5% for visibility
        
        coverage_class = "high" if coverage >= 70 else ("medium" if coverage >= 30 else "low")
        
        html_content += f"""
                    <div class="bar {coverage_class}" style="height: {height}%;">
                        <div class="bar-value">{coverage}%</div>
                        <div class="bar-label" style="white-space: nowrap; font-size: 0.8em;">{tactic_name.split()[0]}</div>
                    </div>
"""
    
    html_content += """
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Tactic</th>
                        <th>Coverage</th>
                        <th>Incidents</th>
                        <th>Techniques Covered</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    for tactic_id, tactic_name, color in MITRE_TACTICS:
        data = MITRE_COVERAGE_DATA.get(tactic_id, {})
        coverage = data.get('coverage', 0)
        incidents = data.get('incidents', 0)
        covered = data.get('covered_techniques', 0)
        total = data.get('techniques', 0)
        
        if coverage >= 70:
            risk_badge = '<span class="badge low">Low Risk</span>'
        elif coverage >= 40:
            risk_badge = '<span class="badge medium">Medium Risk</span>'
        else:
            risk_badge = '<span class="badge critical">Critical Risk</span>'
        
        coverage_bar = f'<div class="coverage-indicator"><div class="coverage-fill" style="width: {coverage}%"></div></div>'
        
        html_content += f"""
                    <tr>
                        <td><strong>{tactic_name}</strong></td>
                        <td>{coverage_bar}<span style="margin-left: 10px;">{coverage}%</span></td>
                        <td>{incidents:,}</td>
                        <td>{covered}/{total}</td>
                        <td>{risk_badge}</td>
                    </tr>
"""
    
    html_content += """
                </tbody>
            </table>
        </div>
"""
    
    # Coverage Heatmap
    html_content += """
        <div class="page-break"></div>
        <div class="section">
            <h2>🔥 MITRE Coverage Heatmap</h2>
            <p style="color: #999; margin-bottom: 20px;">Color intensity represents detection coverage: Green (Strong ≥70%), Yellow (Moderate 30-70%), Red (Weak <30%)</p>
            <div class="heatmap-container">
                <div class="heatmap">
"""
    
    # Create heatmap rows
    heatmap_data = [
        ("Initial Access", 95, "hot"),
        ("Execution", 45, "warm"),
        ("Persistence", 38, "warm"),
        ("Privilege Esc.", 32, "warm"),
        ("Defense Evasion", 28, "cold"),
        ("Credential Access", 52, "warm"),
        ("Discovery", 35, "warm"),
        ("Lateral Movement", 0, "cold"),
        ("Collection", 22, "cold"),
        ("Exfiltration", 8, "cold"),
        ("Command & Control", 5, "cold"),
        ("Impact", 12, "cold"),
    ]
    
    for tactic, coverage, intensity in heatmap_data:
        html_content += f"""
                    <div class="heatmap-cell {intensity}" title="{tactic}: {coverage}%">
                        <div>{tactic}</div>
                        <div style="font-size: 1.2em;">{coverage}%</div>
                    </div>
"""
    
    html_content += """
                </div>
            </div>
        </div>
"""
    
    # Assessment Scores by Tactic
    html_content += """
        <div class="section">
            <h2>🎯 Assessment Scores by Category</h2>
            <p style="color: #999; margin-bottom: 20px;">Risk assessment based on coverage percentage and detected incidents</p>
            <div class="assessment-score">
                <div class="score-box">
                    <div class="score-label">Initial Access</div>
                    <div class="score-number" style="color: #10b981;">95/100</div>
                    <div class="score-label">Excellent</div>
                </div>
                <div class="score-box">
                    <div class="score-label">Credential Access</div>
                    <div class="score-number" style="color: #f59e0b;">52/100</div>
                    <div class="score-label">Good</div>
                </div>
                <div class="score-box">
                    <div class="score-label">Execution</div>
                    <div class="score-number" style="color: #f59e0b;">45/100</div>
                    <div class="score-label">Fair</div>
                </div>
                <div class="score-box critical">
                    <div class="score-label">Lateral Movement</div>
                    <div class="score-number">0/100</div>
                    <div class="score-label">Critical Gap</div>
                </div>
                <div class="score-box critical">
                    <div class="score-label">Command & Control</div>
                    <div class="score-number">5/100</div>
                    <div class="score-label">Critical Gap</div>
                </div>
                <div class="score-box critical">
                    <div class="score-label">Exfiltration</div>
                    <div class="score-number">8/100</div>
                    <div class="score-label">Critical Gap</div>
                </div>
            </div>
        </div>
"""
    
    # Detailed Technique Coverage
    html_content += """
        <div class="page-break"></div>
        <div class="section">
            <h2>🔍 Detailed Technique Coverage</h2>
"""
    
    # Show details for high-impact tactics
    high_priority_tactics = [
        ("TA0001", "Initial Access"),
        ("TA0008", "Lateral Movement"),
        ("TA0011", "Command and Control"),
        ("TA0010", "Exfiltration"),
    ]
    
    for tactic_id, tactic_name in high_priority_tactics:
        data = MITRE_COVERAGE_DATA.get(tactic_id, {})
        coverage = data.get('coverage', 0)
        techniques = data.get('techniques_list', [])
        
        html_content += f"""
            <div class="chart-container" style="margin-top: 20px;">
                <div class="chart-title">{tactic_name} (Coverage: {coverage}%)</div>
                <table class="technique-table">
                    <thead>
                        <tr>
                            <th>Technique ID</th>
                            <th>Technique Name</th>
                            <th>Status</th>
                            <th>Coverage</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        
        for tech_id, tech_name, covered, tech_coverage in techniques[:5]:
            status = '<span class="badge low">✓ Covered</span>' if covered else '<span class="badge critical">✗ Gap</span>'
            html_content += f"""
                        <tr>
                            <td><strong>{tech_id}</strong></td>
                            <td>{tech_name}</td>
                            <td>{status}</td>
                            <td>
                                <div class="coverage-indicator">
                                    <div class="coverage-fill" style="width: {tech_coverage}%"></div>
                                </div>
                                {tech_coverage}%
                            </td>
                        </tr>
"""
        
        html_content += """
                    </tbody>
                </table>
            </div>
"""
    
    html_content += """
        </div>
"""
    
    # Recommended Rules
    html_content += """
        <div class="page-break"></div>
        <div class="section">
            <h2>📋 Recommended Detection Rules</h2>
            <p style="color: #999; margin-bottom: 20px;">The following 8 rules are recommended to close critical coverage gaps and improve detection from 38% to 70%</p>
"""
    
    for i, rule in enumerate(RECOMMENDED_RULES, 1):
        priority_class = rule['priority'].lower()
        html_content += f"""
            <div class="finding {priority_class}">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                    <div>
                        <strong>#{i} - {rule['technique_name']}</strong>
                        <span class="badge {priority_class}" style="margin-left: 10px;">{rule['priority']}</span>
                    </div>
                    <div style="font-size: 0.9em; color: #999;">
                        Estimated Incidents: <strong>{rule['estimated_incidents']}</strong>
                    </div>
                </div>
                <p style="margin: 10px 0; color: #ccc;"><strong>Description:</strong> {rule['description']}</p>
                <p style="margin: 10px 0; color: #ccc;"><strong>Detection Method:</strong> {rule['detection_method']}</p>
                <p style="margin: 10px 0; color: #ccc;"><strong>Implementation Effort:</strong> {rule['implementation_effort']}</p>
                <div style="background: #0f0f1e; padding: 10px; border-radius: 4px; margin-top: 10px; font-family: monospace; font-size: 0.85em; overflow-x: auto; color: #67d5ff;">
                    {rule['rule_template'][:100]}... <a href="#" style="color: #667eea;">view full</a>
                </div>
            </div>
"""
    
    html_content += """
        </div>
"""
    
    # Implementation Roadmap
    html_content += """
        <div class="section">
            <h2>🚀 Implementation Roadmap</h2>
            <p style="color: #999; margin-bottom: 20px;">Phased approach to reach 70% coverage in 4-6 weeks</p>
            
            <div style="margin: 20px 0;">
                <h3 style="color: #667eea; margin: 20px 0 10px 0;">Phase 1: Critical Gaps (Week 1-2)</h3>
                <p style="color: #ccc; margin-bottom: 15px;">Deploy 3 rules targeting highest-impact MITRE techniques</p>
                <ul style="color: #ccc; margin-left: 20px; line-height: 2;">
                    <li>🔴 RDP Lateral Movement Detection (T1021.001) - Est. 450 incidents</li>
                    <li>🔴 WinRM Remote Execution Detection (T1021.005) - Est. 280 incidents</li>
                    <li>🔴 Non-Standard Port C2 Detection (T1571) - Est. 180 incidents</li>
                </ul>
            </div>
            
            <div style="margin: 20px 0;">
                <h3 style="color: #667eea; margin: 20px 0 10px 0;">Phase 2: High-Priority Gaps (Week 2-3)</h3>
                <p style="color: #ccc; margin-bottom: 15px;">Deploy 3 rules for persistence and data exfiltration</p>
                <ul style="color: #ccc; margin-left: 20px; line-height: 2;">
                    <li>🟠 Mailbox Forwarding Rule Abuse Detection (T1098) - Est. 195 incidents</li>
                    <li>🟠 Large Data Transfer Detection (T1048.003) - Est. 220 incidents</li>
                    <li>🟠 DCOM Lateral Movement Detection (T1021.003) - Est. 320 incidents</li>
                </ul>
            </div>
            
            <div style="margin: 20px 0;">
                <h3 style="color: #667eea; margin: 20px 0 10px 0;">Phase 3: Secondary Gaps (Week 4-6)</h3>
                <p style="color: #ccc; margin-bottom: 15px;">Deploy 2 rules for masquerading and collection</p>
                <ul style="color: #ccc; margin-left: 20px; line-height: 2;">
                    <li>🟡 Executable Masquerading Detection (T1036) - Est. 145 incidents</li>
                    <li>🟡 Bulk File Collection Detection (T1005) - Est. 130 incidents</li>
                </ul>
            </div>
        </div>
"""
    
    # Key Statistics
    html_content += """
        <div class="section">
            <h2>📈 Key Statistics & Metrics</h2>
            <div class="grid-2">
                <div>
                    <h3 style="color: #667eea; margin-bottom: 15px;">Detection Summary</h3>
                    <ul style="color: #ccc; line-height: 2; list-style: none;">
                        <li>✓ <strong>Total Incidents Analyzed:</strong> 3,640</li>
                        <li>✓ <strong>Covered Tactics:</strong> 10 of 12 (83%)</li>
                        <li>✓ <strong>Techniques with Detection:</strong> 41 of 114 (36%)</li>
                        <li>✓ <strong>Detection Coverage:</strong> 38% (baseline)</li>
                        <li>✓ <strong>Active Analytic Rules:</strong> 27</li>
                    </ul>
                </div>
                <div>
                    <h3 style="color: #667eea; margin-bottom: 15px;">Coverage Gaps</h3>
                    <ul style="color: #ccc; line-height: 2; list-style: none;">
                        <li>✗ <strong>Lateral Movement:</strong> 0% (9 techniques)</li>
                        <li>✗ <strong>Command & Control:</strong> 5% (17 techniques)</li>
                        <li>✗ <strong>Exfiltration:</strong> 8% (13 techniques)</li>
                        <li>✗ <strong>Collection:</strong> 22% (20 techniques)</li>
                        <li>✗ <strong>Techniques Missing Rules:</strong> 73</li>
                    </ul>
                </div>
            </div>
        </div>
"""
    
    # Conclusion
    html_content += """
        <div class="section">
            <h2>🎯 Conclusion & Next Steps</h2>
            <div class="finding high">
                <strong>Current Status:</strong> Your organization has established a strong foundation with Initial Access and Credential Access detection (95% and 52% respectively). However, critical blind spots exist in post-breach attack phases.
            </div>
            <div class="finding critical">
                <strong>Immediate Action Required:</strong> Deploy lateral movement detection (T1021.001, T1021.005, T1021.003) immediately to prevent undetected lateral spread. These represent 1,050+ estimated incidents that are currently invisible.
            </div>
            <div class="finding">
                <strong>60-90 Day Target:</strong> Implement all 8 recommended rules to reach 70% MITRE ATT&CK coverage. This will significantly reduce your organization's attack surface and dwell time.
            </div>
            <div class="finding positive">
                <strong>Success Metrics:</strong> Track coverage improvements monthly. Target: 70% coverage (Month 1), 80% coverage (Month 2), 90% coverage (Month 3).
            </div>
        </div>
        
        <div class="footer">
            <p>© 2026 Infosec-Sentinel-LAW Workspace | Report generated automatically from Sentinel incident analysis</p>
            <p>Next scheduled report: May 18, 2026 | Review period: 90 days</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html_content

# ============================================================================
# PDF GENERATION (using wkhtmltopdf conversion)
# ============================================================================

def html_to_pdf(html_content: str, output_path: str) -> bool:
    """Convert HTML to PDF using available tools."""
    import subprocess
    import sys
    
    try:
        # Use system temp directory to avoid Uvicorn reloads
        import tempfile
        temp_fd, temp_path = tempfile.mkstemp(suffix=".html", prefix="mitre_report_")
        os.close(temp_fd)
        temp_html = Path(temp_path)
        
        with open(temp_html, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Try wkhtmltopdf first
        try:
            result = subprocess.run(
                ['wkhtmltopdf', '--enable-local-file-access', str(temp_html), output_path],
                capture_output=True,
                timeout=60
            )
            if result.returncode == 0:
                print(f"✅ PDF created successfully: {output_path}")
                os.remove(temp_path)
                return True
        except FileNotFoundError:
            print("ℹ️  wkhtmltopdf not found, trying alternative methods...")
        
        # Try using weasyprint (Python)
        try:
            from weasyprint import HTML, CSS
            HTML(str(temp_html)).write_pdf(output_path)
            print(f"✅ PDF created successfully (weasyprint): {output_path}")
            os.remove(temp_path)
            return True
        except ImportError:
            print("ℹ️  weasyprint not available, trying pdfkit...")
        
        # Try pdfkit
        try:
            import pdfkit
            pdfkit.from_file(str(temp_html), output_path)
            print(f"✅ PDF created successfully (pdfkit): {output_path}")
            os.remove(temp_path)
            return True
        except (ImportError, Exception):
            print("ℹ️  pdfkit not available or failed")
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
        print("⚠️  PDF generation tools not found. HTML file saved for manual conversion.")
        return False
        
    except Exception as e:
        print(f"❌ Error generating PDF: {e}")
        return False

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Generate MITRE coverage analysis reports."""
    import sys
    
    # Handle dynamic output path
    output_dir_str = "reports"
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        output_dir_str = sys.argv[1]
        
    output_dir = Path(output_dir_str)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d")
    
    print("=" * 80)
    print("[SEARCH] MITRE ATT&CK Coverage Analysis Report Generator")
    print("=" * 80)
    
    # Generate HTML report
    print("\n[FILE] Generating HTML report...")
    html_content = generate_html_report()
    html_path = output_dir / f"MITRE_ATT_CK_Coverage_Report_{timestamp}.html"
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[OK] HTML report saved: {html_path}")
    
    # Generate PDF report
    print("\n[FILE] Generating PDF report...")
    pdf_path = output_dir / f"MITRE_ATT_CK_Coverage_Report_{timestamp}.pdf"
    
    if html_to_pdf(html_content, str(pdf_path)):
        print(f"[OK] PDF report saved: {pdf_path}")
    else:
        print(f"[INFO] HTML-only report available at: {html_path}")
    
    print("\n" + "=" * 80)
    print("Report generation complete!")
    print("=" * 80)
    print(f"\n[SUMMARY] Report Summary:")
    print(f"   - HTML: {html_path}")
    print(f"   - PDF: {pdf_path}")
    print(f"   - Coverage: 38% baseline -> 70% target (8 rules recommended)")
    print(f"   - Critical Gaps: Lateral Movement (0%), C2 (5%), Exfiltration (8%)")
    print(f"   - Implementation Timeline: 4-6 weeks for Phase 1-3")

if __name__ == "__main__":
    main()
