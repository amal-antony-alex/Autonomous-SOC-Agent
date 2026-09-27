# SOC Security Knowledge

## Brute Force Authentication

Brute force authentication is an attack where an attacker repeatedly attempts
to authenticate using different passwords, usernames, or credentials.

Common indicators include:
- Multiple failed authentication attempts
- Repeated failures from the same source IP
- Failed SSH authentication
- Attempts using non-existent users
- Repeated authentication attempts against privileged accounts

MITRE ATT&CK:
- T1110 - Brute Force
- T1110.001 - Password Guessing

Investigation evidence:
- Source IP
- Username
- Authentication timestamp
- Authentication logs
- Number of failed attempts
- Target system

SOC investigation:
Correlate repeated authentication failures from the same source,
identify the targeted accounts, and determine whether a successful
authentication occurred after the failed attempts.

---

## Malware Detection

Malware is malicious software designed to compromise, damage, disrupt,
or gain unauthorized access to systems.

Common indicators include:
- Suspicious executable files
- Known malware names
- Unexpected process execution
- Suspicious file creation
- Antivirus or EDR detections
- Persistence mechanisms

SOC investigation:
Collect the affected host, file path, process information, hashes,
parent process, user account, and execution timestamp.

---

## Suspicious PowerShell

PowerShell can be abused by attackers to execute commands, download
payloads, perform reconnaissance, and establish persistence.

Common indicators include:
- powershell.exe
- Encoded commands
- -enc or -encodedcommand
- Invoke-Expression
- IEX
- DownloadString

MITRE ATT&CK:
- T1059 - Command and Scripting Interpreter
- T1059.001 - PowerShell

Investigation evidence:
- Command line
- Executing user
- Parent process
- Destination URL or IP
- Downloaded files
- Execution timestamp

---

## Port Scanning

Port scanning is reconnaissance activity used to identify open ports
and available services on a target system.

Common indicators include:
- Multiple destination ports
- Connections to many ports on one host
- Nmap activity
- Port scan detection
- Repeated connection attempts

MITRE ATT&CK:
- T1046 - Network Service Scanning

Investigation evidence:
- Source IP
- Destination IP
- Destination ports
- Scan timestamp
- Number of ports contacted

---

## Active Directory

Active Directory environments contain identities, authentication
services, domain controllers, groups, and access-control information.

Suspicious activity may include:
- Unusual privileged account authentication
- Suspicious Kerberos activity
- Unexpected LDAP queries
- Domain controller access
- Abnormal lateral movement

Relevant investigation areas:
- Username
- Source host
- Destination host
- Authentication protocol
- Privilege level
- Kerberos events
- LDAP activity

SOC investigation should correlate authentication, account activity,
host activity, and network connections to determine whether the activity
is expected.
