# -*- coding: utf-8 -*-
"""
Builds the embedded knowledge-base JSON for TTP Knowledge Hub.
All descriptions are summarised in my own words from the named framework,
and are NOT official text. Mappings are authoritative where I am confident,
and flagged with a source + confidence. Nothing is invented to fill gaps.
"""
import json

DATASET_META = {
    "attack_version": "ATT&CK v20.1 (current; curated subset)",
    "attack_released": "2026-10-13",
    "d3fend_version": "D3FEND 1.0",
    "capec_version": "CAPEC 3.9",
    "cwe_version": "CWE 5.0",
    "owasp_version": "OWASP Top 10:2025",
    "cve_source": "Landmark CVEs, NVD-referenced",
    "built": "2026-11-07",
    "updated": "2026-11-07",
    "sources": {
        "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
        "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
    },
    "source_pages": {
        "ATT&CK": "https://attack.mitre.org/resources/versions/",
        "D3FEND": "https://d3fend.mitre.org/",
        "CAPEC": "https://capec.mitre.org/",
        "CWE": "https://cwe.mitre.org/",
        "OWASP": "https://owasp.org/Top10/"
    },
    "probe_hosts": ["https://attack.mitre.org/favicon.ico", "https://www.mitre.org/favicon.ico", "https://cwe.mitre.org/favicon.ico"],
    "note": "Summarised, labelled knowledge base. Version labels reflect the current framework releases verified Nov 2026 "
            "(ATT&CK v20.1 Oct 2026, D3FEND 1.0, CAPEC 3.9, CWE 5.0, OWASP Top 10:2025). The embedded ATT&CK content is a "
            "curated subset whose tactic/technique IDs remain valid in v20.1 — it is NOT the complete v20.1 catalog. "
            "Descriptions are paraphrased, not official framework text. Mappings carry source + confidence; unknown mappings are omitted, not invented."
}

# ---------------------------------------------------------------------------
# ATT&CK ENTERPRISE — all 14 tactics
# ---------------------------------------------------------------------------
ATTACK_TACTICS = [
    {"id":"TA0043","name":"Reconnaissance","short":"Gathering information to plan future operations.","order":1},
    {"id":"TA0042","name":"Resource Development","short":"Establishing resources to support operations.","order":2},
    {"id":"TA0001","name":"Initial Access","short":"Getting into the target network.","order":3},
    {"id":"TA0002","name":"Execution","short":"Running adversary-controlled code.","order":4},
    {"id":"TA0003","name":"Persistence","short":"Maintaining a foothold across restarts and credential changes.","order":5},
    {"id":"TA0004","name":"Privilege Escalation","short":"Gaining higher-level permissions.","order":6},
    {"id":"TA0005","name":"Defense Evasion","short":"Avoiding detection.","order":7},
    {"id":"TA0006","name":"Credential Access","short":"Stealing account names and secrets.","order":8},
    {"id":"TA0007","name":"Discovery","short":"Learning about the environment.","order":9},
    {"id":"TA0008","name":"Lateral Movement","short":"Moving through the environment.","order":10},
    {"id":"TA0009","name":"Collection","short":"Gathering data of interest.","order":11},
    {"id":"TA0011","name":"Command and Control","short":"Communicating with compromised systems.","order":12},
    {"id":"TA0010","name":"Exfiltration","short":"Stealing data out of the network.","order":13},
    {"id":"TA0040","name":"Impact","short":"Manipulating, interrupting or destroying systems and data.","order":14},
]

# Techniques: id, name, tactics[], platforms[], summary (my words), detection, mitigations[],
# subs[] = [{id,name,summary}], capec[], cwe[], killchain[]
# Accurate IDs/names; summaries paraphrased.
T = ATTACK_TECHNIQUES = [
 {"id":"T1595","name":"Active Scanning","tactics":["TA0043"],"platforms":["PRE"],
  "summary":"Probing victim infrastructure directly, such as scanning IP blocks for open ports and services, to find ways in.",
  "detection":"Monitor for scanning patterns at network edge; much activity occurs off-network and may be invisible.",
  "mitigations":["Pre-compromise (M1056)"],"killchain":["recon"],"capec":["CAPEC-300"],"cwe":[],
  "subs":[{"id":"T1595.001","name":"Scanning IP Blocks","summary":"Sweeping IP ranges to map responsive hosts."},
          {"id":"T1595.002","name":"Vulnerability Scanning","summary":"Checking targets for exploitable weaknesses and versions."},
          {"id":"T1595.003","name":"Wordlist Scanning","summary":"Brute-forcing resource names like directories or buckets."}]},
 {"id":"T1592","name":"Gather Victim Host Information","tactics":["TA0043"],"platforms":["PRE"],
  "summary":"Collecting details about victim hosts (hardware, software, configuration) for targeting.",
  "detection":"Largely external; correlate with later phases.","mitigations":["Pre-compromise (M1056)"],"killchain":["recon"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1590","name":"Gather Victim Network Information","tactics":["TA0043"],"platforms":["PRE"],
  "summary":"Collecting network details such as IP ranges, domains and topology.",
  "detection":"Mostly external; monitor exposed DNS and WHOIS where possible.","mitigations":["Pre-compromise (M1056)"],"killchain":["recon"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1589","name":"Gather Victim Identity Information","tactics":["TA0043"],"platforms":["PRE"],
  "summary":"Collecting identities — emails, employee names, credentials — for later use.",
  "detection":"External; watch for credential exposure.","mitigations":["Pre-compromise (M1056)"],"killchain":["recon"],"capec":[],"cwe":[],"subs":[
      {"id":"T1589.001","name":"Credentials","summary":"Obtaining victim credentials from leaks or purchase."},
      {"id":"T1589.002","name":"Email Addresses","summary":"Harvesting email addresses for phishing/targeting."}]},
 {"id":"T1598","name":"Phishing for Information","tactics":["TA0043"],"platforms":["PRE"],
  "summary":"Soliciting information from victims via deceptive messages, without delivering malware.",
  "detection":"Email gateway analysis; user reporting.","mitigations":["User Training (M1017)"],"killchain":["recon"],"capec":["CAPEC-98"],"cwe":[],"subs":[]},
 {"id":"T1583","name":"Acquire Infrastructure","tactics":["TA0042"],"platforms":["PRE"],
  "summary":"Buying or renting servers, domains and services to run operations.",
  "detection":"Mostly external; threat intel on known infra.","mitigations":["Pre-compromise (M1056)"],"killchain":["weaponization"],"capec":[],"cwe":[],"subs":[
      {"id":"T1583.001","name":"Domains","summary":"Registering domains for C2, phishing or staging."}]},
 {"id":"T1587","name":"Develop Capabilities","tactics":["TA0042"],"platforms":["PRE"],
  "summary":"Building tooling — malware, exploits, certificates — for operations.",
  "detection":"External; reverse-engineering of captured tools.","mitigations":["Pre-compromise (M1056)"],"killchain":["weaponization"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1566","name":"Phishing","tactics":["TA0001"],"platforms":["Linux","macOS","Windows","SaaS","Office 365","Google Workspace"],
  "summary":"Sending deceptive messages to trick users into opening malicious attachments or links.",
  "detection":"Email security, attachment detonation, URL analysis, user reporting.","mitigations":["User Training (M1017)","Network Intrusion Prevention (M1031)","Restrict Web-Based Content (M1021)"],"killchain":["delivery"],"capec":["CAPEC-98"],"cwe":[],"subs":[
      {"id":"T1566.001","name":"Spearphishing Attachment","summary":"Targeted email carrying a malicious file."},
      {"id":"T1566.002","name":"Spearphishing Link","summary":"Targeted email with a link to malicious content."},
      {"id":"T1566.003","name":"Spearphishing via Service","summary":"Using third-party services/DMs to deliver the lure."}]},
 {"id":"T1190","name":"Exploit Public-Facing Application","tactics":["TA0001"],"platforms":["Linux","Windows","macOS","Network","Containers","IaaS"],
  "summary":"Abusing a weakness in an internet-facing application to gain initial access.",
  "detection":"WAF logs, application logs, IDS signatures, anomalous process spawn from web services.","mitigations":["Update Software (M1051)","Vulnerability Scanning (M1016)","Network Segmentation (M1030)","Application Isolation and Sandboxing (M1048)"],"killchain":["exploitation"],"capec":["CAPEC-66","CAPEC-63","CAPEC-100"],"cwe":["CWE-89","CWE-79","CWE-78"],"subs":[]},
 {"id":"T1133","name":"External Remote Services","tactics":["TA0001","TA0003"],"platforms":["Windows","Linux","Containers","SaaS"],
  "summary":"Using exposed remote services (VPN, RDP gateways, Citrix) with valid accounts to get in or stay in.",
  "detection":"Authentication logs, impossible-travel analytics, new external logons.","mitigations":["Multi-factor Authentication (M1032)","Disable or Remove Feature or Program (M1042)","Network Segmentation (M1030)"],"killchain":["delivery"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1078","name":"Valid Accounts","tactics":["TA0001","TA0003","TA0004","TA0005"],"platforms":["Windows","Linux","macOS","SaaS","IaaS","Network","Containers","Office 365","Google Workspace","Azure AD"],
  "summary":"Using legitimate credentials to access, persist, escalate and evade defences.",
  "detection":"Behavioural analytics, logon anomalies, use of dormant accounts.","mitigations":["Multi-factor Authentication (M1032)","Privileged Account Management (M1026)","Account Use Policies (M1036)"],"killchain":["exploitation"],"capec":["CAPEC-560"],"cwe":[],"subs":[
      {"id":"T1078.001","name":"Default Accounts","summary":"Abusing built-in default credentials."},
      {"id":"T1078.002","name":"Domain Accounts","summary":"Abusing AD domain accounts."},
      {"id":"T1078.003","name":"Local Accounts","summary":"Abusing local machine accounts."},
      {"id":"T1078.004","name":"Cloud Accounts","summary":"Abusing cloud identity accounts."}]},
 {"id":"T1059","name":"Command and Scripting Interpreter","tactics":["TA0002"],"platforms":["Windows","Linux","macOS","Network"],
  "summary":"Abusing command-line shells and scripting engines to execute commands and payloads.",
  "detection":"Process creation logging, command-line auditing, script-block logging.","mitigations":["Execution Prevention (M1038)","Disable or Remove Feature or Program (M1042)","Privileged Account Management (M1026)"],"killchain":["exploitation"],"capec":["CAPEC-248"],"cwe":["CWE-78"],"subs":[
      {"id":"T1059.001","name":"PowerShell","summary":"Using PowerShell to run commands and in-memory payloads."},
      {"id":"T1059.002","name":"AppleScript","summary":"Using AppleScript for execution on macOS."},
      {"id":"T1059.003","name":"Windows Command Shell","summary":"Using cmd.exe for execution."},
      {"id":"T1059.004","name":"Unix Shell","summary":"Using bash/sh for execution."},
      {"id":"T1059.005","name":"Visual Basic","summary":"Using VB/VBA/VBScript for execution."},
      {"id":"T1059.006","name":"Python","summary":"Using Python for execution."},
      {"id":"T1059.007","name":"JavaScript","summary":"Using JavaScript/JScript for execution."}]},
 {"id":"T1203","name":"Exploitation for Client Execution","tactics":["TA0002"],"platforms":["Windows","Linux","macOS"],
  "summary":"Exploiting client software (browsers, office apps) to run code when a user opens content.",
  "detection":"Exploit mitigation telemetry, anomalous child processes of office/browser apps.","mitigations":["Application Isolation and Sandboxing (M1048)","Exploit Protection (M1050)","Update Software (M1051)"],"killchain":["exploitation"],"capec":["CAPEC-549"],"cwe":["CWE-787","CWE-416"],"subs":[]},
 {"id":"T1053","name":"Scheduled Task/Job","tactics":["TA0002","TA0003","TA0004"],"platforms":["Windows","Linux","macOS","Containers"],
  "summary":"Abusing task schedulers (cron, Task Scheduler) to run code and persist.",
  "detection":"Monitor task creation, cron edits, at jobs, and related registry/file changes.","mitigations":["Privileged Account Management (M1026)","User Account Management (M1018)","Audit (M1047)"],"killchain":["installation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1053.003","name":"Cron","summary":"Using cron for scheduled execution/persistence on Unix."},
      {"id":"T1053.005","name":"Scheduled Task","summary":"Using Windows Task Scheduler for execution/persistence."}]},
 {"id":"T1543","name":"Create or Modify System Process","tactics":["TA0003","TA0004"],"platforms":["Windows","Linux","macOS"],
  "summary":"Creating or altering services/daemons to run malicious code persistently with high privilege.",
  "detection":"Service creation events, systemd unit changes, launchd changes.","mitigations":["Privileged Account Management (M1026)","User Account Management (M1018)"],"killchain":["installation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1543.003","name":"Windows Service","summary":"Installing/altering a Windows service for persistence."}]},
 {"id":"T1547","name":"Boot or Logon Autostart Execution","tactics":["TA0003","TA0004"],"platforms":["Windows","Linux","macOS"],
  "summary":"Configuring the system to run adversary code at boot or logon.",
  "detection":"Monitor autostart locations: Run keys, startup folders, login items.","mitigations":["User Account Management (M1018)"],"killchain":["installation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1547.001","name":"Registry Run Keys / Startup Folder","summary":"Using Run keys or Startup folder to auto-run."}]},
 {"id":"T1055","name":"Process Injection","tactics":["TA0004","TA0005"],"platforms":["Windows","Linux","macOS"],
  "summary":"Running code inside another live process to evade defences and inherit its context.",
  "detection":"API call monitoring (CreateRemoteThread, ptrace), memory anomalies.","mitigations":["Behavior Prevention on Endpoint (M1040)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1055.001","name":"Dynamic-link Library Injection","summary":"Injecting a DLL into a remote process."},
      {"id":"T1055.012","name":"Process Hollowing","summary":"Replacing a suspended process's image with malicious code."}]},
 {"id":"T1548","name":"Abuse Elevation Control Mechanism","tactics":["TA0004","TA0005"],"platforms":["Windows","Linux","macOS"],
  "summary":"Circumventing elevation controls like UAC or sudo to gain higher privileges.",
  "detection":"Monitor sudo usage, UAC bypass patterns, setuid abuse.","mitigations":["Privileged Account Management (M1026)","User Account Control (M1052)"],"killchain":["exploitation"],"capec":[],"cwe":["CWE-250"],"subs":[
      {"id":"T1548.003","name":"Sudo and Sudo Caching","summary":"Abusing sudo and cached credentials to elevate."}]},
 {"id":"T1068","name":"Exploitation for Privilege Escalation","tactics":["TA0004"],"platforms":["Windows","Linux","macOS","Containers"],
  "summary":"Exploiting a software vulnerability to gain elevated privileges.",
  "detection":"Exploit mitigation telemetry, crashes, anomalous privileged processes.","mitigations":["Update Software (M1051)","Exploit Protection (M1050)","Threat Intelligence Program (M1019)"],"killchain":["exploitation"],"capec":["CAPEC-69"],"cwe":["CWE-269","CWE-416"],"subs":[]},
 {"id":"T1134","name":"Access Token Manipulation","tactics":["TA0004","TA0005"],"platforms":["Windows"],
  "summary":"Manipulating Windows access tokens to run under another user's security context.",
  "detection":"Token privilege use, impersonation events.","mitigations":["Privileged Account Management (M1026)","User Account Management (M1018)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1070","name":"Indicator Removal","tactics":["TA0005"],"platforms":["Windows","Linux","macOS","Network","Containers","Office 365"],
  "summary":"Deleting or altering logs and artifacts to hamper detection and response.",
  "detection":"Log clearing events (e.g., Event ID 1102), gaps in telemetry, file deletions.","mitigations":["Remote Data Storage (M1029)","Restrict File and Directory Permissions (M1022)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1070.001","name":"Clear Windows Event Logs","summary":"Wiping Windows event logs."},
      {"id":"T1070.004","name":"File Deletion","summary":"Deleting files to remove evidence."}]},
 {"id":"T1027","name":"Obfuscated Files or Information","tactics":["TA0005"],"platforms":["Windows","Linux","macOS"],
  "summary":"Encoding, encrypting or packing payloads to make analysis and detection harder.",
  "detection":"Entropy analysis, script deobfuscation, detonation.","mitigations":["Antivirus/Antimalware (M1049)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1562","name":"Impair Defenses","tactics":["TA0005"],"platforms":["Windows","Linux","macOS","IaaS","Containers","Network"],
  "summary":"Disabling or weakening security controls such as AV, EDR, logging and firewalls.",
  "detection":"Monitor for stopping of security services, config changes, driver loads.","mitigations":["Restrict Registry Permissions (M1024)","User Account Management (M1018)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1562.001","name":"Disable or Modify Tools","summary":"Turning off or tampering with security tooling."}]},
 {"id":"T1218","name":"System Binary Proxy Execution","tactics":["TA0005"],"platforms":["Windows"],
  "summary":"Using trusted signed system binaries (LOLBins) to proxy execution of malicious code.",
  "detection":"Command-line monitoring of rundll32, regsvr32, mshta, etc.","mitigations":["Execution Prevention (M1038)","Disable or Remove Feature or Program (M1042)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1218.011","name":"Rundll32","summary":"Abusing rundll32.exe to execute code."},
      {"id":"T1218.010","name":"Regsvr32","summary":"Abusing regsvr32.exe to execute code/scriptlets."}]},
 {"id":"T1003","name":"OS Credential Dumping","tactics":["TA0006"],"platforms":["Windows","Linux","macOS"],
  "summary":"Extracting account credentials from the operating system and memory.",
  "detection":"LSASS access monitoring, suspicious use of credential tools, SAM/registry access.","mitigations":["Credential Access Protection (M1043)","Privileged Account Management (M1026)","Password Policies (M1027)"],"killchain":["exploitation"],"capec":["CAPEC-644"],"cwe":["CWE-522"],"subs":[
      {"id":"T1003.001","name":"LSASS Memory","summary":"Dumping credentials from LSASS process memory."},
      {"id":"T1003.002","name":"Security Account Manager","summary":"Extracting hashes from the SAM database."},
      {"id":"T1003.003","name":"NTDS","summary":"Extracting the AD domain database (ntds.dit)."}]},
 {"id":"T1110","name":"Brute Force","tactics":["TA0006"],"platforms":["Windows","Linux","macOS","SaaS","IaaS","Network","Office 365","Azure AD","Google Workspace","Containers"],
  "summary":"Guessing credentials systematically, including spraying and stuffing.",
  "detection":"Failed-logon spikes, lockouts, spray patterns across accounts.","mitigations":["Account Use Policies (M1036)","Multi-factor Authentication (M1032)","Password Policies (M1027)"],"killchain":["exploitation"],"capec":["CAPEC-49","CAPEC-112"],"cwe":["CWE-307"],"subs":[
      {"id":"T1110.001","name":"Password Guessing","summary":"Trying likely passwords against accounts."},
      {"id":"T1110.003","name":"Password Spraying","summary":"Trying a few common passwords across many accounts."},
      {"id":"T1110.004","name":"Credential Stuffing","summary":"Replaying breached credential pairs."}]},
 {"id":"T1555","name":"Credentials from Password Stores","tactics":["TA0006"],"platforms":["Windows","Linux","macOS","IaaS"],
  "summary":"Harvesting credentials from browsers, keychains and password managers.",
  "detection":"Access to credential store files/APIs.","mitigations":["Password Policies (M1027)","Encrypt Sensitive Information (M1041)"],"killchain":["exploitation"],"capec":[],"cwe":["CWE-522"],"subs":[]},
 {"id":"T1056","name":"Input Capture","tactics":["TA0006","TA0009"],"platforms":["Windows","Linux","macOS","Network"],
  "summary":"Capturing user input such as keystrokes to steal credentials and data.",
  "detection":"Hooking API monitoring, suspicious drivers.","mitigations":["User Training (M1017)"],"killchain":["exploitation"],"capec":["CAPEC-569"],"cwe":[],"subs":[
      {"id":"T1056.001","name":"Keylogging","summary":"Recording keystrokes."}]},
 {"id":"T1082","name":"System Information Discovery","tactics":["TA0007"],"platforms":["Windows","Linux","macOS","IaaS","Network"],
  "summary":"Enumerating OS, hardware and configuration details of a host.",
  "detection":"Command-line auditing of discovery utilities.","mitigations":[],"killchain":["exploitation"],"capec":["CAPEC-312"],"cwe":[],"subs":[]},
 {"id":"T1083","name":"File and Directory Discovery","tactics":["TA0007"],"platforms":["Windows","Linux","macOS","Network"],
  "summary":"Browsing the file system to find files and directories of interest.",
  "detection":"Mass file enumeration patterns.","mitigations":[],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1018","name":"Remote System Discovery","tactics":["TA0007"],"platforms":["Windows","Linux","macOS","Network","IaaS"],
  "summary":"Identifying other hosts on the network by IP, hostname or other means.",
  "detection":"Scanning/enumeration from internal hosts.","mitigations":[],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1087","name":"Account Discovery","tactics":["TA0007"],"platforms":["Windows","Linux","macOS","SaaS","IaaS","Office 365","Azure AD","Google Workspace"],
  "summary":"Enumerating accounts (local, domain, cloud) to inform further actions.",
  "detection":"Directory queries, net/az/ldap enumeration.","mitigations":["Operating System Configuration (M1028)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1087.002","name":"Domain Account","summary":"Enumerating AD domain accounts."}]},
 {"id":"T1021","name":"Remote Services","tactics":["TA0008"],"platforms":["Windows","Linux","macOS","SaaS","IaaS"],
  "summary":"Using remote services (RDP, SMB, SSH, WinRM) with valid accounts to move laterally.",
  "detection":"Lateral logon patterns, new service-based sessions.","mitigations":["Multi-factor Authentication (M1032)","Network Segmentation (M1030)","Privileged Account Management (M1026)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1021.001","name":"Remote Desktop Protocol","summary":"Lateral movement via RDP."},
      {"id":"T1021.002","name":"SMB/Windows Admin Shares","summary":"Lateral movement via admin shares."},
      {"id":"T1021.004","name":"SSH","summary":"Lateral movement via SSH."},
      {"id":"T1021.006","name":"Windows Remote Management","summary":"Lateral movement via WinRM."}]},
 {"id":"T1570","name":"Lateral Tool Transfer","tactics":["TA0008"],"platforms":["Windows","Linux","macOS"],
  "summary":"Copying tools and payloads between systems inside the network.",
  "detection":"Internal file transfers over admin shares/SMB.","mitigations":["Network Intrusion Prevention (M1031)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1550","name":"Use Alternate Authentication Material","tactics":["TA0005","TA0008"],"platforms":["Windows","SaaS","IaaS","Office 365","Azure AD"],
  "summary":"Authenticating with stolen tokens, hashes or tickets instead of passwords.",
  "detection":"Anomalous ticket/token use, pass-the-hash patterns.","mitigations":["Privileged Account Management (M1026)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[
      {"id":"T1550.002","name":"Pass the Hash","summary":"Authenticating with a captured NTLM hash."},
      {"id":"T1550.003","name":"Pass the Ticket","summary":"Authenticating with a stolen Kerberos ticket."}]},
 {"id":"T1056b","name":"Data from Local System","tactics":["TA0009"],"platforms":["Windows","Linux","macOS","Network","IaaS"],
  "summary":"Collecting files and data of interest from the local host.","_realid":"T1005",
  "detection":"Mass file read/copy from sensitive locations.","mitigations":[],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1560","name":"Archive Collected Data","tactics":["TA0009"],"platforms":["Windows","Linux","macOS","IaaS"],
  "summary":"Compressing or encrypting gathered data to prepare it for exfiltration.",
  "detection":"Use of archiving utilities on staged data.","mitigations":["Audit (M1047)"],"killchain":["exploitation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1071","name":"Application Layer Protocol","tactics":["TA0011"],"platforms":["Windows","Linux","macOS","Network"],
  "summary":"Hiding C2 traffic inside common protocols like HTTP(S) and DNS.",
  "detection":"Protocol anomaly detection, beaconing analysis, TLS inspection.","mitigations":["Network Intrusion Prevention (M1031)","Filter Network Traffic (M1037)"],"killchain":["c2"],"capec":[],"cwe":[],"subs":[
      {"id":"T1071.001","name":"Web Protocols","summary":"C2 over HTTP/HTTPS."},
      {"id":"T1071.004","name":"DNS","summary":"C2 over DNS."}]},
 {"id":"T1573","name":"Encrypted Channel","tactics":["TA0011"],"platforms":["Windows","Linux","macOS","Network"],
  "summary":"Encrypting C2 communications to evade inspection.",
  "detection":"TLS metadata/JA3 analysis, unusual certificates.","mitigations":["Network Intrusion Prevention (M1031)"],"killchain":["c2"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1105","name":"Ingress Tool Transfer","tactics":["TA0011"],"platforms":["Windows","Linux","macOS","Network"],
  "summary":"Downloading additional tools and payloads into the environment from outside.",
  "detection":"Downloads to unusual processes, new binaries from the internet.","mitigations":["Network Intrusion Prevention (M1031)"],"killchain":["installation"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1041","name":"Exfiltration Over C2 Channel","tactics":["TA0010"],"platforms":["Windows","Linux","macOS"],
  "summary":"Stealing data back through the same channel used for command and control.",
  "detection":"Outbound volume anomalies on C2 sessions.","mitigations":["Filter Network Traffic (M1037)"],"killchain":["actions"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1567","name":"Exfiltration Over Web Service","tactics":["TA0010"],"platforms":["Windows","Linux","macOS"],
  "summary":"Sending stolen data to legitimate cloud/web services to blend in.",
  "detection":"Uploads to unusual cloud destinations.","mitigations":["Restrict Web-Based Content (M1021)"],"killchain":["actions"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1486","name":"Data Encrypted for Impact","tactics":["TA0040"],"platforms":["Windows","Linux","macOS","IaaS","Containers"],
  "summary":"Encrypting data to disrupt availability — the core of ransomware.",
  "detection":"Mass file modification/rename, shadow copy deletion, ransom notes.","mitigations":["Data Backup (M1053)","Behavior Prevention on Endpoint (M1040)"],"killchain":["actions"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1490","name":"Inhibit System Recovery","tactics":["TA0040"],"platforms":["Windows","Linux","macOS"],
  "summary":"Deleting backups and recovery options to maximise impact.",
  "detection":"vssadmin/wbadmin usage, backup catalog deletion.","mitigations":["Data Backup (M1053)"],"killchain":["actions"],"capec":[],"cwe":[],"subs":[]},
 {"id":"T1498","name":"Network Denial of Service","tactics":["TA0040"],"platforms":["Windows","Linux","macOS","IaaS","Network"],
  "summary":"Flooding networks or services to deny availability.",
  "detection":"Traffic volume anomalies, service degradation.","mitigations":["Filter Network Traffic (M1037)"],"killchain":["actions"],"capec":["CAPEC-125"],"cwe":["CWE-400"],"subs":[]},
]

# Fix synthetic id for Data from Local System
for _t in ATTACK_TECHNIQUES:
    if _t.get("_realid"):
        _t["id"] = _t.pop("_realid")

# ---------------------------------------------------------------------------
# ATT&CK ICS — all 12 tactics + core techniques
# ---------------------------------------------------------------------------
ICS_TACTICS = [
    {"id":"TA0108","name":"Initial Access","short":"Gaining entry into the ICS/OT environment."},
    {"id":"TA0104","name":"Execution","short":"Running adversary code on ICS systems."},
    {"id":"TA0110","name":"Persistence","short":"Maintaining presence in OT networks."},
    {"id":"TA0111","name":"Privilege Escalation","short":"Gaining higher privilege in ICS."},
    {"id":"TA0103","name":"Evasion","short":"Avoiding detection in OT."},
    {"id":"TA0102","name":"Discovery","short":"Learning the OT environment."},
    {"id":"TA0109","name":"Lateral Movement","short":"Moving across OT systems."},
    {"id":"TA0100","name":"Collection","short":"Gathering OT/process data."},
    {"id":"TA0101","name":"Command and Control","short":"Controlling ICS implants."},
    {"id":"TA0107","name":"Inhibit Response Function","short":"Preventing safety/protection functions from responding."},
    {"id":"TA0106","name":"Impair Process Control","short":"Manipulating the physical process."},
    {"id":"TA0105","name":"Impact","short":"Disrupting, damaging or endangering process and safety."},
]
ICS_TECHNIQUES = [
 {"id":"T0817","name":"Drive-by Compromise","tactics":["TA0108"],"platforms":["OT"],"summary":"Compromising OT users via malicious web content to gain access.","detection":"Web proxy/EDR on engineering workstations.","assets":["Engineering Workstation"],"subs":[]},
 {"id":"T0886","name":"Remote Services","tactics":["TA0108","TA0109"],"platforms":["OT"],"summary":"Using remote access services into the OT network.","detection":"Monitor remote logons to OT.","assets":["Engineering Workstation","Data Historian"],"subs":[]},
 {"id":"T0883","name":"Internet Accessible Device","tactics":["TA0108"],"platforms":["OT"],"summary":"Reaching ICS devices directly exposed to the internet.","detection":"External exposure scanning.","assets":["PLC","RTU"],"subs":[]},
 {"id":"T0807","name":"Command-Line Interface","tactics":["TA0104"],"platforms":["OT"],"summary":"Using device/host CLIs to issue commands in OT.","detection":"Command auditing on OT hosts.","assets":["Engineering Workstation"],"subs":[]},
 {"id":"T0889","name":"Modify Program","tactics":["TA0110","TA0106"],"platforms":["OT"],"summary":"Altering PLC/controller logic to change process behaviour.","detection":"Logic integrity monitoring, engineering change control.","assets":["PLC"],"subs":[]},
 {"id":"T0888","name":"Remote System Information Discovery","tactics":["TA0102"],"platforms":["OT"],"summary":"Enumerating OT device details and configuration.","detection":"Unusual protocol queries to devices.","assets":["PLC","RTU","HMI"],"subs":[]},
 {"id":"T0855","name":"Unauthorized Command Message","tactics":["TA0106"],"platforms":["OT"],"summary":"Sending illegitimate control messages to field devices.","detection":"Protocol-aware IDS for control commands.","assets":["PLC","RTU"],"subs":[]},
 {"id":"T0831","name":"Manipulation of Control","tactics":["TA0106"],"platforms":["OT"],"summary":"Changing control logic or setpoints to drive the process off-normal.","detection":"Process anomaly monitoring.","assets":["PLC","HMI"],"subs":[]},
 {"id":"T0814","name":"Denial of Service","tactics":["TA0107"],"platforms":["OT"],"summary":"Disrupting availability of OT devices or communications.","detection":"Comms loss and device watchdog alerts.","assets":["PLC","RTU","HMI"],"subs":[]},
 {"id":"T0826","name":"Loss of Availability","tactics":["TA0105"],"platforms":["OT"],"summary":"Rendering the process or system unavailable.","detection":"Operational monitoring.","assets":["Process"],"subs":[]},
 {"id":"T0880","name":"Loss of Safety","tactics":["TA0105"],"platforms":["OT"],"summary":"Defeating or degrading safety functions, endangering people/plant.","detection":"Safety system integrity monitoring.","assets":["Safety Instrumented System"],"subs":[]},
 {"id":"T0828","name":"Loss of Productivity and Revenue","tactics":["TA0105"],"platforms":["OT"],"summary":"Process disruption causing economic loss.","detection":"Operational/business monitoring.","assets":["Process"],"subs":[]},
]

# ---------------------------------------------------------------------------
# ATT&CK MOBILE — tactics + core techniques (curated)
# ---------------------------------------------------------------------------
MOBILE_TACTICS = [
    {"id":"TA0027","name":"Initial Access","short":"Getting onto a mobile device."},
    {"id":"TA0041","name":"Execution","short":"Running code on mobile."},
    {"id":"TA0028","name":"Persistence","short":"Staying on the device."},
    {"id":"TA0029","name":"Privilege Escalation","short":"Elevating on mobile."},
    {"id":"TA0030","name":"Defense Evasion","short":"Evading mobile defences."},
    {"id":"TA0031","name":"Credential Access","short":"Stealing mobile credentials."},
    {"id":"TA0032","name":"Discovery","short":"Learning the device/environment."},
    {"id":"TA0033","name":"Collection","short":"Gathering data from the device."},
    {"id":"TA0034","name":"Command and Control","short":"Controlling mobile implants."},
    {"id":"TA0035","name":"Exfiltration","short":"Stealing data off the device."},
    {"id":"TA0036","name":"Impact","short":"Disrupting the device/user."},
]
MOBILE_TECHNIQUES = [
 {"id":"T1456","name":"Drive-By Compromise","tactics":["TA0027"],"platforms":["Android","iOS"],"summary":"Compromising a device via malicious web content.","detection":"Mobile threat defence, web filtering.","subs":[]},
 {"id":"T1660","name":"Phishing","tactics":["TA0027"],"platforms":["Android","iOS"],"summary":"Luring mobile users via SMS, email or messaging to malicious content.","detection":"User reporting, message filtering.","subs":[]},
 {"id":"T1575","name":"Native API","tactics":["TA0041"],"platforms":["Android"],"summary":"Using native code APIs to execute on device.","detection":"App vetting.","subs":[]},
 {"id":"T1626","name":"Abuse Elevation Control Mechanism","tactics":["TA0029"],"platforms":["Android","iOS"],"summary":"Escalating privileges on the device.","detection":"Integrity attestation.","subs":[]},
 {"id":"T1655","name":"Masquerading","tactics":["TA0030"],"platforms":["Android","iOS"],"summary":"Disguising malicious apps as legitimate.","detection":"App vetting, signature checks.","subs":[]},
 {"id":"T1417","name":"Input Capture","tactics":["TA0031","TA0033"],"platforms":["Android","iOS"],"summary":"Capturing keystrokes/credentials via overlays or keyboards.","detection":"Accessibility-service abuse monitoring.","subs":[]},
 {"id":"T1430","name":"Location Tracking","tactics":["TA0032","TA0033"],"platforms":["Android","iOS"],"summary":"Tracking device location.","detection":"Permission monitoring.","subs":[]},
 {"id":"T1636","name":"Protected User Data","tactics":["TA0033"],"platforms":["Android","iOS"],"summary":"Accessing contacts, messages, call logs and other protected data.","detection":"Permission auditing.","subs":[]},
 {"id":"T1521","name":"Encrypted Channel","tactics":["TA0034"],"platforms":["Android","iOS"],"summary":"Encrypting C2 on mobile.","detection":"Network analysis.","subs":[]},
 {"id":"T1646","name":"Exfiltration Over C2 Channel","tactics":["TA0035"],"platforms":["Android","iOS"],"summary":"Exfiltrating data over the C2 channel.","detection":"Traffic analysis.","subs":[]},
]

# ---------------------------------------------------------------------------
# D3FEND — 7 tactics + curated countermeasures
# ---------------------------------------------------------------------------
D3FEND_TACTICS = [
    {"id":"model","name":"Model","short":"Understand and inventory the system and its attack surface."},
    {"id":"harden","name":"Harden","short":"Reduce the attack surface before an attack."},
    {"id":"detect","name":"Detect","short":"Identify adversary activity."},
    {"id":"isolate","name":"Isolate","short":"Create barriers that limit adversary movement."},
    {"id":"deceive","name":"Deceive","short":"Mislead the adversary."},
    {"id":"evict","name":"Evict","short":"Remove the adversary from the environment."},
    {"id":"restore","name":"Restore","short":"Return the system to a known-good state."},
]
# id, name, tactic, definition (my words), counters[] = ATT&CK ids, artifacts[]
D3FEND = [
 {"id":"D3-NTA","name":"Network Traffic Analysis","tactic":"detect","definition":"Analysing network flows and protocols to spot malicious communication.","counters":["T1071","T1573","T1041","T1105"],"artifacts":["Network Traffic"]},
 {"id":"D3-PM","name":"Platform Monitoring","tactic":"detect","definition":"Monitoring OS and platform telemetry for signs of compromise.","counters":["T1055","T1543","T1547"],"artifacts":["Operating System"]},
 {"id":"D3-PA","name":"Process Analysis","tactic":"detect","definition":"Examining process behaviour, lineage and memory for malice.","counters":["T1055","T1059","T1218"],"artifacts":["Process"]},
 {"id":"D3-FA","name":"File Analysis","tactic":"detect","definition":"Inspecting files statically/dynamically for malicious properties.","counters":["T1027","T1105","T1566"],"artifacts":["File"]},
 {"id":"D3-UBA","name":"User Behavior Analysis","tactic":"detect","definition":"Baselining user activity to detect anomalous or abused accounts.","counters":["T1078","T1110","T1021"],"artifacts":["User Account"]},
 {"id":"D3-MFA","name":"Multi-factor Authentication","tactic":"harden","definition":"Requiring multiple authentication factors to resist credential abuse.","counters":["T1078","T1110","T1133","T1021"],"artifacts":["Authentication"]},
 {"id":"D3-CH","name":"Credential Hardening","tactic":"harden","definition":"Strengthening how credentials are created, stored and protected.","counters":["T1003","T1110","T1555"],"artifacts":["Credential"]},
 {"id":"D3-ACH","name":"Application Configuration Hardening","tactic":"harden","definition":"Securing application settings to reduce exploitable surface.","counters":["T1190","T1203"],"artifacts":["Application"]},
 {"id":"D3-PH","name":"Platform Hardening","tactic":"harden","definition":"Applying secure OS/firmware configuration and patching.","counters":["T1068","T1190","T1547"],"artifacts":["Operating System"]},
 {"id":"D3-EAL","name":"Executable Allowlisting","tactic":"harden","definition":"Permitting only approved executables to run.","counters":["T1059","T1218","T1105"],"artifacts":["Executable"]},
 {"id":"D3-NI","name":"Network Isolation","tactic":"isolate","definition":"Segmenting networks to contain movement and reach.","counters":["T1021","T1190","T1570","T1498"],"artifacts":["Network"]},
 {"id":"D3-EI","name":"Execution Isolation","tactic":"isolate","definition":"Sandboxing or containerising execution to limit blast radius.","counters":["T1203","T1059"],"artifacts":["Process"]},
 {"id":"D3-DNSDL","name":"DNS Denylisting","tactic":"isolate","definition":"Blocking resolution of known-malicious domains.","counters":["T1071","T1105"],"artifacts":["Network Traffic"]},
 {"id":"D3-DP","name":"Decoy Platform","tactic":"deceive","definition":"Deploying decoy systems to attract and reveal adversaries.","counters":["T1018","T1021","T1595"],"artifacts":["Host"]},
 {"id":"D3-DUC","name":"Decoy User Credential","tactic":"deceive","definition":"Planting honey credentials that alert when used.","counters":["T1003","T1110","T1078"],"artifacts":["Credential"]},
 {"id":"D3-CR","name":"Credential Revoking","tactic":"evict","definition":"Invalidating compromised credentials and sessions.","counters":["T1078","T1550","T1003"],"artifacts":["Credential"]},
 {"id":"D3-PT","name":"Process Termination","tactic":"evict","definition":"Killing malicious processes to stop activity.","counters":["T1055","T1059","T1486"],"artifacts":["Process"]},
 {"id":"D3-RA","name":"Restore Access","tactic":"restore","definition":"Re-establishing legitimate access after eviction.","counters":["T1078","T1531"],"artifacts":["User Account"]},
 {"id":"D3-SR","name":"System Restore","tactic":"restore","definition":"Rebuilding systems/data from known-good backups.","counters":["T1486","T1490","T1561"],"artifacts":["Host"]},
 {"id":"D3-AI","name":"Asset Inventory","tactic":"model","definition":"Maintaining an inventory of assets and their attributes.","counters":["T1595","T1046"],"artifacts":["Asset"]},
 {"id":"D3-NM","name":"Network Mapping","tactic":"model","definition":"Mapping network topology and exposed services.","counters":["T1595","T1018"],"artifacts":["Network"]},
]

# ---------------------------------------------------------------------------
# CAPEC — curated attack patterns
# ---------------------------------------------------------------------------
# id, name, abstraction, summary, prerequisites, skills, mitigations, cwe[], attack[]
CAPEC = [
 {"id":"CAPEC-66","name":"SQL Injection","abstraction":"Standard","summary":"Injecting SQL through unsanitised input to manipulate database queries.","prerequisites":"Input reaches a SQL query without proper handling.","skills":"Low to Medium","mitigations":"Parameterised queries, input validation, least privilege DB accounts.","cwe":["CWE-89"],"attack":["T1190"]},
 {"id":"CAPEC-63","name":"Cross-Site Scripting (XSS)","abstraction":"Standard","summary":"Injecting script into web output executed in victims' browsers.","prerequisites":"Reflected/stored user input rendered without encoding.","skills":"Low to Medium","mitigations":"Output encoding, CSP, input validation.","cwe":["CWE-79"],"attack":["T1190","T1059"]},
 {"id":"CAPEC-100","name":"Overflow Buffers","abstraction":"Standard","summary":"Writing beyond buffer bounds to corrupt memory and alter execution.","prerequisites":"Unsafe memory handling in native code.","skills":"High","mitigations":"Safe functions, bounds checks, ASLR/DEP, memory-safe languages.","cwe":["CWE-120","CWE-787"],"attack":["T1203","T1068"]},
 {"id":"CAPEC-112","name":"Brute Force","abstraction":"Meta","summary":"Exhaustively trying values (e.g., credentials, keys) until success.","prerequisites":"Weak secrets and insufficient rate limiting.","skills":"Low","mitigations":"Lockouts, rate limiting, strong secrets, MFA.","cwe":["CWE-307"],"attack":["T1110"]},
 {"id":"CAPEC-98","name":"Phishing","abstraction":"Standard","summary":"Deceiving users into revealing information or taking harmful actions.","prerequisites":"Reachable users and plausible pretext.","skills":"Low","mitigations":"User training, email security, MFA.","cwe":["CWE-1021"],"attack":["T1566","T1598"]},
 {"id":"CAPEC-115","name":"Authentication Bypass","abstraction":"Meta","summary":"Reaching protected functionality without proper authentication.","prerequisites":"Flawed authentication logic or controls.","skills":"Medium","mitigations":"Robust auth checks, centralised enforcement.","cwe":["CWE-287","CWE-306"],"attack":["T1078"]},
 {"id":"CAPEC-49","name":"Password Brute Forcing","abstraction":"Detailed","summary":"Guessing passwords through systematic trials.","prerequisites":"Password auth without strong throttling.","skills":"Low","mitigations":"Lockout, MFA, strong policy.","cwe":["CWE-307","CWE-521"],"attack":["T1110"]},
 {"id":"CAPEC-242","name":"Code Injection","abstraction":"Meta","summary":"Injecting code that the target interprets and executes.","prerequisites":"Untrusted input reaches an interpreter.","skills":"Medium","mitigations":"Input validation, avoid dynamic eval, sandboxing.","cwe":["CWE-94"],"attack":["T1059"]},
 {"id":"CAPEC-248","name":"Command Injection","abstraction":"Meta","summary":"Injecting OS commands via input passed to a shell.","prerequisites":"Input concatenated into system commands.","skills":"Medium","mitigations":"Avoid shells, allowlist args, parameterise.","cwe":["CWE-78"],"attack":["T1059"]},
 {"id":"CAPEC-125","name":"Flooding","abstraction":"Meta","summary":"Overwhelming a resource to deny service.","prerequisites":"Resource without adequate capacity/limits.","skills":"Low","mitigations":"Rate limiting, filtering, scaling.","cwe":["CWE-400"],"attack":["T1498"]},
 {"id":"CAPEC-69","name":"Target Programs with Elevated Privileges","abstraction":"Standard","summary":"Abusing privileged programs to run attacker actions with high rights.","prerequisites":"Exploitable privileged software.","skills":"High","mitigations":"Least privilege, patching, sandboxing.","cwe":["CWE-250","CWE-269"],"attack":["T1068","T1548"]},
 {"id":"CAPEC-300","name":"Port Scanning","abstraction":"Detailed","summary":"Probing ports to discover reachable services.","prerequisites":"Network reachability.","skills":"Low","mitigations":"Firewalling, minimise exposure, monitoring.","cwe":[],"attack":["T1595"]},
 {"id":"CAPEC-560","name":"Use of Known Domain Credentials","abstraction":"Meta","summary":"Reusing valid credentials to authenticate.","prerequisites":"Obtained valid credentials.","skills":"Low","mitigations":"MFA, credential hygiene, monitoring.","cwe":["CWE-522"],"attack":["T1078"]},
 {"id":"CAPEC-644","name":"Use of Captured Hashes (Pass The Hash)","abstraction":"Detailed","summary":"Authenticating with stolen password hashes.","prerequisites":"Captured NTLM hashes and reachable services.","skills":"Medium","mitigations":"Credential Guard, segmentation, least privilege.","cwe":["CWE-522"],"attack":["T1550","T1003"]},
 {"id":"CAPEC-549","name":"Local Execution of Code","abstraction":"Standard","summary":"Getting code to run on a target via local vectors (e.g., malicious files).","prerequisites":"User interaction or local access.","skills":"Medium","mitigations":"Allowlisting, user training, sandboxing.","cwe":["CWE-94"],"attack":["T1203","T1204"]},
 {"id":"CAPEC-569","name":"Collect Data as Provided by Users","abstraction":"Standard","summary":"Capturing data users enter, e.g., via keylogging or overlays.","prerequisites":"Ability to observe input.","skills":"Medium","mitigations":"Endpoint protection, user awareness.","cwe":[],"attack":["T1056"]},
 {"id":"CAPEC-312","name":"Active OS Fingerprinting","abstraction":"Detailed","summary":"Probing a host to infer its operating system.","prerequisites":"Network reachability.","skills":"Low","mitigations":"Reduce exposure, normalise stacks.","cwe":[],"attack":["T1082"]},
 {"id":"CAPEC-593","name":"Session Hijacking","abstraction":"Standard","summary":"Taking over a valid session to impersonate a user.","prerequisites":"Obtainable session identifiers.","skills":"Medium","mitigations":"Secure cookies, TLS, rotation, binding.","cwe":["CWE-384"],"attack":["T1550"]},
 {"id":"CAPEC-21","name":"Exploitation of Trusted Identifiers","abstraction":"Standard","summary":"Abusing predictable or exposed identifiers/tokens to gain access.","prerequisites":"Weak identifier handling.","skills":"Medium","mitigations":"Unpredictable tokens, validation, expiry.","cwe":["CWE-290","CWE-384"],"attack":["T1550"]},
]

# ---------------------------------------------------------------------------
# CWE — Top-25-style + common weaknesses
# ---------------------------------------------------------------------------
# id, name, summary, consequences, mitigations, capec[], attack[]
CWE = [
 {"id":"CWE-79","name":"Improper Neutralization of Input During Web Page Generation (XSS)","summary":"Web output includes untrusted input without proper encoding, allowing script execution.","consequences":"Session theft, defacement, malware delivery.","mitigations":"Context-aware output encoding, CSP, validation.","capec":["CAPEC-63"],"attack":["T1190"]},
 {"id":"CWE-89","name":"Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)","summary":"Untrusted input alters SQL queries.","consequences":"Data disclosure, modification, auth bypass.","mitigations":"Parameterised queries, least privilege.","capec":["CAPEC-66"],"attack":["T1190"]},
 {"id":"CWE-78","name":"OS Command Injection","summary":"Untrusted input is used to build OS commands.","consequences":"Arbitrary command execution.","mitigations":"Avoid shell calls, allowlist, parameterise.","capec":["CAPEC-248"],"attack":["T1059"]},
 {"id":"CWE-20","name":"Improper Input Validation","summary":"Input is not validated for type, length, format or range.","consequences":"Varied — injection, crashes, logic abuse.","mitigations":"Strict validation, canonicalisation.","capec":[],"attack":[]},
 {"id":"CWE-287","name":"Improper Authentication","summary":"Authentication is not correctly enforced.","consequences":"Unauthorised access.","mitigations":"Robust, centralised auth; MFA.","capec":["CAPEC-115"],"attack":["T1078"]},
 {"id":"CWE-306","name":"Missing Authentication for Critical Function","summary":"A sensitive function lacks an authentication check.","consequences":"Unauthenticated privileged actions.","mitigations":"Enforce auth on all sensitive paths.","capec":["CAPEC-115"],"attack":["T1190"]},
 {"id":"CWE-862","name":"Missing Authorization","summary":"Access control checks are absent for a resource/action.","consequences":"Unauthorised data/actions.","mitigations":"Centralised authorization enforcement.","capec":[],"attack":[]},
 {"id":"CWE-269","name":"Improper Privilege Management","summary":"Privileges are assigned or managed incorrectly.","consequences":"Privilege escalation.","mitigations":"Least privilege, careful privilege transitions.","capec":["CAPEC-69"],"attack":["T1068","T1548"]},
 {"id":"CWE-250","name":"Execution with Unnecessary Privileges","summary":"Code runs with more privilege than needed.","consequences":"Greater impact when exploited.","mitigations":"Drop privileges, least privilege.","capec":["CAPEC-69"],"attack":["T1548"]},
 {"id":"CWE-416","name":"Use After Free","summary":"Memory is used after being freed.","consequences":"Crashes, code execution.","mitigations":"Safe allocators, memory-safe languages.","capec":["CAPEC-100"],"attack":["T1203"]},
 {"id":"CWE-787","name":"Out-of-bounds Write","summary":"Data is written outside buffer bounds.","consequences":"Corruption, code execution.","mitigations":"Bounds checks, safe languages, mitigations.","capec":["CAPEC-100"],"attack":["T1203"]},
 {"id":"CWE-125","name":"Out-of-bounds Read","summary":"Data is read outside buffer bounds.","consequences":"Info disclosure, crashes.","mitigations":"Bounds checks, safe languages.","capec":[],"attack":[]},
 {"id":"CWE-120","name":"Buffer Copy without Checking Size of Input (Classic Buffer Overflow)","summary":"Copying input without size checks overflows a buffer.","consequences":"Corruption, code execution.","mitigations":"Safe functions, bounds checks.","capec":["CAPEC-100"],"attack":["T1203"]},
 {"id":"CWE-22","name":"Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)","summary":"Input manipulates file paths to escape intended directories.","consequences":"Unauthorised file access.","mitigations":"Canonicalise and validate paths.","capec":["CAPEC-126"],"attack":[]},
 {"id":"CWE-352","name":"Cross-Site Request Forgery (CSRF)","summary":"Forged requests ride a user's authenticated session.","consequences":"Unauthorised state-changing actions.","mitigations":"Anti-CSRF tokens, SameSite cookies.","capec":["CAPEC-62"],"attack":[]},
 {"id":"CWE-434","name":"Unrestricted Upload of File with Dangerous Type","summary":"Dangerous file types can be uploaded and executed.","consequences":"Remote code execution.","mitigations":"Validate type, store safely, no execute.","capec":[],"attack":["T1190"]},
 {"id":"CWE-502","name":"Deserialization of Untrusted Data","summary":"Untrusted serialized data is deserialized unsafely.","consequences":"Code execution, logic abuse.","mitigations":"Avoid native deserialization, integrity checks.","capec":[],"attack":["T1190"]},
 {"id":"CWE-918","name":"Server-Side Request Forgery (SSRF)","summary":"Server is tricked into making attacker-chosen requests.","consequences":"Internal access, metadata theft.","mitigations":"Allowlist egress, validate URLs.","capec":[],"attack":["T1190"]},
 {"id":"CWE-522","name":"Insufficiently Protected Credentials","summary":"Credentials are stored/transmitted without adequate protection.","consequences":"Credential theft.","mitigations":"Hashing, encryption, secure storage.","capec":["CAPEC-560"],"attack":["T1003","T1555"]},
 {"id":"CWE-798","name":"Use of Hard-coded Credentials","summary":"Credentials are embedded in code/config.","consequences":"Trivial unauthorised access.","mitigations":"Secrets management, no hard-coding.","capec":[],"attack":["T1078"]},
 {"id":"CWE-307","name":"Improper Restriction of Excessive Authentication Attempts","summary":"No effective limit on auth attempts.","consequences":"Brute-force success.","mitigations":"Lockout, throttling, MFA.","capec":["CAPEC-112","CAPEC-49"],"attack":["T1110"]},
 {"id":"CWE-400","name":"Uncontrolled Resource Consumption","summary":"Resource use is not bounded.","consequences":"Denial of service.","mitigations":"Limits, quotas, backpressure.","capec":["CAPEC-125"],"attack":["T1498"]},
 {"id":"CWE-384","name":"Session Fixation","summary":"Session identifiers are not rotated after authentication.","consequences":"Session hijacking.","mitigations":"Rotate session IDs, secure cookies.","capec":["CAPEC-593"],"attack":["T1550"]},
 {"id":"CWE-77","name":"Command Injection","summary":"Untrusted input influences a command that is executed.","consequences":"Arbitrary command execution.","mitigations":"Parameterise, avoid interpreters.","capec":["CAPEC-248"],"attack":["T1059"]},
 {"id":"CWE-94","name":"Improper Control of Generation of Code (Code Injection)","summary":"Untrusted input is incorporated into code that is executed.","consequences":"Code execution.","mitigations":"Avoid eval, validate input, sandbox.","capec":["CAPEC-242"],"attack":["T1059"]},
 {"id":"CWE-732","name":"Incorrect Permission Assignment for Critical Resource","summary":"A critical resource is assigned permissions that allow unintended actors to read or modify it.","consequences":"Unauthorised access or modification.","mitigations":"Least-privilege permissions, review ACLs, secure defaults.","capec":[],"attack":[]},
 {"id":"CWE-1104","name":"Use of Unmaintained Third Party Components","summary":"Reliance on third-party components that are no longer maintained or patched.","consequences":"Exposure to known, unfixed vulnerabilities; supply-chain risk.","mitigations":"Inventory dependencies (SBOM), track EOL/maintenance, patch or replace.","capec":[],"attack":[]},
 {"id":"CWE-778","name":"Insufficient Logging","summary":"Security-relevant events are not logged (or logged with inadequate detail), hampering detection and response.","consequences":"Undetected attacks; impaired investigation.","mitigations":"Log auth, access-control and server-side failures; centralise and alert.","capec":[],"attack":[]},
 {"id":"CWE-755","name":"Improper Handling of Exceptional Conditions","summary":"Errors or exceptional states are not handled correctly, leading to insecure behaviour or information exposure.","consequences":"Crashes, inconsistent state, information disclosure.","mitigations":"Handle errors explicitly, fail securely, avoid leaking detail in messages.","capec":[],"attack":[]},
]

# ---------------------------------------------------------------------------
# CVE — landmark, NVD-referenced (not fabricated)
# ---------------------------------------------------------------------------
# id, desc (my words), severity, cvss, products, cwe[], attack[]
CVE = [
 {"id":"CVE-2021-44228","desc":"Log4Shell — remote code execution in Apache Log4j 2 via JNDI lookups in logged strings.","severity":"Critical","cvss":"10.0","products":["Apache Log4j 2"],"cwe":["CWE-502","CWE-20"],"attack":["T1190"]},
 {"id":"CVE-2017-0144","desc":"EternalBlue — SMBv1 remote code execution used by WannaCry and NotPetya.","severity":"Critical","cvss":"8.1","products":["Microsoft Windows SMBv1"],"cwe":["CWE-20"],"attack":["T1190","T1210"]},
 {"id":"CVE-2021-26855","desc":"ProxyLogon — SSRF in Microsoft Exchange enabling pre-auth access, chained to RCE.","severity":"Critical","cvss":"9.8","products":["Microsoft Exchange Server"],"cwe":["CWE-918"],"attack":["T1190"]},
 {"id":"CVE-2014-0160","desc":"Heartbleed — out-of-bounds read in OpenSSL TLS heartbeat leaking memory (keys, secrets).","severity":"High","cvss":"7.5","products":["OpenSSL"],"cwe":["CWE-125"],"attack":["T1190"]},
 {"id":"CVE-2014-6271","desc":"Shellshock — Bash processes trailing code in crafted environment variables, enabling RCE.","severity":"Critical","cvss":"9.8","products":["GNU Bash"],"cwe":["CWE-78"],"attack":["T1190","T1059"]},
 {"id":"CVE-2019-0708","desc":"BlueKeep — pre-auth RCE in Windows Remote Desktop Services, wormable.","severity":"Critical","cvss":"9.8","products":["Microsoft Windows RDP"],"cwe":["CWE-416"],"attack":["T1210"]},
 {"id":"CVE-2020-1472","desc":"Zerologon — cryptographic flaw in Netlogon allowing domain controller takeover.","severity":"Critical","cvss":"10.0","products":["Microsoft Windows Netlogon"],"cwe":["CWE-330"],"attack":["T1068","T1210"]},
 {"id":"CVE-2021-34527","desc":"PrintNightmare — RCE/LPE in Windows Print Spooler.","severity":"Critical","cvss":"8.8","products":["Microsoft Windows Print Spooler"],"cwe":["CWE-269"],"attack":["T1068"]},
 {"id":"CVE-2018-13379","desc":"Path traversal in Fortinet FortiOS SSL VPN allowing credential/file disclosure.","severity":"High","cvss":"9.8","products":["Fortinet FortiOS SSL VPN"],"cwe":["CWE-22"],"attack":["T1190","T1133"]},
 {"id":"CVE-2023-34362","desc":"SQL injection in Progress MOVEit Transfer exploited for mass data theft.","severity":"Critical","cvss":"9.8","products":["Progress MOVEit Transfer"],"cwe":["CWE-89"],"attack":["T1190"]},
 {"id":"CVE-2022-1388","desc":"Authentication bypass in F5 BIG-IP iControl REST enabling unauthenticated RCE.","severity":"Critical","cvss":"9.8","products":["F5 BIG-IP"],"cwe":["CWE-287"],"attack":["T1190"]},
 {"id":"CVE-2021-21972","desc":"Unauthenticated file upload/RCE in VMware vCenter vSphere Client plugin.","severity":"Critical","cvss":"9.8","products":["VMware vCenter Server"],"cwe":["CWE-434"],"attack":["T1190"]},
]

# ---------------------------------------------------------------------------
# CYBER KILL CHAIN
# ---------------------------------------------------------------------------
KILLCHAIN = [
 {"id":"recon","n":1,"name":"Reconnaissance","summary":"Researching and selecting targets; gathering information to plan the intrusion.",
  "objectives":["Identify targets and attack surface","Collect emails, names, technologies","Prioritise approach"],
  "behaviours":["OSINT","Scanning","Harvesting identities"],"attack":["T1595","T1592","T1589","T1598"],"capec":["CAPEC-300"],
  "defence":["Reduce external exposure","Monitor for scanning","Threat intel"],"detection":["Edge IDS","Exposure management"],
  "scenario":"Attacker enumerates a company's subdomains and employees before crafting phishing.","questions":["What is externally exposed?","What identities are discoverable?"]},
 {"id":"weaponization","n":2,"name":"Weaponization","summary":"Coupling an exploit or lure with a deliverable payload.",
  "objectives":["Build malware/exploit","Prepare infrastructure","Craft lures"],
  "behaviours":["Payload creation","Domain registration"],"attack":["T1587","T1583"],"capec":[],
  "defence":["Threat intel on infra/tooling","Harden clients"],"detection":["IOC feeds"],
  "scenario":"A malicious document is built to exploit an office client.","questions":["What payloads would bypass our controls?"]},
 {"id":"delivery","n":3,"name":"Delivery","summary":"Transmitting the weapon to the target (email, web, USB, remote service).",
  "objectives":["Reach the target","Induce interaction"],
  "behaviours":["Phishing","Drive-by","Abusing remote services"],"attack":["T1566","T1133","T1189"],"capec":["CAPEC-98"],
  "defence":["Email security","Web filtering","MFA on remote services"],"detection":["Gateway detonation","User reporting"],
  "scenario":"A spearphishing email delivers the lure to finance staff.","questions":["How do payloads reach users?"]},
 {"id":"exploitation","n":4,"name":"Exploitation","summary":"Triggering the exploit/code to gain execution on the target.",
  "objectives":["Execute code","Gain a foothold"],
  "behaviours":["Client exploitation","Public app exploitation","Script execution"],"attack":["T1203","T1190","T1059"],"capec":["CAPEC-66","CAPEC-100"],
  "defence":["Patch","Exploit protection","Sandboxing"],"detection":["EDR","Anomalous child processes"],
  "scenario":"Opening the document runs macro code that launches PowerShell.","questions":["Which exploit paths are viable?"]},
 {"id":"installation","n":5,"name":"Installation","summary":"Installing persistence so access survives reboots and credential changes.",
  "objectives":["Persist","Stage tooling"],
  "behaviours":["Services","Scheduled tasks","Autostart"],"attack":["T1053","T1543","T1547","T1105"],"capec":[],
  "defence":["Least privilege","Monitor autostart","Allowlisting"],"detection":["Service/task creation events"],
  "scenario":"A scheduled task is created to re-launch the implant.","questions":["Where could persistence hide?"]},
 {"id":"c2","n":6,"name":"Command and Control","summary":"Establishing a channel to control compromised systems.",
  "objectives":["Remote control","Tasking"],
  "behaviours":["HTTP/DNS C2","Encrypted channels"],"attack":["T1071","T1573"],"capec":[],
  "defence":["Egress filtering","DNS controls","TLS inspection"],"detection":["Beaconing analysis","Protocol anomalies"],
  "scenario":"The implant beacons to an attacker domain over HTTPS.","questions":["How would C2 blend into our traffic?"]},
 {"id":"actions","n":7,"name":"Actions on Objectives","summary":"Achieving the goal — data theft, destruction, or disruption.",
  "objectives":["Collect and exfiltrate","Impact operations"],
  "behaviours":["Collection","Exfiltration","Encryption for impact"],"attack":["T1005","T1041","T1486","T1490"],"capec":["CAPEC-125"],
  "defence":["DLP","Backups","Segmentation"],"detection":["Exfil volume anomalies","Mass encryption"],
  "scenario":"Data is archived and exfiltrated, then systems are ransomed.","questions":["What is our crown-jewel data and its egress paths?"]},
]

# ---------------------------------------------------------------------------
# PTES phases
# ---------------------------------------------------------------------------
PTES = [
 {"id":"pre","name":"Pre-engagement Interactions","summary":"Agreeing scope, rules of engagement, objectives, timelines and authorisation.",
  "steps":["Define scope and targets","Set rules of engagement","Obtain written authorisation","Agree communication and escalation"],
  "checklist":["Signed authorisation in place","Scope boundaries documented","Emergency contacts agreed","Testing windows set"],"attack":[]},
 {"id":"intel","name":"Intelligence Gathering","summary":"Collecting information about the target through OSINT and enumeration.",
  "steps":["Passive OSINT","Active enumeration","Attack surface mapping"],
  "checklist":["External footprint mapped","Technologies identified","Identities enumerated"],"attack":["T1595","T1592","T1589"]},
 {"id":"threat","name":"Threat Modeling","summary":"Identifying likely threats, assets and attack paths to prioritise testing.",
  "steps":["Identify assets","Model threat actors","Prioritise attack paths"],
  "checklist":["Crown jewels identified","Relevant actors profiled","Paths prioritised"],"attack":[]},
 {"id":"vuln","name":"Vulnerability Analysis","summary":"Finding and validating weaknesses across the attack surface.",
  "steps":["Scan","Manual verification","False-positive triage"],
  "checklist":["Findings validated","CVE/CWE correlated","Risk rated"],"attack":["T1595","T1190"]},
 {"id":"exploit","name":"Exploitation","summary":"Safely proving impact by exploiting validated weaknesses within scope.",
  "steps":["Select vectors","Controlled exploitation","Capture evidence"],
  "checklist":["Scope respected","PoC captured","Impact demonstrated safely"],"attack":["T1190","T1203","T1059"]},
 {"id":"post","name":"Post-Exploitation","summary":"Assessing the value of access — escalation, movement, data reach — within rules.",
  "steps":["Privilege escalation assessment","Lateral movement assessment","Data access assessment"],
  "checklist":["Reach documented","Sensitive access shown","No unauthorised damage"],"attack":["T1068","T1021","T1003","T1005"]},
 {"id":"report","name":"Reporting","summary":"Communicating findings, risk and remediation to stakeholders.",
  "steps":["Executive summary","Technical detail","Remediation and retest"],
  "checklist":["Risks prioritised","Evidence attached","Remediation actionable"],"attack":[]},
]

# ---------------------------------------------------------------------------
# OWASP WSTG categories (with representative test IDs)
# ---------------------------------------------------------------------------
WSTG = [
 {"id":"WSTG-INFO","name":"Information Gathering","summary":"Fingerprinting the app, server, and surface before testing.","tests":["WSTG-INFO-02 Fingerprint Web Server","WSTG-INFO-08 Fingerprint Web App Framework","WSTG-INFO-10 Map Application Architecture"]},
 {"id":"WSTG-CONF","name":"Configuration & Deployment Management","summary":"Reviewing platform/config, files, HTTP methods and TLS.","tests":["WSTG-CONF-01 Network/Infra Config","WSTG-CONF-02 App Platform Config","WSTG-CONF-07 TLS"]},
 {"id":"WSTG-IDNT","name":"Identity Management","summary":"Testing roles, registration and account provisioning.","tests":["WSTG-IDNT-02 User Registration","WSTG-IDNT-04 Account Enumeration"]},
 {"id":"WSTG-ATHN","name":"Authentication","summary":"Testing login, lockout, password and credential handling.","tests":["WSTG-ATHN-03 Lockout Mechanism","WSTG-ATHN-07 Weak Password Policy"]},
 {"id":"WSTG-ATHZ","name":"Authorization","summary":"Testing access control, privilege, IDOR and path traversal.","tests":["WSTG-ATHZ-02 Bypassing Authorization","WSTG-ATHZ-04 IDOR"]},
 {"id":"WSTG-SESS","name":"Session Management","summary":"Testing cookies, fixation, CSRF and session lifecycle.","tests":["WSTG-SESS-03 Session Fixation","WSTG-SESS-05 CSRF"]},
 {"id":"WSTG-INPV","name":"Input Validation","summary":"Testing injection, XSS and related input flaws.","tests":["WSTG-INPV-05 SQL Injection","WSTG-INPV-01 Reflected XSS","WSTG-INPV-12 Command Injection"]},
 {"id":"WSTG-ERRH","name":"Error Handling","summary":"Reviewing error messages and stack traces for leakage.","tests":["WSTG-ERRH-01 Improper Error Handling"]},
 {"id":"WSTG-CRYP","name":"Cryptography","summary":"Testing TLS, weak crypto and sensitive data protection.","tests":["WSTG-CRYP-01 Weak Transport Encryption","WSTG-CRYP-04 Weak Encryption"]},
 {"id":"WSTG-BUSL","name":"Business Logic","summary":"Testing logic flaws, workflow and abuse cases.","tests":["WSTG-BUSL-01 Business Logic Data Validation","WSTG-BUSL-07 Circumvention of Workflows"]},
 {"id":"WSTG-CLNT","name":"Client-Side","summary":"Testing DOM XSS, client storage and postMessage.","tests":["WSTG-CLNT-01 DOM XSS","WSTG-CLNT-12 Web Storage"]},
 {"id":"WSTG-APIT","name":"API Testing","summary":"Testing API-specific weaknesses and abuse.","tests":["WSTG-APIT-01 API Reconnaissance"]},
]

# OWASP Top 10:2025 (released Nov 2025). Two new categories vs 2021:
# A03 Software Supply Chain Failures (expands 'Vulnerable and Outdated Components')
# and A10 Mishandling of Exceptional Conditions. SSRF folded into A01 Broken Access Control.
OWASP_TOP10 = [
 {"id":"A01:2025","name":"Broken Access Control","summary":"Users act outside their intended permissions; in 2025 this category also absorbs Server-Side Request Forgery (SSRF).","cwe":["CWE-862","CWE-22","CWE-918","CWE-732"]},
 {"id":"A02:2025","name":"Security Misconfiguration","summary":"Insecure defaults, incomplete or ad-hoc configuration, excessive permissions and verbose errors.","cwe":["CWE-732","CWE-798"]},
 {"id":"A03:2025","name":"Software Supply Chain Failures","summary":"Risk from vulnerable or compromised dependencies, build systems and distribution pipelines (new; expands 2021 'Vulnerable and Outdated Components').","cwe":["CWE-1104","CWE-502"]},
 {"id":"A04:2025","name":"Cryptographic Failures","summary":"Weak or missing protection of sensitive data in transit and at rest.","cwe":["CWE-522"]},
 {"id":"A05:2025","name":"Injection","summary":"Untrusted input interpreted as code/queries (SQLi, XSS, command injection).","cwe":["CWE-89","CWE-79","CWE-78"]},
 {"id":"A06:2025","name":"Insecure Design","summary":"Missing or ineffective security controls at the design level.","cwe":["CWE-20"]},
 {"id":"A07:2025","name":"Authentication Failures","summary":"Weaknesses in authentication and session management (renamed from 'Identification and Authentication Failures').","cwe":["CWE-287","CWE-307","CWE-384","CWE-798"]},
 {"id":"A08:2025","name":"Software and Data Integrity Failures","summary":"Trusting unverified code or data; insecure deserialization.","cwe":["CWE-502"]},
 {"id":"A09:2025","name":"Logging & Alerting Failures","summary":"Insufficient logging, detection and alerting that hampers response (renamed from 'Security Logging and Monitoring Failures').","cwe":["CWE-778"]},
 {"id":"A10:2025","name":"Mishandling of Exceptional Conditions","summary":"Improper handling of errors and exceptional states leading to insecure behaviour (new in 2025).","cwe":["CWE-755"]},
]

NIST_CSF = [
 {"id":"GV","name":"Govern","summary":"Establish and monitor cybersecurity risk governance and strategy."},
 {"id":"ID","name":"Identify","summary":"Understand assets, risks and context."},
 {"id":"PR","name":"Protect","summary":"Implement safeguards to limit impact."},
 {"id":"DE","name":"Detect","summary":"Identify occurrence of events."},
 {"id":"RS","name":"Respond","summary":"Take action on detected incidents."},
 {"id":"RC","name":"Recover","summary":"Restore capabilities and services."},
]
NIST_800115 = [
 {"id":"planning","name":"Planning","summary":"Define scope, rules, logistics and objectives of the assessment."},
 {"id":"discovery","name":"Discovery","summary":"Gather information and identify vulnerabilities."},
 {"id":"attack","name":"Attack","summary":"Verify vulnerabilities by attempting exploitation within scope."},
 {"id":"reporting","name":"Reporting","summary":"Document findings, risk and remediation guidance."},
]

# ---------------------------------------------------------------------------
# PENTEST LEARNING HUB
# ---------------------------------------------------------------------------
LEARNING = [
 {"phase":"Phase 1 — Fundamentals","topics":[
   {"name":"Security & Networking Fundamentals","objectives":["Understand CIA triad and defence-in-depth","Know TCP/IP, DNS, HTTP basics"],"methodology":["Study core models","Lab networking basics"],"frameworks":["NIST CSF"],"checklist":["Explain CIA triad","Trace a DNS + HTTP request"],"quiz":[{"q":"Which triad property is attacked by ransomware encryption?","a":["Confidentiality","Integrity","Availability","Non-repudiation"],"c":2}]},
   {"name":"Threat Modeling & Attack Surface","objectives":["Model threats (e.g., STRIDE)","Enumerate attack surface"],"methodology":["Identify assets","Enumerate entry points","Prioritise"],"frameworks":["ATT&CK","CAPEC"],"checklist":["Produce a threat model","List external surface"],"quiz":[{"q":"STRIDE's 'E' stands for?","a":["Encryption","Elevation of Privilege","Enumeration","Exfiltration"],"c":1}]},
 ]},
 {"phase":"Phase 2 — Reconnaissance","topics":[
   {"name":"Passive & Active Recon","objectives":["Perform OSINT safely","Enumerate services"],"methodology":["Passive OSINT","DNS enumeration","Service enumeration"],"frameworks":["ATT&CK","PTES"],"checklist":["Map external footprint","Identify technologies"],"quiz":[{"q":"Which is passive recon?","a":["Port scanning","WHOIS lookup","Vuln scanning","Exploitation","c"],"c":1}]},
 ]},
 {"phase":"Phase 3 — Vulnerability Analysis","topics":[
   {"name":"Finding & Validating Vulnerabilities","objectives":["Scan and validate","Correlate CVE/CWE","Handle false positives"],"methodology":["Automated scan","Manual verification","Risk rating"],"frameworks":["CVE","CWE","PTES"],"checklist":["Validate each finding","Correlate to CWE/CVE"],"quiz":[{"q":"A scanner flag with no proof is best treated as?","a":["Confirmed","False positive until validated","Critical","Ignored"],"c":1}]},
 ]},
 {"phase":"Phase 4 — Initial Access & Exploitation","topics":[
   {"name":"Web & Network Exploitation","objectives":["Exploit validated issues safely","Capture evidence"],"methodology":["Select vector","Controlled exploit","Evidence"],"frameworks":["ATT&CK","OWASP WSTG"],"checklist":["Stay in scope","Capture PoC"],"quiz":[{"q":"Primary defence against SQL injection?","a":["WAF only","Parameterised queries","Obfuscation","Rate limiting"],"c":1}]},
 ]},
 {"phase":"Phase 5 — Post-Exploitation","topics":[
   {"name":"Escalation, Movement & Impact","objectives":["Assess privilege escalation","Assess lateral movement","Assess data reach"],"methodology":["Local enumeration","Credential assessment","Movement assessment"],"frameworks":["ATT&CK"],"checklist":["Document reach","No unauthorised damage"],"quiz":[{"q":"Pass-the-Hash abuses which?","a":["Kerberos tickets","NTLM hashes","TLS certs","OAuth tokens"],"c":1}]},
 ]},
 {"phase":"Phase 6 — Reporting","topics":[
   {"name":"Communicating Risk","objectives":["Write executive + technical findings","Prioritise remediation"],"methodology":["Executive summary","Technical detail","Remediation + retest"],"frameworks":["PTES","NIST 800-115"],"checklist":["Risk-rated findings","Actionable remediation"],"quiz":[{"q":"Executive summary should focus on?","a":["Exploit code","Business risk","Tool output","Payloads"],"c":1}]},
 ]},
 {"phase":"Phase 7 — Advanced Methodologies","topics":[
   {"name":"AD, Cloud, API & Red/Purple Teaming","objectives":["Understand AD attack paths","Grasp cloud/API testing","Know red vs purple"],"methodology":["AD assessment","Cloud assessment","Purple exercises"],"frameworks":["ATT&CK","D3FEND"],"checklist":["Map AD paths","Align detections (purple)"],"quiz":[{"q":"Purple teaming primarily improves?","a":["Only offence","Only compliance","Detection & response via collaboration","Marketing"],"c":2}]},
 ]},
]

SCENARIO_TEMPLATES = {
 "environments":["Enterprise Windows/AD","Web Application","Cloud (IaaS/SaaS)","OT/ICS","Mobile Fleet"],
 "actors":["Opportunistic criminal","Ransomware affiliate","Organised crime","Nation-state","Insider"],
 "objectives":["Data theft","Ransomware impact","Espionage","Fraud","Disruption"],
 "access":["Phishing","Exploit public app","Valid accounts","External remote services","Supply chain"],
}

# ---------------------------------------------------------------------------
# DETECTION ENGINEERING — real, standard telemetry references + curated per-technique
# All content is curated educational guidance, labelled; it references REAL
# Windows Event IDs / Sysmon event IDs / Linux audit sources, not invented rules.
# ---------------------------------------------------------------------------
TELREF = [
 {"id":"4688","src":"Windows Security","name":"Process Creation","use":"Command-line / parent-child process auditing (requires audit policy + cmdline logging)."},
 {"id":"4624","src":"Windows Security","name":"Successful Logon","use":"Logon type (2 interactive, 3 network, 10 RDP), source, account."},
 {"id":"4625","src":"Windows Security","name":"Failed Logon","use":"Brute force / spray detection via failure spikes."},
 {"id":"4648","src":"Windows Security","name":"Explicit Credential Logon","use":"runas / lateral movement with alternate creds."},
 {"id":"4672","src":"Windows Security","name":"Special Privileges Assigned","use":"Privileged logon sessions."},
 {"id":"4697","src":"Windows Security","name":"Service Installed","use":"New service persistence (also System log 7045)."},
 {"id":"4698","src":"Windows Security","name":"Scheduled Task Created","use":"Task-based persistence/execution."},
 {"id":"4720","src":"Windows Security","name":"User Account Created","use":"Rogue account creation."},
 {"id":"1102","src":"Windows Security","name":"Audit Log Cleared","use":"Indicator removal / anti-forensics."},
 {"id":"4104","src":"Windows PowerShell","name":"Script Block Logging","use":"Deobfuscated PowerShell content."},
 {"id":"4103","src":"Windows PowerShell","name":"Module Logging","use":"Pipeline/module execution detail."},
 {"id":"4768","src":"Windows Security","name":"Kerberos TGT Requested","use":"AS-REP / auth baseline."},
 {"id":"4769","src":"Windows Security","name":"Kerberos Service Ticket","use":"Kerberoasting (RC4, many TGS)."},
 {"id":"4662","src":"Windows Security","name":"Directory Service Access","use":"DCSync-style replication access."},
 {"id":"5140","src":"Windows Security","name":"Network Share Accessed","use":"Admin share / SMB lateral movement."},
 {"id":"Sysmon-1","src":"Sysmon","name":"Process Create","use":"Full cmdline, hashes, parent image."},
 {"id":"Sysmon-3","src":"Sysmon","name":"Network Connection","use":"Process→destination, ports (C2, lateral)."},
 {"id":"Sysmon-7","src":"Sysmon","name":"Image Loaded","use":"Suspicious / unsigned DLL loads."},
 {"id":"Sysmon-8","src":"Sysmon","name":"CreateRemoteThread","use":"Process injection."},
 {"id":"Sysmon-10","src":"Sysmon","name":"Process Access","use":"Handle to LSASS / credential dumping (GrantedAccess)."},
 {"id":"Sysmon-11","src":"Sysmon","name":"File Create","use":"Dropped payloads, mass file writes (ransomware)."},
 {"id":"Sysmon-12/13","src":"Sysmon","name":"Registry Add/Set","use":"Run-key & autostart persistence."},
 {"id":"Sysmon-22","src":"Sysmon","name":"DNS Query","use":"DNS C2 / tunnelling."},
 {"id":"auditd-execve","src":"Linux auditd","name":"execve","use":"Command execution auditing."},
 {"id":"auditd-connect","src":"Linux auditd","name":"connect","use":"Outbound connections."},
 {"id":"authlog","src":"Linux /var/log/auth.log","name":"Auth / sudo / SSH","use":"Logon, sudo, SSH session events."},
 {"id":"netflow","src":"Network","name":"NetFlow / Zeek","use":"Beaconing, volume anomalies, lateral flows."},
 {"id":"proxy","src":"Network","name":"Web Proxy / TLS","use":"Downloads, exfil, JA3/SNI anomalies."},
]
# Per-technique curated detection. conf: Curated (educational; validate before use).
DET = {
 "T1003.001":{"conf":"Curated","hypotheses":["A non-security process obtained a handle to lsass.exe with memory-read access.","Known dumping tooling or MiniDumpWriteDump behaviour observed."],
   "windows":["4688 (suspicious process spawning before dump)"],"sysmon":["Sysmon EID 10 ProcessAccess → TargetImage lsass.exe, GrantedAccess 0x1010/0x1410/0x143a","Sysmon EID 11 .dmp file creation"],"linux":[],"network":[],
   "logic":"detection:\n  target_image|endswith: '\\\\lsass.exe'\n  granted_access: ['0x1010','0x1410','0x143a']\n  filter_known_edr: true\ncondition: selection and not filter_known_edr","fp":["EDR/AV and some backup agents legitimately read LSASS.","Windows Error Reporting (WerFault) crash dumps."],
   "investigation":["Identify the SourceImage and its signer/hash.","Check for a corresponding .dmp file create.","Correlate with recent logon / privilege events on the host."]},
 "T1059.001":{"conf":"Curated","hypotheses":["Encoded or obfuscated PowerShell executed.","PowerShell spawned by Office/browser or with network egress."],
   "windows":["4104 Script Block Logging (deobfuscated content)","4103 Module Logging"],"sysmon":["Sysmon EID 1 powershell.exe with -enc / -w hidden / IEX","Sysmon EID 3 powershell.exe → external IP"],"linux":[],"network":["proxy: powershell UA / download cradles"],
   "logic":"selection:\n  image|endswith: '\\\\powershell.exe'\n  command_line|contains: ['-enc','FromBase64String','IEX','DownloadString']\ncondition: selection","fp":["Legitimate admin / deployment scripts.","Monitoring agents using PowerShell."],
   "investigation":["Decode EncodedCommand from 4104.","Review parent process (Office macro?).","Check outbound connections from the PowerShell PID."]},
 "T1053.005":{"conf":"Curated","hypotheses":["A scheduled task was created to run a non-standard binary or script.","Task registered by an unexpected user/process."],
   "windows":["4698 Scheduled Task Created (XML action)","4688 schtasks.exe / at.exe"],"sysmon":["Sysmon EID 1 schtasks.exe create","Sysmon EID 11 under C:\\\\Windows\\\\System32\\\\Tasks"],"linux":[],"network":[],
   "logic":"selection:\n  image|endswith: '\\\\schtasks.exe'\n  command_line|contains: '/create'\ncondition: selection","fp":["Software installers and legitimate admin automation."],
   "investigation":["Inspect the task action (binary/script path & args).","Attribute the creating account.","Check if the action path is user-writable or unusual."]},
 "T1021.001":{"conf":"Curated","hypotheses":["Interactive RDP logon from an unusual source or to many hosts.","RDP to servers that normally receive none."],
   "windows":["4624 LogonType 10 (RemoteInteractive)","4778/4779 session connect/disconnect"],"sysmon":["Sysmon EID 3 destination port 3389"],"linux":[],"network":["netflow: 3389 flows"],
   "logic":"selection:\n  event_id: 4624\n  logon_type: 10\ncondition: selection and unusual_source","fp":["Legitimate remote administration and jump hosts."],
   "investigation":["Map source→destination pairs and baseline them.","Check account role vs. target.","Correlate with preceding credential access."]},
 "T1021.002":{"conf":"Curated","hypotheses":["Access to ADMIN$/C$ shares from a workstation.","Service or tool copied over SMB then executed."],
   "windows":["5140/5145 share access to ADMIN$/C$","4624 LogonType 3","7045 service install (PsExec-style)"],"sysmon":["Sysmon EID 11 writes to \\\\\\\\host\\\\ADMIN$"],"linux":[],"network":["netflow: 445 lateral flows"],
   "logic":"selection:\n  share_name: ['\\\\\\\\*\\\\ADMIN$','\\\\\\\\*\\\\C$']\ncondition: selection and source_is_workstation","fp":["Backup agents, SCCM, legitimate admin."],
   "investigation":["Identify the source host/account.","Look for a service install or remote execution after access.","Baseline which hosts legitimately use admin shares."]},
 "T1547.001":{"conf":"Curated","hypotheses":["A Run/RunOnce key or Startup folder entry points to a non-standard path."],
   "windows":["4657 registry value modified (if audited)"],"sysmon":["Sysmon EID 12/13 on ...\\\\CurrentVersion\\\\Run","Sysmon EID 11 in Startup folder"],"linux":[],"network":[],
   "logic":"selection:\n  target_object|contains: '\\\\CurrentVersion\\\\Run'\n  details|contains: ['\\\\Users\\\\','\\\\Temp\\\\','.vbs','.ps1']\ncondition: selection","fp":["Legitimate software registering autostart."],
   "investigation":["Resolve the referenced binary/script and verify signer.","Check creation time vs. software installs."]},
 "T1055":{"conf":"Curated","hypotheses":["A process created a remote thread in another process.","Unsigned image loaded into a sensitive process."],
   "windows":[],"sysmon":["Sysmon EID 8 CreateRemoteThread","Sysmon EID 10 ProcessAccess (VM_WRITE)","Sysmon EID 7 unsigned image load"],"linux":["auditd ptrace syscalls"],"network":[],
   "logic":"selection:\n  event_id: 8\n  source_image != target_image\ncondition: selection and not known_injectors","fp":["Some AV/EDR and legitimate software inject."],
   "investigation":["Identify source and target images.","Check the started-thread start address / module.","Correlate with earlier delivery/execution."]},
 "T1110":{"conf":"Curated","hypotheses":["A spike of failed logons against one or many accounts (spray vs. guess).","Lockout events across the estate."],
   "windows":["4625 Failed Logon (cluster by source/account)","4740 Account Lockout"],"sysmon":[],"linux":["authlog: repeated sshd auth failures"],"network":["netflow: many short auth sessions"],
   "logic":"selection:\n  event_id: 4625\ncondition: count(selection) by source > threshold within 10m","fp":["Misconfigured apps/service accounts with stale creds.","Password-change churn."],
   "investigation":["Distinguish spray (many accounts, few tries) from brute force (one account).","Identify source IP/host.","Check for a subsequent successful 4624."]},
 "T1486":{"conf":"Curated","hypotheses":["Mass file modification with a new/consistent extension.","Shadow copies deleted around the same time."],
   "windows":["4688 vssadmin.exe delete shadows","4663 bulk file writes (if audited)"],"sysmon":["Sysmon EID 11 high-rate file creates with new extension","Sysmon EID 1 vssadmin/wbadmin/bcdedit"],"linux":["auditd rapid open/rename"],"network":[],
   "logic":"selection_vss:\n  command_line|contains: ['vssadmin delete shadows','wbadmin delete']\nselection_mass: file_create_rate > threshold\ncondition: selection_vss or selection_mass","fp":["Legitimate backup/encryption software (baseline it)."],
   "investigation":["Identify the encrypting process and its origin.","Isolate host; preserve a sample and ransom note.","Check for prior exfiltration (double extortion)."]},
 "T1070.001":{"conf":"Curated","hypotheses":["Security event log cleared outside maintenance windows."],
   "windows":["1102 Audit Log Cleared","104 (System log cleared)"],"sysmon":["Sysmon EID 1 wevtutil cl / Clear-EventLog"],"linux":["auditd: truncation of /var/log, 'history -c'"],"network":[],
   "logic":"selection:\n  event_id: [1102,104]\ncondition: selection and not maintenance_window","fp":["Rare legitimate administrative log rotation."],
   "investigation":["Treat as high-signal; identify the account/process.","Pivot to other telemetry (EDR, network) given local logs are gone."]},
 "T1078":{"conf":"Curated","hypotheses":["Valid account used from an anomalous location/time/device.","Dormant account suddenly active."],
   "windows":["4624 anomalous source/time","4672 unexpected privilege"],"sysmon":[],"linux":["authlog anomalies"],"network":["proxy/VPN impossible-travel"],
   "logic":"selection:\n  event_id: 4624\ncondition: selection and (new_geo or dormant_account or new_asn)","fp":["Travel, VPN, new devices (tune with UEBA)."],
   "investigation":["Baseline the account's normal access.","Confirm with the user/owner.","Check for creation of persistence after logon."]},
 "T1566":{"conf":"Curated","hypotheses":["User received/opened an attachment or link leading to child-process execution."],
   "windows":["4688 Office app spawning script hosts"],"sysmon":["Sysmon EID 1 winword/excel → powershell/cmd/wscript","Sysmon EID 11 attachment written to Temp"],"linux":[],"network":["proxy: click-through to newly-registered domain"],
   "logic":"selection:\n  parent_image|endswith: ['\\\\winword.exe','\\\\excel.exe','\\\\outlook.exe']\n  image|endswith: ['\\\\powershell.exe','\\\\cmd.exe','\\\\wscript.exe']\ncondition: selection","fp":["Legitimate document macros in some orgs (baseline)."],
   "investigation":["Pull the original email and attachment/URL.","Detonate safely; identify payload and C2.","Scope other recipients."]},
 "T1190":{"conf":"Curated","hypotheses":["Public-facing app process spawned a shell or wrote a webshell.","Anomalous requests preceding new child processes."],
   "windows":["4688 w3wp.exe/httpd spawning cmd/powershell"],"sysmon":["Sysmon EID 1 web service → shell","Sysmon EID 11 webshell written to web root"],"linux":["auditd: httpd/nginx → /bin/sh","file create in web root"],"network":["WAF alerts, anomalous POSTs"],
   "logic":"selection:\n  parent_image|endswith: ['\\\\w3wp.exe','\\\\httpd','\\\\nginx']\n  image|endswith: ['\\\\cmd.exe','/bin/sh','\\\\powershell.exe']\ncondition: selection","fp":["Some apps legitimately shell out (baseline)."],
   "investigation":["Identify the vulnerable endpoint from web logs.","Hunt for persistence (webshell) in web root.","Patch and validate."]},
 "T1105":{"conf":"Curated","hypotheses":["A process downloaded an executable/script from the internet to disk."],
   "windows":["4688 certutil/bitsadmin/curl download"],"sysmon":["Sysmon EID 1 LOLBin download cradle","Sysmon EID 3 to new external IP","Sysmon EID 11 new PE in Temp"],"linux":["auditd: wget/curl then chmod +x"],"network":["proxy: binary download from rare domain"],
   "logic":"selection:\n  image|endswith: ['\\\\certutil.exe','\\\\bitsadmin.exe','\\\\curl.exe']\n  command_line|contains: ['http://','https://','-urlcache','/transfer']\ncondition: selection","fp":["Software updates and admin tooling."],
   "investigation":["Identify the downloaded artifact and hash it.","Determine the requesting process lineage.","Block the source and sweep for the artifact."]},
 "T1018":{"conf":"Curated","hypotheses":["Host enumeration / ping sweeps from a single internal host."],
   "windows":["4688 net view / nltest / ping loops"],"sysmon":["Sysmon EID 1 discovery utilities in short window"],"linux":["auditd: nmap/ping/for-loops"],"network":["netflow: fan-out to many hosts"],
   "logic":"selection:\n  image|endswith: ['\\\\net.exe','\\\\nltest.exe','\\\\ping.exe']\ncondition: count(distinct target) by host > threshold","fp":["Admin/inventory tools and vuln scanners (allowlist)."],
   "investigation":["Baseline which hosts legitimately scan.","Correlate with preceding initial access on the source.","Watch for subsequent lateral movement."]},
}

# Generic lab template fields reused by the Labs tab (educational, lab-scoped).
LAB_GENERIC = {
 "prereqs":["Written authorization / explicit scope for the target systems","Isolated, non-production lab (snapshot/rollback enabled)","No connectivity to live/production networks","Logging/telemetry enabled to observe the behaviour"],
 "validation":["The expected telemetry (see Detection Engineering) is produced","Behaviour is contained to the lab scope","Artifacts are catalogued for the report","Environment is reverted after the exercise"],
 "cleanup":["Revert VM snapshots","Remove created accounts/tasks/services","Rotate any test credentials used"],
}

# ---------------------------------------------------------------------------
# STRUCTURED LEARNING PATHS (courses) — lessons chain existing KB records.
# refs are openable IDs (techniques / CAPEC / CWE / D3FEND / kill chain).
# ---------------------------------------------------------------------------
COURSES = [
 {"id":"attack-fund","name":"ATT&CK Fundamentals","level":"Beginner","icon":"⚔",
  "desc":"Understand how ATT&CK is structured and how adversary behaviour maps to tactics and techniques.",
  "lessons":[
    {"title":"What ATT&CK is (and isn't)","body":"ATT&CK is a curated knowledge base of adversary tactics (the why) and techniques (the how), observed in real intrusions. Tactics are goals (e.g., Credential Access); techniques are the means (e.g., OS Credential Dumping). It is a common language for describing behaviour — not a checklist or a maturity score.","refs":[]},
    {"title":"Tactics as the adversary lifecycle","body":"The 14 Enterprise tactics run roughly from Reconnaissance to Impact. A single technique can serve several tactics. Learn to read a technique's tactic(s) to understand where in an intrusion it sits.","refs":["T1566","T1059","T1486"]},
    {"title":"Techniques and sub-techniques","body":"Sub-techniques refine a parent (e.g., T1059.001 PowerShell under T1059 Command and Scripting Interpreter). Always record the most specific ID you can support with evidence.","refs":["T1059","T1003","T1021"]},
    {"title":"From behaviour to defence","body":"Each technique links outward to CAPEC (attack patterns), CWE (weaknesses), D3FEND (countermeasures) and kill-chain stages. Following those links is how you turn an observation into a defensive action.","refs":["T1190","T1078"]},
  ],
  "quiz":[{"q":"What does an ATT&CK tactic represent?","a":["A specific tool","The adversary's goal/objective","A CVE","A log source"],"c":1},
          {"q":"T1059.001 is best described as…","a":["A tactic","A parent technique","A sub-technique (PowerShell)","A mitigation"],"c":2}]},
 {"id":"threat-hunt","name":"Threat Hunting Fundamentals","level":"Intermediate","icon":"🎯",
  "desc":"Run a hypothesis-driven hunt loop using ATT&CK techniques and the telemetry that reveals them.",
  "lessons":[
    {"title":"The hunt loop","body":"Hypothesis → data → analysis → outcome (detection, finding, or refined hypothesis). Hunts are driven by a specific behaviour you expect an adversary to exhibit, not by alerts.","refs":[]},
    {"title":"Form a hypothesis from a technique","body":"Pick a technique, read its Detection Engineering tab, and state a falsifiable hypothesis — e.g., 'a non-EDR process obtained a read handle to LSASS in the last 7 days.'","refs":["T1003.001","T1055"]},
    {"title":"Know your telemetry","body":"Hunts live or die on data. Map each hypothesis to concrete sources: Sysmon EID 10 for LSASS access, 4104 for PowerShell, 4625 clusters for brute force.","refs":["T1059.001","T1110"]},
    {"title":"From hunt to detection","body":"A successful hunt graduates into a tuned detection with documented false positives. Record coverage in the Navigator Matrix (detection layer).","refs":["T1021.002","T1105"]},
  ],
  "quiz":[{"q":"A threat hunt should begin with…","a":["An alert","A falsifiable hypothesis","A firewall rule","A CVE scan"],"c":1},
          {"q":"Which telemetry best supports hunting LSASS credential dumping?","a":["DNS logs","Sysmon EID 10 ProcessAccess","DHCP leases","TLS cert logs"],"c":1}]},
 {"id":"detection-eng","name":"Detection Engineering","level":"Intermediate","icon":"📡",
  "desc":"Turn adversary behaviour into reliable, low-false-positive detections.",
  "lessons":[
    {"title":"Telemetry first","body":"You can only detect what you collect. Establish process creation with command lines (4688/Sysmon 1), PowerShell logging (4104), authentication (4624/4625) and network (Sysmon 3/NetFlow) before writing logic.","refs":[]},
    {"title":"Writing detection logic","body":"Describe the behaviour, select the signal, express selection + condition, then enumerate false positives and tune. Favour behaviour over static IOCs.","refs":["T1059.001","T1053.005"]},
    {"title":"False positives and tuning","body":"Every detection needs an explicit FP list and a tuning plan (allowlists, thresholds, enrichment). An untuned rule is an alert-fatigue generator.","refs":["T1110","T1018"]},
    {"title":"Validate and track coverage","body":"Mark a detection 'validated' only after you have tested it against the behaviour. Track status honestly in the Navigator Matrix and the Coverage dashboard.","refs":["T1486","T1070.001"]},
  ],
  "quiz":[{"q":"Before writing a detection you must first ensure…","a":["A SIEM vendor","The relevant telemetry is collected","A CVE exists","An EDR license"],"c":1},
          {"q":"A detection should be marked 'validated' when…","a":["It is written","It is deployed","It has been tested against the behaviour","It has a title"],"c":2}]},
 {"id":"ad-security","name":"Active Directory Security","level":"Advanced","icon":"🏛",
  "desc":"Follow an AD attack path from discovery to domain dominance, with the defences at each step.",
  "lessons":[
    {"title":"Enumeration","body":"Adversaries map users, groups and trusts (Account Discovery, Remote System Discovery) often with valid accounts. Baseline who legitimately enumerates the directory.","refs":["T1087","T1018"]},
    {"title":"Credential access","body":"LSASS dumping and NTDS extraction yield hashes and tickets. These are the pivot to everything else — protect and monitor them heavily.","refs":["T1003.001","T1003.003"]},
    {"title":"Lateral movement","body":"Pass-the-Hash / Pass-the-Ticket and remote services (SMB, RDP, WinRM) move the adversary across the estate using alternate authentication material.","refs":["T1550.002","T1021.002","T1021.001"]},
    {"title":"Defending AD","body":"Tiered admin, Credential Guard, MFA, and strong monitoring of 4769/4662/4624 reduce both opportunity and dwell time.","refs":["T1078"]},
  ],
  "quiz":[{"q":"Pass-the-Hash abuses…","a":["Kerberos TGTs","Captured NTLM hashes","TLS certificates","OAuth tokens"],"c":1},
          {"q":"Which is the high-value credential-access target in AD?","a":["DNS cache","NTDS.dit / LSASS","Print spooler","Event log"],"c":1}]},
 {"id":"kill-chain","name":"Cyber Kill Chain","level":"Beginner","icon":"⛓",
  "desc":"Walk the seven stages of an intrusion and the defensive opportunity at each.",
  "lessons":[
    {"title":"Recon → Weaponization → Delivery","body":"Early stages are largely off your network, but delivery (phishing, exposed services) is where defence begins to bite.","refs":["recon","delivery"]},
    {"title":"Exploitation → Installation","body":"Code executes and persistence is established. Endpoint telemetry and least privilege are decisive here.","refs":["exploitation","installation"]},
    {"title":"C2 → Actions on Objectives","body":"The adversary controls hosts and pursues the goal (theft, ransom). Egress control, segmentation and backups blunt the impact.","refs":["c2","actions"]},
  ],
  "quiz":[{"q":"Ransomware encryption falls under which kill-chain stage?","a":["Delivery","Reconnaissance","Actions on Objectives","Weaponization"],"c":2}]},
 {"id":"d3fend-course","name":"MITRE D3FEND Essentials","level":"Intermediate","icon":"🛡",
  "desc":"Learn the defensive tactics and how countermeasures map back to adversary techniques.",
  "lessons":[
    {"title":"The defensive tactics","body":"D3FEND organises countermeasures into Model, Harden, Detect, Isolate, Deceive, Evict and Restore — a defensive counterpart to ATT&CK.","refs":["D3-NTA","D3-MFA"]},
    {"title":"Mapping defence to offence","body":"Each countermeasure 'counters' specific ATT&CK techniques. Use this to justify controls against the behaviours you actually face.","refs":["D3-CH","D3-NI"]},
    {"title":"Building coverage","body":"Combine Harden + Detect + Isolate for defence in depth, then validate coverage in the Attack-Defence studio.","refs":["D3-PA","D3-SR"]},
  ],
  "quiz":[{"q":"Which is a D3FEND defensive tactic?","a":["Exfiltration","Detect","Credential Access","Impact"],"c":1}]},
]

def build():
    data = {
        "meta": DATASET_META,
        "attack": {"tactics": ATTACK_TACTICS, "techniques": ATTACK_TECHNIQUES},
        "ics": {"tactics": ICS_TACTICS, "techniques": ICS_TECHNIQUES},
        "mobile": {"tactics": MOBILE_TACTICS, "techniques": MOBILE_TECHNIQUES},
        "d3fend": {"tactics": D3FEND_TACTICS, "techniques": D3FEND},
        "capec": CAPEC,
        "cwe": CWE,
        "cve": CVE,
        "killchain": KILLCHAIN,
        "ptes": PTES,
        "wstg": WSTG,
        "owasp_top10": OWASP_TOP10,
        "nist_csf": NIST_CSF,
        "nist_800115": NIST_800115,
        "learning": LEARNING,
        "scenario_templates": SCENARIO_TEMPLATES,
        "detection": {"telemetry": TELREF, "techniques": DET, "lab_generic": LAB_GENERIC},
        "courses": COURSES,
    }
    # counts
    data["meta"]["counts"] = {
        "attack_tactics": len(ATTACK_TACTICS),
        "attack_techniques": len(ATTACK_TECHNIQUES),
        "attack_subtechniques": sum(len(t["subs"]) for t in ATTACK_TECHNIQUES),
        "ics_techniques": len(ICS_TECHNIQUES),
        "mobile_techniques": len(MOBILE_TECHNIQUES),
        "d3fend": len(D3FEND),
        "capec": len(CAPEC),
        "cwe": len(CWE),
        "cve": len(CVE),
        "detection_profiles": len(DET),
        "telemetry_sources": len(TELREF),
        "courses": len(COURSES),
    }
    return data

if __name__ == "__main__":
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    out = root / "data" / "kb_data.json"
    out.parent.mkdir(exist_ok=True)
    data = build()
    with open(out, "w") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    print("Wrote", out)
    print(json.dumps(data["meta"]["counts"], indent=2))
