# Windows Events Integration Guide

## Overview

This document provides an understanding of the implementation method used to integrate the Windows log source into the Splunk environment. This log source utilizes the collected security logs from Windows Servers.

**Log Source Type:** Agent-based (Universal Forwarder)  
**Vendor:** Microsoft  
**Category:** Operating System Logs  
**Primary Index:** `win_os`  
**Sourcetype:** `WinEventLog:Security`, `WinEventLog:System`, `WinEventLog:Application`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Windows Server** - Windows Server 2016 or later (recommended)
2. **Administrative Access** - Local administrator privileges on target servers
3. **Splunk Infrastructure** - Active Splunk deployment with:
   - Deployment Server configured
   - Heavy Forwarder(s) available for receiving logs
4. **Network Connectivity** - Required ports open between components
5. **Splunk Universal Forwarder Installer** - Download from Splunk website (version 9.x recommended)

## Network Connectivity Requirements

The following network connectivity is required for this integration:

| # | Source | Destination | Port | Direction | Purpose |
|---|--------|-------------|------|-----------|---------|
| 1 | Windows Server (UF) | Splunk Heavy Forwarder | TCP 9997 | Unidirectional | Log forwarding |
| 2 | Windows Server (UF) | Deployment Server | TCP 8089 | Unidirectional | Management/Config deployment |

**Firewall Rules:**
- Ensure stateful inspection allows return traffic
- Consider using encrypted connections (TLS) for sensitive environments

## Logging Standard

### Recommended Event Logs

We recommend collecting the following Security-related logs from all Windows Servers:

| Event Log | Index | Priority | Description |
|-----------|-------|----------|-------------|
| Security | win_os | High | Authentication, authorization, security policy changes |
| System | win_os | Medium | System services, drivers, hardware events |
| Application | win_os | Medium | Application-level events and errors |

### Event ID Blacklist (Optional)

Consider excluding high-volume, low-value events:
- **4658** - Handle closed (very noisy)
- **5156** - Windows Filtering Platform connection (high volume)
- **4663** - Object access attempt (can be noisy in file servers)

### Time Synchronization

- Ensure NTP is configured on all Windows servers
- Use consistent time zone settings (UTC recommended for SIEM)
- Windows Event Log timestamps are in local time by default

## Log Collection Standard

### Source-Side Steps (Windows Server)

#### Step 1: Download Universal Forwarder

Download the Splunk Universal Forwarder from:
```
https://www.splunk.com/page/previous_releases/universalforwarder#x86_64windows
```

Select the Windows 64-bit MSI installer (version 9.4.0 or later recommended).

#### Step 2: Installation Options

**Option A: Silent Mode Installation (Recommended for automation)**

Open Command Prompt as Administrator and run:

```cmd
msiexec.exe /i splunkforwarder-9.4.0-6b4ebe426ca6-windows-x64.msi ^
  DEPLOYMENT_SERVER="<DEPLOYMENT_SERVER_IP>:8089" ^
  SPLUNKUSER=UF_admin ^
  SPLUNKPASSWORD=<SECURE_PASSWORD> ^
  AGREETOLICENSE=Yes /quiet
```

**Option B: GUI Installation**

1. Run the MSI installer as Administrator
2. Accept the License Agreement and select "Splunk Enterprise"
3. Click **Next** to create an administrator account
4. Configure options:
   - **Destination Folder**: Default or custom path
   - **Certificate Information**: Skip (click Next)
   - **User Account**: Keep default least-privileged user (splunkfwd)

5. **Grant SeSecurityPrivilege**: Enable to allow collection of Windows Security Event Logs
   
   > **Note:** SeSecurityPrivilege permissions are READ/WRITE by design on Windows. This allows the user to also modify and delete Security Event Logs.

6. **Create Administrator Account**:
   - Username: `UF_admin`
   - Uncheck "Generate a password"
   - Set a secure password manually

7. **Configure Deployment Server**:
   - Enter hostname or IP: `<DEPLOYMENT_SERVER_IP>`
   - Port: `8089`

8. **Receiving Indexer**: Leave blank (configured via Deployment Server)

9. Click **Install** and wait for completion

10. Verify the **SplunkForwarder** service is running in Windows Services

#### Step 3: Verify Installation

```cmd
# Check service status
sc query SplunkForwarder

# Check Splunk processes
tasklist | findstr splunk
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Windows

Install `Splunk_TA_windows` on:
- Deployment Server (for distribution)
- Heavy Forwarders (for parsing)
- Search Heads (for field extractions)

#### Step 2: Configure Input Stanzas

Copy the add-on to the deployment-apps directory:
```
/opt/splunk/etc/deployment-apps/Splunk_TA_windows
```

Create or edit `local/inputs.conf`:

```ini
[WinEventLog://Application]
disabled = 0
index = win_os

[WinEventLog://Security]
disabled = 0
index = win_os
blacklist = 4658,5156,4663

[WinEventLog://System]
disabled = 0
index = win_os
```

#### Step 3: Restart Splunk on Deployment Server

```bash
/opt/splunk/bin/splunk restart
```

#### Step 4: Create Server Class

1. Log in to Splunk Enterprise on the Deployment Server
2. Navigate to **Settings > Forwarder Management**
3. Click **Server Classes** tab > **New Server Class**
4. Name: `Windows_Servers`
5. Click **Add Apps** and select `Splunk Add-on for Windows`
6. Click **Add Clients** and specify Windows server patterns:
   - Example: `WIN*` or specific hostnames
7. Click **Save**

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk_TA_windows | Input collection and field extraction |
| Index | win_os | Storage for Windows events |

### Configuration Files Summary

| File | Location | Purpose |
|------|----------|---------|
| inputs.conf | Splunk_TA_windows/local/ | Define which event logs to collect |
| props.conf | Splunk_TA_windows/default/ | Event parsing configuration |
| outputs.conf | 100_splunkcloud/ | Forward to Splunk Cloud (if applicable) |

## Sample Configuration Snippets

### inputs.conf (Universal Forwarder)

```ini
[WinEventLog://Application]
disabled = 0
index = win_os
start_from = oldest
current_only = 0

[WinEventLog://Security]
disabled = 0
index = win_os
blacklist = 4658,5156,4663
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1

[WinEventLog://System]
disabled = 0
index = win_os
start_from = oldest
current_only = 0
```

### outputs.conf (Cloud Forwarding)

```ini
[tcpout]
defaultGroup = splunkcloud

[tcpout:splunkcloud]
server = <SPLUNK_CLOUD_INGEST_FQDN>:9997
sslCertPath = $SPLUNK_HOME/etc/auth/mycerts/client.pem
sslRootCAPath = $SPLUNK_HOME/etc/auth/mycerts/cacert.pem
useACK = true
```

## Validation & Troubleshooting

### Verify Log Collection

Run the following search in Splunk:

```spl
index=win_os earliest=-15m
| stats count by host, sourcetype
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No events in index | UF not started | Check SplunkForwarder service |
| Missing Security logs | SeSecurityPrivilege not granted | Re-run installer with permission |
| Connection refused | Firewall blocking | Open TCP 9997, 8089 |
| Deployment Server not receiving | Wrong IP/Port | Verify deploymentclient.conf |

### Useful Diagnostic Commands

**On Universal Forwarder:**
```cmd
# Check connectivity to HF
telnet <HF_IP> 9997

# View forwarder logs
type "%SPLUNK_HOME%\var\log\splunk\splunkd.log"

# List configured inputs
"%SPLUNK_HOME%\bin\splunk" btool inputs list --debug
```

**On Splunk:**
```spl
# Check indexer connectivity
| rest /services/deployment/server/clients

# Monitor input status
index=_internal source=*metrics.log group=per_sourcetype_thruput
| stats sum(kb) by series
```

## Security Notes

1. **Least Privilege**: The Universal Forwarder runs as `splunkfwd` user by default (version 9.1+), providing minimal necessary permissions.

2. **SeSecurityPrivilege Warning**: Granting this permission allows READ/WRITE access to Security Event Logs. In highly sensitive environments, consider:
   - Regular auditing of forwarder activity
   - Network segmentation
   - Additional monitoring of forwarder accounts

3. **Credential Security**: 
   - Use deployment server for credential distribution
   - Never hardcode passwords in scripts
   - Consider certificate-based authentication

4. **Network Security**:
   - Enable TLS encryption for log forwarding
   - Use dedicated management VLAN if possible
   - Implement firewall rules to restrict access

5. **Event Log Tampering**: Be aware that compromised forwarders could potentially modify local event logs. Consider:
   - Real-time forwarding (minimize local retention)
   - Windows Event Forwarding (WEF) as alternative
   - Log integrity monitoring

---

*Last Updated: January 2025*  
*Version: 1.0*
