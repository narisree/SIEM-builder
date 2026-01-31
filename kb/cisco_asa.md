# Cisco ASA Integration Guide

## Overview

This document provides guidance for integrating Cisco ASA firewall logs into Splunk. Cisco ASA logs provide visibility into network traffic, VPN connections, security events, and administrative activities.

**Log Source Type:** Syslog  
**Vendor:** Cisco  
**Category:** Firewall / Network Security  
**Primary Index:** `cisco_asa`  
**Sourcetype:** `cisco:asa`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Cisco ASA** - ASA 8.x or later (recommended 9.x+)
2. **Splunk Infrastructure** - Active Splunk deployment with Heavy Forwarder
3. **Network Connectivity** - Syslog connectivity from ASA to Splunk HF
4. **Administrative Access** - Enable/config level access on ASA
5. **Splunk Add-on for Cisco ASA** - Downloaded from Splunkbase

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Cisco ASA | Splunk HF | UDP 514 | UDP | Syslog forwarding |
| Splunk HF | Splunk Indexer | TCP 9997 | TCP | Log forwarding |

## Logging Standard

### Recommended Syslog Levels

| Level | Name | Description | Recommended |
|-------|------|-------------|-------------|
| 0 | Emergencies | System unusable | Yes |
| 1 | Alerts | Immediate action needed | Yes |
| 2 | Critical | Critical conditions | Yes |
| 3 | Errors | Error conditions | Yes |
| 4 | Warnings | Warning conditions | Yes |
| 5 | Notifications | Normal but significant | Yes |
| 6 | Informational | Informational messages | Selective |
| 7 | Debugging | Debug messages | No (high volume) |

### Key Message IDs

- **%ASA-4-106023**: Denied packet
- **%ASA-6-302013/302014**: TCP connection built/teardown
- **%ASA-6-302015/302016**: UDP connection built/teardown
- **%ASA-4-419002**: Duplicate TCP SYN
- **%ASA-5-111008/111010**: Configuration changes

## Log Collection Standard

### Source-Side Steps (Cisco ASA)

#### Step 1: Configure Logging

```
! Enter configuration mode
conf t

! Enable logging
logging enable

! Set logging level
logging trap informational

! Configure syslog server
logging host inside <SPLUNK_HF_IP> 17/514

! Set timestamp format
logging timestamp

! Include device ID
logging device-id hostname
```

#### Step 2: Configure EMBLEM Format (Optional)

```
logging emblem
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Cisco ASA

Deploy to Heavy Forwarders and Search Heads.

#### Step 2: Configure Syslog Input

```ini
[udp://514]
index = cisco_asa
sourcetype = cisco:asa
connection_host = ip
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk_TA_cisco-asa | Parsing and field extraction |
| Index | cisco_asa | Storage for ASA logs |

## Sample Configuration Snippets

### inputs.conf

```ini
[udp://514]
index = cisco_asa
sourcetype = cisco:asa
connection_host = ip
no_appending_timestamp = true
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=cisco_asa earliest=-15m
| stats count by host, action
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No logs | Syslog not configured | Verify ASA logging config |
| Missing events | Log level too low | Increase trap level |
| Parsing errors | EMBLEM mismatch | Align EMBLEM setting with props.conf |

## Security Notes

1. Use dedicated management interface for syslog
2. Consider encrypted syslog (TLS) for sensitive traffic
3. Implement rate limiting on ASA to prevent log flooding
4. Monitor for configuration change events

---

*Last Updated: January 2025*  
*Version: 1.0 (Stub - Expand as needed)*
