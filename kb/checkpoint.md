# Check Point Firewall Integration Guide

## Overview

This document provides guidance for integrating Check Point firewall logs into Splunk. Check Point logs provide visibility into network security events, threat prevention, and administrative activities.

**Log Source Type:** OPSEC LEA or Syslog  
**Vendor:** Check Point Software Technologies  
**Category:** Firewall / Network Security  
**Primary Index:** `checkpoint`  
**Sourcetype:** `cp_log`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Check Point Management Server** - R80.x or later
2. **Splunk Infrastructure** - Active Splunk deployment
3. **OPSEC LEA Certificate** (if using LEA)
4. **Network Connectivity** - Required ports open
5. **Splunk Add-on for Check Point** - Downloaded from Splunkbase

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Splunk HF | Check Point Mgmt | TCP 18184 | TCP | OPSEC LEA |
| Check Point | Splunk HF | UDP 514 | UDP | Syslog (alternative) |
| Splunk HF | Splunk Indexer | TCP 9997 | TCP | Log forwarding |

## Logging Standard

### Recommended Log Types

| Log Type | Description | Priority |
|----------|-------------|----------|
| Firewall | Connection logs, accept/drop events | High |
| IPS | Intrusion Prevention events | High |
| URL Filtering | Web access logs | High |
| Anti-Bot | Bot detection events | High |
| Application Control | App identification | Medium |
| DLP | Data Loss Prevention | Medium |

## Log Collection Standard

### Option 1: OPSEC LEA (Recommended)

1. Create OPSEC Application in SmartConsole
2. Generate SIC certificate
3. Configure Splunk Add-on with certificate
4. Enable log forwarding

### Option 2: Syslog Export

1. Configure Log Exporter on Management Server
2. Set target syslog server (Splunk HF)
3. Select log types to export
4. Configure format (CEF recommended)

### SIEM-Side Steps

#### Configure inputs.conf

```ini
# For OPSEC LEA
[opsec_lea://<input_name>]
server = <MANAGEMENT_SERVER_IP>
port = 18184
certificate = <path_to_certificate>
index = checkpoint
sourcetype = cp_log

# For Syslog
[udp://514]
index = checkpoint
sourcetype = cp_log
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk_TA_checkpoint | LEA collection and parsing |
| Index | checkpoint | Storage for Check Point logs |

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=checkpoint earliest=-15m
| stats count by product, action
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| SIC errors | Certificate mismatch | Regenerate OPSEC certificate |
| No logs via LEA | Port blocked | Verify TCP 18184 connectivity |
| Parsing issues | Wrong format | Verify log exporter format |

## Security Notes

1. Secure OPSEC LEA with proper certificate management
2. Restrict network access to LEA port
3. Monitor certificate expiration
4. Use encrypted syslog when possible

---

*Last Updated: January 2025*  
*Version: 1.0 (Stub - Expand as needed)*
