# Zscaler Proxy Integration Guide

## Overview

This document provides guidance for integrating Zscaler Internet Access (ZIA) logs into Splunk. Zscaler logs provide visibility into web traffic, security events, cloud application usage, and threat detection.

**Log Source Type:** NSS (Nanolog Streaming Service) or Cloud NSS  
**Vendor:** Zscaler  
**Category:** Secure Web Gateway / Cloud Security  
**Primary Index:** `zscaler`  
**Sourcetypes:** `zscalernss-web`, `zscalernss-fw`, `zscalernss-dns`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Zscaler ZIA** - Active subscription with logging enabled
2. **NSS Server** - Deployed on-premises or Cloud NSS configured
3. **Splunk Infrastructure** - Active Splunk deployment with Heavy Forwarder
4. **Network Connectivity** - NSS to Splunk connectivity
5. **Splunk Add-on for Zscaler** - Downloaded from Splunkbase

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Zscaler NSS | Splunk HF | TCP 9997 | TCP | Log forwarding |
| Zscaler Cloud | Splunk HF | TCP 443 | HTTPS | Cloud NSS |
| Splunk HF | Splunk Indexer | TCP 9997 | TCP | Forward to indexers |

## Logging Standard

### Recommended Log Types

| Log Type | Description | Priority |
|----------|-------------|----------|
| Web Logs | HTTP/HTTPS traffic | High |
| Firewall Logs | Network firewall events | High |
| DNS Logs | DNS queries and responses | High |
| Tunnel Logs | GRE/IPSec tunnel status | Medium |
| CASB Logs | Cloud app security events | Medium |

### Key Fields

- User identity (username, department)
- Source IP and destination
- URL and hostname
- Action (allowed, blocked, cautioned)
- Threat category (if applicable)
- Application name

## Log Collection Standard

### Option 1: On-Premises NSS

1. Deploy NSS VM in your datacenter
2. Configure NSS to send logs to Splunk HF
3. Set log format and fields
4. Enable required log types

### Option 2: Cloud NSS

1. Enable Cloud NSS in ZIA admin portal
2. Configure destination as Splunk
3. Set up authentication (API token)
4. Select log types to stream

### Source-Side Steps (Zscaler Admin Portal)

#### Configure NSS Feed

1. Go to **Administration > Nanolog Streaming Service**
2. Click **Add NSS Feed**
3. Configure:
   - **Name**: Splunk-Feed
   - **NSS Type**: Web logs (or desired type)
   - **Status**: Enabled
   - **SIEM IP**: `<SPLUNK_HF_IP>`
   - **SIEM Port**: 9997
4. Select output format: **JSON** or **CSV**
5. Configure fields to include
6. Save and activate

### SIEM-Side Steps (Splunk)

#### Configure inputs.conf

```ini
# For NSS TCP input
[tcp://9997]
index = zscaler
sourcetype = zscalernss-web
connection_host = ip

# For Cloud NSS (HTTP Event Collector)
[http://zscaler_cloud_nss]
index = zscaler
sourcetype = zscalernss-web
token = <HEC_TOKEN>
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk_TA_zscaler | Parsing and field extraction |
| Index | zscaler | Storage for Zscaler logs |

## Sample Configuration Snippets

### inputs.conf

```ini
[tcp://9997]
index = zscaler
sourcetype = zscalernss-web
connection_host = ip
no_appending_timestamp = true

[tcp://9998]
index = zscaler
sourcetype = zscalernss-fw
connection_host = ip
```

### props.conf

```ini
[zscalernss-web]
SHOULD_LINEMERGE = false
TIME_FORMAT = %s
TIME_PREFIX = \"datetime\":\"
MAX_TIMESTAMP_LOOKAHEAD = 20
KV_MODE = json
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=zscaler earliest=-15m
| stats count by sourcetype, action
```

### Monitor Traffic Categories

```spl
index=zscaler sourcetype=zscalernss-web
| stats count by urlcategory
| sort -count
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No data received | NSS not configured | Verify NSS feed is active |
| Parsing errors | Wrong sourcetype | Check sourcetype assignment |
| Missing fields | Incomplete NSS config | Add required fields to feed |
| High latency | Network issues | Check NSS to Splunk connectivity |
| Duplicate events | Multiple feeds | Review NSS feed configuration |

### Diagnostic Commands

**Check NSS Status:**
1. Go to ZIA Admin Portal
2. Navigate to **Administration > NSS**
3. Verify feed status is "Active"

**On Splunk:**
```spl
# Check incoming data rate
index=_internal source=*metrics.log group=per_sourcetype_thruput series=zscaler*
| timechart avg(kb) by series
```

## Security Notes

1. **Data Sensitivity**: Zscaler logs contain user activity and may include PII
2. **Access Control**: Implement role-based access to Zscaler index in Splunk
3. **Encryption**: Use TLS for NSS to Splunk communication when possible
4. **Retention**: Align log retention with compliance requirements
5. **NSS Security**: Secure NSS VM with proper network segmentation
6. **API Credentials**: Rotate Cloud NSS tokens periodically

## Use Cases

### Detect Data Exfiltration

```spl
index=zscaler sourcetype=zscalernss-web action=allowed
| stats sum(requestsize) as upload_bytes by user
| where upload_bytes > 100000000
| sort -upload_bytes
```

### Monitor Blocked Threats

```spl
index=zscaler action=blocked threatname=*
| stats count by threatname, threatcategory
| sort -count
```

---

*Last Updated: January 2025*  
*Version: 1.0 (Stub - Expand as needed)*
