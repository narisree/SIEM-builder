# Proofpoint Integration Guide

## Overview

This document provides guidance for integrating Proofpoint email security logs into Splunk. Proofpoint logs provide visibility into email threats, spam filtering, phishing attempts, and email flow.

**Log Source Type:** Syslog or API-based  
**Vendor:** Proofpoint  
**Category:** Email Security  
**Primary Index:** `proofpoint`  
**Sourcetypes:** `proofpoint:pps:messagelog`, `proofpoint:tap`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Proofpoint Protection Server** - Active subscription
2. **Proofpoint TAP** - For threat intelligence (if applicable)
3. **Splunk Infrastructure** - Active Splunk deployment
4. **Network Connectivity** - Syslog or API access
5. **Splunk Add-on for Proofpoint** - Downloaded from Splunkbase

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Proofpoint PPS | Splunk HF | UDP/TCP 514 | Syslog | Message logs |
| Splunk HF | tap-api.proofpoint.com | 443 | HTTPS | TAP API |

## Logging Standard

### Recommended Log Types

| Log Type | Description | Priority |
|----------|-------------|----------|
| Message Logs | Email delivery and filtering | High |
| Filter Logs | Spam/malware filtering decisions | High |
| TAP SIEM | Threat intelligence events | High |
| Clicks Permitted | URL click tracking | Medium |
| Messages Blocked | Quarantined messages | High |

## Log Collection Standard

### Option 1: Syslog (PPS Logs)

1. Configure Proofpoint to send syslog
2. Set destination to Splunk HF
3. Configure parsing with TA

### Option 2: TAP SIEM API

1. Obtain TAP API credentials
2. Configure Splunk Add-on
3. Set up scheduled polling

### SIEM-Side Steps

```ini
# Syslog input
[udp://514]
index = proofpoint
sourcetype = proofpoint:pps:messagelog

# TAP API input
[proofpoint_tap://tap_events]
api_host = tap-api.proofpoint.com
principal = <SERVICE_PRINCIPAL>
secret = <API_SECRET>
index = proofpoint
interval = 300
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | TA-proofpoint | Syslog and TAP integration |
| Index | proofpoint | Storage for email logs |

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=proofpoint earliest=-1h
| stats count by sourcetype, action
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No syslog data | Incorrect destination | Verify Proofpoint config |
| TAP auth failed | Wrong credentials | Verify principal/secret |
| Missing events | Time sync issue | Check NTP on both systems |

## Security Notes

1. TAP API credentials should be stored securely
2. Syslog may contain sensitive email metadata
3. Consider encrypted syslog for compliance
4. Monitor for email exfiltration patterns

---

*Last Updated: January 2025*  
*Version: 1.0 (Stub - Expand as needed)*
