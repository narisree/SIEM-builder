# CrowdStrike EDR Integration Guide

## Overview

This document provides guidance for integrating CrowdStrike Falcon endpoint detection and response (EDR) logs into Splunk. CrowdStrike provides comprehensive endpoint telemetry including detections, incidents, and device events.

**Log Source Type:** API-based (Falcon Data Replicator or Streaming API)  
**Vendor:** CrowdStrike  
**Category:** Endpoint Detection & Response  
**Primary Index:** `crowdstrike`  
**Sourcetypes:** `crowdstrike:events`, `crowdstrike:detections`, `crowdstrike:incidents`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **CrowdStrike Falcon** - Active Falcon subscription with API access
2. **API Credentials** - Client ID and Secret from Falcon console
3. **Splunk Infrastructure** - Active Splunk deployment with Heavy Forwarder
4. **Network Connectivity** - Outbound HTTPS to CrowdStrike API
5. **Splunk Add-on for CrowdStrike** - Downloaded from Splunkbase

### CrowdStrike Subscription Requirements

| Feature | Subscription |
|---------|-------------|
| Event Streaming | Falcon Insight/Prevent |
| Falcon Data Replicator | Enterprise license |
| API Access | All subscriptions |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Splunk HF | api.crowdstrike.com | 443 | HTTPS | API authentication |
| Splunk HF | firehose.crowdstrike.com | 443 | HTTPS | Event streaming |
| Splunk HF | <FDR_S3_bucket> | 443 | HTTPS | FDR data (if applicable) |

## Logging Standard

### Recommended Event Types

| Event Type | Description | Priority |
|------------|-------------|----------|
| Detection Events | Threat detections from Falcon | High |
| Incident Events | Grouped detection incidents | High |
| Authentication Events | Login/logout to endpoints | High |
| Process Events | Process execution telemetry | High |
| Network Events | Network connection data | Medium |
| File Events | File operations | Medium |

## Log Collection Standard

### Option 1: Streaming API (Real-time)

1. Create API client in Falcon Console
2. Grant required API scopes
3. Configure Splunk Add-on with credentials
4. Enable streaming input

### Option 2: Falcon Data Replicator (High volume)

1. Enable FDR in Falcon subscription
2. Configure S3 bucket destination
3. Set up Splunk S3 input
4. Configure parsing and index

### Source-Side Steps (CrowdStrike Falcon)

#### Create API Client

1. Navigate to **Support > API Clients and Keys**
2. Click **Add new API client**
3. Grant scopes:
   - Event Streams: Read
   - Detections: Read
   - Incidents: Read
   - Hosts: Read
4. Save Client ID and Secret

### SIEM-Side Steps (Splunk)

#### Configure inputs.conf

```ini
[crowdstrike://detection_events]
client_id = <CLIENT_ID>
client_secret = <CLIENT_SECRET>
index = crowdstrike
sourcetype = crowdstrike:events
interval = 60
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | TA-crowdstrike-falcon-event-streams | API-based collection |
| Add-on | Splunk_TA_crowdstrike_fdr | FDR collection |
| Index | crowdstrike | Storage for EDR logs |

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=crowdstrike earliest=-1h
| stats count by sourcetype, event_type
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Authentication failed | Invalid credentials | Verify Client ID/Secret |
| No events | Wrong API scopes | Grant required permissions |
| Duplicate events | Multiple inputs | Check for overlapping inputs |

## Security Notes

1. Rotate API credentials periodically
2. Use dedicated API client for Splunk
3. Implement minimum required scopes
4. Monitor for API rate limiting

---

*Last Updated: January 2025*  
*Version: 1.0 (Stub - Expand as needed)*
