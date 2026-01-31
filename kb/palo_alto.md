# Palo Alto Firewall Integration Guide

## Overview

This document provides an understanding of the implementation method used to onboard the Palo Alto Firewall log source into the Splunk environment, following Splunk best practices. This log source utilizes collected logs from Palo Alto firewall devices via syslog mechanism.

**Log Source Type:** Syslog  
**Vendor:** Palo Alto Networks  
**Category:** Firewall / Network Security  
**Primary Index:** `pan_logs`  
**Sourcetype:** `pan:firewall`

## Pre-requisites

Before beginning the integration process, ensure the following prerequisites are met:

1. **Palo Alto Firewall** - Running PAN-OS version 9.x or higher
2. **Splunk Instance** - Active Splunk deployment with Heavy Forwarder
3. **Administrative Access** - Admin credentials for both Palo Alto firewall and Splunk
4. **Network Connectivity** - Firewall and Splunk HF network connectivity established
5. **Splunk Add-on for Palo Alto** - Downloaded from Splunkbase

## Network Connectivity Requirements

The following network connectivity is required for this integration:

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Palo Alto Firewall | Splunk HF/Syslog Server | 514 | UDP | Primary log forwarding |
| Palo Alto Firewall | Splunk HF/Syslog Server | 515 | UDP | Alternate log forwarding |
| Splunk Heavy Forwarder | Splunk Indexer | 9997 | TCP | Forward parsed logs |

**Notes:**
- TCP can be used instead of UDP for reliable delivery
- Consider using TLS-encrypted syslog (port 6514) for sensitive environments

## Logging Standard

### Recommended Logging Level

We recommend collecting **Informational level (level 6)** logs from all Palo Alto Firewalls. This captures:
- Interface changes
- Login attempts
- Routing events
- Configuration changes
- Security alerts

Without excessive debugging-level details or low-level messages.

### Types of Logs for Security Baseline

The following log types should be integrated for security visibility and effective use-case building:

| Log Type | Log Forwarding Name | Description | Priority |
|----------|---------------------|-------------|----------|
| **Traffic Logs** | Traffic | Session start/end, rules applied, actions (allow/deny/drop) | High |
| **Threat Logs** | Threat | Security profile alerts, threat descriptions | High |
| **URL Filtering** | Url | URL category matches, web traffic monitoring | High |
| **Authentication Logs** | Auth | User authentication events, access control | High |
| **GlobalProtect** | Tunnel | VPN and mobile user connections | Medium |
| **Config Logs** | Config | Firewall configuration changes | Medium |

### Log Type Details

1. **Traffic Logs** - The most important log type for firewall monitoring. Displays entries for session start and end, security rules applied, and actions taken.

2. **Threat Logs** - Critical for security use cases. Generates alerts when traffic matches security profiles. Contains threat descriptions with detailed information.

3. **URL Filtering Logs** - Comprehensive information about traffic matching URL categories in security policy.

4. **Authentication Logs** - Information about authentication events when users access network resources controlled by Authentication Policy rules.

5. **GlobalProtect Logs** - Mobile and VPN-related access logs.

6. **Config Logs** - Audit trail of firewall configuration changes.

## Log Collection Standard

### Source-Side Steps (Palo Alto Firewall)

#### Step 1: Configure Syslog Server Profile

1. **Log in** to the Palo Alto Web Interface
2. Navigate to **Device > Server Profiles > Syslog**
3. Click **Add (+)** to create a new profile
4. **Profile Name**: `Splunk-Syslog` (or descriptive name)

#### Step 2: Add Syslog Server Details

Configure the syslog server entry:

| Field | Value |
|-------|-------|
| **Name** | Splunk-Syslog |
| **Syslog Server** | `<IP_OF_SPLUNK_HF>` |
| **Port** | 514 (or 515) |
| **Transport** | UDP (or TCP for reliability) |
| **Facility** | LOG_USER |
| **Format** | BSD (recommended for compatibility) |

Click **OK** to save the server profile.

#### Step 3: Configure Log Forwarding Profile

1. Navigate to **Objects > Log Forwarding**
2. Click **Add** to create a new profile
3. Configure the profile:
   - **Name**: `Forward-to-Splunk`
   - **Syslog**: Select `Splunk-Syslog` (created in Step 1)

4. Enable the following Log Types:
   - **Traffic Logs**: Select **All**
   - **Threat Logs**: Select **All**
   - **URL Filtering**: Enable
   - **Authentication Logs**: Enable
   - **System Logs**: Enable (optional)

5. Click **OK** to save

#### Step 4: Apply Log Forwarding to Security Policies

1. Navigate to **Policies > Security**
2. Select the security rule to enable logging (e.g., "Any Allow")
3. Click on the rule to edit
4. Go to the **Actions** tab
5. Under **Log Forwarding**, select `Forward-to-Splunk`
6. Enable logging options:
   - ✅ **Log at Session Start** (for connection tracking)
   - ✅ **Log at Session End** (for full session details)
7. Click **OK**
8. Verify the forwarding icon appears in the 'Options' column

#### Step 5: Commit Changes

Click **Commit** to apply all configuration changes to the firewall.

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Palo Alto

Install `Splunk_TA_paloalto` on:
- Heavy Forwarder (for syslog ingestion)
- Search Heads (for field extractions)
- Deployment Server (for distribution)

#### Step 2: Configure Syslog Input

If using syslog-ng on the Heavy Forwarder, configure log storage:

```bash
# Create log directory
mkdir -p /u01/syslog-data/palo/
chown splunk:splunk /u01/syslog-data/palo/
```

#### Step 3: Deploy Add-on via Deployment Server

Copy the add-on to the deployment-apps directory:

```bash
cp -r Splunk_TA_paloalto /opt/splunk/etc/deployment-apps/
```

#### Step 4: Configure Input Stanzas

Create or edit `local/inputs.conf` in the add-on directory:

```ini
[monitor:///u01/syslog-data/palo/.../*.log]
index = pan_logs
sourcetype = pan:firewall
disabled = 0
host_segment = 4
```

**Alternative: Direct Syslog Input**

```ini
[udp://514]
index = pan_logs
sourcetype = pan:firewall
connection_host = ip
```

#### Step 5: Configure Outputs (if forwarding to Cloud)

Create `local/outputs.conf`:

```ini
[tcpout]
defaultGroup = splunkcloud

[tcpout:splunkcloud]
server = <YOUR_SPLUNK_CLOUD_INGEST_FQDN>:9997
sslCertPath = $SPLUNK_HOME/etc/auth/mycerts/client.pem
sslRootCAPath = $SPLUNK_HOME/etc/auth/mycerts/cacert.pem
sslPassword = <optional_if_needed>
useACK = true
```

#### Step 6: Restart Splunk

```bash
/opt/splunk/bin/splunk restart
```

#### Step 7: Create Server Class

1. Log in to Splunk Deployment Server
2. Navigate to **Settings > Forwarder Management**
3. Click **Server Classes** > **New Server Class**
4. Name: `Palo_Alto_Forwarders`
5. **Add Apps**: Select `Splunk_TA_paloalto`
6. **Add Clients**: Specify Heavy Forwarder hostnames
7. Click **Save**

## Required Add-on / Parser

| Component | Name | Version | Purpose |
|-----------|------|---------|---------|
| Add-on | Splunk_TA_paloalto | Latest | Parsing and field extraction |
| Index | pan_logs | - | Storage for firewall logs |

### Configuration Files Summary

| App Name | File | Details |
|----------|------|---------|
| Splunk_TA_paloalto | inputs.conf | Syslog/monitor input configuration |
| Splunk_TA_paloalto | props.conf | Default parsing rules (use as-is) |
| 100_splunkcloud | outputs.conf | Encrypted output to Splunk Cloud |

## Sample Configuration Snippets

### inputs.conf (Monitor-based)

```ini
[monitor:///u01/syslog-data/palo/.../*.log]
index = pan_logs
sourcetype = pan:firewall
disabled = 0
host_segment = 4
crcSalt = <SOURCE>
```

### inputs.conf (Direct Syslog)

```ini
[udp://514]
index = pan_logs
sourcetype = pan:firewall
connection_host = ip
no_appending_timestamp = true

[tcp://514]
index = pan_logs
sourcetype = pan:firewall
connection_host = ip
```

### props.conf (Reference)

```ini
[pan:firewall]
SHOULD_LINEMERGE = false
TIME_FORMAT = %Y/%m/%d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 44
TZ = UTC
```

## Validation & Troubleshooting

### Verify Log Collection

Run the following search in Splunk:

```spl
index=pan_logs earliest=-15m
| stats count by host, sourcetype, log_subtype
```

### Check Specific Log Types

```spl
index=pan_logs sourcetype=pan:firewall
| stats count by log_subtype
| sort -count
```

Expected log_subtype values:
- `traffic`
- `threat`
- `url`
- `auth`
- `tunnel`
- `config`

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No logs received | Firewall not sending | Verify syslog profile and commit |
| Logs not parsing | Wrong sourcetype | Check inputs.conf sourcetype setting |
| Missing log types | Log forwarding not applied | Apply forwarding profile to all policies |
| Timestamp issues | Timezone mismatch | Set TZ in props.conf |
| High latency | UDP packet loss | Switch to TCP syslog |

### Diagnostic Commands

**On Palo Alto Firewall (CLI):**

```bash
# Show syslog configuration
show log-collector detail

# Test syslog connectivity
debug syslog server status

# View recent logs
show log traffic last 10
```

**On Splunk Heavy Forwarder:**

```bash
# Check syslog port listening
netstat -ulnp | grep 514

# View incoming data
tcpdump -i any port 514 -c 10

# Check Splunk internal logs
tail -f /opt/splunk/var/log/splunk/splunkd.log
```

### Splunk Search Diagnostics

```spl
# Check indexing throughput
index=_internal source=*metrics.log group=per_sourcetype_thruput series=pan:firewall
| timechart avg(kb) by series

# Verify data reaching indexers
| tstats count where index=pan_logs by sourcetype, host
```

## Security Notes

1. **Syslog Security**: 
   - UDP syslog is unencrypted and unreliable
   - Consider TCP syslog or TLS-encrypted syslog (port 6514)
   - Use dedicated management VLAN for syslog traffic

2. **Access Control**:
   - Restrict syslog server access in firewall policies
   - Use dedicated service accounts for Splunk
   - Enable audit logging on Splunk infrastructure

3. **Data Sensitivity**:
   - Firewall logs may contain sensitive information (IPs, usernames, URLs)
   - Implement appropriate data retention policies
   - Consider data masking for PII in log fields

4. **High Availability**:
   - Configure multiple syslog destinations for redundancy
   - Use load balancers for syslog distribution
   - Monitor syslog queue health on firewalls

5. **Rate Limiting**:
   - High-volume environments may require rate limiting
   - Consider log sampling for extremely high-volume rules
   - Monitor Heavy Forwarder queue sizes

6. **Firewall Admin Access**:
   - Limit who can modify syslog configurations
   - Enable MFA for firewall admin access
   - Log and monitor administrative changes

## Architecture Diagram

```
┌─────────────────┐    UDP/TCP 514    ┌─────────────────┐    TCP 9997    ┌─────────────────┐
│   Palo Alto     │ ─────────────────▶│  Splunk Heavy   │ ─────────────▶│    Splunk       │
│   Firewall      │                   │   Forwarder     │               │    Indexer      │
└─────────────────┘                   └─────────────────┘               └─────────────────┘
                                              │
                                              │ TCP 8089
                                              ▼
                                      ┌─────────────────┐
                                      │   Deployment    │
                                      │     Server      │
                                      └─────────────────┘
```

---

*Last Updated: January 2025*  
*Version: 1.0*
