# Linux (Syslog) Integration Guide

## Overview

This document provides guidance for integrating Linux system logs into Splunk via syslog or Universal Forwarder. Linux logs provide visibility into system events, authentication, security alerts, and application activities.

**Log Source Type:** Agent-based (UF) or Syslog  
**Vendor:** Various (Red Hat, Ubuntu, CentOS, etc.)  
**Category:** Operating System Logs  
**Primary Index:** `linux_os`  
**Sourcetypes:** `syslog`, `linux_secure`, `linux_messages`, `linux_audit`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Linux Server** - Supported distributions (RHEL 7+, Ubuntu 18.04+, CentOS 7+)
2. **Root/Sudo Access** - Administrative privileges on target servers
3. **Splunk Infrastructure** - Active Splunk deployment with Heavy Forwarder or Indexer
4. **Network Connectivity** - Required ports open between components
5. **Splunk Universal Forwarder** - Downloaded for Linux x64

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Linux Server (UF) | Splunk HF/Indexer | TCP 9997 | TCP | Log forwarding |
| Linux Server (UF) | Deployment Server | TCP 8089 | TCP | Management |
| Linux Server (Syslog) | Syslog Server | UDP 514 | UDP | Syslog forwarding |

## Logging Standard

### Recommended Log Files

| Log File | Description | Priority |
|----------|-------------|----------|
| `/var/log/secure` | Authentication events (RHEL/CentOS) | High |
| `/var/log/auth.log` | Authentication events (Ubuntu/Debian) | High |
| `/var/log/messages` | General system messages | High |
| `/var/log/syslog` | System log (Ubuntu/Debian) | High |
| `/var/log/audit/audit.log` | SELinux/Audit events | High |
| `/var/log/cron` | Cron job logs | Medium |

### Time Synchronization

- Ensure NTP is configured (`chronyd` or `ntpd`)
- Use UTC timezone for consistency
- Verify time sync: `timedatectl status`

## Log Collection Standard

### Source-Side Steps (Linux Server)

#### Step 1: Download Universal Forwarder

```bash
wget -O splunkforwarder.rpm "https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6.x86_64.rpm"
```

#### Step 2: Install Universal Forwarder

```bash
# RHEL/CentOS
sudo rpm -i splunkforwarder.rpm

# Ubuntu/Debian
sudo dpkg -i splunkforwarder.deb
```

#### Step 3: Configure and Start

```bash
cd /opt/splunkforwarder/bin
sudo ./splunk start --accept-license
sudo ./splunk enable boot-start
```

#### Step 4: Configure Deployment Server

```bash
sudo ./splunk set deploy-poll <DEPLOYMENT_SERVER>:8089
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Unix and Linux

Deploy to Search Heads, Heavy Forwarders, and Deployment Server.

#### Step 2: Configure inputs.conf

```ini
[monitor:///var/log/secure]
index = linux_os
sourcetype = linux_secure
disabled = 0

[monitor:///var/log/messages]
index = linux_os
sourcetype = linux_messages
disabled = 0

[monitor:///var/log/audit/audit.log]
index = linux_os
sourcetype = linux_audit
disabled = 0
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk_TA_nix | Input collection and field extraction |
| Index | linux_os | Storage for Linux logs |

## Sample Configuration Snippets

### inputs.conf

```ini
[monitor:///var/log]
whitelist = (messages|secure|auth\.log|syslog|cron)
blacklist = (\.gz$|\.bz2$|\.zip$|\.\d+$)
index = linux_os
sourcetype = syslog
disabled = 0
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=linux_os earliest=-15m
| stats count by host, sourcetype
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Permission denied | UF user lacks read access | Add splunk user to adm group |
| No data | Logs not being written | Check rsyslog/journald configuration |
| Duplicate events | Multiple inputs for same file | Review inputs.conf for overlaps |

## Security Notes

1. Run Universal Forwarder as non-root user
2. Grant only necessary file read permissions
3. Use TLS for log forwarding in sensitive environments
4. Monitor forwarder health and connectivity

---

*Last Updated: January 2025*  
*Version: 1.0 (Stub - Expand as needed)*
