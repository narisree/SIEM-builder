# Azure AD (Microsoft Entra ID) Integration Guide

## Overview

This document provides guidance for integrating Microsoft Entra ID (formerly Azure Active Directory) logs into Splunk. Azure AD logs provide critical visibility into identity and access management events, including sign-ins, user activities, and security alerts.

**Log Source Type:** API-based (Azure Event Hub or Direct API)  
**Vendor:** Microsoft  
**Category:** Identity & Access Management  
**Primary Index:** `azure_ad`  
**Sourcetypes:** `azure:aad:signin`, `azure:aad:audit`, `azure:aad:identity`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Azure Subscription** - Active Azure subscription with Azure AD Premium P1/P2 license (required for full sign-in logs)
2. **Azure Permissions** - Global Administrator or Security Administrator role
3. **Splunk Infrastructure** - Active Splunk deployment
4. **Splunk Add-on for Microsoft Cloud Services** - Downloaded from Splunkbase
5. **Azure App Registration** - Service principal with appropriate permissions
6. **Network Connectivity** - Outbound HTTPS access to Azure APIs

### Azure AD License Requirements

| Log Type | License Required |
|----------|------------------|
| Audit Logs | Azure AD Free |
| Sign-in Logs | Azure AD Premium P1/P2 |
| Provisioning Logs | Azure AD Premium P1/P2 |
| Identity Protection | Azure AD Premium P2 |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Splunk HF | login.microsoftonline.com | 443 | HTTPS | OAuth authentication |
| Splunk HF | graph.microsoft.com | 443 | HTTPS | Microsoft Graph API |
| Splunk HF | management.azure.com | 443 | HTTPS | Azure Management API |
| Splunk HF | *.servicebus.windows.net | 443 | HTTPS | Event Hub (if used) |

## Logging Standard

### Recommended Log Types

| Log Type | Description | Priority | Retention |
|----------|-------------|----------|-----------|
| **Sign-in Logs** | Interactive and non-interactive sign-ins | High | 30 days (Azure) |
| **Audit Logs** | Directory changes, user/group management | High | 30 days (Azure) |
| **Provisioning Logs** | SCIM provisioning activities | Medium | 30 days (Azure) |
| **Risky Sign-ins** | Sign-ins flagged by Identity Protection | High | 30 days |
| **Risky Users** | Users flagged for risk | High | 30 days |

### Key Fields to Capture

- `userPrincipalName` - User identifier
- `ipAddress` - Source IP address
- `location` - Geographic location
- `clientAppUsed` - Application type
- `deviceDetail` - Device information
- `status.errorCode` - Sign-in result
- `conditionalAccessStatus` - CA policy evaluation
- `riskLevelDuringSignIn` - Risk assessment

### Time Synchronization

- Azure AD logs are in UTC timezone
- Timestamps are in ISO 8601 format
- Consider timezone conversion for local reporting

## Log Collection Standard

### Collection Method Options

1. **Azure Event Hub** (Recommended for high volume)
2. **Microsoft Graph API** (Direct polling)
3. **Azure Monitor Integration** (Log Analytics)

### Source-Side Steps (Azure Portal)

#### Step 1: Create Azure App Registration

1. Sign in to **Azure Portal** > **Azure Active Directory**
2. Navigate to **App registrations** > **New registration**
3. Configure:
   - **Name**: `Splunk-AAD-Integration`
   - **Supported account types**: Single tenant
   - **Redirect URI**: Leave blank
4. Click **Register**
5. Note the **Application (client) ID** and **Directory (tenant) ID**

#### Step 2: Create Client Secret

1. In the App Registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Add description: `Splunk Integration`
4. Select expiration: 24 months (maximum)
5. Click **Add**
6. **Copy the secret value immediately** (shown only once)

#### Step 3: Assign API Permissions

1. Go to **API permissions** > **Add a permission**
2. Select **Microsoft Graph**
3. Choose **Application permissions**
4. Add the following permissions:
   - `AuditLog.Read.All`
   - `Directory.Read.All`
   - `IdentityRiskEvent.Read.All`
   - `IdentityRiskyUser.Read.All`
   - `Policy.Read.All`
   - `SecurityEvents.Read.All`
5. Click **Grant admin consent**

#### Step 4: Configure Diagnostic Settings (Event Hub Method)

1. Navigate to **Azure Active Directory** > **Diagnostic settings**
2. Click **Add diagnostic setting**
3. Configure:
   - **Name**: `Export-to-Splunk`
   - **Logs**: Select all log categories
   - **Destination**: Stream to Event Hub
4. Configure Event Hub:
   - Create new Event Hub namespace if needed
   - Select or create Event Hub
5. Click **Save**

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Microsoft Cloud Services

```bash
# Download from Splunkbase
# Install on Search Heads and Heavy Forwarders
/opt/splunk/bin/splunk install app splunk-add-on-for-microsoft-cloud-services.tgz
```

#### Step 2: Configure Azure AD Account

1. Navigate to **Settings** > **Data Inputs**
2. Click **Splunk Add-on for Microsoft Cloud Services**
3. Go to **Configuration** > **Account**
4. Click **Add**
5. Enter credentials:
   - **Account Name**: `Azure-AD-Production`
   - **Client ID**: `<Application_ID>`
   - **Client Secret**: `<Secret_Value>`
   - **Tenant ID**: `<Directory_ID>`

#### Step 3: Create Data Inputs

**For Azure AD Audit Logs:**

1. Go to **Inputs** > **Create New Input** > **Azure AD Audit**
2. Configure:
   - **Name**: `azuread_audit_prod`
   - **Account**: Select configured account
   - **Index**: `azure_ad`
   - **Interval**: 300 (5 minutes)

**For Azure AD Sign-in Logs:**

1. Create New Input > **Azure AD Sign-in**
2. Configure:
   - **Name**: `azuread_signin_prod`
   - **Account**: Select configured account
   - **Index**: `azure_ad`
   - **Interval**: 300

#### Step 4: Configure Index

Create the index in `indexes.conf`:

```ini
[azure_ad]
homePath = $SPLUNK_DB/azure_ad/db
coldPath = $SPLUNK_DB/azure_ad/colddb
thawedPath = $SPLUNK_DB/azure_ad/thaweddb
maxTotalDataSizeMB = 512000
frozenTimePeriodInSecs = 7776000
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk Add-on for Microsoft Cloud Services | Data collection and parsing |
| Add-on | Splunk Add-on for Microsoft Azure | Additional Azure data |
| Index | azure_ad | Log storage |

### Configuration Files Summary

| File | Purpose |
|------|---------|
| inputs.conf | Define Azure AD data inputs |
| azure_ad_account.conf | Store Azure credentials (encrypted) |
| props.conf | Parsing and field extraction |
| transforms.conf | Field transformations |

## Sample Configuration Snippets

### inputs.conf (Graph API Method)

```ini
[azure_ad_audit://azuread_audit]
account = Azure-AD-Production
index = azure_ad
interval = 300
sourcetype = azure:aad:audit

[azure_ad_signin://azuread_signin]
account = Azure-AD-Production  
index = azure_ad
interval = 300
sourcetype = azure:aad:signin
```

### inputs.conf (Event Hub Method)

```ini
[azure_event_hub://aad_events]
event_hub_namespace = <NAMESPACE>.servicebus.windows.net
event_hub_name = insights-logs-auditlogs
consumer_group = $Default
account = Azure-EventHub-Account
index = azure_ad
sourcetype = azure:eventhub
interval = 60
```

### props.conf

```ini
[azure:aad:signin]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%Z
TIME_PREFIX = "createdDateTime"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 32
TZ = UTC
SHOULD_LINEMERGE = false
KV_MODE = json
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=azure_ad earliest=-1h
| stats count by sourcetype
```

### Check Sign-in Activity

```spl
index=azure_ad sourcetype="azure:aad:signin"
| stats count by userPrincipalName, status.errorCode
| sort -count
```

### Monitor Failed Sign-ins

```spl
index=azure_ad sourcetype="azure:aad:signin" "status.errorCode"!=0
| stats count by userPrincipalName, ipAddress, status.failureReason
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No data collected | Invalid credentials | Verify App Registration and secret |
| Permission denied | Missing API permissions | Add and grant admin consent for required permissions |
| Partial data | License limitation | Verify Azure AD Premium license |
| Duplicate events | Multiple inputs | Check for overlapping input configurations |
| Stale data | API throttling | Increase polling interval |

### API Throttling

Microsoft Graph API has rate limits:
- 10,000 requests per 10 minutes per app
- Throttled requests return HTTP 429
- Implement exponential backoff

### Diagnostic Searches

```spl
# Check modular input health
index=_internal sourcetype=splunkd component=ModularInputs azure
| stats count by log_level, message

# Monitor API calls
index=_internal source=*azure* 
| stats count by action, status
```

## Security Notes

1. **Credential Security**:
   - Store client secrets securely (Splunk encrypts automatically)
   - Rotate secrets before expiration (set calendar reminder)
   - Use certificate authentication for higher security

2. **Least Privilege**:
   - Grant only required API permissions
   - Use read-only permissions where possible
   - Avoid Global Administrator for integration account

3. **Data Sensitivity**:
   - Sign-in logs contain PII (usernames, IPs, locations)
   - Implement role-based access in Splunk
   - Consider data masking for sensitive fields

4. **Monitoring the Integration**:
   - Alert on authentication failures to Azure
   - Monitor for gaps in log collection
   - Track API quota usage

5. **Conditional Access**:
   - Consider excluding Splunk service principal from CA policies
   - Or ensure it meets CA requirements (managed device, etc.)

6. **Audit Trail**:
   - Azure logs the service principal's Graph API calls
   - Monitor for unusual API access patterns
   - Review Azure AD audit logs for changes to the app registration

## Use Cases

### Security Monitoring

```spl
# Impossible travel detection
index=azure_ad sourcetype="azure:aad:signin" 
| iplocation ipAddress
| stats earliest(_time) as first_login, latest(_time) as last_login, 
  values(City) as cities, values(Country) as countries by userPrincipalName
| where mvcount(countries) > 1
```

### Compliance Reporting

```spl
# MFA usage report
index=azure_ad sourcetype="azure:aad:signin"
| stats count as total,
  count(eval(authenticationMethodsUsed="*mfa*")) as mfa_count
  by userPrincipalName
| eval mfa_percentage = round((mfa_count/total)*100, 2)
```

---

*Last Updated: January 2025*  
*Version: 1.0*
