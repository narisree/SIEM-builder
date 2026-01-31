"""
Use Case Loader
Handles loading and parsing of use cases from library.csv
"""

import csv
from pathlib import Path
from typing import Dict, List, Optional

class UseCaseLoader:
    """Loads and manages security use cases from library.csv."""
    
    # Mapping of log source names in KB to log source names in library.csv
    LOG_SOURCE_MAPPING = {
        "palo_alto": ["Palo Alto", "Palo Alto Firewall"],
        "windows_events": ["Windows", "Windows Events", "Windows Event"],
        "linux": ["Linux", "Linux Auditd"],
        "azure_ad": ["Azure AD", "Azure Active Directory", "AzureAD"],
        "cisco_asa": ["Cisco ASA", "Cisco Secure Firewall"],
        "checkpoint": ["Checkpoint", "Checkpoint Firewall", "Check Point"],
        "crowdstrike_edr": ["Crowdstrike", "CrowdStrike", "Crowdstrike EDR"],
        "o365": ["O365", "Office 365", "Microsoft 365"],
        "proofpoint": ["Proofpoint", "Proofpoint "],  # Note: some entries have trailing space
        "zscaler_proxy": ["Zscaler", "Zscaler Proxy"]
    }
    
    # L1 Analyst guidance templates based on MITRE tactics
    L1_DETECTION_GUIDANCE = {
        "Credential Access": {
            "what_it_detects": "This use case identifies attempts to steal or guess user credentials. Attackers often try multiple passwords or exploit authentication systems to gain unauthorized access.",
            "validation_steps": [
                "Verify if the source IP belongs to your organization or is from a known location",
                "Check if the affected user account is a service account or human user",
                "Review if there were any successful logins after the failed attempts",
                "Confirm with the user if they were having login issues at that time",
                "Check if the source IP has triggered similar alerts for other users",
                "Look for any password reset requests around the same timeframe"
            ]
        },
        "Command and Control": {
            "what_it_detects": "This use case detects potential communication between compromised systems and attacker-controlled infrastructure. Malware often 'phones home' to receive commands or exfiltrate data.",
            "validation_steps": [
                "Check if the destination IP/domain is in threat intelligence feeds (VirusTotal, AbuseIPDB)",
                "Verify if this is a legitimate business application (check with app owner)",
                "Look for regular interval patterns in the connections (beaconing behavior)",
                "Check if other hosts are connecting to the same destination",
                "Review the volume of data transferred - is it unusually high?",
                "Verify if the destination is a known CDN or cloud service"
            ]
        },
        "Exfiltration": {
            "what_it_detects": "This use case identifies potential data theft where sensitive information may be transferred outside the organization through various channels.",
            "validation_steps": [
                "Identify the user and check if large transfers are part of their normal job",
                "Verify the destination - is it an approved cloud storage or file sharing service?",
                "Check what type of data was transferred if possible",
                "Review if this user has accessed sensitive files recently",
                "Confirm if there's a legitimate business reason (e.g., project delivery, backup)",
                "Check if the transfer occurred outside business hours"
            ]
        },
        "Execution": {
            "what_it_detects": "This use case detects attempts to run malicious code or commands on systems. Attackers execute code to achieve their objectives after gaining initial access.",
            "validation_steps": [
                "Verify if the process/script is part of legitimate IT operations or software deployment",
                "Check if the parent process is expected (e.g., scheduled task, admin tool)",
                "Review if this activity was performed by an IT administrator",
                "Look at the timing - was this during a maintenance window?",
                "Check if the same activity occurred on multiple systems",
                "Verify the file hash against known malware databases"
            ]
        },
        "Initial Access": {
            "what_it_detects": "This use case identifies techniques attackers use to gain their first foothold in your network, such as phishing emails or exploiting public-facing applications.",
            "validation_steps": [
                "Check if the email sender is known or from a legitimate domain",
                "Verify if the attachment or link has been scanned by security tools",
                "Confirm if any user clicked on links or opened attachments",
                "Check threat intelligence for the sender domain/IP",
                "Review if similar emails were sent to other users (campaign detection)",
                "Verify if any malware was downloaded or executed after email delivery"
            ]
        },
        "Defense Evasion": {
            "what_it_detects": "This use case detects attempts by attackers to avoid detection by security tools, such as disabling security software, clearing logs, or modifying file permissions.",
            "validation_steps": [
                "Verify if the activity was performed by an authorized administrator",
                "Check if this is part of a legitimate system maintenance task",
                "Review change management tickets for any approved changes",
                "Confirm if the affected system is a development/test system",
                "Check if security tools are still functioning properly",
                "Look for other suspicious activities on the same system"
            ]
        },
        "Discovery": {
            "what_it_detects": "This use case identifies reconnaissance activities where attackers try to learn about your environment, such as scanning for open ports, enumerating users, or mapping the network.",
            "validation_steps": [
                "Check if the source is an authorized vulnerability scanner (Nessus, Qualys, etc.)",
                "Verify if this is a scheduled security assessment or penetration test",
                "Confirm if an IT admin was performing troubleshooting",
                "Review if the activity occurred during a known maintenance window",
                "Check the scope - is it targeting specific systems or scanning broadly?",
                "Look for follow-up activities that might indicate compromise"
            ]
        }
    }
    
    # Default guidance for unknown tactics
    DEFAULT_GUIDANCE = {
        "what_it_detects": "This use case identifies potentially suspicious activity that may indicate a security threat. The specific behavior detected should be investigated to determine if it's malicious.",
        "validation_steps": [
            "Review the source and destination of the activity",
            "Check if the user/system involved has legitimate business reasons for this activity",
            "Look for similar patterns across other users or systems",
            "Verify with the asset owner or user if this is expected behavior",
            "Check threat intelligence sources for any indicators of compromise",
            "Review historical data to see if this is normal for the environment",
            "If still suspicious, escalate to L2 for deeper investigation"
        ]
    }
    
    def __init__(self, kb_path: str = "kb"):
        """Initialize the Use Case Loader."""
        self.kb_path = Path(kb_path)
        self.library_file = self.kb_path / "library.csv"
        self._use_cases = self._load_use_cases()
    
    def _load_use_cases(self) -> List[Dict]:
        """Load all use cases from the CSV file."""
        use_cases = []
        
        if not self.library_file.exists():
            return use_cases
        
        try:
            with open(self.library_file, 'r', encoding='utf-8') as f:
                # Read the entire content and handle potential issues
                content = f.read()
                
            # Parse CSV content
            lines = content.strip().split('\n')
            if len(lines) < 2:
                return use_cases
            
            # Manual parsing to handle multi-line SPL queries
            headers = self._parse_csv_line(lines[0])
            
            # Combine all remaining lines and parse records
            current_record = []
            in_quotes = False
            
            for line in lines[1:]:
                current_record.append(line)
                # Count quotes to determine if we're inside a quoted field
                quote_count = line.count('"')
                if quote_count % 2 == 1:
                    in_quotes = not in_quotes
                
                if not in_quotes:
                    # We have a complete record
                    full_line = '\n'.join(current_record)
                    try:
                        record = self._parse_csv_record(full_line, headers)
                        if record:
                            use_cases.append(record)
                    except Exception as e:
                        pass  # Skip malformed records
                    current_record = []
            
        except Exception as e:
            print(f"Error loading use cases: {e}")
        
        return use_cases
    
    def _parse_csv_line(self, line: str) -> List[str]:
        """Parse a CSV line into fields."""
        import csv
        import io
        reader = csv.reader(io.StringIO(line))
        for row in reader:
            return row
        return []
    
    def _parse_csv_record(self, record_text: str, headers: List[str]) -> Optional[Dict]:
        """Parse a CSV record into a dictionary."""
        import csv
        import io
        
        reader = csv.reader(io.StringIO(record_text))
        for row in reader:
            if len(row) >= len(headers):
                return {headers[i]: row[i] for i in range(len(headers))}
            elif len(row) > 0:
                # Pad with empty strings if needed
                padded_row = row + [''] * (len(headers) - len(row))
                return {headers[i]: padded_row[i] for i in range(len(headers))}
        return None
    
    def get_use_cases_for_source(self, source_slug: str) -> List[Dict]:
        """Get all use cases for a specific log source."""
        matching_names = self.LOG_SOURCE_MAPPING.get(source_slug, [])
        
        if not matching_names:
            return []
        
        filtered_cases = []
        for use_case in self._use_cases:
            log_source = use_case.get('Log Source', '').strip()
            # Check if the log source matches any of the mapping names
            for name in matching_names:
                if name.lower() in log_source.lower() or log_source.lower() in name.lower():
                    # Add L1 guidance
                    enriched_case = self._enrich_with_l1_guidance(use_case)
                    filtered_cases.append(enriched_case)
                    break
        
        return filtered_cases
    
    def _enrich_with_l1_guidance(self, use_case: Dict) -> Dict:
        """Add L1 analyst guidance based on MITRE tactic."""
        enriched = use_case.copy()
        
        tactic = use_case.get('MITRE Tactics', '').strip()
        
        # Find matching guidance based on tactic
        guidance = self.DEFAULT_GUIDANCE
        for tactic_key, tactic_guidance in self.L1_DETECTION_GUIDANCE.items():
            if tactic_key.lower() in tactic.lower():
                guidance = tactic_guidance
                break
        
        enriched['L1_What_It_Detects'] = guidance['what_it_detects']
        enriched['L1_Validation_Steps'] = guidance['validation_steps']
        
        return enriched
    
    def get_all_log_sources(self) -> List[str]:
        """Get all unique log sources from the library."""
        sources = set()
        for use_case in self._use_cases:
            source = use_case.get('Log Source', '').strip()
            if source:
                sources.add(source)
        return sorted(list(sources))
    
    def get_use_case_count(self, source_slug: str) -> int:
        """Get the count of use cases for a specific log source."""
        return len(self.get_use_cases_for_source(source_slug))
    
    def search_use_cases(self, query: str, source_slug: Optional[str] = None) -> List[Dict]:
        """Search use cases by keyword."""
        query_lower = query.lower()
        
        if source_slug:
            use_cases = self.get_use_cases_for_source(source_slug)
        else:
            use_cases = [self._enrich_with_l1_guidance(uc) for uc in self._use_cases]
        
        results = []
        for use_case in use_cases:
            # Search in name, description, and technique
            searchable_text = ' '.join([
                use_case.get('Use case Name', ''),
                use_case.get('Description', ''),
                use_case.get('MITRE Technique', ''),
                use_case.get('MITRE Tactics', '')
            ]).lower()
            
            if query_lower in searchable_text:
                results.append(use_case)
        
        return results
