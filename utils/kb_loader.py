"""
Knowledge Base Loader
Handles loading and parsing of markdown KB files and references.
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional

class KBLoader:
    """Loads and manages Knowledge Base content for log sources."""
    
    def __init__(self, kb_path: str = "kb"):
        """
        Initialize the KB Loader.
        
        Args:
            kb_path: Path to the knowledge base directory
        """
        self.kb_path = Path(kb_path)
        self.references_file = self.kb_path / "references.json"
        self._sources_catalog = self._load_sources_catalog()
    
    def _load_sources_catalog(self) -> Dict:
        """
        Load the catalog of available log sources.
        Returns a dictionary mapping source slugs to their metadata.
        """
        # Define the catalog of supported log sources
        catalog = {
            "palo_alto": {
                "display_name": "Palo Alto Firewall",
                "category": "Firewall",
                "vendor": "Palo Alto Networks"
            },
            "windows_events": {
                "display_name": "Windows Events",
                "category": "Operating System",
                "vendor": "Microsoft"
            },
            "linux": {
                "display_name": "Linux (Syslog)",
                "category": "Operating System",
                "vendor": "Various"
            },
            "azure_ad": {
                "display_name": "Azure AD (Microsoft Entra ID)",
                "category": "Identity & Access",
                "vendor": "Microsoft"
            },
            "cisco_asa": {
                "display_name": "Cisco ASA",
                "category": "Firewall",
                "vendor": "Cisco"
            },
            "checkpoint": {
                "display_name": "Check Point Firewall",
                "category": "Firewall",
                "vendor": "Check Point"
            },
            "crowdstrike_edr": {
                "display_name": "CrowdStrike EDR",
                "category": "Endpoint Detection & Response",
                "vendor": "CrowdStrike"
            },
            "o365": {
                "display_name": "Office 365 (Microsoft 365)",
                "category": "Cloud Services",
                "vendor": "Microsoft"
            },
            "proofpoint": {
                "display_name": "Proofpoint",
                "category": "Email Security",
                "vendor": "Proofpoint"
            },
            "zscaler_proxy": {
                "display_name": "Zscaler Proxy",
                "category": "Secure Web Gateway",
                "vendor": "Zscaler"
            }
        }
        return catalog
    
    def get_available_sources(self) -> Dict:
        """
        Get all available log sources from the catalog.
        
        Returns:
            Dictionary of source slugs to their metadata
        """
        return self._sources_catalog
    
    def load_kb_content(self, source_slug: str) -> Dict:
        """
        Load the knowledge base content for a specific log source.
        
        Args:
            source_slug: The slug identifier for the log source
            
        Returns:
            Dictionary with 'success', 'content', and 'message' keys
        """
        kb_file = self.kb_path / f"{source_slug}.md"
        
        try:
            if kb_file.exists():
                with open(kb_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                return {
                    "success": True,
                    "content": content,
                    "message": "KB content loaded successfully"
                }
            else:
                return {
                    "success": False,
                    "content": "",
                    "message": f"Knowledge base file not found: {kb_file}"
                }
        except Exception as e:
            return {
                "success": False,
                "content": "",
                "message": f"Error loading KB content: {str(e)}"
            }
    
    def get_references(self, source_slug: str) -> Dict:
        """
        Get reference links for a specific log source.
        
        Args:
            source_slug: The slug identifier for the log source
            
        Returns:
            Dictionary with 'success', 'data', and 'message' keys
        """
        try:
            if self.references_file.exists():
                with open(self.references_file, 'r', encoding='utf-8') as f:
                    all_references = json.load(f)
                
                if source_slug in all_references:
                    return {
                        "success": True,
                        "data": all_references[source_slug],
                        "message": "References loaded successfully"
                    }
                else:
                    return {
                        "success": False,
                        "data": {},
                        "message": f"No references found for source: {source_slug}"
                    }
            else:
                return {
                    "success": False,
                    "data": {},
                    "message": f"References file not found: {self.references_file}"
                }
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "data": {},
                "message": f"Error parsing references JSON: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "data": {},
                "message": f"Error loading references: {str(e)}"
            }
    
    def get_source_metadata(self, source_slug: str) -> Optional[Dict]:
        """
        Get metadata for a specific log source.
        
        Args:
            source_slug: The slug identifier for the log source
            
        Returns:
            Dictionary with source metadata or None if not found
        """
        return self._sources_catalog.get(source_slug)
    
    def source_exists(self, source_slug: str) -> bool:
        """
        Check if a log source exists in the catalog.
        
        Args:
            source_slug: The slug identifier for the log source
            
        Returns:
            True if source exists, False otherwise
        """
        return source_slug in self._sources_catalog
    
    def kb_file_exists(self, source_slug: str) -> bool:
        """
        Check if the KB markdown file exists for a source.
        
        Args:
            source_slug: The slug identifier for the log source
            
        Returns:
            True if KB file exists, False otherwise
        """
        kb_file = self.kb_path / f"{source_slug}.md"
        return kb_file.exists()
    
    def get_kb_sections(self, source_slug: str) -> List[str]:
        """
        Extract section headings from a KB file.
        
        Args:
            source_slug: The slug identifier for the log source
            
        Returns:
            List of section headings found in the KB
        """
        kb_data = self.load_kb_content(source_slug)
        if not kb_data["success"]:
            return []
        
        sections = []
        for line in kb_data["content"].split('\n'):
            if line.startswith('## '):
                sections.append(line[3:].strip())
            elif line.startswith('### '):
                sections.append(line[4:].strip())
        
        return sections
