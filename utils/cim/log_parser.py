"""
Log Format Detection and Field Extraction Module
Supports: JSON, XML, Key-Value, Syslog, CEF, LEEF, CSV
"""
import re
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class LogFormat(Enum):
    """Supported log formats."""
    JSON = "json"
    XML = "xml"
    KEY_VALUE = "key_value"
    SYSLOG = "syslog"
    CEF = "cef"
    LEEF = "leef"
    CSV = "csv"
    UNKNOWN = "unknown"


@dataclass
class ParsedLog:
    """Container for parsed log information."""
    format: LogFormat
    fields: Dict[str, List[str]]
    sample_events: List[str]
    vendor: Optional[str] = None
    product: Optional[str] = None
    confidence: float = 0.0


class LogParser:
    """Intelligent log parser with format detection and field extraction."""
    
    def __init__(self):
        self.cef_pattern = re.compile(
            r'CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)'
        )
        self.leef_pattern = re.compile(
            r'LEEF:(\d+\.\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)'
        )
        self.kv_pattern = re.compile(r'(\w+)=("[^"]*"|\'[^\']*\'|[^\s]+)')
    
    def parse_file(self, file_content: bytes, filename: str = "") -> ParsedLog:
        """Parse log file and extract fields."""
        try:
            content = file_content.decode('utf-8', errors='ignore')
        except Exception:
            content = file_content.decode('latin-1', errors='ignore')
        
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        if not lines:
            return ParsedLog(
                format=LogFormat.UNKNOWN,
                fields={},
                sample_events=[],
                confidence=0.0
            )
        
        format_type, confidence = self._detect_format(lines, filename)
        
        if format_type == LogFormat.JSON:
            fields, vendor, product = self._parse_json(lines)
        elif format_type == LogFormat.CEF:
            fields, vendor, product = self._parse_cef(lines)
        elif format_type == LogFormat.LEEF:
            fields, vendor, product = self._parse_leef(lines)
        elif format_type == LogFormat.CSV:
            fields, vendor, product = self._parse_csv(lines)
        elif format_type == LogFormat.SYSLOG:
            fields, vendor, product = self._parse_syslog(lines)
        else:
            fields, vendor, product = self._parse_key_value(lines)
        
        return ParsedLog(
            format=format_type,
            fields=fields,
            sample_events=lines[:5],
            vendor=vendor,
            product=product,
            confidence=confidence
        )
    
    def _detect_format(self, lines: List[str], filename: str) -> Tuple[LogFormat, float]:
        """Detect log format with confidence score."""
        sample = lines[0] if lines else ""
        
        if sample.strip().startswith('{'):
            try:
                json.loads(sample)
                return LogFormat.JSON, 0.95
            except:
                pass
        
        if sample.strip().startswith('<'):
            return LogFormat.XML, 0.9
        
        if 'CEF:' in sample:
            return LogFormat.CEF, 0.95
        
        if 'LEEF:' in sample:
            return LogFormat.LEEF, 0.95
        
        if filename.endswith('.csv') or ',' in sample:
            if sample.count(',') >= 3:
                return LogFormat.CSV, 0.8
        
        syslog_pattern = r'^<\d+>|^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        if re.match(syslog_pattern, sample):
            return LogFormat.SYSLOG, 0.85
        
        kv_matches = self.kv_pattern.findall(sample)
        if len(kv_matches) >= 3:
            return LogFormat.KEY_VALUE, 0.7
        
        return LogFormat.UNKNOWN, 0.3
    
    def _parse_json(self, lines: List[str]) -> Tuple[Dict[str, List[str]], Optional[str], Optional[str]]:
        """Parse JSON formatted logs."""
        fields = {}
        vendor = None
        product = None
        
        for line in lines[:100]:
            try:
                event = json.loads(line)
                self._extract_fields_recursive(event, fields)
                
                if not vendor:
                    vendor = event.get('vendor') or event.get('Vendor') or event.get('source_vendor')
                if not product:
                    product = event.get('product') or event.get('Product') or event.get('source_product')
                    
            except json.JSONDecodeError:
                continue
        
        return fields, vendor, product
    
    def _parse_cef(self, lines: List[str]) -> Tuple[Dict[str, List[str]], Optional[str], Optional[str]]:
        """Parse CEF (Common Event Format) logs."""
        fields = {
            'cef_version': [], 'device_vendor': [], 'device_product': [],
            'device_version': [], 'signature_id': [], 'name': [], 'severity': []
        }
        vendor = None
        product = None
        
        for line in lines[:100]:
            match = self.cef_pattern.search(line)
            if match:
                fields['cef_version'].append(match.group(1))
                vendor = vendor or match.group(2)
                product = product or match.group(3)
                fields['device_vendor'].append(match.group(2))
                fields['device_product'].append(match.group(3))
                fields['device_version'].append(match.group(4))
                fields['signature_id'].append(match.group(5))
                fields['name'].append(match.group(6))
                fields['severity'].append(match.group(7))
                
                extension = match.group(8)
                ext_fields = self.kv_pattern.findall(extension)
                for key, value in ext_fields:
                    if key not in fields:
                        fields[key] = []
                    fields[key].append(value.strip('"\''))
        
        return fields, vendor, product
    
    def _parse_leef(self, lines: List[str]) -> Tuple[Dict[str, List[str]], Optional[str], Optional[str]]:
        """Parse LEEF (Log Event Extended Format) logs."""
        fields = {'leef_version': [], 'vendor': [], 'product': [], 'version': []}
        vendor = None
        product = None
        
        for line in lines[:100]:
            match = self.leef_pattern.search(line)
            if match:
                fields['leef_version'].append(match.group(1))
                vendor = vendor or match.group(2)
                product = product or match.group(3)
                fields['vendor'].append(match.group(2))
                fields['product'].append(match.group(3))
                fields['version'].append(match.group(4))
                
                attributes = match.group(5)
                attr_fields = self.kv_pattern.findall(attributes)
                for key, value in attr_fields:
                    if key not in fields:
                        fields[key] = []
                    fields[key].append(value.strip('"\''))
        
        return fields, vendor, product
    
    def _parse_csv(self, lines: List[str]) -> Tuple[Dict[str, List[str]], Optional[str], Optional[str]]:
        """Parse CSV formatted logs."""
        fields = {}
        
        if not lines:
            return fields, None, None
        
        headers = [h.strip() for h in lines[0].split(',')]
        
        for header in headers:
            fields[header] = []
        
        for line in lines[1:101]:
            values = [v.strip().strip('"') for v in line.split(',')]
            for i, value in enumerate(values):
                if i < len(headers):
                    fields[headers[i]].append(value)
        
        return fields, None, None
    
    def _parse_syslog(self, lines: List[str]) -> Tuple[Dict[str, List[str]], Optional[str], Optional[str]]:
        """Parse Syslog formatted logs."""
        fields = {'timestamp': [], 'hostname': [], 'process': [], 'message': []}
        
        syslog_pattern = r'^(?:<\d+>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s*(.*)'
        
        for line in lines[:100]:
            match = re.match(syslog_pattern, line)
            if match:
                fields['timestamp'].append(match.group(1))
                fields['hostname'].append(match.group(2))
                fields['process'].append(match.group(3))
                message = match.group(4)
                fields['message'].append(message)
                
                kv_matches = self.kv_pattern.findall(message)
                for key, value in kv_matches:
                    if key not in fields:
                        fields[key] = []
                    fields[key].append(value.strip('"\''))
        
        return fields, None, None
    
    def _parse_key_value(self, lines: List[str]) -> Tuple[Dict[str, List[str]], Optional[str], Optional[str]]:
        """Parse key-value formatted logs."""
        fields = {}
        
        for line in lines[:100]:
            matches = self.kv_pattern.findall(line)
            for key, value in matches:
                if key not in fields:
                    fields[key] = []
                fields[key].append(value.strip('"\''))
        
        return fields, None, None
    
    def _extract_fields_recursive(self, obj, fields: Dict[str, List[str]], prefix: str = ""):
        """Recursively extract fields from nested JSON objects."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                field_name = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._extract_fields_recursive(value, fields, field_name)
                else:
                    if field_name not in fields:
                        fields[field_name] = []
                    fields[field_name].append(str(value))
        elif isinstance(obj, list):
            for item in obj:
                self._extract_fields_recursive(item, fields, prefix)
