"""
LLM-based CIM Mapping Chain
Uses the shared AI client from the main app
"""
import re
import json
import re
import json
from typing import Dict, List, Optional, Tuple
from utils.cim.log_parser import ParsedLog
from utils.cim.vector_store import CIMVectorStore


# System prompt for CIM mapping
CIM_MAPPING_SYSTEM_PROMPT = """You are a Splunk CIM (Common Information Model) mapping expert. Your task is to map log fields to CIM data model fields.

CRITICAL INSTRUCTION: You MUST check the '[FLAG: ...]' for each CIM field in the provided "Relevant CIM Knowledge".

**FIELD FLAG RULES (STRICTLY FOLLOW):**
1. [FLAG: CALCULATED]
   - Transformation MUST be 'Eval'
   - Field Flag MUST be 'calculated'
   - You MUST write an EVAL expression for this field
   - EXAMPLE: | raw_field | cim_field | Eval | calculated | Required | coalesce(raw_field, "unknown") |

2. [FLAG: EXTRACTED]
   - Transformation MUST be 'Alias'
   - Field Flag MUST be 'extracted'
   - You MUST use a simple field alias
   - EXAMPLE: | raw_field | cim_field | Alias | extracted | Required | Direct mapping |

3. [FLAG: INHERITED]
   - DO NOT MAP these fields (host, source, sourcetype, _time)

== CORRECT ROW EXAMPLE ==
| action_id | action | Eval  | calculated | Required | case(action_id=1, "success", action_id=0, "failure") |
| src_ip    | src    | Alias | extracted  | Required | Direct mapping |

NEVER use 'Alias' for a field marked as [FLAG: CALCULATED].
NEVER use 'Eval' for a field marked as [FLAG: EXTRACTED] unless you are actually transforming the value (e.g. lower()).

CRITICAL: The 'Raw Field' in your output MUST be exactly one of the known field names derived from the Log Format (listed below in 'DETECTED FIELDS').
NEVER use a sample value (like an IP address "192.168.1.1" or timestamp) as a field name. 
Structure your output so that the Raw Field is always the NAME of the field.
"""

CIM_MAPPING_USER_PROMPT = """Analyze the following log data and provide CIM mappings.

LOG FORMAT: {log_format}
VENDOR: {vendor}
PRODUCT: {product}
CONFIDENCE: {format_confidence}

DETECTED FIELDS (These are the ONLY valid Raw Field names you can use):
{field_list}

VENDOR DOCUMENTATION:
{vendor_docs}
(Note: This documentation might contain unrelated text. FOCUS ONLY on log field definitions, schema details, and example events.)

SAMPLE LOG EVENTS:
{sample_events}

RELEVANT CIM KNOWLEDGE:
{cim_context}

Provide your analysis in this EXACT format:

## Data Model: [Primary CIM Data Model Name]
## Dataset: [Specific Dataset Name]
## Confidence: [0-100]%
## Reasoning: [Why this data model was chosen]

## Field Mappings:
| Raw Field | CIM Field | Transformation | Field Flag | Requirement | Notes |
|-----------|-----------|----------------|------------|-------------|-------|
| raw_field1 | cim_field1 | Alias | extracted | Required | Direct mapping |
| raw_field2 | cim_field2 | Eval | calculated | Required | coalesce(field1, field2) |

## Required Tags:
- tag1
- tag2

## Calculated Fields (EVAL expressions):
```
EVAL-action = case(status="allow", "allowed", status="deny", "blocked", 1=1, "allowed")
EVAL-src = coalesce(src_ip, source_address, client_ip)
```

## Field Aliases:
```
FIELDALIAS-src_port = source_port AS src_port
```

## Validation SPL:
```spl
index=* sourcetype=your_sourcetype
| table _time, [key CIM fields]
| head 100
```

## Warnings/Uncertainties:
- List any fields you couldn't map with high confidence
"""


class CIMMappingChain:
    """RAG chain for intelligent CIM field mapping using the shared AI client."""
    
    def __init__(self, vector_store: CIMVectorStore, ai_client=None):
        """
        Initialize the CIM mapping chain.
        
        Args:
            vector_store: Initialized CIM vector store
            ai_client: AI client from the main app (GroqClient, etc.)
        """
        self.vector_store = vector_store
        self.ai_client = ai_client
    
    def _get_cim_context(self, field_list: str) -> str:
        """Retrieve relevant CIM documentation based on detected fields."""
        if not self.vector_store.available:
            return "CIM knowledge base not available. Providing general guidance."
        
        results = self.vector_store.search_similar_fields(field_list, n_results=20)
        
        if not results:
            return "No relevant CIM documentation found."
        
        context_parts = []
        seen_models = set()
        
        for result in results:
            metadata = result['metadata']
            data_model = metadata.get('data_model', '')
            dataset = metadata.get('dataset', '')
            field_name = metadata.get('field_name', '')
            requirement = metadata.get('requirement', '')
            prescribed_values = metadata.get('prescribed_values', '')
            field_flag = metadata.get('field_flag', 'extracted')
            
            model_key = f"{data_model}_{dataset}"
            if model_key not in seen_models:
                context_parts.append(f"\n### {data_model} > {dataset}")
                context_parts.append(f"Tags: {metadata.get('tags', '')}")
                seen_models.add(model_key)
            
            flag_display = f"[FLAG: {field_flag.upper()}]"
            mapping_hint = ""
            if field_flag == "calculated":
                mapping_hint = " → MUST use EVAL"
            elif field_flag == "extracted":
                mapping_hint = " → use FIELDALIAS"
            elif field_flag == "inherited":
                mapping_hint = " → DO NOT MAP"
            
            field_info = f"- **{field_name}** {flag_display}{mapping_hint} ({requirement})"
            if prescribed_values:
                field_info += f"\n  Prescribed values: {prescribed_values}"
            
            context_parts.append(field_info)
        
        context_header = """
=== FIELD FLAG REFERENCE (VITAL) ===
- [FLAG: CALCULATED] -> MUST be 'Eval' -> MUST be 'calculated'
- [FLAG: EXTRACTED]  -> MUST be 'Alias' -> MUST be 'extracted'
- [FLAG: INHERITED]  -> DO NOT MAP
====================================
"""
        
        return context_header + "\n".join(context_parts)
    
    def analyze(self, parsed_log: ParsedLog, vendor_docs: Optional[str] = None) -> Dict:
        """Analyze parsed log and generate CIM mappings."""
        if not self.ai_client:
            return {
                "success": False,
                "error": "No AI client configured. Please configure an AI provider in AI Setup tab.",
                "mapping": None,
                "confidence": 0.0,
                "data_model": None,
                "dataset": None,
                "parsed_log": parsed_log
            }
        
        # Format field list
        field_list = "\n".join([
            f"- Field Name: \"{field_name}\" | Samples: {json.dumps(list(set(values))[:3])}"
            for field_name, values in list(parsed_log.fields.items())[:25]
        ])
        
        # Format sample events
        sample_events = "\n\n".join([
            f"Event {i+1}:\n{event}"
            for i, event in enumerate(parsed_log.sample_events[:3])
        ])
        
        # Get CIM context
        cim_context = self._get_cim_context(field_list)
        
        # Build the prompt
        user_prompt = CIM_MAPPING_USER_PROMPT.format(
            log_format=parsed_log.format.value,
            vendor=parsed_log.vendor or "Unknown",
            product=parsed_log.product or "Unknown",
            format_confidence=f"{parsed_log.confidence:.0%}",
            field_list=field_list,
            sample_events=sample_events,
            cim_context=cim_context,
            vendor_docs=vendor_docs[:2000] if vendor_docs else "No vendor documentation provided."
        )
        
        # Build KB content for the AI client
        kb_content = f"{CIM_MAPPING_SYSTEM_PROMPT}\n\n{cim_context}"
        
        try:
            # Use the shared AI client
            response = self.ai_client.get_response(
                question=user_prompt,
                kb_content=kb_content,
                source_name="CIM Mapping Assistant"
            )
            
            if response["success"]:
                result_text = response["response"]
                confidence = self._extract_confidence(result_text)
                data_model = self._extract_data_model(result_text)
                dataset = self._extract_dataset(result_text)
                # Repair mapping (fix values -> keys)
                repaired_mapping, repair_notes = self._repair_mapping(result_text, parsed_log)
                
                confidence = self._extract_confidence(repaired_mapping)
                data_model = self._extract_data_model(repaired_mapping)
                dataset = self._extract_dataset(repaired_mapping)
                
                return {
                    "success": True,
                    "mapping": repaired_mapping,
                    "repair_notes": repair_notes,
                    "confidence": confidence,
                    "data_model": data_model,
                    "dataset": dataset,
                    "parsed_log": parsed_log
                }
            else:
                return {
                    "success": False,
                    "error": response["message"],
                    "mapping": None,
                    "confidence": 0.0,
                    "data_model": None,
                    "dataset": None,
                    "parsed_log": parsed_log
                }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "mapping": None,
                "confidence": 0.0,
                "data_model": None,
                "dataset": None,
                "parsed_log": parsed_log
            }
    
    def _extract_confidence(self, result: str) -> float:
        """Extract confidence score from LLM response."""
        match = re.search(r'Confidence:\s*(\d+)%', result)
        if match:
            return float(match.group(1)) / 100
        return 0.5
    
    def _extract_data_model(self, result: str) -> Optional[str]:
        """Extract data model name from LLM response."""
        match = re.search(r'Data Model:\s*(.+)', result)
        if match:
            return match.group(1).strip()
        return None
    
    def _extract_dataset(self, result: str) -> Optional[str]:
        """Extract dataset name from LLM response."""
        match = re.search(r'Dataset:\s*(.+)', result)
        if match:
            return match.group(1).strip()
        return None

    def _repair_mapping(self, mapping_text: str, parsed_log: ParsedLog) -> Tuple[str, List[str]]:
        """
        Post-process the LLM output to fix common hallucinations.
        Specifically, replaces field VALUES (e.g., '192.168.1.1') with field NAMES (e.g., 'src_ip').
        """
        repair_notes = []
        
        # Create a Value -> Field Name map
        # We handle string representations of values
        value_to_field = {}
        for field_name, values in parsed_log.fields.items():
            for val in values:
                # Normalization for matching (strip quotes, lowercase if reasonable, but standard string match is safest)
                # We map the string representation of the value to the field name
                v_str = str(val).strip('"').strip("'")
                if len(v_str) > 1: # Avoid mapping single chars which might be risky
                    value_to_field[v_str] = field_name
        
        # Regex to find table rows: | raw_val | cim_field | ...
        # We capture the line and the first cell content
        def replace_row(match):
            full_line = match.group(0)
            raw_content = match.group(1).strip()
            
            # If the raw content is already a valid field name, do nothing
            if raw_content in parsed_log.fields:
                return full_line
            
            # If it's a known value, swap it
            clean_raw = raw_content.strip('"').strip("'")
            if clean_raw in value_to_field:
                correct_field = value_to_field[clean_raw]
                repair_notes.append(f"Repaired: '{raw_content}' -> '{correct_field}'")
                # Rebuild the line with the correct field name
                # We replace the first occurrence of the raw content in the line
                return full_line.replace(raw_content, correct_field, 1)
            
            return full_line

        # Pattern matches a markdown table row starts with | 
        # Group 1 is the content of the first cell
        # We look for lines that look like field mappings
        repaired_text = re.sub(r'^\|\s*([^|]+?)\s*\|', replace_row, mapping_text, flags=re.MULTILINE)
        
        return repaired_text, repair_notes


def create_mapping_chain(vector_store: CIMVectorStore, ai_client=None) -> CIMMappingChain:
    """Factory function to create a CIM mapping chain."""
    return CIMMappingChain(vector_store, ai_client)
