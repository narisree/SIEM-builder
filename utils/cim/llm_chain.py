"""
LLM-based CIM Mapping Chain
Uses the shared AI client from the main app
"""
import re
from typing import Dict, List, Optional
from utils.cim.log_parser import ParsedLog
from utils.cim.vector_store import CIMVectorStore


# System prompt for CIM mapping
CIM_MAPPING_SYSTEM_PROMPT = """You are a Splunk CIM (Common Information Model) mapping expert. Your task is to analyze log fields and map them to the appropriate CIM data model fields.

CRITICAL RULES:
1. NEVER invent field names or CIM mappings
2. ONLY use prescribed values where specified in the CIM documentation
3. If uncertain, clearly state your uncertainty
4. Provide confidence scores for your mappings

**FIELD FLAG RULES (MUST FOLLOW):**
- Fields marked as "inherited" should NEVER be mapped - they are automatic (_time, host, source, sourcetype)
- Fields marked as "extracted" should use FIELDALIAS (simple 1:1 field rename)
- Fields marked as "calculated" MUST use EVAL expressions

PRESCRIBED VALUES (MUST USE EXACTLY):
- Authentication.action: success, failure, pending, error
- Change.action: acl_modified, cleared, created, deleted, modified, stopped, lockout, read, logoff, updated, started, restarted, unlocked
- Network_Traffic.action: allowed, blocked, dropped, teardown
- Malware.action: allowed, blocked, deferred, quarantined, deleted
"""

CIM_MAPPING_USER_PROMPT = """Analyze the following log data and provide CIM mappings.

LOG FORMAT: {log_format}
VENDOR: {vendor}
PRODUCT: {product}
CONFIDENCE: {format_confidence}

DETECTED FIELDS:
{field_list}

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
=== FIELD FLAG REFERENCE ===
- inherited: Automatic Splunk fields - DO NOT MAP
- extracted: Use FIELDALIAS for direct field rename  
- calculated: MUST use EVAL expression for transformation
===============================
"""
        
        return context_header + "\n".join(context_parts)
    
    def analyze(self, parsed_log: ParsedLog) -> Dict:
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
            f"- {field_name} (sample values: {', '.join(list(set(values))[:3])})"
            for field_name, values in list(parsed_log.fields.items())[:20]
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
            cim_context=cim_context
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
                
                return {
                    "success": True,
                    "mapping": result_text,
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


def create_mapping_chain(vector_store: CIMVectorStore, ai_client=None) -> CIMMappingChain:
    """Factory function to create a CIM mapping chain."""
    return CIMMappingChain(vector_store, ai_client)
