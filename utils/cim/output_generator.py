"""
Output Generator for CIM Mappings
Generates both GUI instructions (Splunk Cloud) and config files (Splunk Enterprise)
"""
import re
from typing import Dict, List
from dataclasses import dataclass


@dataclass
class FieldMapping:
    """Represents a single field mapping."""
    raw_field: str
    cim_field: str
    transformation: str
    field_flag: str
    requirement: str
    notes: str


class OutputGenerator:
    """Generates output in multiple formats based on deployment mode."""
    
    def __init__(self, deployment_mode: str = "both"):
        """Initialize output generator."""
        self.deployment_mode = deployment_mode.lower()
    
    def generate_output(self, mapping_result: Dict, sourcetype: str) -> Dict[str, str]:
        """Generate output based on deployment mode."""
        outputs = {}
        
        mappings = self._parse_mapping_result(mapping_result.get('mapping', ''))
        data_model = mapping_result.get('data_model', 'Unknown')
        dataset = mapping_result.get('dataset', 'Unknown')
        tags = self._extract_tags(mapping_result.get('mapping', ''))
        eval_expressions = self._extract_eval_expressions(mapping_result.get('mapping', ''))
        
        if self.deployment_mode in ['cloud', 'both']:
            outputs['gui_instructions'] = self._generate_gui_instructions(
                mappings, sourcetype, data_model, dataset, tags, eval_expressions
            )
        
        if self.deployment_mode in ['enterprise', 'both']:
            outputs['props_conf'] = self._generate_props_conf(
                mappings, sourcetype, data_model, dataset, eval_expressions
            )
            outputs['transforms_conf'] = self._generate_transforms_conf(mappings, sourcetype)
            outputs['eventtypes_conf'] = self._generate_eventtypes_conf(sourcetype, data_model)
            outputs['tags_conf'] = self._generate_tags_conf(sourcetype, data_model, tags)
        
        outputs['validation_spl'] = self._generate_validation_spl(
            sourcetype, data_model, dataset, mappings
        )
        
        return outputs
    
    def _parse_mapping_result(self, mapping_text: str) -> List[FieldMapping]:
        """Parse the LLM mapping result into structured field mappings."""
        mappings = []
        
        if not mapping_text:
            return mappings
        
        table_match = re.search(
            r'\|\s*Raw Field\s*\|.*?\n\|[-\s|]+\n((?:\|.*?\n)+)',
            mapping_text,
            re.MULTILINE
        )
        
        if table_match:
            table_content = table_match.group(1)
            for line in table_content.strip().split('\n'):
                parts = [p.strip() for p in line.split('|')[1:-1]]
                if len(parts) >= 5:
                    if len(parts) >= 6:
                        mappings.append(FieldMapping(
                            raw_field=parts[0],
                            cim_field=parts[1],
                            transformation=parts[2],
                            field_flag=parts[3],
                            requirement=parts[4],
                            notes=parts[5] if len(parts) > 5 else ""
                        ))
                    else:
                        transformation = parts[2].lower()
                        field_flag = 'extracted' if transformation == 'alias' else 'calculated'
                        
                        mappings.append(FieldMapping(
                            raw_field=parts[0],
                            cim_field=parts[1],
                            transformation=parts[2],
                            field_flag=field_flag,
                            requirement=parts[3],
                            notes=parts[4] if len(parts) > 4 else ""
                        ))
        
        return mappings
    
    def _extract_tags(self, mapping_text: str) -> List[str]:
        """Extract required tags from mapping result."""
        tags = []
        
        if not mapping_text:
            return tags
        
        tags_match = re.search(
            r'## Required Tags:\s*\n((?:- .+\n?)+)',
            mapping_text,
            re.MULTILINE
        )
        
        if tags_match:
            tags_content = tags_match.group(1)
            tags = [line.strip('- ').strip() for line in tags_content.strip().split('\n')]
        
        return tags
    
    def _extract_eval_expressions(self, mapping_text: str) -> Dict[str, str]:
        """Extract EVAL expressions from the mapping result."""
        eval_expressions = {}
        
        if not mapping_text:
            return eval_expressions
        
        calc_match = re.search(
            r'## Calculated Fields.*?```\s*\n(.*?)```',
            mapping_text,
            re.MULTILINE | re.DOTALL
        )
        
        if calc_match:
            calc_content = calc_match.group(1)
            for line in calc_content.strip().split('\n'):
                line = line.strip()
                if line.startswith('EVAL-'):
                    match = re.match(r'EVAL-(\w+)\s*=\s*(.+)', line)
                    if match:
                        eval_expressions[match.group(1)] = match.group(2)
        
        return eval_expressions
    
    def _generate_gui_instructions(self, mappings: List[FieldMapping], sourcetype: str,
                                   data_model: str, dataset: str, tags: List[str],
                                   eval_expressions: Dict[str, str]) -> str:
        """Generate step-by-step GUI instructions for Splunk Cloud."""
        
        dm_safe = data_model.lower().replace(' ', '_') if data_model else 'unknown'
        
        instructions = f"""# Splunk Cloud GUI Configuration Instructions

## Overview
- **Data Model**: {data_model}
- **Dataset**: {dataset}
- **Sourcetype**: `{sourcetype}`
- **Tags**: {', '.join(tags) if tags else 'N/A'}

---

## Step 1: Create Event Type

1. Navigate to **Settings → Event Types**
2. Click **New Event Type**
3. Configure:
   - **Name**: `{sourcetype}_{dm_safe}`
   - **Search String**: `sourcetype={sourcetype}`
   - **Tags**: {', '.join(tags) if tags else 'authentication'}
4. Click **Save**

---

## Step 2: Configure Field Aliases (EXTRACTED fields)

Navigate to **Settings → Fields → Field Aliases**

"""
        alias_count = 1
        for mapping in mappings:
            if mapping.transformation.lower() == 'alias' or mapping.field_flag.lower() == 'extracted':
                instructions += f"""### Field Alias {alias_count}: {mapping.cim_field}
1. Click **New Field Alias**
2. Configure:
   - **Name**: `{sourcetype}_{mapping.cim_field}_alias`
   - **Apply to**: `sourcetype` = `{sourcetype}`
   - **Field Alias**: `{mapping.raw_field} AS {mapping.cim_field}`
3. Click **Save**

"""
                alias_count += 1
        
        if alias_count == 1:
            instructions += "_No field aliases needed for this log source._\n\n"
        
        instructions += """---

## Step 3: Configure Calculated Fields (CALCULATED fields)

Navigate to **Settings → Fields → Calculated Fields**

"""
        calc_count = 1
        for mapping in mappings:
            if mapping.transformation.lower() == 'eval' or mapping.field_flag.lower() == 'calculated':
                eval_expr = eval_expressions.get(mapping.cim_field, f"coalesce({mapping.raw_field}, null)")
                instructions += f"""### Calculated Field {calc_count}: {mapping.cim_field}
1. Click **New Calculated Field**
2. Configure:
   - **Name**: `{sourcetype}_{mapping.cim_field}_calc`
   - **Apply to**: `sourcetype` = `{sourcetype}`
   - **Eval Expression**: `{eval_expr}`
3. Click **Save**

"""
                calc_count += 1
        
        if calc_count == 1:
            instructions += "_No calculated fields needed for this log source._\n\n"
        
        cim_fields_str = ', '.join([m.cim_field for m in mappings[:10]]) if mappings else 'field1, field2'
        
        instructions += f"""---

## Step 4: Validate Configuration

Run the validation search in Splunk:

```spl
index=* sourcetype={sourcetype}
| head 100
| table _time, {cim_fields_str}
```

---

## Step 5: Test Data Model Compliance

```spl
| datamodel {data_model} {dataset} search
| search sourcetype={sourcetype}
| head 100
```

---

## Field Mapping Summary

| CIM Field | Type | Raw Field | Configuration Method |
|-----------|------|-----------|---------------------|
"""
        for mapping in mappings:
            config_method = "Field Alias" if mapping.field_flag.lower() == 'extracted' else "Calculated Field (EVAL)"
            instructions += f"| {mapping.cim_field} | {mapping.field_flag} | {mapping.raw_field} | {config_method} |\n"
        
        return instructions
    
    def _generate_props_conf(self, mappings: List[FieldMapping], sourcetype: str,
                            data_model: str, dataset: str,
                            eval_expressions: Dict[str, str]) -> str:
        """Generate props.conf configuration."""
        
        config = f"""# props.conf configuration for {sourcetype}
# Data Model: {data_model} > {dataset}

[{sourcetype}]

# ============================================
# FIELD ALIASES (extracted fields)
# ============================================
"""
        has_aliases = False
        for mapping in mappings:
            if mapping.field_flag.lower() == 'extracted' or mapping.transformation.lower() == 'alias':
                config += f"FIELDALIAS-{mapping.cim_field} = {mapping.raw_field} AS {mapping.cim_field}\n"
                has_aliases = True
        
        if not has_aliases:
            config += "# No field aliases needed\n"
        
        config += """
# ============================================
# CALCULATED FIELDS (calculated fields)
# ============================================
"""
        has_calcs = False
        for mapping in mappings:
            if mapping.field_flag.lower() == 'calculated' or mapping.transformation.lower() == 'eval':
                eval_expr = eval_expressions.get(mapping.cim_field, f"coalesce({mapping.raw_field}, null)")
                config += f"EVAL-{mapping.cim_field} = {eval_expr}\n"
                has_calcs = True
        
        if not has_calcs:
            config += "# No calculated fields needed\n"
        
        return config
    
    def _generate_transforms_conf(self, mappings: List[FieldMapping], sourcetype: str) -> str:
        """Generate transforms.conf if needed."""
        lookup_mappings = [m for m in mappings if m.transformation.lower() == 'lookup']
        
        if not lookup_mappings:
            return "# No transforms.conf needed - no lookup transformations required"
        
        config = f"""# transforms.conf for {sourcetype}

[{sourcetype}_lookup]
filename = {sourcetype}_lookup.csv
"""
        return config
    
    def _generate_eventtypes_conf(self, sourcetype: str, data_model: str) -> str:
        """Generate eventtypes.conf configuration."""
        dm_safe = data_model.lower().replace(' ', '_') if data_model else 'unknown'
        return f"""# eventtypes.conf for {sourcetype}

[{sourcetype}_{dm_safe}]
search = sourcetype={sourcetype}
"""
    
    def _generate_tags_conf(self, sourcetype: str, data_model: str, tags: List[str]) -> str:
        """Generate tags.conf configuration."""
        dm_safe = data_model.lower().replace(' ', '_') if data_model else 'unknown'
        config = f"""# tags.conf for {sourcetype}

[eventtype={sourcetype}_{dm_safe}]
"""
        if tags:
            for tag in tags:
                config += f"{tag} = enabled\n"
        else:
            config += "# Add appropriate tags here\n"
        
        return config
    
    def _generate_validation_spl(self, sourcetype: str, data_model: str,
                                dataset: str, mappings: List[FieldMapping]) -> str:
        """Generate validation SPL queries."""
        
        cim_fields = ', '.join([m.cim_field for m in mappings[:15]]) if mappings else 'action, src, dest, user'
        first_field = mappings[0].cim_field if mappings else 'action'
        
        calculated_fields = [m.cim_field for m in mappings if m.field_flag.lower() == 'calculated']
        extracted_fields = [m.cim_field for m in mappings if m.field_flag.lower() == 'extracted']
        
        calc_fields_str = ', '.join(calculated_fields[:10]) if calculated_fields else 'action, src, dest'
        ext_fields_str = ', '.join(extracted_fields[:10]) if extracted_fields else 'src_port, dest_port'
        
        return f"""# Validation SPL Queries for {sourcetype}

## 1. Field Population Check
```spl
index=* sourcetype={sourcetype}
| head 1000
| table _time, {cim_fields}
| stats count by {first_field}
```

## 2. Validate CALCULATED Fields
```spl
index=* sourcetype={sourcetype}
| head 100
| table _time, {calc_fields_str}
| where isnotnull(action) OR isnotnull(src)
```

## 3. Validate EXTRACTED Fields
```spl
index=* sourcetype={sourcetype}
| head 100
| table _time, {ext_fields_str}
```

## 4. Data Model Validation
```spl
| datamodel {data_model} {dataset} search
| search sourcetype={sourcetype}
| head 100
| table _time, {cim_fields}
```

## 5. Tag Verification
```spl
index=* sourcetype={sourcetype}
| head 100
| eval has_tags = if(tag!="", "yes", "no")
| stats count by has_tags
```

## 6. CIM Compliance Check
```spl
| datamodel {data_model} {dataset} search
| search sourcetype={sourcetype}
| eval compliance_status = case(
    isnull(action), "FAIL: action field missing",
    isnull(src), "FAIL: src field missing",
    isnull(dest), "FAIL: dest field missing",
    1=1, "PASS"
)
| stats count by compliance_status
```

## Field Type Summary
**Calculated Fields (EVAL required):** {', '.join(calculated_fields) if calculated_fields else 'None detected'}
**Extracted Fields (FIELDALIAS):** {', '.join(extracted_fields) if extracted_fields else 'None detected'}
"""
