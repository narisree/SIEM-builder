"""
Claude API Client
Handles communication with the Anthropic Claude API for chat functionality.
"""

import anthropic
from typing import Dict, List, Optional

class ClaudeClient:
    """Client for interacting with Claude API."""
    
    # Maximum tokens for KB context to avoid exceeding limits
    MAX_KB_TOKENS = 8000
    
    def __init__(self, api_key: str):
        """
        Initialize the Claude client.
        
        Args:
            api_key: Anthropic API key
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-20250514"
    
    def _truncate_kb_content(self, content: str, max_chars: int = 32000) -> str:
        """
        Truncate KB content if it exceeds the maximum character limit.
        
        Args:
            content: The KB content to truncate
            max_chars: Maximum number of characters allowed
            
        Returns:
            Truncated content with notice if truncated
        """
        if len(content) <= max_chars:
            return content
        
        truncated = content[:max_chars]
        # Try to truncate at a reasonable boundary (paragraph or section)
        last_section = truncated.rfind('\n## ')
        if last_section > max_chars * 0.7:
            truncated = truncated[:last_section]
        else:
            last_para = truncated.rfind('\n\n')
            if last_para > max_chars * 0.8:
                truncated = truncated[:last_para]
        
        return truncated + "\n\n[... KB content truncated for length ...]"
    
    def _build_system_prompt(self, source_name: str, kb_content: str) -> str:
        """
        Build the system prompt for Claude.
        
        Args:
            source_name: Display name of the log source
            kb_content: The knowledge base content for context
            
        Returns:
            Formatted system prompt
        """
        truncated_kb = self._truncate_kb_content(kb_content)
        
        system_prompt = f"""You are a senior SIEM/Splunk integration specialist assistant. Your role is to help Security Engineers onboard log sources into Splunk.

## Your Expertise
- Deep knowledge of Splunk architecture (Indexers, Heavy Forwarders, Universal Forwarders, Deployment Servers)
- Log source integrations (syslog, API-based, agent-based)
- Security logging best practices
- Network connectivity requirements
- Troubleshooting common integration issues

## Current Context
You are helping with the integration of: **{source_name}**

## Knowledge Base Content
The following is the official KB documentation for this log source. Base your answers primarily on this content:

---
{truncated_kb}
---

## Response Guidelines
1. **Stay grounded**: Answer based on the KB content provided. If the KB doesn't contain specific information, clearly state what's missing and suggest what should be added.

2. **Be practical**: Provide step-by-step guidance when applicable. Include specific configuration examples where possible.

3. **State assumptions**: If you need to make assumptions (e.g., about network architecture, Splunk version), state them clearly.

4. **Security first**: Always consider security implications in your recommendations.

5. **Format for clarity**: Use bullet points, numbered steps, and code blocks appropriately for technical content.

6. **Acknowledge limitations**: If asked about something outside the scope of the KB or your expertise, acknowledge it honestly.

7. **Splunk-specific**: When discussing configurations, use Splunk-appropriate terminology and file formats (inputs.conf, outputs.conf, props.conf, etc.)."""

        return system_prompt
    
    def _format_chat_history(self, history: List[Dict]) -> List[Dict]:
        """
        Format chat history for the API request.
        
        Args:
            history: List of chat messages
            
        Returns:
            Formatted messages list for API
        """
        formatted = []
        for msg in history:
            formatted.append({
                "role": msg["role"],
                "content": msg["content"]
            })
        return formatted
    
    def get_response(
        self,
        question: str,
        kb_content: str,
        source_name: str,
        chat_history: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Get a response from Claude for the user's question.
        
        Args:
            question: The user's question
            kb_content: The KB content for context
            source_name: Display name of the log source
            chat_history: Previous messages in the conversation
            
        Returns:
            Dictionary with 'success', 'response', and 'message' keys
        """
        try:
            # Build system prompt
            system_prompt = self._build_system_prompt(source_name, kb_content)
            
            # Build messages list
            messages = []
            
            # Add chat history if available
            if chat_history:
                messages.extend(self._format_chat_history(chat_history))
            
            # Add current question
            messages.append({
                "role": "user",
                "content": question
            })
            
            # Make API request
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=system_prompt,
                messages=messages
            )
            
            # Extract response text
            response_text = response.content[0].text
            
            return {
                "success": True,
                "response": response_text,
                "message": "Response generated successfully"
            }
            
        except anthropic.AuthenticationError:
            return {
                "success": False,
                "response": "",
                "message": "Authentication failed. Please check your API key."
            }
        except anthropic.RateLimitError:
            return {
                "success": False,
                "response": "",
                "message": "Rate limit exceeded. Please wait a moment and try again."
            }
        except anthropic.APIConnectionError:
            return {
                "success": False,
                "response": "",
                "message": "Failed to connect to Claude API. Please check your internet connection."
            }
        except anthropic.APIStatusError as e:
            return {
                "success": False,
                "response": "",
                "message": f"API error: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "response": "",
                "message": f"Unexpected error: {str(e)}"
            }
    
    def test_connection(self) -> Dict:
        """
        Test the API connection with a simple request.
        
        Returns:
            Dictionary with 'success' and 'message' keys
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Hello"}]
            )
            return {
                "success": True,
                "message": "API connection successful"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Connection test failed: {str(e)}"
            }
