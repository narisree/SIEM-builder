"""
AI Client - Multi-backend support
Supports Claude (paid), Groq (free), and HuggingFace (free) for chat functionality.
"""

import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

# ============================================
# Abstract Base Class for AI Clients
# ============================================

class BaseAIClient(ABC):
    """Abstract base class for AI clients."""
    
    MAX_KB_TOKENS = 8000
    
    def _truncate_kb_content(self, content: str, max_chars: int = 32000) -> str:
        """Truncate KB content if it exceeds the maximum character limit."""
        if len(content) <= max_chars:
            return content
        
        truncated = content[:max_chars]
        last_section = truncated.rfind('\n## ')
        if last_section > max_chars * 0.7:
            truncated = truncated[:last_section]
        else:
            last_para = truncated.rfind('\n\n')
            if last_para > max_chars * 0.8:
                truncated = truncated[:last_para]
        
        return truncated + "\n\n[... KB content truncated for length ...]"
    
    def _build_system_prompt(self, source_name: str, kb_content: str) -> str:
        """Build the system prompt for the AI."""
        truncated_kb = self._truncate_kb_content(kb_content)
        
        return f"""You are a senior SIEM/Splunk integration specialist assistant. Your role is to help Security Engineers onboard log sources into Splunk.

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

    @abstractmethod
    def get_response(self, question: str, kb_content: str, source_name: str, 
                     chat_history: Optional[List[Dict]] = None) -> Dict:
        """Get a response from the AI for the user's question."""
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the name of the AI provider."""
        pass


# ============================================
# Claude Client (Anthropic - Paid)
# ============================================

class ClaudeClient(BaseAIClient):
    """Client for Anthropic's Claude API."""
    
    def __init__(self, api_key: str):
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
            self.model = "claude-sonnet-4-20250514"
            self.available = True
        except ImportError:
            self.available = False
    
    def get_provider_name(self) -> str:
        return "Claude (Anthropic)"
    
    def _format_chat_history(self, history: List[Dict]) -> List[Dict]:
        return [{"role": msg["role"], "content": msg["content"]} for msg in history]
    
    def get_response(self, question: str, kb_content: str, source_name: str,
                     chat_history: Optional[List[Dict]] = None) -> Dict:
        try:
            import anthropic
            
            system_prompt = self._build_system_prompt(source_name, kb_content)
            messages = []
            
            if chat_history:
                messages.extend(self._format_chat_history(chat_history))
            
            messages.append({"role": "user", "content": question})
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=system_prompt,
                messages=messages
            )
            
            return {
                "success": True,
                "response": response.content[0].text,
                "message": "Response generated successfully"
            }
            
        except anthropic.AuthenticationError:
            return {"success": False, "response": "", "message": "Authentication failed. Please check your API key."}
        except anthropic.RateLimitError:
            return {"success": False, "response": "", "message": "Rate limit exceeded. Please wait and try again."}
        except anthropic.APIConnectionError:
            return {"success": False, "response": "", "message": "Failed to connect to Claude API."}
        except Exception as e:
            return {"success": False, "response": "", "message": f"Error: {str(e)}"}


# ============================================
# Groq Client (Free Tier - Llama, Mixtral)
# ============================================

class GroqClient(BaseAIClient):
    """Client for Groq's free inference API with open-source models."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        # Llama 4 Scout - Latest and most capable free model on Groq
        # Alternative: "meta-llama/llama-4-maverick-17b-128e-instruct" for larger model
        self.model = "meta-llama/llama-4-scout-17b-16e-instruct"
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.available = True
    
    def get_provider_name(self) -> str:
        return "Llama 4 Scout (Groq - Free)"
    
    def get_response(self, question: str, kb_content: str, source_name: str,
                     chat_history: Optional[List[Dict]] = None) -> Dict:
        try:
            import requests
            
            system_prompt = self._build_system_prompt(source_name, kb_content)
            
            messages = [{"role": "system", "content": system_prompt}]
            
            if chat_history:
                for msg in chat_history:
                    messages.append({"role": msg["role"], "content": msg["content"]})
            
            messages.append({"role": "user", "content": question})
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": 2048,
                "temperature": 0.7
            }
            
            response = requests.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "response": data["choices"][0]["message"]["content"],
                    "message": "Response generated successfully"
                }
            elif response.status_code == 401:
                return {"success": False, "response": "", "message": "Invalid Groq API key."}
            elif response.status_code == 429:
                return {"success": False, "response": "", "message": "Rate limit exceeded. Groq free tier has limits."}
            else:
                return {"success": False, "response": "", "message": f"Groq API error: {response.status_code}"}
                
        except requests.exceptions.Timeout:
            return {"success": False, "response": "", "message": "Request timed out. Please try again."}
        except Exception as e:
            return {"success": False, "response": "", "message": f"Error: {str(e)}"}


# ============================================
# HuggingFace Client (Free Inference API)
# ============================================

class HuggingFaceClient(BaseAIClient):
    """Client for HuggingFace's free Inference API."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        # Using Mistral or other capable free models
        self.model = "mistralai/Mixtral-8x7B-Instruct-v0.1"
        self.base_url = f"https://api-inference.huggingface.co/models/{self.model}"
        self.available = True
    
    def get_provider_name(self) -> str:
        return "Mixtral 8x7B (HuggingFace - Free)"
    
    def get_response(self, question: str, kb_content: str, source_name: str,
                     chat_history: Optional[List[Dict]] = None) -> Dict:
        try:
            import requests
            
            system_prompt = self._build_system_prompt(source_name, kb_content)
            
            # Build conversation for instruct model
            prompt = f"<s>[INST] {system_prompt}\n\n"
            
            if chat_history:
                for msg in chat_history:
                    if msg["role"] == "user":
                        prompt += f"User: {msg['content']}\n"
                    else:
                        prompt += f"Assistant: {msg['content']}\n"
            
            prompt += f"User question: {question} [/INST]"
            
            # Truncate prompt if too long (HF has input limits)
            if len(prompt) > 24000:
                # Keep system prompt and question, truncate KB
                truncated_kb = self._truncate_kb_content(kb_content, 12000)
                system_prompt = self._build_system_prompt(source_name, truncated_kb)
                prompt = f"<s>[INST] {system_prompt}\n\nUser question: {question} [/INST]"
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 1500,
                    "temperature": 0.7,
                    "return_full_text": False
                }
            }
            
            response = requests.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=120  # HF can be slower
            )
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    generated_text = data[0].get("generated_text", "")
                    return {
                        "success": True,
                        "response": generated_text.strip(),
                        "message": "Response generated successfully"
                    }
                return {"success": False, "response": "", "message": "Unexpected response format"}
            elif response.status_code == 401:
                return {"success": False, "response": "", "message": "Invalid HuggingFace API key."}
            elif response.status_code == 503:
                return {"success": False, "response": "", "message": "Model is loading. Please wait 20-30 seconds and try again."}
            elif response.status_code == 429:
                return {"success": False, "response": "", "message": "Rate limit exceeded. Please try again later."}
            else:
                return {"success": False, "response": "", "message": f"HuggingFace API error: {response.status_code}"}
                
        except requests.exceptions.Timeout:
            return {"success": False, "response": "", "message": "Request timed out. HuggingFace free tier can be slow."}
        except Exception as e:
            return {"success": False, "response": "", "message": f"Error: {str(e)}"}


# ============================================
# Ollama Client (Local - Completely Free)
# ============================================

class OllamaClient(BaseAIClient):
    """Client for local Ollama instance (completely free, runs locally)."""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.model = "llama3.2"  # or mistral, codellama, etc.
        self.available = self._check_availability()
    
    def _check_availability(self) -> bool:
        try:
            import requests
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def get_provider_name(self) -> str:
        return f"Ollama Local ({self.model})"
    
    def get_response(self, question: str, kb_content: str, source_name: str,
                     chat_history: Optional[List[Dict]] = None) -> Dict:
        try:
            import requests
            
            system_prompt = self._build_system_prompt(source_name, kb_content)
            
            messages = [{"role": "system", "content": system_prompt}]
            
            if chat_history:
                for msg in chat_history:
                    messages.append({"role": msg["role"], "content": msg["content"]})
            
            messages.append({"role": "user", "content": question})
            
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False
            }
            
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "response": data["message"]["content"],
                    "message": "Response generated successfully"
                }
            else:
                return {"success": False, "response": "", "message": f"Ollama error: {response.status_code}"}
                
        except requests.exceptions.ConnectionError:
            return {"success": False, "response": "", "message": "Cannot connect to Ollama. Is it running locally?"}
        except Exception as e:
            return {"success": False, "response": "", "message": f"Error: {str(e)}"}


# ============================================
# AI Client Factory
# ============================================

class AIClientFactory:
    """Factory for creating AI clients based on available credentials."""
    
    PROVIDERS = {
        "groq": {
            "name": "Groq (Llama 4 Scout) - FREE",
            "description": "Fast inference with Llama 4 Scout (latest). Free tier available.",
            "key_name": "GROQ_API_KEY",
            "signup_url": "https://console.groq.com/keys",
            "free": True
        },
        "huggingface": {
            "name": "HuggingFace (Mixtral) - FREE", 
            "description": "Mixtral 8x7B model. Free tier with rate limits.",
            "key_name": "HUGGINGFACE_API_KEY",
            "signup_url": "https://huggingface.co/settings/tokens",
            "free": True
        },
        "claude": {
            "name": "Claude (Anthropic) - PAID",
            "description": "Most capable, but requires paid API key.",
            "key_name": "ANTHROPIC_API_KEY",
            "signup_url": "https://console.anthropic.com/",
            "free": False
        },
        "ollama": {
            "name": "Ollama (Local) - FREE",
            "description": "Run locally. Requires Ollama installed on your machine.",
            "key_name": None,
            "signup_url": "https://ollama.ai/download",
            "free": True
        }
    }
    
    @classmethod
    def get_available_providers(cls) -> Dict:
        """Return information about all supported providers."""
        return cls.PROVIDERS
    
    @classmethod
    def create_client(cls, provider: str, api_key: str = None, **kwargs) -> Optional[BaseAIClient]:
        """Create an AI client for the specified provider."""
        
        if provider == "claude" and api_key:
            return ClaudeClient(api_key)
        elif provider == "groq" and api_key:
            return GroqClient(api_key)
        elif provider == "huggingface" and api_key:
            return HuggingFaceClient(api_key)
        elif provider == "ollama":
            base_url = kwargs.get("base_url", "http://localhost:11434")
            return OllamaClient(base_url)
        
        return None
    
    @classmethod
    def get_first_available_client(cls, secrets: dict) -> Optional[BaseAIClient]:
        """Try to create a client from available secrets, preferring free options."""
        
        # Priority order: Groq (free, fast) > HuggingFace (free) > Claude (paid) > Ollama (local)
        priority_order = ["groq", "huggingface", "claude", "ollama"]
        
        for provider in priority_order:
            provider_info = cls.PROVIDERS.get(provider, {})
            key_name = provider_info.get("key_name")
            
            if provider == "ollama":
                client = cls.create_client("ollama")
                if client and client.available:
                    return client
            elif key_name and secrets.get(key_name):
                client = cls.create_client(provider, secrets.get(key_name))
                if client:
                    return client
        
        return None
