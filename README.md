# 🛡️ SIEM Log Source Onboarding Assistant + CIM Mapper

A Streamlit application that helps Security Engineers onboard common log sources into Splunk SIEM. Features a local Knowledge Base, reference documentation, security use cases, **CIM Field Mapper**, and an AI-powered chat assistant with **FREE AI options** (Groq, HuggingFace).

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Free AI](https://img.shields.io/badge/Free_AI-Groq_|_HuggingFace-green?style=for-the-badge)

## 📋 Features

- **📘 Integration Guides**: Detailed markdown-based knowledge base for each log source
- **🔗 References**: Curated links to official documentation and YouTube tutorials
- **🎯 Use Cases**: Security detection rules with SPL queries and L1 analyst guidance
- **🔧 CIM Mapper**: AI-powered field mapping to Splunk Common Information Model (NEW!)
  - Supports 11 CIM data models (Authentication, Network_Traffic, Web, etc.)
  - Auto-detects log formats (JSON, XML, CEF, LEEF, Syslog, CSV)
  - Generates props.conf, transforms.conf for Splunk Enterprise
  - Generates GUI instructions for Splunk Cloud
- **💬 AI Chat**: AI-powered assistant supporting multiple providers:
  - 🆓 **Groq** (Llama 4 Scout) - FREE, fast (460+ tokens/sec)
  - 🆓 **HuggingFace** (Mixtral 8x7B) - FREE
  - 💰 **Claude** (Anthropic) - Paid, most capable
  - 🏠 **Ollama** - Local, completely free
- **🎯 10+ Log Sources**: Palo Alto, Windows, Linux, Azure AD, Cisco ASA, and more
- **📱 Responsive UI**: Clean, modern interface with tabbed navigation

## 🤖 AI Provider Comparison

| Provider | Model | Cost | Speed | Setup |
|----------|-------|------|-------|-------|
| **Groq** | Llama 4 Scout | 🆓 FREE | ⚡ Very Fast | Easy - API key only |
| **HuggingFace** | Mixtral 8x7B | 🆓 FREE | 🐢 Slower | Easy - API token |
| **Claude** | Claude Sonnet | 💰 Paid | ⚡ Fast | Requires payment |
| **Ollama** | Various | 🆓 FREE | ⚡ Local | Requires local install |

**Recommendation:** Start with **Groq** - it's free, fast, and very capable!

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- Anthropic API key (for chat functionality)
- Git

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/siem-onboarding-app.git
   cd siem-onboarding-app
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure secrets** (for AI chat - choose one)
   ```bash
   mkdir -p .streamlit
   
   # Option 1: Groq (FREE - Recommended)
   echo 'GROQ_API_KEY = "gsk_your_key"' > .streamlit/secrets.toml
   
   # Option 2: HuggingFace (FREE)
   echo 'HUGGINGFACE_API_KEY = "hf_your_token"' > .streamlit/secrets.toml
   
   # Option 3: Claude (Paid)
   echo 'ANTHROPIC_API_KEY = "sk-ant-your_key"' > .streamlit/secrets.toml
   
   # Option 4: Ollama (Local - no key needed, just install Ollama)
   ```

5. **Run the app**
   ```bash
   streamlit run app.py
   ```

6. **Open in browser**
   Navigate to `http://localhost:8501`

## ☁️ Deploy to Streamlit Cloud

### Step 1: Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/your-username/siem-onboarding-app.git
git push -u origin main
```

### Step 2: Deploy on Streamlit Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Click "New app"
3. Select your GitHub repository
4. Set main file path: `app.py`
5. Click "Deploy"

### Step 3: Configure Secrets (Choose ONE free option)

1. In Streamlit Cloud, go to your app settings
2. Navigate to "Secrets" section
3. Add your API key (Groq recommended - it's FREE):
   ```toml
   # FREE Option (Recommended)
   GROQ_API_KEY = "gsk_your_key_here"
   
   # OR another FREE option
   HUGGINGFACE_API_KEY = "hf_your_token_here"
   
   # OR paid option
   ANTHROPIC_API_KEY = "sk-ant-your-key-here"
   ```
4. Save and reboot the app

### Get Your Free API Key

| Provider | Sign Up Link | Key Format |
|----------|--------------|------------|
| **Groq** (Recommended) | [console.groq.com/keys](https://console.groq.com/keys) | `gsk_...` |
| **HuggingFace** | [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens) | `hf_...` |

## 📁 Project Structure

```
siem-onboarding-app/
├── app.py                    # Main Streamlit application
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── .streamlit/
│   └── secrets.toml          # Local secrets (git-ignored)
├── kb/                       # Knowledge Base directory
│   ├── references.json       # Reference links metadata
│   ├── palo_alto.md          # Palo Alto integration guide
│   ├── windows_events.md     # Windows Events guide
│   ├── azure_ad.md           # Azure AD guide
│   ├── linux.md              # Linux syslog guide
│   ├── cisco_asa.md          # Cisco ASA guide
│   ├── checkpoint.md         # Check Point guide
│   ├── crowdstrike_edr.md    # CrowdStrike EDR guide
│   ├── o365.md               # Office 365 guide
│   ├── proofpoint.md         # Proofpoint guide
│   └── zscaler_proxy.md      # Zscaler Proxy guide
└── utils/
    ├── __init__.py           # Package init
    ├── kb_loader.py          # KB loading utilities
    └── claude_client.py      # Claude API client
```

## ➕ Adding a New Log Source

### Step 1: Create KB Markdown File

Create a new file in `kb/` directory with the source slug name:

```bash
touch kb/new_source.md
```

Use this template structure:

```markdown
# [Source Name] Integration Guide

## Overview
Brief description of the log source and integration method.

## Pre-requisites
List of requirements before starting.

## Network Connectivity Requirements
| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| ... | ... | ... | ... | ... |

## Logging Standard
Recommended log types and levels.

## Log Collection Standard
### Source-Side Steps
Step-by-step configuration on the source.

### SIEM-Side Steps
Step-by-step configuration on Splunk.

## Required Add-on / Parser
| Component | Name | Purpose |
|-----------|------|---------|
| ... | ... | ... |

## Sample Configuration Snippets
Code examples for configs.

## Validation & Troubleshooting
Common issues and solutions.

## Security Notes
Security considerations.
```

### Step 2: Add Source to Catalog

Edit `utils/kb_loader.py` and add the source to `_load_sources_catalog()`:

```python
"new_source": {
    "display_name": "New Source Display Name",
    "category": "Category",
    "vendor": "Vendor Name"
},
```

### Step 3: Add References

Edit `kb/references.json` and add an entry:

```json
"new_source": {
    "official_docs": [
        {"title": "Official Doc Title", "url": "https://..."}
    ],
    "youtube": [
        {"title": "Video Title", "url": "https://..."}
    ],
    "blogs_optional": []
}
```

### Step 4: Test

Restart the app and verify the new source appears in the dropdown.

## 🔧 Configuration Options

### Environment Variables / Secrets

| Variable | Description | Required | Free |
|----------|-------------|----------|------|
| `GROQ_API_KEY` | Groq API key (Llama 3.3) | One of these | ✅ Yes |
| `HUGGINGFACE_API_KEY` | HuggingFace token (Mixtral) | is required | ✅ Yes |
| `ANTHROPIC_API_KEY` | Claude API key | for chat | ❌ Paid |

### Streamlit Secrets

For Streamlit Cloud deployment, add secrets in the dashboard:

```toml
# Pick ONE (Groq recommended for free tier)
GROQ_API_KEY = "gsk_..."
# HUGGINGFACE_API_KEY = "hf_..."
# ANTHROPIC_API_KEY = "sk-ant-..."
```

## 🤖 Chat Features

The AI-powered chat assistant:

- **Multiple providers**: Choose between free (Groq, HuggingFace) or paid (Claude) options
- **Grounded responses**: Answers based on the selected log source KB
- **Session persistence**: Chat history maintained during session
- **Context-aware**: Includes source name and KB content in prompts
- **Error handling**: Graceful handling of API errors and rate limits

### Chat Limitations

- Chat history clears when switching log sources
- KB content is truncated if too large (>32K chars)
- Free tiers have rate limits (Groq: ~30 req/min, HuggingFace: varies)

## 🔒 Security Notes

- API keys are stored securely in Streamlit Secrets
- No secrets are logged or exposed in the UI
- KB content is read-only
- No user data is stored persistently

## 🐛 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "AI Assistant Not Configured" | Add API key to secrets (Groq is free!) |
| "Rate limit exceeded" | Wait a minute (free tier limits) |
| "Model is loading" (HuggingFace) | Wait 30 seconds and retry |
| "KB Not Found" | Create the markdown file in `kb/` |
| "References Not Found" | Add entry to `kb/references.json` |
| App not loading | Check `requirements.txt` versions |

### Debug Mode

Run with debug logging:

```bash
streamlit run app.py --logger.level=debug
```

## 📝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-source`)
3. Add your KB content and references
4. Test locally
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- [Splunk Documentation](https://docs.splunk.com)
- [Anthropic Claude](https://www.anthropic.com)
- [Streamlit](https://streamlit.io)

---

**Built with ❤️ for Security Engineers**
