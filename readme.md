# 🛡️ VulnFixer

**Open Source Automated Vulnerability Fixing with Local Ollama AI & Bitbucket**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688.svg)](https://fastapi.tiangolo.com)
[![Ollama](https://img.shields.io/badge/AI-Local%20Ollama-00ff88.svg)](https://ollama.ai)
[![Bitbucket](https://img.shields.io/badge/Git-Bitbucket-0052cc.svg)](https://bitbucket.org)

> Automatically analyze security vulnerability reports and generate fixes using **local Ollama AI** - completely free, private, and no API keys needed!

## ✨ Features

- 🦙 **Local Ollama AI** - No API keys, no costs, 100% private processing
- 📊 **Multiple Report Formats** - BlackDuck, OWASP Dependency Check, Snyk
- 🔧 **Bitbucket Integration** - Automated cloning, fixing, and pull request creation
- 🚀 **Fast & Free** - No rate limits, no subscription costs
- 🌐 **Modern Web Interface** - Clean, responsive UI for easy vulnerability management
- 📱 **REST API** - Complete API for CI/CD pipeline integration
- 🔒 **Privacy First** - Your code never leaves your machine
- 🌍 **Works Offline** - No internet required after initial setup

## 🎯 Why Ollama Integration is Revolutionary

### **Traditional Solutions vs VulnFixer**

| Feature | VulnFixer (Ollama) | GPT-4/Copilot APIs |
|---------|-------------------|-------------------|
| **Cost** | 🟢 **FREE** | 🔴 $0.02-0.03/1K tokens |
| **Privacy** | 🟢 **100% Local** | 🔴 Code sent to external servers |
| **Rate Limits** | 🟢 **None** | 🔴 Limited requests/minute |
| **Setup** | 🟢 **No API Keys** | 🔴 Requires API subscriptions |
| **Offline** | 🟢 **Works Offline** | 🔴 Internet required |
| **Enterprise** | 🟢 **Air-gap friendly** | 🔴 External dependencies |

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Python 3.8+
- Ollama installed
- Bitbucket account (for repository operations)

### 1. Install Ollama
```bash
# Linux/Mac
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama server
ollama serve

# Pull CodeLlama model (optimized for code)
ollama pull codellama:7b
```

### 2. Setup VulnFixer
```bash
# Clone repository
git clone https://github.com/yourusername/vulnfixer.git
cd vulnfixer

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Bitbucket credentials (Ollama needs no API keys!)
```

### 3. Run the Application
```bash
# Start the server
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Access the Application
- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api/docs
- **Health Check**: http://localhost:8000/health

## 📋 Usage

### Web Interface
1. **Upload Report**: Drag & drop your vulnerability report (JSON/XML)
2. **Repository URL**: Enter your Bitbucket repository URL  
3. **Configure**: Set branch name and options
4. **Fix**: Click "Fix Vulnerabilities" and watch local Ollama AI work!

### API Usage
```bash
curl -X POST "http://localhost:8000/api/fix-vulnerabilities" \
     -F "report_file=@blackduck_report.json" \
     -F "repo_url=https://bitbucket.org/workspace/repository" \
     -F "repo_token=your_app_password" \
     -F "create_pr=true"
```

### Response Format
```json
{
  "status": "success",
  "message": "Successfully processed 5/8 vulnerabilities using local Ollama",
  "fixes_applied": 5,
  "vulnerabilities_found": 8,
  "pr_url": "https://bitbucket.org/workspace/repo/pull-requests/42",
  "branch_name": "vulnfixer-fixes-1699123456",
  "processing_time": 23.45,
  "model_used": "codellama:7b"
}
```

## 🦙 Ollama Model Options

### **CodeLlama 7B** (Recommended for MVP)
```bash
ollama pull codellama:7b
```
- **RAM**: 4GB required
- **Best for**: General vulnerability fixing, fast processing
- **Quality**: Excellent for most common vulnerabilities

### **DeepSeek Coder 6.7B** (Most Efficient)
```bash
ollama pull deepseek-coder:6.7b
```
- **RAM**: 3.5GB required
- **Best for**: Resource-constrained environments
- **Quality**: Very good coding capabilities, faster than CodeLlama

### **CodeLlama 13B** (Better Quality)
```bash
ollama pull codellama:13b
```
- **RAM**: 8GB required
- **Best for**: Production environments with more RAM
- **Quality**: Higher accuracy for complex vulnerability patterns

### **Phind-CodeLlama 34B** (Enterprise Grade)
```bash
ollama pull phind-codellama:34b
```
- **RAM**: 16GB+ required
- **Best for**: Enterprise deployments, highest accuracy
- **Quality**: Best-in-class code understanding and generation

## 🏗️ Architecture

### Simple & Powerful Design
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web/API       │───▶│  Vulnerability   │───▶│  Local Ollama   │
│   Interface     │    │  Parser          │    │  AI Engine      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   File Upload   │    │  Fix Generator   │    │  Code Analysis  │
│   Handler       │    │  & Applicator    │    │  & Generation   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Bitbucket     │    │  Git Operations  │    │  Pull Request   │
│   Integration   │    │  & File Mods     │    │  Creation       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Tech Stack
- **Backend**: FastAPI + Python 3.8+
- **AI Engine**: Local Ollama with CodeLlama
- **Git**: Bitbucket API + GitPython  
- **Frontend**: Modern HTML5/CSS3/JavaScript
- **Parsing**: Native JSON/XML parsers
- **Privacy**: 100% local processing

## 📊 Supported Formats

### Vulnerability Reports
- **BlackDuck** - Enterprise security scanning reports
- **OWASP Dependency Check** - JSON and XML formats
- **Snyk** - Developer security platform reports
- **Generic JSON** - Custom vulnerability report formats

### Repository Types  
- **Bitbucket** - Full support with automated PR creation
- **GitHub** - Coming soon

### Languages & Build Systems
- **Java** - Maven (pom.xml), Gradle (build.gradle)
- **JavaScript/Node.js** - npm (package.json) 
- **Python** - pip (requirements.txt), Pipenv (Pipfile)
- **C#/.NET** - NuGet packages
- **Go** - Go modules (go.mod)
- **PHP** - Composer (composer.json)

## 🔧 Configuration

### Environment Variables (.env)
```env
# 🦙 LOCAL OLLAMA (No API keys needed!)
USE_OLLAMA=true
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=codellama:7b
OLLAMA_TIMEOUT=120

# 📦 BITBUCKET (Required for repository operations)  
BITBUCKET_USERNAME=your_username
BITBUCKET_TOKEN=your_app_password

# ⚙️ APPLICATION SETTINGS
LOG_LEVEL=INFO
ENVIRONMENT=development
```

### Ollama Setup Verification
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Test model availability
ollama list

# Pull additional models
ollama pull deepseek-coder:6.7b
```

## 🧪 Testing Your Setup

### 1. Test Ollama Connection
```python
from agents.tools.ollama_client import OllamaClient

client = OllamaClient()
status = await client.check_model_availability()
print(f"Ollama Status: {status}")
```

### 2. Test Vulnerability Fix Generation
```bash
# Upload a sample BlackDuck report via web interface
# Watch the logs to see Ollama processing in real-time
tail -f logs/vulnfixer.log
```

## 🚦 API Reference

### Main Endpoints

#### `POST /api/fix-vulnerabilities`
Process vulnerabilities with local Ollama AI

#### `GET /api/agent-status`  
Check Ollama availability and model status

#### `GET /api/supported-formats`
List supported vulnerability report formats

## 🎯 Performance Optimization

### Memory Management
```python
# Optimize for your system RAM
OLLAMA_MODELS = {
    "4GB":  "deepseek-coder:6.7b",    # Most efficient
    "8GB":  "codellama:13b",          # Better quality
    "16GB": "phind-codellama:34b"     # Best quality
}
```

### GPU Acceleration (Optional)
```bash
# If you have NVIDIA GPU
export CUDA_VISIBLE_DEVICES=0
ollama pull codellama:7b
```

## 🐳 Docker Deployment

```bash
# Build with Ollama support
docker build -t vulnfixer-ollama .

# Run with local Ollama
docker run -p 8000:8000 -p 11434:11434 \
  --env-file .env \
  -v ollama_data:/root/.ollama \
  vulnfixer-ollama
```

## 🤝 Contributing

We welcome contributions! The Ollama integration makes VulnFixer accessible to everyone.

### Development Setup
```bash
git clone https://github.com/yourusername/vulnfixer.git
cd vulnfixer
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start Ollama
ollama serve &
ollama pull codellama:7b

# Run development server
python -m uvicorn app.main:app --reload
```

## 📄 License

MIT License - Use freely for personal and commercial projects!

## 🏆 Why VulnFixer with Ollama Wins

### **For Individuals**
- ✅ **Zero cost** - No API subscriptions ever
- ✅ **Complete privacy** - Code stays on your machine
- ✅ **No limits** - Process unlimited vulnerabilities

### **For Teams**  
- ✅ **Enterprise ready** - Air-gap compatible
- ✅ **Consistent results** - Same AI model for everyone
- ✅ **No vendor lock-in** - Own your AI infrastructure

### **For Organizations**
- ✅ **Cost effective** - No per-usage fees
- ✅ **Compliance friendly** - Data never leaves premises  
- ✅ **Scalable** - Deploy on your own infrastructure

## 🎉 Get Started Now!

```bash
# Complete setup in 5 commands:
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve &
ollama pull codellama:7b
git clone https://github.com/yourusername/vulnfixer.git
cd vulnfixer && pip install -r requirements.txt && python -m uvicorn app.main:app --reload
```

**Open http://localhost:8000 and start fixing vulnerabilities with free, local AI!** 🚀

---

**🦙 Powered by Ollama - Because your code deserves privacy and your wallet deserves a break!**
