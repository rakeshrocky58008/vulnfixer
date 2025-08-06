# 🛡️ VulnFixer

**Open Source Automated Vulnerability Fixing with Microsoft Copilot & Bitbucket**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688.svg)](https://fastapi.tiangolo.com)
[![Microsoft Copilot](https://img.shields.io/badge/AI-Microsoft%20Copilot-00d4ff.svg)](https://copilot.github.com)
[![Bitbucket](https://img.shields.io/badge/Git-Bitbucket-0052cc.svg)](https://bitbucket.org)

> Automatically analyze security vulnerability reports and generate fixes using Microsoft Copilot AI, with seamless Bitbucket integration for automated pull requests.

## ✨ Features

- 🤖 **Microsoft Copilot Integration** - Leverage advanced AI for intelligent vulnerability fixes
- 📊 **Multiple Report Formats** - Support for BlackDuck, OWASP Dependency Check, Snyk
- 🔧 **Bitbucket Integration** - Automated cloning, fixing, and pull request creation
- 🚀 **Fast Processing** - Simple architecture designed for 1-week MVP deployment
- 🌐 **Web Interface** - Clean, modern UI for easy vulnerability management
- 📱 **REST API** - Complete API for integration with CI/CD pipelines
- 🔒 **Security First** - Minimal, targeted fixes that preserve functionality

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Microsoft Copilot API access
- Bitbucket account with app password

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnfixer.git
cd vulnfixer

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
```

### 2. Configuration

Edit `.env` file with your credentials:

```env
# Microsoft Copilot API Configuration
COPILOT_API_KEY=your_copilot_api_key_here

# Bitbucket Configuration
BITBUCKET_USERNAME=your_bitbucket_username
BITBUCKET_TOKEN=your_bitbucket_app_password

# Application Settings
LOG_LEVEL=INFO
ENVIRONMENT=development
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
4. **Fix**: Click "Fix Vulnerabilities" and let Copilot work its magic!

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
  "message": "Successfully processed 5/8 vulnerabilities",
  "fixes_applied": 5,
  "vulnerabilities_found": 8,
  "pr_url": "https://bitbucket.org/workspace/repo/pull-requests/42",
  "branch_name": "vulnfixer-fixes-1699123456",
  "processing_time": 23.45
}
```

## 🏗️ Architecture

### Simple & Effective Design

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web/API       │───▶│  Vulnerability   │───▶│  Microsoft      │
│   Interface     │    │  Parser          │    │  Copilot        │
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
- **AI**: Microsoft Copilot API
- **Git**: Bitbucket API + GitPython
- **Frontend**: Vanilla HTML/CSS/JavaScript
- **Parsing**: Native JSON/XML parsers

## 📊 Supported Formats

### Vulnerability Reports
- **BlackDuck** - JSON format with components and vulnerabilities
- **OWASP Dependency Check** - JSON and XML formats
- **Snyk** - JSON vulnerability reports
- **Generic** - Custom JSON format with standard fields

### Repository Types
- **Bitbucket** - Full support with automated PR creation
- **GitHub** - Planned for future release

### Languages & Build Systems
- **Java** - Maven (pom.xml), Gradle (build.gradle)
- **JavaScript/Node.js** - npm (package.json)
- **Python** - pip (requirements.txt), Pipenv (Pipfile)
- **C#/.NET** - NuGet packages
- **Go** - Go modules (go.mod)
- **PHP** - Composer (composer.json)

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `COPILOT_API_KEY` | Microsoft Copilot API key | ✅ | - |
| `BITBUCKET_USERNAME` | Your Bitbucket username | ✅ | - |
| `BITBUCKET_TOKEN` | Bitbucket app password | ✅ | - |
| `LOG_LEVEL` | Logging level | ❌ | INFO |
| `MAX_FILE_SIZE` | Max upload size in bytes | ❌ | 10485760 |
| `LLM_TEMPERATURE` | AI creativity (0-1) | ❌ | 0.1 |
| `PR_BRANCH_PREFIX` | Branch name prefix | ❌ | vulnfixer |

### Microsoft Copilot Setup

1. Get access to [Microsoft Copilot API](https://docs.github.com/en/copilot)
2. Generate API key from GitHub settings
3. Add key to your `.env` file

### Bitbucket Setup

1. Create [App Password](https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/) in Bitbucket
2. Grant permissions: `Repositories: Write`, `Pull requests: Write`
3. Add username and app password to `.env` file

## 🚦 API Reference

### Endpoints

#### `POST /api/fix-vulnerabilities`
Fix vulnerabilities in a repository

**Parameters:**
- `report_file` (file): Vulnerability report
- `repo_url` (string): Bitbucket repository URL
- `repo_token` (string, optional): Repository access token
- `create_pr` (boolean): Create pull request
- `branch_name` (string, optional): Custom branch name

#### `POST /api/analyze-report`
Analyze vulnerability report without fixing

#### `GET /api/supported-formats`
Get list of supported report formats

#### `GET /api/agent-status`
Get AI agent status and capabilities

## 🧪 Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/

# Run with coverage
pytest --cov=app tests/
```

## 🐳 Docker Deployment

```bash
# Build image
docker build -t vulnfixer .

# Run container
docker run -p 8000:8000 --env-file .env vulnfixer
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](docs/CONTRIBUTING.md).

### Development Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/vulnfixer.git
cd vulnfixer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install development dependencies
pip install -r requirements.txt
pip install black flake8 pytest

# Run in development mode
python -m uvicorn app.main:app --reload
```

### Code Style

We use [Black](https://black.readthedocs.io/) for code formatting:

```bash
black app/ agents/ tests/
flake8 app/ agents/ tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Microsoft Copilot** for intelligent code generation
- **Bitbucket** for seamless Git integration
- **FastAPI** for the robust web framework
- **OWASP** for vulnerability standards
- **BlackDuck** for security scanning

## 📞 Support

- 📧 **Issues**: [GitHub Issues](https://github.com/yourusername/vulnfixer/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/vulnfixer/discussions)
- 📖 **Documentation**: [Wiki](https://github.com/yourusername/vulnfixer/wiki)

---

**⚡ Built for speed, security, and simplicity. Get your vulnerabilities fixed in minutes, not hours!**
