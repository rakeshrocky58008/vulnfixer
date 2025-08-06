# VulnFixer - Open Source Vulnerability Fix Automation

## 🎯 Project Overview
Automated vulnerability fixing tool that parses security reports and generates code fixes using AI agents.

## 📁 Project Structure
```
vulnfixer/
├── README.md
├── LICENSE
├── requirements.txt
├── setup.py
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── 
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── config.py               # Configuration management
│   ├── models.py               # Pydantic models
│   └── api/
│       ├── __init__.py
│       └── routes.py           # API endpoints
│
├── agents/
│   ├── __init__.py
│   ├── vulnerability_agent.py  # Main AI agent
│   └── tools/
│       ├── __init__.py
│       ├── parsers.py          # Vulnerability report parsers
│       ├── git_helper.py       # Git operations
│       └── fix_generator.py    # Code fix generators
│
├── web/
│   ├── index.html              # Simple frontend
│   ├── style.css
│   └── script.js
│
├── tests/
│   ├── __init__.py
│   ├── test_agent.py
│   ├── test_parsers.py
│   └── fixtures/
│       └── sample_reports/
│
├── docs/
│   ├── API.md
│   ├── CONTRIBUTING.md
│   └── DEPLOYMENT.md
│
└── examples/
    ├── sample_blackduck_report.json
    └── sample_usage.py
```

## 🚀 Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/yourusername/vulnfixer.git
cd vulnfixer
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
```

### 2. Run the Application
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Access Web Interface
Open http://localhost:8000 in your browser

### 4. API Usage
```bash
curl -X POST "http://localhost:8000/api/fix-vulnerabilities" \
     -F "report=@sample_report.json" \
     -F "github_repo=https://github.com/user/repo" \
     -F "github_token=your_token"
```

## 🔧 Environment Variables
```env
OPENAI_API_KEY=your_openai_key
GITHUB_TOKEN=your_github_token
LOG_LEVEL=INFO
```

## 📊 Supported Formats
- BlackDuck Security Reports
- OWASP Dependency Check
- Snyk Reports (coming soon)
- SonarQube Reports (coming soon)

## 🔧 AI Integration
- Microsoft Copilot API for code generation
- Bitbucket repository support
- Automated pull request creation

## 🤝 Contributing
See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## 📄 License
MIT License - see [LICENSE](LICENSE) file.