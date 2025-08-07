#!/bin/bash
# VulnFixer Development Setup Script for Linux

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🛡️ VulnFixer Development Setup${NC}"
echo "=================================="

# Install Ollama if not present
if ! command -v ollama &> /dev/null; then
    echo -e "${YELLOW}Installing Ollama...${NC}"
    curl -fsSL https://ollama.ai/install.sh | sh
else
    echo -e "${GREEN}✅ Ollama already installed${NC}"
fi

# Start Ollama service
echo -e "${YELLOW}Starting Ollama service...${NC}"
ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to start
echo -e "${YELLOW}Waiting for Ollama to start...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Ollama is running${NC}"
        break
    fi
    echo "Waiting... ($i/30)"
    sleep 2
done

# Pull required models
echo -e "${YELLOW}Pulling AI models...${NC}"
ollama pull codellama:7b
ollama pull deepseek-coder:6.7b

# Setup Python environment
echo -e "${YELLOW}Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create .env if doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file...${NC}"
    cp .env.example .env
    echo -e "${RED}⚠️ Please edit .env file with your Bitbucket credentials${NC}"
fi

echo -e "${GREEN}🎉 Setup complete!${NC}"
echo -e "${GREEN}Next steps:${NC}"
echo "1. Edit .env file with your Bitbucket credentials"
echo "2. Run: source venv/bin/activate"
echo "3. Run: python -m uvicorn app.main:app --reload"
echo "4. Open: http://localhost:8000"

# Cleanup function
cleanup() {
    if [ ! -z "$OLLAMA_PID" ]; then
        kill $OLLAMA_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT
