#!/bin/bash
# Kubernetes Deployment Script

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

NAMESPACE="vulnfixer"

echo -e "${GREEN}🚀 VulnFixer Kubernetes Deployment${NC}"
echo "===================================="

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl not found. Please install kubectl${NC}"
    exit 1
fi

if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}❌ Cannot connect to Kubernetes cluster${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"

# Create namespace and basic resources
echo -e "${YELLOW}📁 Creating namespace and resources...${NC}"
kubectl apply -f k8s/namespace.yaml

# Create secrets (prompt for credentials)
if ! kubectl get secret vulnfixer-secrets -n ${NAMESPACE} &> /dev/null; then
    echo -e "${YELLOW}🔑 Setting up secrets...${NC}"
    read -p "Enter Bitbucket username: " BITBUCKET_USERNAME
    read -s -p "Enter Bitbucket app password: " BITBUCKET_TOKEN
    echo
    
    kubectl create secret generic vulnfixer-secrets \
        --from-literal=BITBUCKET_USERNAME="$BITBUCKET_USERNAME" \
        --from-literal=BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
        -n ${NAMESPACE}
    
    echo -e "${GREEN}✅ Secrets created${NC}"
else
    echo -e "${GREEN}✅ Secrets already exist${NC}"
fi

# Deploy Ollama first
echo -e "${YELLOW}🦙 Deploying Ollama AI service...${NC}"
kubectl apply -f k8s/ollama-deployment.yaml

# Wait for Ollama to be ready
echo -e "${YELLOW}⏳ Waiting for Ollama to be ready...${NC}"
kubectl wait --for=condition=ready pod -l app=ollama -n ${NAMESPACE} --timeout=600s

# Deploy VulnFixer application
echo -e "${YELLOW}🛡️ Deploying VulnFixer application...${NC}"
kubectl apply -f k8s/vulnfixer-deployment.yaml

# Wait for VulnFixer to be ready
echo -e "${YELLOW}⏳ Waiting for VulnFixer deployment...${NC}"
kubectl wait --for=condition=available deployment/vulnfixer-deployment -n ${NAMESPACE} --timeout=300s

# Show deployment status
echo -e "${GREEN}🎉 Deployment complete!${NC}"
echo
echo "=== Deployment Status ==="
kubectl get pods -n ${NAMESPACE}
echo
kubectl get services -n ${NAMESPACE}

# Get access information
echo
echo -e "${GREEN}=== Access Information ===${NC}"
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}')
if [ -z "$NODE_IP" ]; then
    NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
fi

echo -e "${GREEN}Ollama API:${NC} http://${NODE_IP}:30434"
echo -e "${GREEN}VulnFixer:${NC} kubectl port-forward svc/vulnfixer-service 8000:8000 -n ${NAMESPACE}"
echo
echo -e "${YELLOW}To access VulnFixer web interface:${NC}"
echo "kubectl port-forward svc/vulnfixer-service 8000:8000 -n ${NAMESPACE}"
echo "Then open: http://localhost:8000"
