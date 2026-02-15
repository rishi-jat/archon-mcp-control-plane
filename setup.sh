#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ARCHON — one-command setup for the Archestra platform
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# Prerequisites:
#   - Docker running
#   - curl / jq available
#   - GITHUB_TOKEN environment variable (optional but recommended)
# ---------------------------------------------------------------------------
set -euo pipefail

ARCHESTRA_URL="${ARCHESTRA_URL:-http://localhost:9000}"
ARCHESTRA_API="${ARCHESTRA_URL}/api"
FRONTEND_URL="${ARCHESTRA_FRONTEND:-http://localhost:3000}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "Running pre-flight checks..."

command -v docker >/dev/null 2>&1 || fail "Docker is not installed."
command -v curl   >/dev/null 2>&1 || fail "curl is not installed."
command -v jq     >/dev/null 2>&1 || warn "jq is not installed — some output will be raw JSON."

if [ -z "${GITHUB_TOKEN:-}" ]; then
    warn "GITHUB_TOKEN is not set. The repo-intel and actions servers"
    warn "will use unauthenticated GitHub API (60 req/hr limit)."
    warn "Set it with: export GITHUB_TOKEN=ghp_..."
fi

ok "Pre-flight checks passed."

# ---------------------------------------------------------------------------
# Step 1: Start Archestra (if not already running)
# ---------------------------------------------------------------------------
info "Checking Archestra platform..."

if curl -sf "${ARCHESTRA_URL}/healthcheck" >/dev/null 2>&1; then
    ok "Archestra is already running at ${ARCHESTRA_URL}"
else
    info "Starting Archestra platform via Docker..."
    docker run -d \
        --name archestra-platform \
        -p 9000:9000 \
        -p 3000:3000 \
        -e ARCHESTRA_QUICKSTART=true \
        archestra/platform:latest 2>/dev/null || true

    info "Waiting for Archestra to become healthy..."
    for i in $(seq 1 30); do
        if curl -sf "${ARCHESTRA_URL}/healthcheck" >/dev/null 2>&1; then
            ok "Archestra is running."
            break
        fi
        if [ "$i" -eq 30 ]; then
            fail "Archestra did not start within 60 seconds."
        fi
        sleep 2
    done
fi

# ---------------------------------------------------------------------------
# Step 2: Build MCP server images
# ---------------------------------------------------------------------------
info "Building MCP server Docker images..."

SERVERS=("repo-intel" "security" "actions")
for srv in "${SERVERS[@]}"; do
    info "  Building archon-${srv}..."
    docker build -t "archon-${srv}:latest" "mcp-servers/${srv}/" -q
    ok "  archon-${srv} image built."
done

ok "All MCP server images built."

# ---------------------------------------------------------------------------
# Step 3: Register MCP servers with Archestra
# ---------------------------------------------------------------------------
info "Registering MCP servers with Archestra..."

register_server() {
    local name="$1"
    local description="$2"
    local image="archon-${name}:latest"

    local payload
    payload=$(cat <<EOF
{
    "name": "archon-${name}",
    "description": "${description}",
    "type": "docker",
    "image": "${image}",
    "transport": "stdio",
    "envVars": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN:-}",
        "NVD_API_KEY": "${NVD_API_KEY:-}"
    }
}
EOF
    )

    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST "${ARCHESTRA_API}/mcp-servers" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null) || true

    case "$status" in
        200|201) ok "  archon-${name} registered." ;;
        409)     ok "  archon-${name} already registered." ;;
        *)       warn "  archon-${name} registration returned HTTP ${status:-error}." ;;
    esac
}

register_server "repo-intel" "Repository intelligence — commit, PR, and health analysis via GitHub API"
register_server "security"   "Security scanning — dependency CVEs, secret detection via NVD API"
register_server "actions"    "Operational actions — GitHub issue creation, report generation"

ok "MCP server registration complete."

# ---------------------------------------------------------------------------
# Step 4: Upload knowledge base documents
# ---------------------------------------------------------------------------
info "Uploading knowledge base to Archestra..."

upload_kb() {
    local file="$1"
    local name
    name=$(basename "$file" .md)

    if [ -f "$file" ]; then
        local status
        status=$(curl -sf -o /dev/null -w "%{http_code}" \
            -X POST "${ARCHESTRA_API}/knowledge" \
            -H "Content-Type: multipart/form-data" \
            -F "file=@${file}" \
            -F "name=${name}" 2>/dev/null) || true

        case "$status" in
            200|201) ok "  ${name} uploaded." ;;
            409)     ok "  ${name} already exists." ;;
            *)       warn "  ${name} upload returned HTTP ${status:-error}." ;;
        esac
    else
        warn "  ${file} not found, skipping."
    fi
}

upload_kb "knowledge-base/security-playbook.md"
upload_kb "knowledge-base/incident-response.md"

ok "Knowledge base upload complete."

# ---------------------------------------------------------------------------
# Step 5: Create the orchestrator agent
# ---------------------------------------------------------------------------
info "Creating ARCHON orchestrator agent..."

ORCHESTRATOR_PROMPT=$(cat agent/orchestrator-prompt.md 2>/dev/null || echo "See agent/orchestrator-prompt.md")
# Escape for JSON
ORCHESTRATOR_PROMPT_JSON=$(echo "$ORCHESTRATOR_PROMPT" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '"ARCHON orchestrator"')

AGENT_PAYLOAD=$(cat <<EOF
{
    "name": "ARCHON Orchestrator",
    "description": "Autonomous operational control agent — signal collection, correlation, and action execution for DevSecOps",
    "systemPrompt": ${ORCHESTRATOR_PROMPT_JSON},
    "mcpServers": ["archon-repo-intel", "archon-security", "archon-actions"],
    "knowledgeBases": ["security-playbook", "incident-response"],
    "delegatesTo": ["archon-analysis"],
    "settings": {
        "model": "auto",
        "temperature": 0.2,
        "maxTokens": 8192
    }
}
EOF
)

AGENT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "${ARCHESTRA_API}/agents" \
    -H "Content-Type: application/json" \
    -d "$AGENT_PAYLOAD" 2>/dev/null) || true

case "$AGENT_STATUS" in
    200|201) ok "ARCHON Orchestrator agent created." ;;
    409)     ok "ARCHON Orchestrator agent already exists." ;;
    *)       warn "Agent creation returned HTTP ${AGENT_STATUS:-error}." ;;
esac

# ---------------------------------------------------------------------------
# Step 6: Create the analysis sub-agent
# ---------------------------------------------------------------------------
info "Creating ARCHON Analysis sub-agent..."

ANALYSIS_PROMPT=$(cat agent/analysis-agent-prompt.md 2>/dev/null || echo "See agent/analysis-agent-prompt.md")
ANALYSIS_PROMPT_JSON=$(echo "$ANALYSIS_PROMPT" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '"ARCHON analysis sub-agent"')

SUBAGENT_PAYLOAD=$(cat <<EOF
{
    "name": "archon-analysis",
    "description": "Deep analysis sub-agent — severity classification, pattern recognition, risk assessment",
    "systemPrompt": ${ANALYSIS_PROMPT_JSON},
    "mcpServers": [],
    "knowledgeBases": ["security-playbook", "incident-response"],
    "settings": {
        "model": "auto",
        "temperature": 0.1,
        "maxTokens": 4096
    }
}
EOF
)

SUBAGENT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "${ARCHESTRA_API}/agents" \
    -H "Content-Type: application/json" \
    -d "$SUBAGENT_PAYLOAD" 2>/dev/null) || true

case "$SUBAGENT_STATUS" in
    200|201) ok "Analysis sub-agent created." ;;
    409)     ok "Analysis sub-agent already exists." ;;
    *)       warn "Sub-agent creation returned HTTP ${SUBAGENT_STATUS:-error}." ;;
esac

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ARCHON is deployed and ready!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Platform UI:   ${CYAN}${FRONTEND_URL}${NC}"
echo -e "  Platform API:  ${CYAN}${ARCHESTRA_URL}${NC}"
echo ""
echo -e "  MCP Servers:"
echo -e "    • archon-repo-intel  (repository intelligence)"
echo -e "    • archon-security    (vulnerability & secret scanning)"
echo -e "    • archon-actions     (issue creation & reporting)"
echo ""
echo -e "  Agents:"
echo -e "    • ARCHON Orchestrator  (main agent — 3 MCP servers + 2 KB docs)"
echo -e "    • archon-analysis      (sub-agent — delegated via A2A)"
echo ""
# ---------------------------------------------------------------------------
# Step 7: Install dashboard dependencies
# ---------------------------------------------------------------------------
info "Installing dashboard dependencies..."
pip install -q -r dashboard/requirements.txt 2>/dev/null && ok "Dashboard dependencies installed." || warn "Dashboard dependency install failed."

echo -e "  ${YELLOW}Demo:${NC} Open the Archestra chat UI and ask:"
echo -e "    \"Analyze the security posture of torvalds/linux\""
echo ""
echo -e "  ${YELLOW}Dashboard:${NC} Run the visual dashboard:"
echo -e "    cd dashboard && python api.py"
echo -e "    Open ${CYAN}http://localhost:8501${NC}"
echo ""
