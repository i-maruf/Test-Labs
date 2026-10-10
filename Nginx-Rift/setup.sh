#!/bin/bash
set -e
cd "$(dirname "$0")"

# Prefer the project-local Docker Compose binary (v2) if present, then the
# docker compose v2 plugin, then the system docker-compose (v1).
if [ -x "./bin/docker-compose" ] && ./bin/docker-compose version &>/dev/null; then
    DOCKER_COMPOSE="./bin/docker-compose"
elif docker compose version &>/dev/null; then
    DOCKER_COMPOSE="docker compose"
elif docker-compose version &>/dev/null || docker-compose --version &>/dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "Error: neither 'docker compose' nor 'docker-compose' is installed." >&2
    exit 1
fi

echo "Building Docker image (compiles nginx from source)..."
$DOCKER_COMPOSE -f env/docker-compose.yml build

echo ""
echo "Done. To run:"
echo ""
echo "  # Terminal 1 (server) — nginx runs with ASLR disabled (setarch -R):"
echo "  $DOCKER_COMPOSE -f env/docker-compose.yml up"
echo ""
echo "  # Terminal 2 (attacker):"
echo "  python3 poc.py --cmd 'echo hello from depthfirst > /tmp/pwned'"
echo ""
echo "  # Verify RCE:"
echo "  $DOCKER_COMPOSE -f env/docker-compose.yml exec nginx ls -la /tmp/pwned"
echo "  $DOCKER_COMPOSE -f env/docker-compose.yml exec nginx cat /tmp/pwned"
