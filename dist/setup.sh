#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# Pepper SAST — Automated Setup Script
# Installs Docker, Ollama, and starts Pepper
# Supports: Ubuntu/Debian, macOS, Amazon Linux, RHEL/CentOS
# ──────────────────────────────────────────────────────────────────────

PEPPER_DIR="$(cd "$(dirname "$0")" && pwd)"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5-coder:7b}"

# ─── Helpers ─────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

command_exists() { command -v "$1" &>/dev/null; }

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux)
      if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
          ubuntu|debian|pop|linuxmint) echo "debian" ;;
          amzn|amazon)                 echo "amazon" ;;
          rhel|centos|rocky|alma)      echo "rhel" ;;
          fedora)                      echo "fedora" ;;
          *)                           echo "linux" ;;
        esac
      else
        echo "linux"
      fi
      ;;
    *) echo "unknown" ;;
  esac
}

# ─── Step 1: Install Docker ─────────────────────────────────────────

install_docker() {
  if command_exists docker; then
    ok "Docker already installed: $(docker --version)"
    return
  fi

  info "Installing Docker..."
  local os
  os=$(detect_os)

  case "$os" in
    macos)
      if command_exists brew; then
        brew install --cask docker
        info "Docker Desktop installed. Please open Docker Desktop from Applications to start the daemon."
        info "Press Enter once Docker Desktop is running..."
        read -r
      else
        err "Please install Docker Desktop from https://www.docker.com/products/docker-desktop/"
        err "Then re-run this script."
        exit 1
      fi
      ;;
    debian)
      sudo apt-get update -qq
      sudo apt-get install -y -qq ca-certificates curl gnupg
      sudo install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      sudo chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      sudo apt-get update -qq
      sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
      sudo systemctl enable --now docker
      sudo usermod -aG docker "$USER"
      ;;
    amazon)
      sudo yum install -y docker
      sudo systemctl enable --now docker
      sudo usermod -aG docker "$USER"
      # Install compose plugin
      sudo mkdir -p /usr/local/lib/docker/cli-plugins
      curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /tmp/docker-compose
      sudo mv /tmp/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose
      sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
      ;;
    rhel|fedora)
      sudo dnf install -y dnf-plugins-core
      sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      sudo systemctl enable --now docker
      sudo usermod -aG docker "$USER"
      ;;
    *)
      err "Unsupported OS. Please install Docker manually: https://docs.docker.com/engine/install/"
      exit 1
      ;;
  esac

  ok "Docker installed successfully"
}

# ─── Step 2: Install Ollama ──────────────────────────────────────────

install_ollama() {
  if command_exists ollama; then
    ok "Ollama already installed: $(ollama --version 2>/dev/null || echo 'installed')"
  else
    info "Installing Ollama..."
    local os
    os=$(detect_os)

    case "$os" in
      macos)
        if command_exists brew; then
          brew install ollama
        else
          curl -fsSL https://ollama.com/install.sh | sh
        fi
        ;;
      *)
        curl -fsSL https://ollama.com/install.sh | sh
        ;;
    esac
    ok "Ollama installed"
  fi

  # Ensure Ollama is running
  info "Starting Ollama service..."
  local os
  os=$(detect_os)
  if [ "$os" = "macos" ]; then
    # On macOS, ollama serve runs as an app or launchd
    if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
      ollama serve &>/dev/null &
      sleep 3
    fi
  else
    # On Linux, use systemd
    if command_exists systemctl; then
      sudo systemctl enable --now ollama 2>/dev/null || ollama serve &>/dev/null &
      sleep 3
    else
      ollama serve &>/dev/null &
      sleep 3
    fi
  fi

  # Verify Ollama is responding
  if curl -sf http://localhost:11434/api/tags &>/dev/null; then
    ok "Ollama is running"
  else
    warn "Ollama may not be running. You can start it manually with: ollama serve"
  fi

  # Pull the recommended model
  info "Pulling model: ${OLLAMA_MODEL} (this may take a few minutes)..."
  ollama pull "$OLLAMA_MODEL"
  ok "Model ${OLLAMA_MODEL} ready"
}

# ─── Step 3: Configure .env ──────────────────────────────────────────

configure_env() {
  if [ -f "$PEPPER_DIR/.env" ]; then
    ok ".env file already exists"
    return
  fi

  info "Creating .env configuration..."
  cp "$PEPPER_DIR/.env.example" "$PEPPER_DIR/.env"

  # Generate random secrets
  local pg_password nextauth_secret admin_password
  pg_password=$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)
  nextauth_secret=$(openssl rand -base64 32)
  admin_password=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)

  # Set passwords in .env
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sed -i '' "s|POSTGRES_PASSWORD=\"CHANGE_ME_strong_random_password\"|POSTGRES_PASSWORD=\"${pg_password}\"|" "$PEPPER_DIR/.env"
    sed -i '' "s|NEXTAUTH_SECRET=\"CHANGE_ME_random_secret\"|NEXTAUTH_SECRET=\"${nextauth_secret}\"|" "$PEPPER_DIR/.env"
    sed -i '' "s|ADMIN_PASSWORD=\"CHANGE_ME_admin_password\"|ADMIN_PASSWORD=\"${admin_password}\"|" "$PEPPER_DIR/.env"
  else
    sed -i "s|POSTGRES_PASSWORD=\"CHANGE_ME_strong_random_password\"|POSTGRES_PASSWORD=\"${pg_password}\"|" "$PEPPER_DIR/.env"
    sed -i "s|NEXTAUTH_SECRET=\"CHANGE_ME_random_secret\"|NEXTAUTH_SECRET=\"${nextauth_secret}\"|" "$PEPPER_DIR/.env"
    sed -i "s|ADMIN_PASSWORD=\"CHANGE_ME_admin_password\"|ADMIN_PASSWORD=\"${admin_password}\"|" "$PEPPER_DIR/.env"
  fi

  # Set Ollama host based on OS
  local os
  os=$(detect_os)
  if [ "$os" != "macos" ]; then
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "172.17.0.1")
    if [[ "$(uname -s)" == "Darwin" ]]; then
      sed -i '' "s|OLLAMA_HOST=\"http://host.docker.internal:11434\"|OLLAMA_HOST=\"http://${host_ip}:11434\"|" "$PEPPER_DIR/.env"
    else
      sed -i "s|OLLAMA_HOST=\"http://host.docker.internal:11434\"|OLLAMA_HOST=\"http://${host_ip}:11434\"|" "$PEPPER_DIR/.env"
    fi
  fi

  ok ".env configured with auto-generated secrets"
  echo ""
  echo "  Admin email:    admin@yourcompany.com"
  echo "  Admin password: ${admin_password}"
  echo ""
  warn "Save the admin password above! You can also find it in .env"
}

# ─── Step 4: Start Pepper ────────────────────────────────────────────

start_pepper() {
  info "Pulling Pepper images..."
  docker compose -f "$PEPPER_DIR/docker-compose.yml" --env-file "$PEPPER_DIR/.env" pull

  info "Starting Pepper SAST..."
  docker compose -f "$PEPPER_DIR/docker-compose.yml" --env-file "$PEPPER_DIR/.env" up -d

  # Wait for API to be healthy
  info "Waiting for Pepper to start..."
  local retries=30
  while [ $retries -gt 0 ]; do
    if curl -sf http://localhost:${PEPPER_PORT:-3000}/api/health &>/dev/null 2>&1; then
      break
    fi
    sleep 2
    retries=$((retries - 1))
  done

  if [ $retries -gt 0 ]; then
    ok "Pepper is running!"
  else
    warn "Pepper may still be starting. Check logs with: docker compose logs -f"
  fi
}

# ─── Step 5: Print summary ───────────────────────────────────────────

print_summary() {
  local port="${PEPPER_PORT:-3000}"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  ${GREEN}Pepper SAST is ready!${NC}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "  Web UI:   http://localhost:${port}"
  echo "  Login:    Check .env for ADMIN_EMAIL and ADMIN_PASSWORD"
  echo ""
  echo "  Useful commands:"
  echo "    docker compose logs -f          # view logs"
  echo "    docker compose ps               # check status"
  echo "    docker compose down             # stop (keeps data)"
  echo "    docker compose down -v          # stop and delete data"
  echo "    docker compose pull && docker compose up -d  # upgrade"
  echo ""
  echo "  Ollama model: ${OLLAMA_MODEL}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ─── Main ────────────────────────────────────────────────────────────

main() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Pepper SAST — Setup"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""

  # Parse flags
  local skip_ollama=false
  for arg in "$@"; do
    case "$arg" in
      --no-ollama) skip_ollama=true ;;
      --help|-h)
        echo "Usage: ./setup.sh [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --no-ollama    Skip Ollama installation (no AI scanning)"
        echo "  --help         Show this help"
        echo ""
        echo "Environment variables:"
        echo "  OLLAMA_MODEL   Model to pull (default: qwen2.5-coder:7b)"
        echo "  PEPPER_PORT    Port for web UI (default: 3000)"
        exit 0
        ;;
    esac
  done

  # Step 1: Docker
  info "Step 1/4: Docker"
  install_docker
  echo ""

  # Step 2: Ollama
  if [ "$skip_ollama" = true ]; then
    info "Step 2/4: Ollama (skipped with --no-ollama)"
  else
    info "Step 2/4: Ollama + AI Model"
    install_ollama
  fi
  echo ""

  # Step 3: Configure
  info "Step 3/4: Configuration"
  configure_env
  echo ""

  # Step 4: Start
  info "Step 4/4: Starting Pepper"
  start_pepper

  # Summary
  print_summary
}

main "$@"
