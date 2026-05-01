#!/usr/bin/env bash
set -euo pipefail

PEPPER_DIR="$(cd "$(dirname "$0")" && pwd)"

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
          amzn|amazon) echo "amazon" ;;
          rhel|centos|rocky|alma) echo "rhel" ;;
          fedora) echo "fedora" ;;
          *) echo "linux" ;;
        esac
      else
        echo "linux"
      fi
      ;;
    *) echo "unknown" ;;
  esac
}

replace_in_file() {
  local file="$1"
  local search="$2"
  local replace="$3"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sed -i '' "s|${search}|${replace}|" "$file"
  else
    sed -i "s|${search}|${replace}|" "$file"
  fi
}

generate_secret() {
  if command_exists openssl; then
    openssl rand -base64 32 | tr -d '\r\n'
  else
    head -c 32 /dev/urandom | base64 | tr -d '\r\n'
  fi
}

generate_password() {
  if command_exists openssl; then
    openssl rand -base64 24 | tr -d '/+=\r\n' | head -c 24
  else
    head -c 24 /dev/urandom | base64 | tr -d '/+=\r\n' | head -c 24
  fi
}

install_docker() {
  if command_exists docker; then
    ok "Docker already installed: $(docker --version)"
    return
  fi

  info "Installing Docker..."
  case "$(detect_os)" in
    macos)
      if command_exists brew; then
        brew install --cask docker
        info "Open Docker Desktop, wait for the daemon, then press Enter."
        read -r
      else
        err "Install Docker Desktop manually, then rerun this script."
        exit 1
      fi
      ;;
    debian)
      sudo apt-get update -qq
      sudo apt-get install -y -qq ca-certificates curl gnupg
      sudo install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      sudo chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
      sudo apt-get update -qq
      sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
      sudo systemctl enable --now docker
      sudo usermod -aG docker "$USER"
      ;;
    amazon)
      sudo yum install -y docker
      sudo systemctl enable --now docker
      sudo usermod -aG docker "$USER"
      ;;
    rhel|fedora)
      sudo dnf install -y dnf-plugins-core
      sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      sudo systemctl enable --now docker
      sudo usermod -aG docker "$USER"
      ;;
    *)
      err "Unsupported OS. Install Docker manually, then rerun this script."
      exit 1
      ;;
  esac

  ok "Docker installed successfully"
}

create_env() {
  if [ -f "$PEPPER_DIR/.env" ]; then
    ok ".env already exists"
    return
  fi

  info "Creating .env configuration..."
  cp "$PEPPER_DIR/.env.example" "$PEPPER_DIR/.env"

  local pg_password nextauth_secret admin_password minio_password
  pg_password="$(generate_password)"
  nextauth_secret="$(generate_secret)"
  admin_password="$(generate_password)"
  minio_password="$(generate_password)"

  replace_in_file "$PEPPER_DIR/.env" 'POSTGRES_PASSWORD="CHANGE_ME_strong_random_password"' "POSTGRES_PASSWORD=\"${pg_password}\""
  replace_in_file "$PEPPER_DIR/.env" 'NEXTAUTH_SECRET="CHANGE_ME_random_secret"' "NEXTAUTH_SECRET=\"${nextauth_secret}\""
  replace_in_file "$PEPPER_DIR/.env" 'ADMIN_PASSWORD="CHANGE_ME_admin_password"' "ADMIN_PASSWORD=\"${admin_password}\""
  replace_in_file "$PEPPER_DIR/.env" '# MINIO_SECRET_KEY="CHANGE_ME_minio_password"' "MINIO_SECRET_KEY=\"${minio_password}\""

  if grep -q 'LLM_API_KEY="CHANGE_ME_openrouter_api_key"' "$PEPPER_DIR/.env"; then
    warn "Set LLM_API_KEY in .env before first AI scan."
  fi

  ok ".env configured"
  echo ""
  echo "  Admin email:    admin@yourcompany.com"
  echo "  Admin password: ${admin_password}"
  echo ""
  warn "Save the admin password above. It is also written to .env."
}

docker_login_if_configured() {
  if ! grep -q '^PEPPER_REGISTRY=' "$PEPPER_DIR/.env"; then
    return
  fi

  # shellcheck disable=SC1090
  . "$PEPPER_DIR/.env"

  if [ -n "${PEPPER_REGISTRY:-}" ] && [ -n "${PEPPER_REGISTRY_USERNAME:-}" ] && [ -n "${PEPPER_REGISTRY_PASSWORD:-}" ]; then
    info "Logging in to private registry ${PEPPER_REGISTRY}..."
    echo "${PEPPER_REGISTRY_PASSWORD}" | docker login "${PEPPER_REGISTRY}" --username "${PEPPER_REGISTRY_USERNAME}" --password-stdin
    ok "Registry login successful"
  else
    info "Skipping registry login: PEPPER_REGISTRY credentials not set"
  fi
}

start_pepper() {
  info "Pulling Pepper images..."
  docker compose -f "$PEPPER_DIR/docker-compose.yml" --env-file "$PEPPER_DIR/.env" pull

  info "Starting Pepper..."
  docker compose -f "$PEPPER_DIR/docker-compose.yml" --env-file "$PEPPER_DIR/.env" up -d

  info "Waiting for Pepper API..."
  local retries=45
  local port
  port=$(grep '^PEPPER_PORT=' "$PEPPER_DIR/.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || true)
  port="${port:-3000}"

  while [ $retries -gt 0 ]; do
    if curl -sf "http://localhost:${port}/api/health" >/dev/null 2>&1; then
      ok "Pepper is running"
      return
    fi
    sleep 2
    retries=$((retries - 1))
  done

  warn "Pepper may still be starting. Check logs with: docker compose logs -f"
}

print_summary() {
  local port
  port=$(grep '^PEPPER_PORT=' "$PEPPER_DIR/.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || true)
  port="${port:-3000}"

  echo ""
  echo "------------------------------------------------------------"
  echo "Pepper SAST is ready"
  echo "------------------------------------------------------------"
  echo "Web UI: http://localhost:${port}"
  echo "Login: check .env for ADMIN_EMAIL and ADMIN_PASSWORD"
  echo ""
  echo "Useful commands:"
  echo "  docker compose ps"
  echo "  docker compose logs -f"
  echo "  docker compose down"
  echo "  docker compose pull && docker compose up -d"
}

main() {
  echo ""
  echo "Pepper SAST setup"
  echo ""

  install_docker
  create_env
  docker_login_if_configured
  start_pepper
  print_summary
}

main "$@"
