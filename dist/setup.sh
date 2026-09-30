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

set_env() {
  # set_env KEY VALUE — replace the KEY= line in .env (value is quoted).
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" 'BEGIN{done=0} $0 ~ "^"k"=" {print k"=\""v"\""; done=1; next} {print} END{if(!done) print k"=\""v"\""}' "$PEPPER_DIR/.env" > "$tmp"
  mv "$tmp" "$PEPPER_DIR/.env"
  chmod 600 "$PEPPER_DIR/.env"
}

env_value() {
  grep -E "^$1=" "$PEPPER_DIR/.env" 2>/dev/null | tail -1 | cut -d'=' -f2- | tr -d '"'
}

create_env() {
  mkdir -p "$PEPPER_DIR/certs"

  if [ -f "$PEPPER_DIR/.env" ]; then
    ok ".env already exists (not modified)"
    return
  fi

  info "Creating .env configuration..."
  cp "$PEPPER_DIR/.env.example" "$PEPPER_DIR/.env"

  local url version admin_email admin_password
  read -r -p "Pepper URL users will open [http://$(hostname -f 2>/dev/null || hostname):3000]: " url
  url="${url:-http://$(hostname -f 2>/dev/null || hostname):3000}"
  read -r -p "Pepper version tag (from your Pepper contact): " version
  read -r -p "Administrator email [admin@yourcompany.com]: " admin_email
  admin_email="${admin_email:-admin@yourcompany.com}"
  admin_password="$(generate_password)"

  set_env NEXTAUTH_URL "$url"
  [ -n "$version" ] && set_env PEPPER_VERSION "$version"
  set_env NEXTAUTH_SECRET "$(generate_secret)"
  set_env POSTGRES_PASSWORD "$(generate_password)"
  set_env MINIO_ROOT_PASSWORD "$(generate_password)"
  set_env ADMIN_EMAIL "$admin_email"
  set_env ADMIN_PASSWORD "$admin_password"

  ok ".env created (permissions 600)"
  echo ""
  echo "  Admin email:    ${admin_email}"
  echo "  Admin password: ${admin_password}"
  echo ""
  warn "Save the admin password. Set LLM_API_KEY (or your internal LLM) in .env before the first AI scan."
}

docker_login_if_configured() {
  local registry user pass
  registry="$(env_value PEPPER_REGISTRY)"
  user="$(env_value PEPPER_REGISTRY_USERNAME)"
  pass="$(env_value PEPPER_REGISTRY_PASSWORD)"
  if [ -n "$registry" ] && [ -n "$user" ] && [ -n "$pass" ]; then
    info "Logging in to registry ${registry}..."
    echo "$pass" | docker login "$registry" --username "$user" --password-stdin
    ok "Registry login successful"
  fi
}

images_present() {
  local img
  for img in $(docker compose -f "$PEPPER_DIR/docker-compose.yml" --env-file "$PEPPER_DIR/.env" config --images); do
    docker image inspect "$img" >/dev/null 2>&1 || return 1
  done
}

start_pepper() {
  if [ "$(env_value PEPPER_VERSION)" = "CHANGE_ME_version_tag" ] || [ -z "$(env_value PEPPER_VERSION)" ]; then
    err "Set PEPPER_VERSION in .env first."
    exit 1
  fi

  if images_present; then
    ok "All images are already loaded (offline install); skipping pull"
  else
    info "Pulling Pepper images..."
    docker compose -f "$PEPPER_DIR/docker-compose.yml" --env-file "$PEPPER_DIR/.env" pull
  fi

  info "Starting Pepper..."
  docker compose -f "$PEPPER_DIR/docker-compose.yml" --env-file "$PEPPER_DIR/.env" up -d

  info "Waiting for Pepper (first start applies the database schema; can take a few minutes)..."
  local retries=90
  local port
  port="$(env_value PEPPER_PORT)"
  port="${port:-3000}"

  while [ $retries -gt 0 ]; do
    if curl -sf "http://localhost:${port}/api/health" >/dev/null 2>&1; then
      ok "Pepper is running"
      return
    fi
    sleep 5
    retries=$((retries - 1))
  done

  warn "Pepper is still starting. Check: docker compose logs -f pepper-api"
}

print_summary() {
  local port
  port=$(grep '^PEPPER_PORT=' "$PEPPER_DIR/.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || true)
  port="${port:-3000}"

  echo ""
  echo "------------------------------------------------------------"
  echo "Pepper SAST is ready"
  echo "------------------------------------------------------------"
  echo "Web UI: $(env_value NEXTAUTH_URL)"
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
