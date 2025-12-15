#!/bin/sh

set -eu

CONFIG_DIR="/usr/local/etc/hysteria"
CONFIG_FILE_NAME="server.yaml"
SERVICE_NAME_DEFAULT="hysteria-server"

read_prompt_value() {
  _var_name="$1"

  # If the script is executed from a file, stdin can safely be used for prompts
  # (e.g. CI piping answers via `printf ... | sh ./script.sh`).
  #
  # If the script is executed from stdin (e.g. `curl ... | sh`), stdin contains
  # the script itself and must NOT be used for prompts. In that case, prefer
  # /dev/tty and fail if it's unavailable.
  if [ -f "${0}" ] || [ -f "./${0}" ]; then
    if IFS= read -r "${_var_name}"; then
      return 0
    fi
    if [ -r /dev/tty ] && IFS= read -r "${_var_name}" < /dev/tty; then
      return 0
    fi
    return 1
  fi

  if [ -r /dev/tty ] && IFS= read -r "${_var_name}" < /dev/tty; then
    return 0
  fi
  return 1
}

prompt() {
  _prompt_name="$1"
  _prompt_text="$2"
  _prompt_default="${3-}"

  _prompt_value=""
  if [ -n "${_prompt_default}" ]; then
    printf '%s [%s]: ' "${_prompt_text}" "${_prompt_default}"
    if ! read_prompt_value _prompt_value; then
      _prompt_value=""
    fi
    [ -z "${_prompt_value}" ] && _prompt_value="${_prompt_default}"
  else
    while :; do
      printf '%s: ' "${_prompt_text}"
      if ! read_prompt_value _prompt_value; then
        echo "No input available for prompt '${_prompt_text}'." >&2
        echo "Tip: run the script in an interactive shell (TTY) so it can read your input." >&2
        echo "If you must run non-interactively, download to a file and pipe answers in, e.g.:" >&2
        echo "  curl -fsSL <URL> -o /tmp/setup-hysteria.sh" >&2
        echo "  printf \"<service>\\n<domain>\\n<port>\\n<tls_mode>\\n<email/cert>\\n<key>\\n\" | sh /tmp/setup-hysteria.sh" >&2
        exit 1
      fi
      [ -n "${_prompt_value}" ] && break
      echo "Value is required, please try again."
    done
  fi
  eval "${_prompt_name}=\${_prompt_value}"
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  elif command -v apk >/dev/null 2>&1; then
    echo "apk"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper"
  else
    echo "unknown"
  fi
}

install_deps() {
  pm="$1"

  case "${pm}" in
    apt)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl openssl
      ;;
    dnf)
      dnf -y install ca-certificates curl openssl
      ;;
    yum)
      yum -y install ca-certificates curl openssl
      ;;
    pacman)
      pacman -Sy --noconfirm ca-certificates curl openssl
      ;;
    apk)
      apk add --no-cache ca-certificates curl openssl
      ;;
    zypper)
      zypper --non-interactive install -y ca-certificates curl openssl
      ;;
    *)
      echo "Unsupported package manager '${pm}'." >&2
      echo "Please install dependencies manually: curl, ca-certificates, openssl, sha256sum." >&2
      return 1
      ;;
  esac
}

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (for installing packages and configuring services)."
    exit 1
  fi
}

is_ipv4() {
  ip="$1"
  printf "%s" "${ip}" | awk -F. '
    NF != 4 { exit 1 }
    {
      for (i = 1; i <= 4; i++) {
        if ($i !~ /^[0-9]+$/) exit 1
        if ($i < 0 || $i > 255) exit 1
      }
      exit 0
    }
  '
}

detect_public_ipv4() {
  if command -v curl >/dev/null 2>&1; then
    for url in \
      "https://api.ipify.org" \
      "https://checkip.amazonaws.com" \
      "https://ipv4.icanhazip.com" \
      "https://ifconfig.me/ip" \
      "https://ip.sb"; do
      ip="$(curl -fsSL --connect-timeout 3 --max-time 5 "${url}" 2>/dev/null | tr -d '\r\n[:space:]' | sed -n '1p')"
      if [ -n "${ip}" ] && is_ipv4 "${ip}"; then
        printf "%s\n" "${ip}"
        return 0
      fi
    done
  fi
  return 1
}

get_server_addr() {
  if [ -n "${HYSTERIA_SERVER_ADDR:-}" ]; then
    printf "%s\n" "${HYSTERIA_SERVER_ADDR}"
    return 0
  fi
  detect_public_ipv4
}

random_urlsafe_string() {
  # Generate a URL-safe string usable in hysteria2:// auth component without encoding.
  # Length default: 16.
  _len="${1:-16}"
  if command -v openssl >/dev/null 2>&1; then
    # base64 can contain +/=; strip to alnum for simplicity.
    openssl rand -base64 48 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "${_len}"
  else
    head -c 128 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "${_len}"
  fi
}

detect_hysteria_arch() {
  if [ -n "${HYSTERIA_ARCHITECTURE:-}" ]; then
    printf "%s\n" "${HYSTERIA_ARCHITECTURE}"
    return 0
  fi

  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    i386|i686) echo "386" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7|armv7l|armhf) echo "arm" ;;
    armv6l) echo "arm" ;;
    armv5tel) echo "armv5" ;;
    loongarch64|loong64) echo "loong64" ;;
    mipsle) echo "mipsle" ;;
    riscv64) echo "riscv64" ;;
    s390x) echo "s390x" ;;
    *)
      echo "unknown"
      ;;
  esac
}

install_hysteria() {
  if command -v hysteria >/dev/null 2>&1; then
    echo "hysteria already installed at $(command -v hysteria)"
    return 0
  fi

  if [ "$(uname -s)" != "Linux" ]; then
    echo "This installer currently supports Linux only. (Detected: $(uname -s))" >&2
    exit 1
  fi

  pm="$(detect_pkg_manager)"
  echo "Detected package manager: ${pm}"
  install_deps "${pm}" >/dev/null 2>&1 || install_deps "${pm}"

  arch="$(detect_hysteria_arch)"
  if [ "${arch}" = "unknown" ]; then
    echo "Unsupported architecture: $(uname -m)" >&2
    echo "Tip: set HYSTERIA_ARCHITECTURE=<one of: amd64, amd64-avx, arm64, arm, 386, ...> to override." >&2
    exit 1
  fi

  tmpdir="$(mktemp -d)"
  bin_file="${tmpdir}/hysteria"
  hashes_file="${tmpdir}/hashes.txt"

  download_link="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${arch}"
  hashes_link="https://github.com/apernet/hysteria/releases/latest/download/hashes.txt"

  echo "Downloading Hysteria from ${download_link}"
  curl -fsSL -H 'Cache-Control: no-cache' -o "${bin_file}" "${download_link}"
  curl -fsSL -H 'Cache-Control: no-cache' -o "${hashes_file}" "${hashes_link}"

  expected="$(awk -v target="build/hysteria-linux-${arch}" '$2==target {print $1; exit}' "${hashes_file}")"
  if [ -z "${expected}" ]; then
    echo "Failed to locate SHA256 in hashes.txt for arch '${arch}'." >&2
    rm -rf "${tmpdir}"
    exit 1
  fi

  localsum="$(sha256sum "${bin_file}" | awk '{print $1}')"
  if [ "${expected}" != "${localsum}" ]; then
    echo "SHA256 verification failed for downloaded Hysteria binary." >&2
    rm -rf "${tmpdir}"
    exit 1
  fi

  install -m 0755 "${bin_file}" /usr/local/bin/hysteria
  rm -rf "${tmpdir}"

  if ! command -v hysteria >/dev/null 2>&1; then
    echo "hysteria installation seems to have failed (binary not found in PATH)." >&2
    exit 1
  fi

  hysteria version || true
}

extract_existing_config_values() {
  config_path="$1"

  EXIST_DOMAIN=""
  EXIST_PORT=""
  EXIST_TLS_MODE=""
  EXIST_ACME_EMAIL=""
  EXIST_CERT=""
  EXIST_KEY=""
  EXIST_AUTH_PASSWORD=""
  EXIST_OBFS_PASSWORD=""
  EXIST_MASQ_URL=""

  [ -f "${config_path}" ] || return 0

  # listen: :443
  EXIST_PORT="$(awk '
    $0 ~ /^[[:space:]]*listen:[[:space:]]*:/ {
      sub(/^[[:space:]]*listen:[[:space:]]*:/, "", $0)
      gsub(/[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  if grep -q "^[[:space:]]*acme:" "${config_path}" 2>/dev/null; then
    EXIST_TLS_MODE="acme"
  elif grep -q "^[[:space:]]*tls:" "${config_path}" 2>/dev/null; then
    EXIST_TLS_MODE="tls"
  fi

  EXIST_DOMAIN="$(awk '
    $0 ~ /^[[:space:]]*acme:[[:space:]]*$/ {in_acme=1; next}
    in_acme && $0 ~ /^[[:space:]]*tls:[[:space:]]*$/ {in_acme=0}
    in_acme && $0 ~ /^[[:space:]]*auth:[[:space:]]*$/ {in_acme=0}
    in_acme && $0 ~ /^[[:space:]]*-[[:space:]]*/ {
      sub(/^[[:space:]]*-[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_ACME_EMAIL="$(awk '
    $0 ~ /^[[:space:]]*acme:[[:space:]]*$/ {in_acme=1; next}
    in_acme && $0 ~ /^[[:space:]]*email:[[:space:]]*/ {
      sub(/^[[:space:]]*email:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_CERT="$(awk '
    $0 ~ /^[[:space:]]*tls:[[:space:]]*$/ {in_tls=1; next}
    in_tls && $0 ~ /^[[:space:]]*cert:[[:space:]]*/ {
      sub(/^[[:space:]]*cert:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_KEY="$(awk '
    $0 ~ /^[[:space:]]*tls:[[:space:]]*$/ {in_tls=1; next}
    in_tls && $0 ~ /^[[:space:]]*key:[[:space:]]*/ {
      sub(/^[[:space:]]*key:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_AUTH_PASSWORD="$(awk '
    $0 ~ /^[[:space:]]*auth:[[:space:]]*$/ {in_auth=1; next}
    in_auth && $0 ~ /^[[:space:]]*password:[[:space:]]*/ {
      sub(/^[[:space:]]*password:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_OBFS_PASSWORD="$(awk '
    $0 ~ /^[[:space:]]*obfs:[[:space:]]*$/ {in_obfs=1; next}
    in_obfs && $0 ~ /^[[:space:]]*password:[[:space:]]*/ {
      sub(/^[[:space:]]*password:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_MASQ_URL="$(awk '
    $0 ~ /^[[:space:]]*masquerade:[[:space:]]*$/ {in_m=1; next}
    in_m && $0 ~ /^[[:space:]]*url:[[:space:]]*/ {
      sub(/^[[:space:]]*url:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"
}

detect_existing_service_name() {
  config_path="$1"

  if [ -d /etc/systemd/system ]; then
    for f in /etc/systemd/system/*.service; do
      [ -f "${f}" ] || continue
      if grep -q "\-c ${config_path}" "${f}" 2>/dev/null; then
        basename "${f}" .service
        return 0
      fi
    done
  fi

  if [ -d /etc/init.d ]; then
    for f in /etc/init.d/*; do
      [ -f "${f}" ] || continue
      if grep -q "\-c ${config_path}" "${f}" 2>/dev/null; then
        basename "${f}"
        return 0
      fi
    done
  fi

  return 1
}

validate_config_basic() {
  config_path="$1"

  if [ ! -s "${config_path}" ]; then
    echo "Config file is empty: ${config_path}" >&2
    exit 1
  fi

  if ! grep -Eq "^[[:space:]]*listen:" "${config_path}"; then
    echo "Config missing 'listen:'." >&2
    exit 1
  fi

  has_acme="0"
  has_tls="0"
  grep -Eq "^[[:space:]]*acme:" "${config_path}" && has_acme="1" || true
  grep -Eq "^[[:space:]]*tls:" "${config_path}" && has_tls="1" || true
  if [ "${has_acme}" = "1" ] && [ "${has_tls}" = "1" ]; then
    echo "Config must not contain both 'acme' and 'tls' sections." >&2
    exit 1
  fi
  if [ "${has_acme}" = "0" ] && [ "${has_tls}" = "0" ]; then
    echo "Config must contain either 'acme' or 'tls' section." >&2
    exit 1
  fi

  if ! grep -Eq "^[[:space:]]*auth:" "${config_path}"; then
    echo "Config missing 'auth:'." >&2
    exit 1
  fi
}

create_config() {
  config_dir="$1"

  mkdir -p "${config_dir}"
  mkdir -p /var/log/hysteria >/dev/null 2>&1 || true

  config_path="${config_dir}/${CONFIG_FILE_NAME}"
  extract_existing_config_values "${config_path}"
  if [ -f "${config_path}" ]; then
    echo "Detected existing config at: ${config_path}"
    echo "Will use existing values as defaults, and reuse existing secrets when possible."
  fi

  echo "=== Basic parameters ==="
  domain=""
  port=""
  tls_mode=""

  prompt domain "Enter domain (used for ACME domain / TLS SNI)" "${EXIST_DOMAIN}"
  prompt port "Enter listen port" "${EXIST_PORT:-443}"

  default_mode="${EXIST_TLS_MODE:-acme}"
  prompt tls_mode "TLS mode (acme|tls)" "${default_mode}"
  case "${tls_mode}" in
    acme|tls)
      ;;
    *)
      echo "Invalid TLS mode: ${tls_mode} (expected: acme|tls)" >&2
      exit 1
      ;;
  esac

  acme_email=""
  cert=""
  key=""

  if [ "${tls_mode}" = "acme" ]; then
    prompt acme_email "ACME email" "${EXIST_ACME_EMAIL}"
  else
    prompt cert "TLS cert path" "${EXIST_CERT}"
    prompt key "TLS key path" "${EXIST_KEY}"
  fi

  echo
  echo "=== Secrets ==="
  auth_password=""
  if [ -n "${EXIST_AUTH_PASSWORD}" ] && [ -z "${HYSTERIA_REGEN_SECRETS:-}" ]; then
    echo "Reusing existing auth password..."
    auth_password="${EXIST_AUTH_PASSWORD}"
  else
    echo "Generating auth password..."
    auth_password="$(random_urlsafe_string 18)"
  fi

  obfs_enabled="no"
  if [ -n "${EXIST_OBFS_PASSWORD}" ]; then
    obfs_enabled="yes"
  fi
  prompt obfs_enabled "Enable obfuscation salamander? (yes|no)" "${obfs_enabled}"
  case "${obfs_enabled}" in
    yes|no)
      ;;
    *)
      echo "Invalid value: ${obfs_enabled} (expected: yes|no)" >&2
      exit 1
      ;;
  esac

  obfs_password=""
  if [ "${obfs_enabled}" = "yes" ]; then
    if [ -n "${EXIST_OBFS_PASSWORD}" ] && [ -z "${HYSTERIA_REGEN_SECRETS:-}" ]; then
      echo "Reusing existing obfs password..."
      obfs_password="${EXIST_OBFS_PASSWORD}"
    else
      echo "Generating obfs password..."
      obfs_password="$(random_urlsafe_string 18)"
    fi
  fi

  masquerade_enabled="no"
  if [ -n "${EXIST_MASQ_URL}" ]; then
    masquerade_enabled="yes"
  fi
  prompt masquerade_enabled "Enable masquerade proxy? (yes|no)" "${masquerade_enabled}"
  case "${masquerade_enabled}" in
    yes|no)
      ;;
    *)
      echo "Invalid value: ${masquerade_enabled} (expected: yes|no)" >&2
      exit 1
      ;;
  esac

  masq_url=""
  if [ "${masquerade_enabled}" = "yes" ]; then
    prompt masq_url "Masquerade proxy url" "${EXIST_MASQ_URL:-https://news.ycombinator.com/}"
  fi

  {
    echo "listen: :${port}"
    echo
    if [ "${tls_mode}" = "acme" ]; then
      cat <<EOF
acme:
  domains:
    - ${domain}
  email: ${acme_email}
EOF
    else
      cat <<EOF
tls:
  cert: ${cert}
  key: ${key}
EOF
    fi
    echo
    cat <<EOF
auth:
  type: password
  password: ${auth_password}
EOF

    if [ "${obfs_enabled}" = "yes" ]; then
      echo
      cat <<EOF
obfs:
  type: salamander
  salamander:
    password: ${obfs_password}
EOF
    fi

    if [ "${masquerade_enabled}" = "yes" ]; then
      echo
      cat <<EOF
masquerade:
  type: proxy
  proxy:
    url: ${masq_url}
    rewriteHost: true
EOF
    fi
  } > "${config_path}"

  echo "Config written to: ${config_path}"

  HYSTERIA_CONFIG_PATH="${config_path}"
  HYSTERIA_DOMAIN="${domain}"
  HYSTERIA_PORT="${port}"
  HYSTERIA_TLS_MODE="${tls_mode}"
  HYSTERIA_ACME_EMAIL="${acme_email}"
  HYSTERIA_CERT="${cert}"
  HYSTERIA_KEY="${key}"
  HYSTERIA_AUTH_PASSWORD="${auth_password}"
  HYSTERIA_OBFS_ENABLED="${obfs_enabled}"
  HYSTERIA_OBFS_PASSWORD="${obfs_password}"
  HYSTERIA_MASQUERADE_ENABLED="${masquerade_enabled}"
  HYSTERIA_MASQ_URL="${masq_url}"
}

install_systemd_service() {
  service_name="$1"
  config_path="$2"

  service_file="/etc/systemd/system/${service_name}.service"

  cat > "${service_file}" <<EOF
[Unit]
Description=Hysteria 2 server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(command -v hysteria) --disable-update-check -c ${config_path} server
Restart=on-failure
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNPROC=512
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  echo "systemd service written to: ${service_file}"

  systemctl daemon-reload
  systemctl enable --now "${service_name}.service"
  systemctl --no-pager --full status "${service_name}.service" || true
}

detect_init_system() {
  pid1="$(ps -p 1 -o comm= 2>/dev/null || echo "")"
  if command -v systemctl >/dev/null 2>&1 && [ "${pid1}" = "systemd" ]; then
    echo "systemd"
  elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
    echo "openrc"
  else
    echo "unknown"
  fi
}

install_openrc_service() {
  service_name="$1"
  config_path="$2"

  if ! command -v rc-update >/dev/null 2>&1 || ! command -v rc-service >/dev/null 2>&1; then
    echo "OpenRC tools (rc-update / rc-service) not found; cannot install service automatically."
    return 1
  fi

  service_file="/etc/init.d/${service_name}"

  cat > "${service_file}" <<EOF
#!/sbin/openrc-run
name="${service_name}"
description="Hysteria 2 server"

command="$(command -v hysteria)"
command_args="--disable-update-check -c ${config_path} server"
command_background="yes"
pidfile="/run/${service_name}.pid"
rc_ulimit="-n 1048576"

depend() {
  need net
  after net
}
EOF

  chmod +x "${service_file}"
  rc-update add "${service_name}" default || true

  action="start"
  status_out="$(rc-service "${service_name}" status 2>&1 || true)"
  if printf "%s" "${status_out}" | grep -q "started"; then
    action="restart"
  fi

  tmpout="$(mktemp)"
  if rc-service "${service_name}" "${action}" >"${tmpout}" 2>&1; then
    cat "${tmpout}"
    rm -f "${tmpout}"
  else
    rc="$?"
    out="$(cat "${tmpout}")"
    cat "${tmpout}"
    rm -f "${tmpout}"

    if printf "%s" "${out}" | grep -qi "already starting"; then
      echo "Service '${service_name}' is still starting; waiting..."
      for i in $(seq 1 30); do
        status_out="$(rc-service "${service_name}" status 2>&1 || true)"
        echo "${status_out}"
        if printf "%s" "${status_out}" | grep -q "started"; then
          rc=0
          break
        fi
        sleep 1
      done
    fi

    if [ "${rc}" -ne 0 ]; then
      echo "OpenRC service '${service_name}' failed to ${action}."
      return 1
    fi
  fi

  rc-service "${service_name}" status || true
}

setup_service() {
  service_name="$1"
  config_path="$2"

  if [ -n "${HYSTERIA_SKIP_SERVICE:-}" ]; then
    echo "HYSTERIA_SKIP_SERVICE is set; skipping service setup."
    return 0
  fi

  init="$(detect_init_system)"
  case "${init}" in
    systemd)
      install_systemd_service "${service_name}" "${config_path}"
      ;;
    openrc)
      install_openrc_service "${service_name}" "${config_path}"
      ;;
    *)
      echo "Could not detect supported init system (systemd or OpenRC); skipping service setup."
      echo "You can start Hysteria manually, for example:"
      echo "  $(command -v hysteria) --disable-update-check -c ${config_path} server"
      return 0
      ;;
  esac
}

print_client_snippet() {
  server_addr="$1"
  port="$2"
  domain="$3"
  auth_password="$4"
  obfs_enabled="$5"
  obfs_password="$6"

  cat <<EOF
---
# Hysteria 2 client config (example)
server: ${server_addr}:${port}
auth: ${auth_password}
tls:
  sni: ${domain}
  insecure: false
EOF

  if [ "${obfs_enabled}" = "yes" ]; then
    cat <<EOF
obfs:
  type: salamander
  salamander:
    password: ${obfs_password}
EOF
  fi
}

print_share_uri() {
  server_addr="$1"
  port="$2"
  domain="$3"
  auth_password="$4"
  obfs_enabled="$5"
  obfs_password="$6"

  uri="hysteria2://${auth_password}@${server_addr}:${port}/?sni=${domain}&insecure=0"
  if [ "${obfs_enabled}" = "yes" ]; then
    uri="${uri}&obfs=salamander&obfs-password=${obfs_password}"
  fi
  printf "%s\n" "${uri}"
}

print_mihomo_snippet() {
  name="$1"
  server_addr="$2"
  port="$3"
  domain="$4"
  auth_password="$5"
  obfs_enabled="$6"
  obfs_password="$7"

  cat <<EOF
---
# mihomo / Clash.Meta compatible node snippet
proxies:
  - name: ${name}
    type: hysteria2
    server: ${server_addr}
    port: ${port}
    password: ${auth_password}
    sni: ${domain}
    skip-cert-verify: false
    alpn:
      - h3
    udp: true
EOF

  if [ "${obfs_enabled}" = "yes" ]; then
    cat <<EOF
    obfs: salamander
    obfs-password: ${obfs_password}
EOF
  fi
}

main() {
  ensure_root

  echo "=== Hysteria 2 server setup helper ==="
  echo
  echo "Config will be written to: ${CONFIG_DIR}/${CONFIG_FILE_NAME}"

  existing_service_name="$(detect_existing_service_name "${CONFIG_DIR}/${CONFIG_FILE_NAME}" 2>/dev/null || true)"
  if [ -n "${existing_service_name}" ]; then
    prompt SERVICE_NAME "Service name (systemd/OpenRC)" "${existing_service_name}"
  else
    prompt SERVICE_NAME "Service name (systemd/OpenRC)" "${SERVICE_NAME_DEFAULT}"
  fi

  install_hysteria
  create_config "${CONFIG_DIR}"
  validate_config_basic "${HYSTERIA_CONFIG_PATH}"
  setup_service "${SERVICE_NAME}" "${HYSTERIA_CONFIG_PATH}"

  echo
  echo "=== Client config / share URI ==="
  server_addr="$(get_server_addr 2>/dev/null || true)"
  if [ -z "${server_addr}" ]; then
    server_addr="${HYSTERIA_DOMAIN}"
    echo "Warning: failed to detect public IPv4; using '${server_addr}' as server address."
    echo "Tip: set HYSTERIA_SERVER_ADDR=<your VPS IP/domain> to override."
  fi

  print_client_snippet "${server_addr}" "${HYSTERIA_PORT}" "${HYSTERIA_DOMAIN}" "${HYSTERIA_AUTH_PASSWORD}" "${HYSTERIA_OBFS_ENABLED}" "${HYSTERIA_OBFS_PASSWORD}"
  echo
  echo "# share URI"
  print_share_uri "${server_addr}" "${HYSTERIA_PORT}" "${HYSTERIA_DOMAIN}" "${HYSTERIA_AUTH_PASSWORD}" "${HYSTERIA_OBFS_ENABLED}" "${HYSTERIA_OBFS_PASSWORD}"
  echo
  echo "=== Mihomo / Clash.Meta node snippet ==="
  print_mihomo_snippet "hysteria2" "${server_addr}" "${HYSTERIA_PORT}" "${HYSTERIA_DOMAIN}" "${HYSTERIA_AUTH_PASSWORD}" "${HYSTERIA_OBFS_ENABLED}" "${HYSTERIA_OBFS_PASSWORD}"

  echo
  echo "Reminder: open UDP port ${HYSTERIA_PORT} in your firewall / security group."
  if [ "${HYSTERIA_TLS_MODE}" = "acme" ]; then
    echo "Reminder: ACME may require port 80/443 depending on challenge type and configuration."
  fi
}

main "$@"
