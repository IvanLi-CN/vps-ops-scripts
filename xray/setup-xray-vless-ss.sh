#!/bin/sh

set -eu

CONFIG_DIR="/usr/local/etc/xray"
CONFIG_FILE_NAME="vless-ss-reality.yaml"
SERVICE_NAME_DEFAULT="xray-vless-ss"

read_prompt_value() {
  _var_name="$1"
  # First try stdin (works for interactive shells and CI where input is piped),
  # then fall back to /dev/tty (works for `curl ... | sh` cases).
  if IFS= read -r "${_var_name}"; then
    return 0
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
        echo "Tip: do not run the script via 'curl ... | sh'." >&2
        echo "Instead, download to a file and run it, e.g.:" >&2
        echo "  curl -fsSL <URL> -o /tmp/setup-xray.sh && sh /tmp/setup-xray.sh" >&2
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

install_xray() {
  if command -v xray >/dev/null 2>&1; then
    echo "xray already installed at $(command -v xray)"
    return 0
  fi

  pm="$(detect_pkg_manager)"
  echo "Detected package manager: ${pm}"

  case "${pm}" in
    pacman)
      echo "Installing xray on Arch Linux..."
      # First, prefer any xray package already provided by configured repositories (e.g. Arch Linux CN).
      if pacman -Si xray >/dev/null 2>&1; then
        pacman -S --noconfirm xray
      else
        # Otherwise, install paru-bin from AUR and use it to get xray-bin/xray.
        install_paru
        if paru -S --noconfirm xray-bin; then
          :
        else
          paru -S --noconfirm xray
        fi
      fi
      ;;
    apk)
      echo "Installing xray on Alpine Linux..."
      # Keep the installation self-contained (no external installer scripts),
      # because upstream repo layouts can change.
      apk add --no-cache curl unzip ca-certificates openssl >/dev/null

      machine=""
      case "$(uname -m)" in
        i386|i686) machine="32" ;;
        amd64|x86_64) machine="64" ;;
        armv5tel) machine="arm32-v5" ;;
        armv6l) machine="arm32-v6" ;;
        armv7|armv7l) machine="arm32-v7a" ;;
        armv8|aarch64) machine="arm64-v8a" ;;
        mips) machine="mips32" ;;
        mipsle) machine="mips32le" ;;
        mips64) machine="mips64" ;;
        mips64le) machine="mips64le" ;;
        ppc64) machine="ppc64" ;;
        ppc64le) machine="ppc64le" ;;
        riscv64) machine="riscv64" ;;
        s390x) machine="s390x" ;;
      esac
      if [ -z "${machine}" ]; then
        echo "Unsupported architecture: $(uname -m)"
        exit 1
      fi

      tmpdir="$(mktemp -d)"
      zip_file="${tmpdir}/Xray-linux-${machine}.zip"
      dgst_file="${zip_file}.dgst"
      extract_dir="${tmpdir}/extract"
      download_link="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${machine}.zip"

      echo "Downloading Xray from ${download_link}"
      curl -fsSL -H 'Cache-Control: no-cache' -o "${zip_file}" "${download_link}"
      curl -fsSL -H 'Cache-Control: no-cache' -o "${dgst_file}" "${download_link}.dgst"

      checksum="$(awk -F '= ' '/256=/ {print $2}' "${dgst_file}" | head -n1)"
      localsum="$(sha256sum "${zip_file}" | awk '{print $1}')"
      if [ -z "${checksum}" ] || [ "${checksum}" != "${localsum}" ]; then
        echo "SHA256 verification failed for downloaded Xray zip."
        rm -rf "${tmpdir}"
        exit 1
      fi

      mkdir -p "${extract_dir}"
      unzip -q "${zip_file}" -d "${extract_dir}"
      install -m 0755 "${extract_dir}/xray" /usr/local/bin/xray
      install -d /usr/local/share/xray
      if [ -f "${extract_dir}/geoip.dat" ]; then
        install -m 0644 "${extract_dir}/geoip.dat" /usr/local/share/xray/geoip.dat
      fi
      if [ -f "${extract_dir}/geosite.dat" ]; then
        install -m 0644 "${extract_dir}/geosite.dat" /usr/local/share/xray/geosite.dat
      fi
      rm -rf "${tmpdir}"

      # Some upstream builds may require glibc compatibility on musl systems.
      if ! xray version >/dev/null 2>&1; then
        echo "xray executable failed to run; trying to install gcompat..."
        apk add --no-cache gcompat >/dev/null 2>&1 || true
        xray version >/dev/null 2>&1 || {
          echo "xray was installed, but it cannot run on this system."
          echo "Try: apk add gcompat"
          exit 1
        }
      fi
      ;;
    *)
      echo "Unsupported package manager '${pm}'."
      echo "This helper currently supports only Arch Linux (pacman) and Alpine (apk)."
      exit 1
      ;;
  esac

  if ! command -v xray >/dev/null 2>&1; then
    echo "xray installation seems to have failed (binary not found in PATH)."
    exit 1
  fi
}

generate_uuid() {
  xray uuid
}

generate_reality_keys() {
  # openssl-based keypair to avoid xray x25519 output changes
  tmp="$(mktemp)"
  openssl genpkey -algorithm X25519 -out "${tmp}" >/dev/null 2>&1
  # Xray REALITY expects x25519 keys in base64url (no padding), same as `xray x25519` output.
  priv="$(openssl pkey -in "${tmp}" -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '\n=')"
  pub="$(openssl pkey -in "${tmp}" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '\n=')"
  rm -f "${tmp}"
  echo "Private key: ${priv}"
  echo "Public key: ${pub}"
}

derive_public_key_from_private() {
  _key_priv="$1"
  tmp="$(mktemp)"
  printf "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n" "$(printf "%s" "${_key_priv}" | fold -w64)" > "${tmp}"
  pub="$(openssl pkey -in "${tmp}" -inform PEM -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d "\n")"
  rm -f "${tmp}"
  printf "%s\n" "${pub}"
}

generate_ss2022_password() {
  # Xray does not provide a dedicated ss2022 keygen, use strong random.
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 16
  else
    # fallback: 16 random bytes hex-encoded
    head -c 16 /dev/urandom | xxd -p
  fi
}

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (for installing packages and configuring systemd)."
    exit 1
  fi
}

create_config_from_template() {
  config_dir="$1"

  mkdir -p "${config_dir}"
  mkdir -p /var/log/xray

  echo "=== Basic parameters ==="
  domain=
  port_vless=
  port_ss=
  prompt domain "Enter REALITY domain (SNI / dest host)" ""
  prompt port_vless "Enter VLESS listen port" "443"
  prompt port_ss "Enter Shadowsocks 2022 listen port" "8443"

  echo
  echo "=== Generating secrets using xray and system RNG ==="

  echo "Generating UUID (VLESS client id)..."
  uuid="$(generate_uuid)"

  echo "Generating Reality x25519 keypair..."
  # capture both private and public key output
  reality_output="$(generate_reality_keys)"
  private_key="$(printf '%s\n' "${reality_output}" | awk '/Private key:/ {print $3}')"
  public_key="$(printf '%s\n' "${reality_output}" | awk '/Public key:/ {print $3}')"

  if [ -z "${private_key}" ] || [ -z "${public_key}" ]; then
    echo "Failed to parse x25519 keys from xray output."
    exit 1
  fi

  echo "Generating Shadowsocks 2022 password..."
  ss_password="$(generate_ss2022_password)"

  config_path="${config_dir}/${CONFIG_FILE_NAME}"

  cat <<'EOF' | sed \
    -e "s|\\\$PORT_VLESS\\\$|${port_vless}|g" \
    -e "s|\\\$PORT_SS\\\$|${port_ss}|g" \
    -e "s|\\\$DOMAIN\\\$|${domain}|g" \
    -e "s|\\\$ID\\\$|${uuid}|g" \
    -e "s|\\\$PRIVATE_KEY\\\$|${private_key}|g" \
    -e "s|\\\$PASSWORD\\\$|${ss_password}|g" \
    > "${config_path}"
log:
  loglevel: info
#  access: /var/log/xray/access.log
  error: /var/log/xray/error.log

inbounds:
  - tag: vless-vision
    listen: 0.0.0.0
    port: $PORT_VLESS$
    protocol: vless
    settings:
      clients:
        - id: $ID$
          flow: xtls-rprx-vision
      decryption: none
    streamSettings:
      network: tcp
      security: reality
      realitySettings:
        show: false
        dest: $DOMAIN$:443
        serverNames:
          - $DOMAIN$
        privateKey: $PRIVATE_KEY$
        shortIds:
          - ""
    sniffing:
      enabled: true
      destOverride:
        - http
        - tls
        - quic

  - tag: ss2022-aes128
    listen: 0.0.0.0
    port: $PORT_SS$
    protocol: shadowsocks
    settings:
      method: 2022-blake3-aes-128-gcm
      password: $PASSWORD$
      network: tcp,udp

outbounds:
  - tag: direct
    protocol: freedom
    settings: {}

  - tag: block
    protocol: blackhole
    settings: {}

routing:
  rules:
    - type: field
      inboundTag:
        - vless-vision
        - ss2022-aes128
      outboundTag: direct
EOF

  echo "Config written to: ${config_path}"

  XRAY_CONFIG_PATH="${config_path}"
  XRAY_DOMAIN="${domain}"
  XRAY_PORT_VLESS="${port_vless}"
  XRAY_PORT_SS="${port_ss}"
  XRAY_UUID="${uuid}"
  XRAY_PRIVATE_KEY="${private_key}"
  XRAY_PUBLIC_KEY="${public_key}"
  XRAY_SS_PASSWORD="${ss_password}"
}

validate_config() {
  config_path="$1"

  echo "Validating config with xray..."
  if xray run -test -c "${config_path}" -format yaml; then
    echo "Config validation succeeded."
  else
  echo "Config validation failed."
    exit 1
  fi
}

install_systemd_service() {
  service_name="$1"
  config_path="$2"

  service_file="/etc/systemd/system/${service_name}.service"

  asset_env_line=""
  if [ -n "${XRAY_LOCATION_ASSET:-}" ]; then
    asset_env_line="Environment=XRAY_LOCATION_ASSET=${XRAY_LOCATION_ASSET}"
  fi

  cat > "${service_file}" <<EOF
[Unit]
Description=Xray VLESS+Reality & SS2022 service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
${asset_env_line}
ExecStart=$(command -v xray) run -c ${config_path} -format yaml
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

install_paru() {
  if command -v paru >/dev/null 2>&1; then
    echo "paru already installed at $(command -v paru)"
    return 0
  fi

  echo "Installing paru-bin from AUR (requires network)..."
  pacman -Sy --needed --noconfirm base-devel git

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  (
    cd "${tmpdir}"
    git clone https://aur.archlinux.org/paru-bin.git
    cd paru-bin
    makepkg -si --noconfirm
  )

  if ! command -v paru >/dev/null 2>&1; then
    echo "paru installation failed (binary not found in PATH)."
    exit 1
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

  asset_export_line=""
  if [ -n "${XRAY_LOCATION_ASSET:-}" ]; then
    asset_export_line="export XRAY_LOCATION_ASSET=\"${XRAY_LOCATION_ASSET}\""
  fi

  cat > "${service_file}" <<EOF
#!/sbin/openrc-run
name="${service_name}"
description="Xray VLESS+Reality & SS2022 service"

command="$(command -v xray)"
command_args="run -c ${config_path} -format yaml"
command_background="yes"
pidfile="/run/${service_name}.pid"
rc_ulimit="-n 1048576"
${asset_export_line}

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

    # OpenRC can report a transient "already starting" state (especially in containers or
    # during runlevel transitions). Treat it as retryable and wait for the service to settle.
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
      echo "You can start Xray manually, for example:"
      echo "  $(command -v xray) run -c ${config_path} --format yaml"
      return 0
      ;;
  esac
}

print_mihomo_snippet() {
  name="$1"
  domain="$2"
  port_vless="$3"
  port_ss="$4"
  uuid="$5"
  public_key="$6"
  ss_password="$7"

  cat <<EOF
---
# mihomo / Clash.Meta compatible node snippets
proxies:
  - name: ${name}
    type: vless
    server: ${domain}
    port: ${port_vless}
    uuid: ${uuid}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${domain}
    reality-opts:
      public-key: ${public_key}
      short-id: ""
    client-fingerprint: chrome
  - name: xray-ss2022
    type: ss
    server: ${domain}
    port: ${port_ss}
    cipher: 2022-blake3-aes-128-gcm
    password: '${ss_password}'
    udp: true
EOF
}

main() {
  ensure_root

  echo "=== Xray VLESS+Reality & SS2022 setup helper ==="
  echo
  echo "Config will be written to: ${CONFIG_DIR}/${CONFIG_FILE_NAME}"
  prompt SERVICE_NAME "Service name (systemd/OpenRC)" "${SERVICE_NAME_DEFAULT}"

  install_xray

  create_config_from_template "${CONFIG_DIR}"
  validate_config "${XRAY_CONFIG_PATH}"
  setup_service "${SERVICE_NAME}" "${XRAY_CONFIG_PATH}"

  echo
  echo "Service '${SERVICE_NAME}' has been configured and started (if supported)."
  echo
  echo "=== Mihomo / Clash.Meta node snippet ==="
  print_mihomo_snippet "xray-vless-reality" "${XRAY_DOMAIN}" "${XRAY_PORT_VLESS}" "${XRAY_PORT_SS}" "${XRAY_UUID}" "${XRAY_PUBLIC_KEY}" "${XRAY_SS_PASSWORD}"
}

main "$@"
