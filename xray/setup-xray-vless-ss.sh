#!/bin/sh

set -eu

CONFIG_DIR="/usr/local/etc/xray"
CONFIG_FILE_NAME="vless-ss-reality.yaml"
SERVICE_NAME_DEFAULT="xray-vless-ss"

normalize_systemd_unit_name() {
  case "$1" in
    *.service) printf "%s\n" "$1" ;;
    *) printf "%s.service\n" "$1" ;;
  esac
}

strip_wrapping_quotes() {
  s="$1"
  case "${s}" in
    \"*\") s="${s#\"}"; s="${s%\"}" ;;
    \'*\') s="${s#\'}"; s="${s%\'}" ;;
  esac
  printf "%s\n" "${s}"
}

infer_config_format_from_path() {
  case "$1" in
    *.yaml|*.yml) echo "yaml" ;;
    *.json) echo "json" ;;
    *) echo "yaml" ;;
  esac
}

extract_xray_config_path_from_cmdline() {
  cmd="$1"

  # Word-splitting is OK here because systemd/OpenRC ExecStart/args normally do not contain spaces in paths.
  # We still strip wrapping quotes for robustness.
  set -- ${cmd}
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -c|-config|--config)
        shift
        [ "$#" -gt 0 ] || return 0
        strip_wrapping_quotes "$1"
        return 0
        ;;
      -c=*)
        printf "%s\n" "${1#-c=}"
        return 0
        ;;
      -config=*)
        printf "%s\n" "${1#-config=}"
        return 0
        ;;
      --config=*)
        printf "%s\n" "${1#--config=}"
        return 0
        ;;
      -confdir|--confdir)
        shift
        [ "$#" -gt 0 ] || return 0
        dir="$(strip_wrapping_quotes "$1")"
        printf "%s/%s\n" "${dir%/}" "${CONFIG_FILE_NAME}"
        return 0
        ;;
      -confdir=*)
        dir="${1#-confdir=}"
        printf "%s/%s\n" "${dir%/}" "${CONFIG_FILE_NAME}"
        return 0
        ;;
      --confdir=*)
        dir="${1#--confdir=}"
        printf "%s/%s\n" "${dir%/}" "${CONFIG_FILE_NAME}"
        return 0
        ;;
    esac
    shift
  done

  return 0
}

extract_xray_config_format_from_cmdline() {
  cmd="$1"

  set -- ${cmd}
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -format|--format)
        shift
        [ "$#" -gt 0 ] || return 0
        strip_wrapping_quotes "$1"
        return 0
        ;;
      -format=*)
        printf "%s\n" "${1#-format=}"
        return 0
        ;;
      --format=*)
        printf "%s\n" "${1#--format=}"
        return 0
        ;;
    esac
    shift
  done

  return 0
}

detect_systemd_execstart() {
  service_name="$1"
  unit="$(normalize_systemd_unit_name "${service_name}")"

  systemctl cat "${unit}" 2>/dev/null | awk '
    BEGIN { exec="" }
    /^[[:space:]]*ExecStart=/ {
      line=$0
      sub(/^[[:space:]]*ExecStart=/, "", line)
      if (line == "") { exec=""; next }
      exec=line
    }
    END { if (exec != "") print exec }
  '
}

detect_openrc_command_args() {
  service_name="$1"
  service_file="/etc/init.d/${service_name}"

  [ -f "${service_file}" ] || return 0

  # Prefer `command_args="..."` then `command_args='...'`
  awk -F= '
    $1 ~ /^[[:space:]]*command_args[[:space:]]*$/ {
      val=$2
      sub(/^[[:space:]]*/, "", val)
      sub(/[[:space:]]*$/, "", val)
      gsub(/^'\''|'\''$/, "", val)
      gsub(/^"|"$/, "", val)
      print val
      exit
    }
  ' "${service_file}"
}

detect_existing_service_execstart() {
  service_name="$1"
  init="$(detect_init_system)"

  case "${init}" in
    systemd) detect_systemd_execstart "${service_name}" ;;
    openrc) detect_openrc_command_args "${service_name}" ;;
    *) return 0 ;;
  esac
}

detect_existing_service_config_path() {
  service_name="$1"

  execstart="$(detect_existing_service_execstart "${service_name}")"
  [ -n "${execstart}" ] || return 0

  extract_xray_config_path_from_cmdline "${execstart}"
}

detect_existing_service_config_format() {
  service_name="$1"
  config_path="$2"

  execstart="$(detect_existing_service_execstart "${service_name}")"
  if [ -n "${execstart}" ]; then
    fmt="$(extract_xray_config_format_from_cmdline "${execstart}")"
    if [ -n "${fmt}" ]; then
      printf "%s\n" "${fmt}"
      return 0
    fi
  fi

  infer_config_format_from_path "${config_path}"
}

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
        echo "  curl -fsSL <URL> -o /tmp/setup-xray.sh" >&2
        echo "  printf \"<service>\\n<config_path_or_empty>\\n<domain>\\n<vless_port>\\n<ss_port>\\n\" | sh /tmp/setup-xray.sh" >&2
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
  # Best-effort: query multiple IP echo services, return the first valid IPv4.
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
  elif command -v wget >/dev/null 2>&1; then
    for url in \
      "https://api.ipify.org" \
      "https://checkip.amazonaws.com" \
      "https://ipv4.icanhazip.com" \
      "https://ifconfig.me/ip" \
      "https://ip.sb"; do
      ip="$(wget -qO- "${url}" 2>/dev/null | tr -d '\r\n[:space:]' | sed -n '1p')"
      if [ -n "${ip}" ] && is_ipv4 "${ip}"; then
        printf "%s\n" "${ip}"
        return 0
      fi
    done
  fi

  return 1
}

get_server_addr() {
  # Prefer explicit override (e.g. when the machine has no IPv4).
  if [ -n "${XRAY_SERVER_ADDR:-}" ]; then
    printf "%s\n" "${XRAY_SERVER_ADDR}"
    return 0
  fi
  detect_public_ipv4
}

extract_existing_config_values() {
  config_path="$1"

  EXIST_DOMAIN=""
  EXIST_PORT_VLESS=""
  EXIST_PORT_SS=""
  EXIST_UUID=""
  EXIST_PRIVATE_KEY=""
  EXIST_SS_PASSWORD=""

  [ -f "${config_path}" ] || return 0

  # domain is embedded in: dest: <domain>:443
  EXIST_DOMAIN="$(awk '
    $0 ~ /^[[:space:]]*dest:[[:space:]]*/ {
      sub(/^[[:space:]]*dest:[[:space:]]*/, "", $0)
      sub(/:[0-9]+[[:space:]]*$/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_PORT_VLESS="$(awk '
    $0 ~ /^[[:space:]]*- tag:[[:space:]]*vless-vision[[:space:]]*$/ {in_section=1; next}
    in_section && $0 ~ /^[[:space:]]*- tag:/ {in_section=0}
    in_section && $0 ~ /^[[:space:]]*port:[[:space:]]*/ {
      sub(/^[[:space:]]*port:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_PORT_SS="$(awk '
    $0 ~ /^[[:space:]]*- tag:[[:space:]]*ss2022-aes128[[:space:]]*$/ {in_section=1; next}
    in_section && $0 ~ /^[[:space:]]*- tag:/ {in_section=0}
    in_section && $0 ~ /^[[:space:]]*port:[[:space:]]*/ {
      sub(/^[[:space:]]*port:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_UUID="$(awk '
    $0 ~ /^[[:space:]]*- tag:[[:space:]]*vless-vision[[:space:]]*$/ {in_section=1; next}
    in_section && $0 ~ /^[[:space:]]*- tag:/ {in_section=0}
    in_section && $0 ~ /^[[:space:]]*- id:[[:space:]]*/ {
      sub(/^[[:space:]]*- id:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_PRIVATE_KEY="$(awk '
    $0 ~ /^[[:space:]]*- tag:[[:space:]]*vless-vision[[:space:]]*$/ {in_section=1; next}
    in_section && $0 ~ /^[[:space:]]*- tag:/ {in_section=0}
    in_section && $0 ~ /^[[:space:]]*privateKey:[[:space:]]*/ {
      sub(/^[[:space:]]*privateKey:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"

  EXIST_SS_PASSWORD="$(awk '
    $0 ~ /^[[:space:]]*- tag:[[:space:]]*ss2022-aes128[[:space:]]*$/ {in_section=1; next}
    in_section && $0 ~ /^[[:space:]]*- tag:/ {in_section=0}
    in_section && $0 ~ /^[[:space:]]*password:[[:space:]]*/ {
      sub(/^[[:space:]]*password:[[:space:]]*/, "", $0)
      gsub(/^'\''|'\''$/, "", $0)
      print $0
      exit
    }
  ' "${config_path}")"
}

detect_existing_service_name() {
  config_path="$1"

  # systemd
  if [ -d /etc/systemd/system ]; then
    for f in /etc/systemd/system/*.service; do
      [ -f "${f}" ] || continue
      if grep -q "run -c ${config_path}" "${f}" 2>/dev/null; then
        basename "${f}" .service
        return 0
      fi
    done
  fi

  # OpenRC
  if [ -d /etc/init.d ]; then
    for f in /etc/init.d/*; do
      [ -f "${f}" ] || continue
      if grep -q "run -c ${config_path}" "${f}" 2>/dev/null; then
        basename "${f}"
        return 0
      fi
    done
  fi

  return 1
}

extract_public_key_from_xray_x25519() {
  x25519_output="$1"
  printf '%s\n' "${x25519_output}" | awk '
    /^[Pp]ublic[[:space:]]+[Kk]ey:/ {print $3; exit}
    /^[Pp]ublic[Kk]ey:/ {print $2; exit}
    /^[Pp]assword:/ {print $2; exit}
  '
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
  config_path="$1"
  config_format="$2"

  config_dir="$(dirname "${config_path}")"

  mkdir -p "${config_dir}"
  mkdir -p /var/log/xray

  extract_existing_config_values "${config_path}"
  if [ -f "${config_path}" ]; then
    echo "Detected existing config at: ${config_path}"
    echo "Will use existing values as defaults, and reuse existing secrets when possible."
  fi

  echo "=== Basic parameters ==="
  domain=
  port_vless=
  port_ss=
  prompt domain "Enter REALITY domain (SNI / dest host)" "${EXIST_DOMAIN}"
  prompt port_vless "Enter VLESS listen port" "${EXIST_PORT_VLESS:-443}"
  prompt port_ss "Enter Shadowsocks 2022 listen port" "${EXIST_PORT_SS:-8443}"

  echo
  echo "=== Generating secrets using xray and system RNG ==="

  uuid=""
  if [ -n "${EXIST_UUID}" ] && [ -z "${XRAY_REGEN_SECRETS:-}" ]; then
    echo "Reusing existing UUID (VLESS client id)..."
    uuid="${EXIST_UUID}"
  else
    echo "Generating UUID (VLESS client id)..."
    uuid="$(generate_uuid)"
  fi

  private_key=""
  public_key=""
  if [ -n "${EXIST_PRIVATE_KEY}" ] && [ -z "${XRAY_REGEN_SECRETS:-}" ]; then
    echo "Reusing existing Reality x25519 private key..."
    private_key="${EXIST_PRIVATE_KEY}"
    x25519_out="$(xray x25519 -i "${private_key}" 2>/dev/null || true)"
    public_key="$(extract_public_key_from_xray_x25519 "${x25519_out}")"
    if [ -z "${public_key}" ]; then
      x25519_out="$(xray x25519 --std-encoding -i "${private_key}" 2>/dev/null || true)"
      public_key="$(extract_public_key_from_xray_x25519 "${x25519_out}")"
    fi
    if [ -z "${public_key}" ]; then
      echo "Failed to derive public key from existing private key."
      echo "Set XRAY_REGEN_SECRETS=1 to regenerate the Reality keypair."
      exit 1
    fi
  else
    echo "Generating Reality x25519 keypair..."
    # capture both private and public key output
    reality_output="$(generate_reality_keys)"
    private_key="$(printf '%s\n' "${reality_output}" | awk '/Private key:/ {print $3}')"
    public_key="$(printf '%s\n' "${reality_output}" | awk '/Public key:/ {print $3}')"
  fi

  if [ -z "${private_key}" ] || [ -z "${public_key}" ]; then
    echo "Failed to parse x25519 keys from xray output."
    exit 1
  fi

  ss_password=""
  if [ -n "${EXIST_SS_PASSWORD}" ] && [ -z "${XRAY_REGEN_SECRETS:-}" ]; then
    echo "Reusing existing Shadowsocks 2022 password..."
    ss_password="${EXIST_SS_PASSWORD}"
  else
    echo "Generating Shadowsocks 2022 password..."
    ss_password="$(generate_ss2022_password)"
  fi

  if [ "${config_format}" = "json" ]; then
    cat <<'EOF' | sed \
      -e "s|\\\$PORT_VLESS\\\$|${port_vless}|g" \
      -e "s|\\\$PORT_SS\\\$|${port_ss}|g" \
      -e "s|\\\$DOMAIN\\\$|${domain}|g" \
      -e "s|\\\$ID\\\$|${uuid}|g" \
      -e "s|\\\$PRIVATE_KEY\\\$|${private_key}|g" \
      -e "s|\\\$PASSWORD\\\$|${ss_password}|g" \
      > "${config_path}"
{
  "log": {
    "loglevel": "info",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "vless-vision",
      "listen": "0.0.0.0",
      "port": $PORT_VLESS$,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$ID$",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$DOMAIN$:443",
          "serverNames": [
            "$DOMAIN$"
          ],
          "privateKey": "$PRIVATE_KEY$",
          "shortIds": [
            ""
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "tag": "ss2022-aes128",
      "listen": "0.0.0.0",
      "port": $PORT_SS$,
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "$PASSWORD$",
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "vless-vision",
          "ss2022-aes128"
        ],
        "outboundTag": "direct"
      }
    ]
  }
}
EOF
  else
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
  fi

  echo "Config written to: ${config_path}"

  XRAY_CONFIG_PATH="${config_path}"
  XRAY_CONFIG_FORMAT="${config_format}"
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
  config_format="$2"

  echo "Validating config with xray..."
  if xray run -test -c "${config_path}" -format "${config_format}"; then
    echo "Config validation succeeded."
  else
  echo "Config validation failed."
    exit 1
  fi
}

install_systemd_service() {
  service_name="$1"
  config_path="$2"
  config_format="$3"

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
ExecStart=$(command -v xray) run -c ${config_path} -format ${config_format}
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
  config_format="$3"

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
command_args="run -c ${config_path} -format ${config_format}"
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
  config_format="$3"

  init="$(detect_init_system)"

  case "${init}" in
    systemd)
      install_systemd_service "${service_name}" "${config_path}" "${config_format}"
      ;;
    openrc)
      install_openrc_service "${service_name}" "${config_path}" "${config_format}"
      ;;
    *)
      echo "Could not detect supported init system (systemd or OpenRC); skipping service setup."
      echo "You can start Xray manually, for example:"
      echo "  $(command -v xray) run -c ${config_path} --format ${config_format}"
      return 0
      ;;
  esac
}

print_mihomo_snippet() {
  name="$1"
  server_addr="$2"
  sni_domain="$3"
  port_vless="$4"
  port_ss="$5"
  uuid="$6"
  public_key="$7"
  ss_password="$8"

  cat <<EOF
---
# mihomo / Clash.Meta compatible node snippets
proxies:
  - name: ${name}
    type: vless
    server: ${server_addr}
    port: ${port_vless}
    uuid: ${uuid}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${sni_domain}
    reality-opts:
      public-key: ${public_key}
      short-id: ""
    client-fingerprint: chrome
  - name: xray-ss2022
    type: ss
    server: ${server_addr}
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
  default_config_path="${CONFIG_DIR}/${CONFIG_FILE_NAME}"
  prompt SERVICE_NAME "Service name (systemd/OpenRC)" "${SERVICE_NAME_DEFAULT}"

  install_xray

  detected_config_path="$(detect_existing_service_config_path "${SERVICE_NAME}" 2>/dev/null || true)"

  config_path_default="${XRAY_CONFIG_PATH:-}"
  if [ -z "${config_path_default}" ]; then
    config_path_default="${detected_config_path:-${default_config_path}}"
  fi

  echo "Config path (default): ${config_path_default}"
  if [ -n "${detected_config_path}" ]; then
    echo "Detected existing service '${SERVICE_NAME}' uses config: ${detected_config_path}"
  fi
  if [ -n "${XRAY_CONFIG_PATH:-}" ]; then
    echo "XRAY_CONFIG_PATH is set; overriding config path to: ${XRAY_CONFIG_PATH}"
  fi

  prompt CONFIG_PATH "Config file path" "${config_path_default}"
  if [ -n "${detected_config_path}" ] && [ "${CONFIG_PATH}" != "${detected_config_path}" ]; then
    echo "Warning: service '${SERVICE_NAME}' currently uses '${detected_config_path}'."
    echo "If systemd/OpenRC overrides ExecStart, the service may keep using the old path."
  fi

  config_format_default="${XRAY_CONFIG_FORMAT:-}"
  if [ -z "${config_format_default}" ]; then
    config_format_default="$(detect_existing_service_config_format "${SERVICE_NAME}" "${CONFIG_PATH}" 2>/dev/null || true)"
  fi
  config_format="${config_format_default:-yaml}"
  echo "Config format: ${config_format}"

  create_config_from_template "${CONFIG_PATH}" "${config_format}"
  validate_config "${XRAY_CONFIG_PATH}" "${XRAY_CONFIG_FORMAT}"
  setup_service "${SERVICE_NAME}" "${XRAY_CONFIG_PATH}" "${XRAY_CONFIG_FORMAT}"

  echo
  echo "Service '${SERVICE_NAME}' has been configured and started (if supported)."
  echo
  echo "=== Mihomo / Clash.Meta node snippet ==="
  server_addr="$(get_server_addr 2>/dev/null || true)"
  if [ -z "${server_addr}" ]; then
    server_addr="${XRAY_DOMAIN}"
    echo "Warning: failed to detect public IPv4; using '${server_addr}' as server address."
    echo "Tip: set XRAY_SERVER_ADDR=<your VPS IP/domain> to override."
  fi
  print_mihomo_snippet "xray-vless-reality" "${server_addr}" "${XRAY_DOMAIN}" "${XRAY_PORT_VLESS}" "${XRAY_PORT_SS}" "${XRAY_UUID}" "${XRAY_PUBLIC_KEY}" "${XRAY_SS_PASSWORD}"
}

main "$@"
