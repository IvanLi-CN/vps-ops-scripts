#!/bin/sh
#
# Initialize an Alpine Linux server:
# - Set root password
# - Create a new user
# - Configure timezone (UTC+8, Asia/Shanghai)
# - Install and configure OpenSSH
# - Set up SSH key-based login from a fixed authorized_keys URL
# - Configure sshd keepalive
# - Install and initialize zsh for the new user

set -u

read_tty() {
  # Usage: read_tty VAR "prompt"
  local __varname="$1"
  shift
  local __prompt="$*"

  if [ -n "$__prompt" ]; then
    if [ -r /dev/tty ]; then
      printf '%s' "$__prompt" > /dev/tty
    else
      printf '%s' "$__prompt"
    fi
  fi

  if [ -r /dev/tty ]; then
    if ! read -r "$__varname" < /dev/tty; then
      eval "$__varname=''"
      return 1
    fi
  else
    if ! read -r "$__varname"; then
      eval "$__varname=''"
      return 1
    fi
  fi

  return 0
}

SSH_AUTH_KEYS_URL="https://webdav-syncthing.ivanli.cc/Ivan-Personal/Credentials/Public/authorized_keys-uys8y1bkrxi55v0gOJWtrKJ2uM9TLsUq"

info() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*" >&2
}

error() {
  printf '[ERROR] %s\n' "$*" >&2
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root."
    exit 1
  fi
}

print_system_info() {
  local os_id os_name os_ver kern arch

  info "System information:"
  if [ -f /etc/os-release ]; then
    os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"')
    os_name=$(grep '^NAME=' /etc/os-release 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"')
    os_ver=$(grep '^VERSION_ID=' /etc/os-release 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"')
    info "  OS ID: ${os_id:-unknown}"
    info "  OS Name: ${os_name:-unknown}"
    info "  OS Version: ${os_ver:-unknown}"
  else
    info "  /etc/os-release not found."
  fi

  kern=$(uname -r 2>/dev/null || echo unknown)
  arch=$(uname -m 2>/dev/null || echo unknown)
  info "  Kernel: $kern"
  info "  Arch: $arch"
}

check_alpine() {
  if [ ! -f /etc/os-release ]; then
    error "/etc/os-release not found; this script is intended for Alpine Linux."
    exit 1
  fi

  if ! grep -q '^ID=alpine' /etc/os-release 2>/dev/null; then
    error "This system is not Alpine Linux (expected ID=alpine). Aborting."
    exit 1
  fi
}

install_base_packages() {
  info "Installing base packages (tzdata, openssh, zsh, git, curl, zoxide)..."
  if ! command -v apk >/dev/null 2>&1; then
    error "apk command not found. Are you sure this is Alpine Linux?"
    exit 1
  fi

  apk update || {
    error "apk update failed; check network or APK repositories."
    exit 1
  }

  apk add --no-cache tzdata openssh zsh git curl zoxide || {
    error "Failed to install base packages."
    exit 1
  }
}

configure_timezone() {
  local zone="Asia/Shanghai"

  if [ ! -f "/usr/share/zoneinfo/$zone" ]; then
    warn "Timezone data for $zone not found; skipping timezone configuration."
    return 1
  fi

  info "Setting timezone to $zone (UTC+8)..."
  ln -sf "/usr/share/zoneinfo/$zone" /etc/localtime || {
    warn "Failed to update /etc/localtime."
    return 1
  }

  echo "$zone" > /etc/timezone || {
    warn "Failed to write /etc/timezone."
    return 1
  }
}

set_root_password() {
  info "Now setting root password (you will be prompted by passwd)."
  while :; do
    if [ -r /dev/tty ]; then
      if passwd root </dev/tty; then
        return 0
      fi
    elif passwd root; then
      return 0
    fi
    warn "Failed to set root password."
    read_tty answer 'Try again? [y/N]: ' || answer=""
    case "$answer" in
      y|Y)
        ;;
      *)
        error "Failed to set root password; aborting."
        exit 1
        ;;
    esac
  done
}

prompt_for_username() {
  local username

  while :; do
    read_tty username 'Enter username to create: ' || username=""

    case "$username" in
      ""|root)
        warn "Username cannot be empty or 'root'."
        ;;
      *[!a-z0-9_-]*)
        warn "Username should only contain lowercase letters, digits, '-', '_' ."
        ;;
      *)
        echo "$username"
        return 0
        ;;
    esac
  done
}

create_user_if_needed() {
  local username="$1"

  if id "$username" >/dev/null 2>&1; then
    info "User '$username' already exists; will reuse it."
    return 0
  fi

  info "Creating user '$username' with default shell /bin/sh (will switch to zsh later)..."
  adduser -D -s /bin/sh "$username" || {
    error "Failed to create user '$username'."
    exit 1
  }

  info "Now setting password for user '$username' (you will be prompted by passwd)."
  if [ -r /dev/tty ]; then
    passwd "$username" </dev/tty || {
      error "Failed to set password for user '$username'."
      exit 1
    }
  else
    passwd "$username" || {
      error "Failed to set password for user '$username'."
      exit 1
    }
  fi
}

setup_zsh_for_user() {
  local username="$1"
  local home="/home/$username"
  local zshrc="$home/.zshrc"

  if [ ! -d "$home" ]; then
    warn "Home directory $home does not exist; skipping zsh configuration."
    return 1
  fi

  if [ -f "$zshrc" ]; then
    warn "$zshrc already exists; leaving it unchanged."
  else
    info "Creating $zshrc with zsh plugins and prompt configuration..."
    cat > "$zshrc" <<'EOF'
# Enable Powerlevel10k instant prompt. Should stay close to the top of ~/.zshrc.
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# Zinit plugin manager
if [[ ! -f $HOME/.local/share/zinit/zinit.git/zinit.zsh ]]; then
  print -P "%F{33} %F{220}Installing %F{33}Zinit%F{220} plugin manager…%f"
  command mkdir -p "$HOME/.local/share/zinit" && command chmod g-rwX "$HOME/.local/share/zinit"
  command git clone https://github.com/zdharma-continuum/zinit "$HOME/.local/share/zinit/zinit.git" && \
    print -P "%F{33} %F{34}Installation successful.%f%b" || \
    print -P "%F{160} The clone has failed.%f%b"
fi

source "$HOME/.local/share/zinit/zinit.git/zinit.zsh"
autoload -Uz _zinit
(( ${+_comps} )) && _comps[zinit]=_zinit

# Basic plugins
zinit load zsh-users/zsh-syntax-highlighting
zinit load zsh-users/zsh-autosuggestions
zinit load ael-code/zsh-colored-man-pages

# Directory jumping
eval "$(zoxide init zsh)"

# Prompt theme
zinit ice depth=1
zinit light romkatv/powerlevel10k

# History
HISTFILE=~/.zsh_history
HISTSIZE=100000
HISTFILESIZE=300000
SAVEHIST=10000
setopt INC_APPEND_HISTORY_TIME
setopt EXTENDED_HISTORY

# To customize prompt, run `p10k configure` or edit ~/.p10k.zsh.
[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh
EOF
    chown "$username:$username" "$zshrc" || warn "Failed to change owner of $zshrc."
  fi

  if command -v chsh >/dev/null 2>&1; then
    chsh -s /bin/zsh "$username" >/dev/null 2>&1 || true
  fi
}

set_sshd_option() {
  local key="$1"
  local value="$2"
  local file="/etc/ssh/sshd_config"

  if [ ! -f "$file" ]; then
    warn "$file not found; sshd may not be installed correctly."
    return 1
  fi

  if grep -Eq "^[#[:space:]]*$key\\b" "$file"; then
    sed -i "s|^[#[:space:]]*$key\\b.*|$key $value|" "$file"
  else
    printf '\n%s %s\n' "$key" "$value" >> "$file"
  fi
}

setup_authorized_keys() {
  local username="$1"
  local url="$2"
  local home="/home/$username"
  local ssh_dir="$home/.ssh"
  local auth_file="$ssh_dir/authorized_keys"
  local tmp_file="$auth_file.tmp"
  local i

  if [ -z "$url" ]; then
    warn "No SSH key URL provided; skipping SSH key setup."
    return 1
  fi

  if [ ! -d "$home" ]; then
    warn "Home directory $home does not exist; cannot configure authorized_keys."
    return 1
  fi

  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"

  info "Fetching SSH public keys for user '$username' from:"
  info "  $url"

  i=1
  while [ "$i" -le 10 ]; do
    info "Download attempt $i/10..."
    if curl -fsS "$url" -o "$tmp_file"; then
      if [ -s "$tmp_file" ]; then
        mv "$tmp_file" "$auth_file"
        chown "$username:$username" "$auth_file"
        chmod 600 "$auth_file"
        info "SSH public keys installed at $auth_file."
        return 0
      else
        warn "Downloaded file is empty; retrying..."
      fi
    else
      warn "Failed to download SSH keys (attempt $i)."
    fi
    i=$((i + 1))
    sleep 3
  done

  rm -f "$tmp_file"
  warn "Unable to fetch SSH keys from $url after 10 attempts."
  warn "SSH password authentication will remain enabled to avoid locking you out."
  return 1
}

configure_sshd() {
  local disable_password="$1"

  info "Configuring sshd..."

  if [ ! -f /etc/ssh/sshd_config ]; then
    warn "/etc/ssh/sshd_config not found, starting sshd once to generate default config..."
    rc-service sshd start >/dev/null 2>&1 || service sshd start >/dev/null 2>&1 || true
    rc-service sshd stop >/dev/null 2>&1 || service sshd stop >/dev/null 2>&1 || true
  fi

  set_sshd_option "PubkeyAuthentication" "yes"

  if [ "$disable_password" -eq 1 ]; then
    set_sshd_option "PasswordAuthentication" "no"
  else
    set_sshd_option "PasswordAuthentication" "yes"
  fi

  # Keepalive settings to avoid frequent disconnects
  set_sshd_option "ClientAliveInterval" "60"
  set_sshd_option "ClientAliveCountMax" "3"
  set_sshd_option "TCPKeepAlive" "yes"

  # Do not change PermitRootLogin here to avoid surprises; keep distro defaults.
}

enable_sshd_service() {
  info "Enabling and starting sshd service..."
  rc-update add sshd default >/dev/null 2>&1 || rc-update add sshd default || true

  if ! rc-service sshd restart >/dev/null 2>&1 && \
     ! service sshd restart >/dev/null 2>&1; then
    warn "Failed to restart sshd; please check manually with 'rc-service sshd status'."
  else
    info "sshd is running."
  fi
}

main() {
  require_root
  print_system_info
  check_alpine

  set_root_password

  local username
  username="$(prompt_for_username)"
  create_user_if_needed "$username"

  local setup_keys_choice
  local want_setup_keys=0
  local ssh_disable_password=0

  read_tty setup_keys_choice 'Do you want to configure SSH key-based login for this user now? [y/N]: ' || setup_keys_choice=""
  case "$setup_keys_choice" in
    y|Y)
      want_setup_keys=1
      ;;
    *)
      info "Skipping SSH key-based login configuration."
      ;;
  esac

  install_base_packages
  configure_timezone

  setup_zsh_for_user "$username"

  if [ "$want_setup_keys" -eq 1 ]; then
    if setup_authorized_keys "$username" "$SSH_AUTH_KEYS_URL"; then
      ssh_disable_password=1
    else
      ssh_disable_password=0
    fi
  fi

  configure_sshd "$ssh_disable_password"
  enable_sshd_service

  info "Initialization complete."
  if [ "$ssh_disable_password" -eq 1 ]; then
    info "SSH password authentication is disabled; key-based login is enabled."
  else
    info "SSH password authentication is still enabled."
  fi
  info "New user: $username"
  info "Timezone: $(cat /etc/timezone 2>/dev/null || echo 'unknown')"
}

main "$@"
