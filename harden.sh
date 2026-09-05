#!/usr/bin/env bash
# harden.sh - Ubuntu/Debian server hardening script
#
# Dry run by default: changes nothing, only shows what would be done.
# To apply for real: sudo ./harden.sh --apply ...
#
# Safeguards (so you don't lock yourself out over SSH):
#   * disables password login only if the user has an SSH key
#   * disables root login only if a user with sudo rights exists
#   * backs up every file it changes
#   * checks with sshd -t and sshd -T, and rolls the change back if that fails
#   * allows the SSH port in ufw FIRST, then enables the firewall
set -uo pipefail

VERSION="1.0.0"
ROOT_PREFIX="${ROOT_PREFIX:-}"   # tests only: fake root directory
DRY_RUN=1
ASSUME_YES=0
SKIP_CHECKS=0
KEEP_PASSWORD_AUTH=0
SELECTED_STEPS="all"
CREATE_USER=""
CREATE_USER_KEY=""
SSH_USER=""
SSH_PORT=""
ALLOW_PORTS=()
BACKUP_DIR=""
DONE_STEPS=()
FAILED_STEPS=()
ALL_STEPS=(user ssh firewall sysctl passwords perms updates)

# ----------------------------------------------------------------- log
log_to_file() {
    (( DRY_RUN )) && return 0
    local f="${ROOT_PREFIX}/var/log/harden.log"
    mkdir -p "$(dirname "$f")" 2>/dev/null || return 0
    printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$f" 2>/dev/null || true
}
info() { echo "[INFO] $*"; log_to_file "INFO $*"; }
warn() { echo "[WARN] $*" >&2; log_to_file "WARN $*"; }
err()  { echo "[ERROR] $*" >&2; log_to_file "ERROR $*"; }
die()  { err "$*"; exit 1; }

# ------------------------------------------------------------ validators
valid_username() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_allow_spec() {
    local re='^([0-9]{1,5})(/(tcp|udp))?$'
    [[ "$1" =~ $re ]] || return 1
    valid_port "${BASH_REMATCH[1]}"
}
valid_ssh_key() {
    local re='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$'
    [[ "$1" =~ $re ]]
}

# --------------------------------------------------------- commands and files
# run: in dry run it only prints; with a fake root (tests) it does not execute
run() {
    local shown
    printf -v shown '%q ' "$@"
    shown="${shown% }"
    if (( DRY_RUN )); then info "[DRY-RUN] $shown"; return 0; fi
    if [[ -n "$ROOT_PREFIX" ]]; then info "[FAKE-ROOT, not executed] $shown"; return 0; fi
    info "Running: $shown"
    "$@" || { err "Failed: $shown"; return 1; }
}

init_backup_dir() {
    if [[ -z "$BACKUP_DIR" ]]; then
        BACKUP_DIR="${ROOT_PREFIX}/var/backups/harden-$(date +%Y%m%d-%H%M%S)"
    fi
}

backup_file() {
    local path="$1" target="${ROOT_PREFIX}$1"
    [[ -e "$target" ]] || return 0
    init_backup_dir
    [[ -e "${BACKUP_DIR}${path}" ]] && return 0      # the first (original) copy is kept
    mkdir -p "$(dirname "${BACKUP_DIR}${path}")"
    cp -a "$target" "${BACKUP_DIR}${path}"
}

restore_file() {
    local path="$1" target="${ROOT_PREFIX}$1"
    if [[ -n "$BACKUP_DIR" && -e "${BACKUP_DIR}${path}" ]]; then
        cp -a "${BACKUP_DIR}${path}" "$target"
    else
        rm -f "$target"
    fi
}

write_file() {   # write_file PATH MODE CONTENT
    local path="$1" mode="$2" content="$3" target="${ROOT_PREFIX}$1"
    if (( DRY_RUN )); then
        info "[DRY-RUN] File will be written: $path (mode $mode)"
        while IFS= read -r line; do echo "         | $line"; done <<<"$content"
        return 0
    fi
    backup_file "$path"
    mkdir -p "$(dirname "$target")"
    printf '%s\n' "$content" > "$target"
    chmod "$mode" "$target"
    info "Written: $path"
}

fs_chmod() {
    local path="$1" mode="$2"
    if (( DRY_RUN )); then info "[DRY-RUN] chmod $mode $path"; return 0; fi
    chmod "$mode" "${ROOT_PREFIX}${path}" && info "chmod $mode $path"
}

fs_chown() {
    local path="$1" owner="$2" grp="$3"
    if [[ "$grp" == "shadow" ]] && ! getent group shadow >/dev/null 2>&1; then grp="root"; fi
    if (( DRY_RUN )); then info "[DRY-RUN] chown $owner:$grp $path"; return 0; fi
    [[ -n "$ROOT_PREFIX" ]] && return 0
    chown "$owner:$grp" "$path" && info "chown $owner:$grp $path"
}

confirm() {
    (( DRY_RUN || ASSUME_YES )) && return 0
    local ans
    read -r -p "$1 [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

# ------------------------------------------------------ user helpers
user_home() { getent passwd "$1" | cut -d: -f6; }

has_authorized_keys() {
    local home f
    home=$(user_home "$1")
    [[ -n "$home" ]] || return 1
    f="${ROOT_PREFIX}${home}/.ssh/authorized_keys"
    [[ -s "$f" ]] && grep -qE '^(ssh-|ecdsa-|sk-)' "$f"
}
user_in_sudo() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; }
will_be_created() { [[ -n "$CREATE_USER" && "$1" == "$CREATE_USER" ]]; }

keys_ok() {   # the user already has a key, or one will be created in this run
    has_authorized_keys "$1" && return 0
    will_be_created "$1" && [[ -n "$CREATE_USER_KEY" ]] && (( DRY_RUN )) && return 0
    return 1
}
sudo_ok() { user_in_sudo "$1" || will_be_created "$1"; }

find_sshd() {
    command -v sshd 2>/dev/null && return 0
    [[ -x /usr/sbin/sshd ]] && echo /usr/sbin/sshd
}

detect_ssh_port() {
    if [[ -n "$SSH_PORT" ]]; then echo "$SSH_PORT"; return 0; fi
    local p="" bin
    bin=$(find_sshd)
    if [[ -z "$ROOT_PREFIX" && -n "$bin" ]]; then
        p=$("$bin" -T 2>/dev/null | awk '$1=="port"{print $2; exit}')
    fi
    echo "${p:-22}"
}

# ------------------------------------------------------ content generators
render_sshd_config() {
    cat <<HEADER
# generated by harden.sh $VERSION ($(date +%F))
# The file name deliberately starts with "00-": in sshd the FIRST value set wins,
# and files such as "50-cloud-init.conf" can override this with PasswordAuthentication yes.
PermitRootLogin no
HEADER
    if (( ! KEEP_PASSWORD_AUTH )); then echo "PasswordAuthentication no"; fi
    cat <<'BODY'
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
BODY
}

render_sysctl() {
    cat <<'SYSCTL_BODY'
# generated by harden.sh
# Note: net.ipv4.ip_forward is deliberately left alone (Docker/VPN/router setups may need it).
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.randomize_va_space = 2
SYSCTL_BODY
}

# --------------------------------------------------------------- steps
install_key() {
    local user="$1" key="$2" home dir
    if (( DRY_RUN )); then info "[DRY-RUN] ~/.ssh/authorized_keys will be created for $user"; return 0; fi
    home=$(user_home "$user")
    [[ -n "$home" ]] || { err "No home directory found for $user"; return 1; }
    dir="${ROOT_PREFIX}${home}/.ssh"
    mkdir -p "$dir" && chmod 700 "$dir"
    touch "$dir/authorized_keys"
    grep -qxF -- "$key" "$dir/authorized_keys" || printf '%s\n' "$key" >> "$dir/authorized_keys"
    chmod 600 "$dir/authorized_keys"
    [[ -z "$ROOT_PREFIX" ]] && chown -R "$user:" "$dir"
    info "SSH key installed for: $user"
}

step_user() {
    if [[ -z "$CREATE_USER" ]]; then info "--create-user not given, skipping"; return 0; fi
    valid_username "$CREATE_USER" || { err "Invalid username: $CREATE_USER"; return 1; }
    if [[ -n "$CREATE_USER_KEY" ]] && ! valid_ssh_key "$CREATE_USER_KEY"; then
        err "SSH key format is invalid (expected something like: ssh-ed25519 AAAA...)"
        return 1
    fi
    if id "$CREATE_USER" >/dev/null 2>&1; then
        info "User already exists: $CREATE_USER"
    else
        run adduser --disabled-password --gecos "" "$CREATE_USER" || return 1
    fi
    run usermod -aG sudo "$CREATE_USER" || return 1
    if [[ -n "$CREATE_USER_KEY" ]]; then install_key "$CREATE_USER" "$CREATE_USER_KEY" || return 1; fi
    info "Next step: set a password for sudo -> sudo passwd $CREATE_USER"
}

verify_sshd() {
    local bin eff
    bin=$(find_sshd)
    [[ -n "$bin" ]] || { err "sshd not found"; return 1; }
    "$bin" -t || { err "sshd -t reported a configuration error"; return 1; }
    eff=$("$bin" -T 2>/dev/null) || { err "sshd -T failed"; return 1; }
    grep -qix 'permitrootlogin no' <<<"$eff" || { err "Effective PermitRootLogin is not 'no'"; return 1; }
    grep -qix 'permitemptypasswords no' <<<"$eff" || { err "Effective PermitEmptyPasswords is not 'no'"; return 1; }
    if (( ! KEEP_PASSWORD_AUTH )); then
        grep -qix 'passwordauthentication no' <<<"$eff" || { err "Effective PasswordAuthentication is not 'no' (overridden by another file?)"; return 1; }
    fi
}

reload_ssh() {
    local unit=sshd
    if systemctl cat ssh.service >/dev/null 2>&1; then unit=ssh; fi
    systemctl reload "$unit"
}

# Checks the SSH change and reloads sshd; puts the file back if anything fails
finalize_ssh_change() {
    local conf="$1"
    if ! verify_sshd; then
        restore_file "$conf"
        err "Change rolled back. The SSH configuration was left as it was."
        return 1
    fi
    if ! reload_ssh; then
        restore_file "$conf"
        reload_ssh || true
        err "SSH reload failed, change rolled back."
        return 1
    fi
    info "SSH reloaded. DON'T CLOSE THE CURRENT SESSION! Test the login from a new terminal."
}

step_ssh() {
    local user="${SSH_USER:-${CREATE_USER:-${SUDO_USER:-}}}"
    local conf="/etc/ssh/sshd_config.d/00-hardening.conf"
    local main="${ROOT_PREFIX}/etc/ssh/sshd_config"

    [[ -f "$main" ]] || { err "/etc/ssh/sshd_config not found (is openssh-server installed?)"; return 1; }
    if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$main"; then
        err "sshd_config has no 'Include /etc/ssh/sshd_config.d/*.conf' line (needs Ubuntu 22.04+). The drop-in file would never be read."
        return 1
    fi

    if (( SKIP_CHECKS )); then
        warn "--skip-checks is on: the checks that keep you from locking yourself out over SSH are skipped!"
    else
        if [[ -z "$user" ]]; then
            err "Could not work out the SSH user. Pass --ssh-user NAME (the account you log in with)."
            return 1
        fi
        if (( ! KEEP_PASSWORD_AUTH )) && ! keys_ok "$user"; then
            err "No ~/.ssh/authorized_keys found for '$user'. If password login is disabled you won't be able to log in."
            err "Set up a key first: ssh-copy-id $user@<server>  (or use --create-user ... --ssh-key '...')"
            err "If you only want to close root login: --keep-password-auth"
            return 1
        fi
        if ! sudo_ok "$user"; then
            err "'$user' is not in the sudo group. If root login is disabled you would lose admin access."
            err "Fix: sudo usermod -aG sudo $user"
            return 1
        fi
    fi

    write_file "$conf" 644 "$(render_sshd_config)" || return 1
    if (( DRY_RUN )); then
        info "[DRY-RUN] then: sshd -t, effective-value check with sshd -T, systemctl reload ssh"
        return 0
    fi
    [[ -n "$ROOT_PREFIX" ]] && return 0
    finalize_ssh_change "$conf"
}

step_firewall() {
    local port spec conn_port
    port=$(detect_ssh_port)
    valid_port "$port" || { err "Invalid SSH port: $port"; return 1; }
    for spec in ${ALLOW_PORTS[@]+"${ALLOW_PORTS[@]}"}; do
        valid_allow_spec "$spec" || { err "Invalid --allow value: $spec (example: 80/tcp)"; return 1; }
    done

    if ! command -v ufw >/dev/null 2>&1; then
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || return 1
    fi
    run ufw default deny incoming || return 1
    run ufw default allow outgoing || return 1
    run ufw limit "${port}/tcp" || return 1          # the SSH port is allowed FIRST

    # If the current SSH session is on a different port, open that one too (so we don't cut ourselves off)
    conn_port=$(awk '{print $4}' <<<"${SSH_CONNECTION:-}")
    if [[ -n "$conn_port" ]] && valid_port "$conn_port" && [[ "$conn_port" != "$port" ]]; then
        warn "The current SSH session is on port $conn_port, allowing that one too"
        run ufw limit "${conn_port}/tcp" || return 1
    fi
    for spec in ${ALLOW_PORTS[@]+"${ALLOW_PORTS[@]}"}; do
        run ufw allow "$spec" || return 1
    done
    run ufw --force enable || return 1
    info "Check with: sudo ufw status verbose"
}

step_sysctl() {
    write_file /etc/sysctl.d/99-hardening.conf 644 "$(render_sysctl)" || return 1
    run sysctl -p /etc/sysctl.d/99-hardening.conf || warn "Some settings could not be applied (normal inside a container)"
    return 0
}

set_login_defs() {   # set_login_defs KEY VALUE
    local key="$1" value="$2" path="/etc/login.defs" target="${ROOT_PREFIX}/etc/login.defs"
    if (( DRY_RUN )); then info "[DRY-RUN] $path: $key = $value"; return 0; fi
    [[ -f "$target" ]] || { warn "$path not found"; return 1; }
    backup_file "$path"
    if grep -qE "^[[:space:]]*${key}[[:space:]]" "$target"; then
        sed -i -E "s/^[[:space:]]*${key}[[:space:]]+.*/${key}\t${value}/" "$target"
    else
        printf '%s\t%s\n' "$key" "$value" >> "$target"
    fi
    info "$path: $key = $value"
}

step_passwords() {
    set_login_defs PASS_MAX_DAYS 90 || return 1
    set_login_defs PASS_MIN_DAYS 1 || return 1
    set_login_defs PASS_WARN_AGE 7 || return 1
    info "Note: this only affects NEW accounts. For an existing account: sudo chage --maxdays 90 <name>"
}

step_perms() {
    local spec path mode owner grp
    for spec in "/etc/passwd:644:root:root" "/etc/group:644:root:root" \
                "/etc/shadow:640:root:shadow" "/etc/gshadow:640:root:shadow" \
                "/etc/ssh/sshd_config:600:root:root"; do
        IFS=: read -r path mode owner grp <<<"$spec"
        if [[ ! -e "${ROOT_PREFIX}${path}" ]]; then info "Skipping (missing): $path"; continue; fi
        fs_chmod "$path" "$mode" || return 1
        fs_chown "$path" "$owner" "$grp" || return 1
    done
}

step_updates() {
    run env DEBIAN_FRONTEND=noninteractive apt-get update || return 1
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades || return 1
    write_file /etc/apt/apt.conf.d/20auto-upgrades 644 \
"APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";"
}

# ------------------------------------------------------------ entry point
usage() {
    cat <<USAGE
harden.sh $VERSION - Ubuntu/Debian server hardening

Usage: ./harden.sh [options]        (default: dry run, changes nothing)

Options:
  --apply                Actually apply the changes (needs root)
  -y, --yes              Don't ask for confirmation
  --steps LIST           Comma-separated steps (default: all)
                         user,ssh,firewall,sysctl,passwords,perms,updates
  --create-user NAME     Create a new sudo user
  --ssh-key "KEY"        Public SSH key for the new user
  --ssh-user NAME        The account you log in with over SSH (for the safety checks)
  --ssh-port N           SSH port (default: detected with sshd -T, else 22)
  --allow PORT[/proto]   Open an extra port in the firewall (repeatable), e.g. 80/tcp
  --keep-password-auth   Leave SSH password login alone (only close root login)
  --skip-checks          Skip the SSH safety checks (DANGEROUS)
  -h, --help             Show this help

Examples:
  ./harden.sh --ssh-user ali                      # see what would be done
  sudo ./harden.sh --apply --ssh-user ali --allow 80/tcp --allow 443/tcp
  sudo ./harden.sh --apply --steps sysctl,perms
USAGE
}

need_arg() { [[ $# -ge 2 ]] || die "$1 needs a value"; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --apply) DRY_RUN=0 ;;
            -y|--yes) ASSUME_YES=1 ;;
            --steps) need_arg "$@"; SELECTED_STEPS="$2"; shift ;;
            --create-user) need_arg "$@"; CREATE_USER="$2"; shift ;;
            --ssh-key) need_arg "$@"; CREATE_USER_KEY="$2"; shift ;;
            --ssh-user) need_arg "$@"; SSH_USER="$2"; shift ;;
            --ssh-port) need_arg "$@"; SSH_PORT="$2"; shift ;;
            --allow) need_arg "$@"; ALLOW_PORTS+=("$2"); shift ;;
            --keep-password-auth) KEEP_PASSWORD_AUTH=1 ;;
            --skip-checks) SKIP_CHECKS=1 ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; die "Unknown option: $1" ;;
        esac
        shift
    done

    local s
    if [[ "$SELECTED_STEPS" != "all" ]]; then
        for s in ${SELECTED_STEPS//,/ }; do
            [[ " ${ALL_STEPS[*]} " == *" $s "* ]] || die "Unknown step: $s (valid: ${ALL_STEPS[*]})"
        done
    fi
    [[ -z "$SSH_PORT" ]] || valid_port "$SSH_PORT" || die "Invalid --ssh-port: $SSH_PORT"
    [[ -z "$SSH_USER" ]] || valid_username "$SSH_USER" || die "Invalid --ssh-user: $SSH_USER"
    [[ -z "$CREATE_USER" ]] || valid_username "$CREATE_USER" || die "Invalid --create-user: $CREATE_USER"
    for s in ${ALLOW_PORTS[@]+"${ALLOW_PORTS[@]}"}; do
        valid_allow_spec "$s" || die "Invalid --allow value: $s (example: 80/tcp)"
    done
}

step_selected() {
    local s
    [[ "$SELECTED_STEPS" == "all" ]] && return 0
    for s in ${SELECTED_STEPS//,/ }; do [[ "$s" == "$1" ]] && return 0; done
    return 1
}

preflight() {
    (( DRY_RUN )) && return 0
    [[ -n "$ROOT_PREFIX" ]] && return 0
    [[ $EUID -eq 0 ]] || die "--apply needs root: sudo ./harden.sh --apply ..."
    local os_id
    # shellcheck disable=SC1091
    os_id=$(. /etc/os-release 2>/dev/null && echo "${ID:-}")
    case "$os_id" in
        ubuntu|debian) ;;
        *) die "Unsupported system (ID='${os_id:-?}'). Ubuntu/Debian only." ;;
    esac
}

summary() {
    echo
    echo "================ SUMMARY ================"
    echo "Succeeded: ${DONE_STEPS[*]:-(none)}"
    echo "Failed   : ${FAILED_STEPS[*]:-(none)}"
    if (( DRY_RUN )); then
        echo "Mode     : DRY-RUN (nothing was changed). Add --apply to apply."
    else
        [[ -n "$BACKUP_DIR" ]] && echo "Backups  : $BACKUP_DIR"
        echo "Log      : ${ROOT_PREFIX}/var/log/harden.log"
        echo "Next     : test SSH login from a new terminal, then run 'sudo ufw status verbose'"
    fi
}

main() {
    parse_args "$@"
    preflight
    if (( DRY_RUN )); then
        info "DRY-RUN mode: nothing is changed. Use --apply to apply."
    else
        warn "REAL MODE: the system configuration will be changed."
        confirm "Continue?" || die "Cancelled by the user."
    fi

    local step
    for step in "${ALL_STEPS[@]}"; do
        step_selected "$step" || continue
        echo
        echo "=== Step: $step ==="
        if "step_$step"; then DONE_STEPS+=("$step"); else FAILED_STEPS+=("$step"); fi
    done
    summary
    [[ ${#FAILED_STEPS[@]} -eq 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

