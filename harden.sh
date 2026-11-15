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

VERSION="1.1.0"
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
USER_STEP_OK=0           # 1 once the user step has finished successfully in this run
NEEDS_PASSWORD_USER=""   # account created without a password in this run
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
    local re='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$'
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
    mkdir -p "$(dirname "${BACKUP_DIR}${path}")" || { err "Could not create the backup directory for $path"; return 1; }
    cp -a "$target" "${BACKUP_DIR}${path}" || { err "Could not back up $path"; return 1; }
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
    backup_file "$path" || return 1               # never change a file that could not be backed up
    mkdir -p "$(dirname "$target")" || { err "Could not create the directory for $path"; return 1; }
    printf '%s\n' "$content" > "$target" || { err "Could not write $path"; return 1; }
    chmod "$mode" "$target" || { err "Could not set mode $mode on $path"; return 1; }
    info "Written: $path"
}

# record_permissions PATH: before the first chmod/chown of PATH in this run, its mode and owner go
# into restore-permissions.sh in the backup directory. Running that script puts them back.
declare -A PERMS_RECORDED=()
record_permissions() {
    local path="$1" target="${ROOT_PREFIX}$1" mode owner script
    [[ -n "${PERMS_RECORDED[$path]:-}" ]] && return 0
    mode=$(stat -c %a "$target" 2>/dev/null) && owner=$(stat -c %U:%G "$target" 2>/dev/null) \
        || { err "Could not read the mode and owner of $path"; return 1; }
    init_backup_dir
    script="${BACKUP_DIR}/restore-permissions.sh"
    if [[ ! -e "$script" ]]; then
        mkdir -p "$BACKUP_DIR" \
            && printf '#!/bin/sh\n# Written by harden.sh: puts back the modes and owners the perms step changed.\n' > "$script" \
            && chmod 700 "$script" \
            || { err "Could not create $script"; return 1; }
    fi
    printf 'chmod %s %s\nchown %s %s\n' "$mode" "$path" "$owner" "$path" >> "$script" \
        || { err "Could not write $script"; return 1; }
    PERMS_RECORDED[$path]=1
}

fs_chmod() {
    local path="$1" mode="$2" old
    if (( DRY_RUN )); then info "[DRY-RUN] chmod $mode $path"; return 0; fi
    record_permissions "$path" || return 1      # never change what could not be recorded
    old=$(stat -c '%a %U:%G' "${ROOT_PREFIX}${path}" 2>/dev/null)
    chmod "$mode" "${ROOT_PREFIX}${path}" && info "chmod $mode $path (was: ${old:-unknown})"
}

fs_chown() {
    local path="$1" owner="$2" grp="$3"
    if [[ "$grp" == "shadow" ]] && ! getent group shadow >/dev/null 2>&1; then grp="root"; fi
    if (( DRY_RUN )); then info "[DRY-RUN] chown $owner:$grp $path"; return 0; fi
    [[ -n "$ROOT_PREFIX" ]] && return 0
    record_permissions "$path" || return 1
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

# authorized_keys_files USER: the files sshd takes this user's keys from (AuthorizedKeysFile, by default
# .ssh/authorized_keys and .ssh/authorized_keys2), one absolute path per line, %h %u %U %% expanded.
# The effective value comes from "sshd -T" (needs root); otherwise it is read from the config files.
authorized_keys_files() {
    local user="$1" home uid spec="" bin f
    home=$(user_home "$user")
    [[ -n "$home" ]] || return 0
    uid=$(getent passwd "$user" | cut -d: -f3)
    if [[ -z "$ROOT_PREFIX" ]]; then
        bin=$(find_sshd)
        if [[ -n "$bin" ]]; then
            spec=$("$bin" -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null \
                | awk '$1 == "authorizedkeysfile" { $1 = ""; print; exit }')
        fi
    fi
    if [[ -z "$spec" ]]; then
        # Ubuntu's sshd_config starts with the Include line, so the drop-ins are read first; the first
        # value outside a Match block wins
        local -a conf_files=()
        for f in "${ROOT_PREFIX}"/etc/ssh/sshd_config.d/*.conf "${ROOT_PREFIX}/etc/ssh/sshd_config"; do
            [[ -r "$f" ]] && conf_files+=("$f")
        done
        if (( ${#conf_files[@]} )); then
            spec=$(awk 'FNR == 1 { in_match = 0 }
                        tolower($1) == "match" { in_match = 1 }
                        !in_match && tolower($1) == "authorizedkeysfile" { $1 = ""; print; exit }' "${conf_files[@]}")
        fi
    fi
    [[ -n "${spec// /}" ]] || spec=".ssh/authorized_keys .ssh/authorized_keys2"
    local -a parts=()
    read -ra parts <<<"$spec"
    for f in "${parts[@]}"; do
        [[ "${f,,}" == "none" ]] && continue
        f=${f//%%/$'\x01'}; f=${f//%h/$home}; f=${f//%u/$user}; f=${f//%U/$uid}; f=${f//$'\x01'/%}
        [[ "$f" == /* ]] || f="$home/$f"
        printf '%s\n' "$f"
    done
}

has_authorized_keys() {
    local f
    while IFS= read -r f; do
        f="${ROOT_PREFIX}$f"
        # A key line may start with options (from="...", command="..."), so the key type does not have to
        # be the first word. Comment lines are ignored.
        [[ -s "$f" ]] && grep -qE '^[[:space:]]*([^#[:space:]].*[[:space:]])?(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[[:space:]]+AAAA' "$f" \
            && return 0
    done < <(authorized_keys_files "$1")
    return 1
}
warn_key_file_perms() {   # with StrictModes (the default) sshd ignores keys in a group/world-writable file
    local f mode
    while IFS= read -r f; do
        mode=$(stat -c %a "${ROOT_PREFIX}$f" 2>/dev/null) || continue
        if (( 8#$mode & 8#022 )); then
            warn "$f is writable by group/others (mode $mode); sshd may ignore it. Fix: chmod 600 $f"
        fi
    done < <(authorized_keys_files "$1")
    return 0
}
user_in_sudo() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; }
will_be_created() { [[ -n "$CREATE_USER" && "$1" == "$CREATE_USER" ]]; }

keys_ok() {   # the user already has a key, or the user step of this run will install one
    has_authorized_keys "$1" && return 0
    will_be_created "$1" && [[ -n "$CREATE_USER_KEY" ]] && step_selected user && (( DRY_RUN )) && return 0
    return 1
}
sudo_ok() {   # the user is in a sudo group, or the user step of THIS run puts them there
    user_in_sudo "$1" && return 0
    will_be_created "$1" || return 1
    step_selected user || return 1       # --create-user without the user step creates nobody
    (( DRY_RUN || USER_STEP_OK ))        # for real, only trust a user step that has succeeded
}

# sudo_password_state USER: being in the sudo group is not enough to keep admin access once root login
# is closed, because sudo asks for the account's password. An account made with --disabled-password
# has none. Returns 0 = a usable password or a NOPASSWD rule, 1 = sudo won't work, 2 = can't tell
# (/etc/shadow is not readable, e.g. a dry run without root).
sudo_password_state() {
    local user="$1" shadow="${ROOT_PREFIX}/etc/shadow" hash
    [[ -r "$shadow" ]] || return 2
    hash=$(awk -F: -v u="$user" '$1 == u { print $2; exit }' "$shadow")
    case "$hash" in
        ''|'!'*|'*'*) ;;            # no password, locked (!) or no password login (*)
        *) return 0 ;;
    esac
    # cloud images often have a passwordless user with "NOPASSWD: ALL"
    if [[ -z "$ROOT_PREFIX" ]] && sudo -n -l -U "$user" 2>/dev/null | grep -qE 'NOPASSWD: *ALL'; then
        return 0
    fi
    return 1
}

find_sshd() {
    command -v sshd 2>/dev/null && return 0
    [[ -x /usr/sbin/sshd ]] && echo /usr/sbin/sshd
}

# Prints every port sshd listens on, one per line. Prints nothing when it cannot tell
# (not root, sshd missing, fake root); the caller then falls back to 22.
detect_ssh_ports() {
    if [[ -n "$SSH_PORT" ]]; then echo "$SSH_PORT"; return 0; fi
    [[ -z "$ROOT_PREFIX" ]] || return 0
    local found="" bin
    bin=$(find_sshd)
    if [[ -n "$bin" ]]; then
        found=$("$bin" -T 2>/dev/null | awk '$1=="port"{print $2}')
    fi
    if command -v ss >/dev/null 2>&1; then
        # sudo removes SSH_CONNECTION from the environment, so also ask the kernel where sshd really listens
        found+=$'\n'$(ss -H -ltnp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }')
    fi
    awk '/^[0-9]+$/ && !seen[$0]++' <<<"$found"
}

# Local ports of the SSH sessions that are open right now, one per line. sudo removes SSH_CONNECTION
# from the environment (env_reset), so the sockets of the running sshd processes are read with ss too.
session_ports() {
    {
        awk '{ print $4 }' <<<"${SSH_CONNECTION:-}"
        if [[ -z "$ROOT_PREFIX" ]] && command -v ss >/dev/null 2>&1; then
            # the first "address:port" field is the local end; "sshd" also matches sshd-session (OpenSSH 9.8+)
            ss -Htnp state established 2>/dev/null | awk '/"sshd/ {
                for (i = 1; i <= NF; i++) if ($i ~ /:[0-9]+$/) { n = split($i, a, ":"); print a[n]; break }
            }'
        fi
    } | awk 'NF && !seen[$0]++'
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
    # "all" and "default" are not enough for redirects: a host takes a redirect on an interface when
    # "all" OR the interface's own value is 1, and "default" only reaches interfaces created later.
    # So each interface that exists now gets its own lines. Short-lived virtual interfaces (containers,
    # VMs) are left out: they are created later and start from "default".
    local dir name header=0
    for dir in "${ROOT_PREFIX}"/proc/sys/net/ipv4/conf/*/; do
        [[ -d "$dir" ]] || continue
        name=$(basename "$dir")
        case "$name" in all|default|lo|veth*|tap*|lxc*|cali*) continue ;; esac
        if (( ! header )); then echo "# interfaces that exist now"; header=1; fi
        echo "$(iface_key ipv4 "$name" accept_redirects) = 0"
        echo "$(iface_key ipv4 "$name" send_redirects) = 0"
        if [[ -d "${ROOT_PREFIX}/proc/sys/net/ipv6/conf/$name" ]]; then
            echo "$(iface_key ipv6 "$name" accept_redirects) = 0"
        fi
    done
}

iface_key() {   # iface_key ipv4 eth0 accept_redirects -> net.ipv4.conf.eth0.accept_redirects
    # a name with a dot in it (a VLAN such as eth0.100) needs the form with slashes
    if [[ "$2" == *.* ]]; then echo "net/$1/conf/$2/$3"; else echo "net.$1.conf.$2.$3"; fi
}

# --------------------------------------------------------------- steps
install_key() {
    local user="$1" key="$2" home dir
    if (( DRY_RUN )); then info "[DRY-RUN] ~/.ssh/authorized_keys will be created for $user"; return 0; fi
    home=$(user_home "$user")
    [[ -n "$home" ]] || { err "No home directory found for $user"; return 1; }
    dir="${ROOT_PREFIX}${home}/.ssh"
    if ! mkdir -p "$dir" || ! chmod 700 "$dir"; then err "Could not create $home/.ssh"; return 1; fi
    touch "$dir/authorized_keys" || { err "Could not create authorized_keys for $user"; return 1; }
    if ! grep -qxF -- "$key" "$dir/authorized_keys"; then
        printf '%s\n' "$key" >> "$dir/authorized_keys" || { err "Could not write the SSH key for $user"; return 1; }
    fi
    chmod 600 "$dir/authorized_keys" || { err "Could not set mode 600 on authorized_keys for $user"; return 1; }
    if [[ -z "$ROOT_PREFIX" ]]; then
        chown -R "$user:" "$dir" || { err "Could not hand $home/.ssh over to $user"; return 1; }
    fi
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
        NEEDS_PASSWORD_USER="$CREATE_USER"
    fi
    run usermod -aG sudo "$CREATE_USER" || return 1
    if [[ -n "$CREATE_USER_KEY" ]]; then install_key "$CREATE_USER" "$CREATE_USER_KEY" || return 1; fi
    USER_STEP_OK=1
    if [[ -n "$NEEDS_PASSWORD_USER" ]]; then
        warn "$CREATE_USER is created WITHOUT a password, so sudo will not work for it yet, and the ssh step"
        warn "will not close root login. Set one (passwd $CREATE_USER), then run: --apply --steps ssh --ssh-user $CREATE_USER"
    else
        info "Reminder: sudo asks for this account's password (set one with: sudo passwd $CREATE_USER)"
    fi
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
        if grep -qix 'kbdinteractiveauthentication yes' <<<"$eff"; then
            warn "KbdInteractiveAuthentication is still 'yes': with PAM, passwords may still be accepted that way."
            warn "Unless you need it (for example for 2FA), set 'KbdInteractiveAuthentication no' in sshd_config."
        fi
    fi
    return 0
}

reload_ssh() {
    local unit=sshd
    if systemctl cat ssh.service >/dev/null 2>&1; then unit=ssh; fi
    # With socket activation (newer Ubuntu) the service only runs while someone is connected. If it is not
    # running there is nothing to reload: the next connection starts sshd with the new configuration.
    if ! systemctl is-active --quiet "$unit" 2>/dev/null; then
        info "$unit.service is not running, nothing to reload (the new configuration applies to the next start)"
        return 0
    fi
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
    # sshd keywords are case-insensitive and a relative path is resolved against /etc/ssh
    if ! grep -qiE '^[[:space:]]*Include[[:space:]]+"?(/etc/ssh/)?sshd_config\.d/' "$main"; then
        err "sshd_config has no 'Include /etc/ssh/sshd_config.d/*.conf' line (needs Ubuntu 22.04+). The drop-in file would never be read."
        return 1
    fi

    if grep -qiE '^[[:space:]]*Match[[:space:]]' "$main" "${ROOT_PREFIX}"/etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
        warn "The SSH configuration contains 'Match' blocks. They can override these settings for some users or"
        warn "hosts and are not checked here. Check a concrete case with: sshd -T -C user=NAME,host=HOST,addr=IP"
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
        local state=0
        sudo_password_state "$user" || state=$?
        if (( state == 1 )) && will_be_created "$user" && (( DRY_RUN )); then
            warn "'$user' will be created without a password. Set one (sudo passwd $user) and then run the ssh step,"
            warn "otherwise --apply stops here: sudo would not work once root login is closed."
        elif (( state == 1 )); then
            err "'$user' has no usable password and no NOPASSWD sudo rule, so sudo won't work once root login is closed."
            err "Fix: sudo passwd $user  (then run again: sudo ./harden.sh --apply --steps ssh --ssh-user $user)"
            return 1
        elif (( state == 2 )); then
            warn "Could not check whether '$user' can use sudo (/etc/shadow is not readable). With --apply this is checked as root."
        fi
        (( KEEP_PASSWORD_AUTH )) || warn_key_file_perms "$user"
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
    local ports port spec conn_port
    ports=$(detect_ssh_ports)
    if [[ -z "$ports" ]]; then
        ports=22
        if [[ -z "$ROOT_PREFIX" ]]; then
            warn "Could not detect the sshd port (that needs root), assuming 22. If sshd listens elsewhere, pass --ssh-port N."
        fi
    fi
    for port in $ports; do
        valid_port "$port" || { err "Invalid SSH port: $port"; return 1; }
    done
    for spec in ${ALLOW_PORTS[@]+"${ALLOW_PORTS[@]}"}; do
        valid_allow_spec "$spec" || { err "Invalid --allow value: $spec (example: 80/tcp)"; return 1; }
    done

    if ! command -v ufw >/dev/null 2>&1; then
        # the package lists may be empty on a fresh image, and the updates step only runs later
        run env DEBIAN_FRONTEND=noninteractive apt-get update || return 1
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || return 1
    fi

    # The SSH rules go in FIRST. If ufw is already active, the default policy below applies immediately.
    for port in $ports; do
        run ufw limit "${port}/tcp" || return 1
    done
    # The port of an SSH session that is open right now is allowed too (so we don't cut ourselves off),
    # also when --ssh-port names another one
    while IFS= read -r conn_port; do
        if valid_port "$conn_port" && ! grep -qx -- "$conn_port" <<<"$ports"; then
            warn "An open SSH session uses port $conn_port, allowing that one too"
            run ufw limit "${conn_port}/tcp" || return 1
            ports+=$'\n'"$conn_port"
        fi
    done < <(session_ports)
    for spec in ${ALLOW_PORTS[@]+"${ALLOW_PORTS[@]}"}; do
        run ufw allow "$spec" || return 1
    done
    run ufw default deny incoming || return 1
    run ufw default allow outgoing || return 1
    run ufw --force enable || return 1
    info "Check with: sudo ufw status verbose"
}

step_sysctl() {
    write_file /etc/sysctl.d/99-hardening.conf 644 "$(render_sysctl)" || return 1
    # /etc/sysctl.conf (99-sysctl.conf) is read AFTER 99-hardening.conf, so a value set there wins
    local key main_conf="${ROOT_PREFIX}/etc/sysctl.conf"
    if [[ -r "$main_conf" ]]; then
        while IFS= read -r key; do
            if grep -qE "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$main_conf"; then
                warn "/etc/sysctl.conf also sets $key and is applied later, so its value wins. Remove that line there."
            fi
        done < <(render_sysctl | sed -nE 's/^([a-z][a-z0-9_.]+)[[:space:]]*=.*/\1/p')
    fi
    run sysctl -p /etc/sysctl.d/99-hardening.conf || warn "Some settings could not be applied (normal inside a container)"
    return 0
}

set_login_defs() {   # set_login_defs KEY VALUE
    local key="$1" value="$2" path="/etc/login.defs" target="${ROOT_PREFIX}/etc/login.defs"
    if (( DRY_RUN )); then info "[DRY-RUN] $path: $key = $value"; return 0; fi
    [[ -f "$target" ]] || { warn "$path not found"; return 1; }
    backup_file "$path" || return 1
    if grep -qE "^[[:space:]]*${key}[[:space:]]" "$target"; then
        sed -i -E "s/^[[:space:]]*${key}[[:space:]]+.*/${key}\t${value}/" "$target" || { err "Could not update $path"; return 1; }
    else
        printf '%s\t%s\n' "$key" "$value" >> "$target" || { err "Could not update $path"; return 1; }
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

    local s n=0
    if [[ "$SELECTED_STEPS" != "all" ]]; then
        for s in ${SELECTED_STEPS//,/ }; do
            [[ " ${ALL_STEPS[*]} " == *" $s "* ]] || die "Unknown step: $s (valid: ${ALL_STEPS[*]})"
            n=$((n + 1))
        done
        (( n > 0 )) || die "--steps needs at least one step (valid: ${ALL_STEPS[*]})"
    fi
    if [[ -n "$CREATE_USER_KEY" && -z "$CREATE_USER" ]]; then
        die "--ssh-key only works together with --create-user (it is the key for the new account)"
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
    if [[ -n "$NEEDS_PASSWORD_USER" ]]; then
        echo "WARNING  : '$NEEDS_PASSWORD_USER' has no password, so it cannot use sudo yet."
        echo "           Run 'passwd $NEEDS_PASSWORD_USER' as root BEFORE you close this session,"
        echo "           then '--apply --steps ssh --ssh-user $NEEDS_PASSWORD_USER' closes root login."
    fi
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
