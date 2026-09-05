#!/usr/bin/env bash
# Tests: bash tests/run_tests.sh
# shellcheck disable=SC2015,SC2030,SC2031,SC2163  # the "A && B || C" pattern is deliberate in test code
# NOTE: every --apply test runs ONLY against a fake root (ROOT_PREFIX) and never touches the real system.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
ROOT_DIR="$PWD"
HARDEN="$ROOT_DIR/harden.sh"
FAKEBIN="$ROOT_DIR/tests/fakebin"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "ok   - $1"; }
fail() {
    FAIL=$((FAIL + 1)); echo "FAIL - $1"
    if [[ -n "${2:-}" ]]; then while IFS= read -r l; do echo "       | $l"; done <<<"$2"; fi
}
t() {  # t NAME COMMAND... : passes if the command returns 0
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$name"; else fail "$name"; fi
}
tn() { # tn NAME COMMAND... : passes if the command returns non-zero
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then fail "$name (succeeded, should have failed)"; else ok "$name"; fi
}
has()  { grep -qF -- "$2" <<<"$1"; }
mode() { stat -c %a "$1"; }

mkroot() {   # create a fake root (with a weak configuration)
    local r="$1"
    mkdir -p "$r/etc/ssh/sshd_config.d" "$r/home"
    printf 'Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n' > "$r/etc/ssh/sshd_config"
    printf 'PasswordAuthentication yes\n' > "$r/etc/ssh/sshd_config.d/50-cloud-init.conf"
    echo 'root:x:0:0:root:/root:/bin/bash' > "$r/etc/passwd"
    echo 'root:x:0:' > "$r/etc/group"
    echo 'root:*:19000:0:99999:7:::' > "$r/etc/shadow"
    echo 'root:*::' > "$r/etc/gshadow"
    printf 'PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\n' > "$r/etc/login.defs"
    chmod 644 "$r/etc/ssh/sshd_config"
    chmod 666 "$r/etc/passwd" "$r/etc/group"
    chmod 644 "$r/etc/shadow" "$r/etc/gshadow"
}

# ------------------------------------------------------- function tests
# shellcheck source=../harden.sh
source "$HARDEN"

for v in ali _svc a-b user1; do t "valid_username accepts: $v" valid_username "$v"; done
for v in "Ali" "1abc" "a b" "" 'x;rm' "a\$b"; do tn "valid_username rejects: '$v'" valid_username "$v"; done
for v in 22 1 65535 2222; do t "valid_port accepts: $v" valid_port "$v"; done
for v in 0 65536 abc "" -1 "22;ls"; do tn "valid_port rejects: '$v'" valid_port "$v"; done
for v in 80 443/tcp 53/udp; do t "valid_allow_spec accepts: $v" valid_allow_spec "$v"; done
for v in 80/icmp abc 99999/tcp "80;rm" ""; do tn "valid_allow_spec rejects: '$v'" valid_allow_spec "$v"; done
t  "valid_ssh_key: valid ed25519" valid_ssh_key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@pc"
tn "valid_ssh_key: type only" valid_ssh_key "ssh-ed25519"
tn "valid_ssh_key: random text" valid_ssh_key "rm -rf /"
tn "valid_ssh_key: unsupported dss" valid_ssh_key "ssh-dss AAAAB3Nza"

out=$(KEEP_PASSWORD_AUTH=0 render_sshd_config)
for line in "PermitRootLogin no" "PasswordAuthentication no" "PermitEmptyPasswords no" "X11Forwarding no" "MaxAuthTries 3"; do
    has "$out" "$line" && ok "sshd config: '$line'" || fail "sshd config: '$line' missing" "$out"
done
out=$(KEEP_PASSWORD_AUTH=1 render_sshd_config)
grep -q '^PasswordAuthentication' <<<"$out" && fail "--keep-password-auth: there must be no PasswordAuthentication directive" || ok "--keep-password-auth: PasswordAuthentication is not written"
has "$(render_sysctl)" "net.ipv4.tcp_syncookies = 1" && ok "sysctl: syncookies" || fail "sysctl: syncookies"
grep -E '^net\.ipv4\.ip_forward' <<<"$(render_sysctl)" >/dev/null && fail "sysctl: must not touch ip_forward" || ok "sysctl: ip_forward is left alone"

# has_authorized_keys
me="$(id -un)"
home="$(getent passwd "$me" | cut -d: -f6)"
if [[ -n "$home" ]]; then
    ( ROOT_PREFIX="$WORK/hk"; mkdir -p "$ROOT_PREFIX$home/.ssh"
      tn "has_authorized_keys: no file" has_authorized_keys "$me"
      : > "$ROOT_PREFIX$home/.ssh/authorized_keys"
      tn "has_authorized_keys: empty file" has_authorized_keys "$me"
      echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample" > "$ROOT_PREFIX$home/.ssh/authorized_keys"
      t  "has_authorized_keys: key present" has_authorized_keys "$me" ) > "$WORK/hk.out"
    cat "$WORK/hk.out"; PASS=$((PASS + $(grep -c '^ok' "$WORK/hk.out"))); FAIL=$((FAIL + $(grep -c '^FAIL' "$WORK/hk.out")))
fi

# restore_file
( ROOT_PREFIX="$WORK/rf"; BACKUP_DIR="$ROOT_PREFIX/bk"; mkdir -p "$ROOT_PREFIX/etc" "$BACKUP_DIR/etc"
  echo original > "$BACKUP_DIR/etc/a.conf"; echo changed > "$ROOT_PREFIX/etc/a.conf"
  restore_file /etc/a.conf; [[ "$(cat "$ROOT_PREFIX/etc/a.conf")" == "original" ]] ) \
    && ok "restore_file: restores from the backup" || fail "restore_file: restore"
( ROOT_PREFIX="$WORK/rf2"; BACKUP_DIR=""; mkdir -p "$ROOT_PREFIX/etc"; echo new > "$ROOT_PREFIX/etc/b.conf"
  restore_file /etc/b.conf; [[ ! -e "$ROOT_PREFIX/etc/b.conf" ]] ) \
    && ok "restore_file: removes the new file when there is no backup" || fail "restore_file: removal"

# ---------------------------------------- finalize_ssh_change (with a fake sshd)
finalize_case() {   # finalize_case NAME EXPECTED(ok|rollback) [ENV=...]
    local name="$1" expect="$2"; shift 2
    local r="$WORK/fin-$RANDOM"; mkdir -p "$r/etc/ssh/sshd_config.d"
    echo "PermitRootLogin no" > "$r/etc/ssh/sshd_config.d/00-hardening.conf"
    local rc
    ( export ROOT_PREFIX="$r" BACKUP_DIR="" FAKE_LOG="$r/reload.log" PATH="$FAKEBIN:$PATH" "$@"
      finalize_ssh_change /etc/ssh/sshd_config.d/00-hardening.conf >/dev/null 2>&1 )
    rc=$?
    if [[ "$expect" == "ok" && $rc -eq 0 && -e "$r/etc/ssh/sshd_config.d/00-hardening.conf" ]]; then ok "$name"
    elif [[ "$expect" == "rollback" && $rc -ne 0 && ! -e "$r/etc/ssh/sshd_config.d/00-hardening.conf" ]]; then ok "$name"
    else fail "$name (rc=$rc)"; fi
}
finalize_case "SSH: checks pass -> change stays" ok
finalize_case "SSH: effective PasswordAuthentication yes -> rolled back" rollback FAKE_PASSWORD_AUTH=yes
finalize_case "SSH: sshd -t error -> rolled back" rollback FAKE_SSHD_T_FAIL=1
finalize_case "SSH: reload fails -> rolled back" rollback FAKE_RELOAD_FAIL=1

# --------------------------------------------------------------- CLI tests
H() { "$HARDEN" "$@"; }

# A dry run must not change anything
r="$WORK/dry"; mkroot "$r"
out=$(ROOT_PREFIX="$r" H --ssh-user "$me" --skip-checks 2>&1); rc=$?
[[ $rc -eq 0 ]] && ok "dry-run: exit code 0" || fail "dry-run: exit code $rc" "$out"
has "$out" "[DRY-RUN]" && ok "dry-run: [DRY-RUN] messages present" || fail "dry-run: no messages"
[[ ! -e "$r/etc/ssh/sshd_config.d/00-hardening.conf" ]] && ok "dry-run: no file written" || fail "dry-run: file was written!"
[[ "$(mode "$r/etc/passwd")" == "666" ]] && ok "dry-run: permissions unchanged" || fail "dry-run: permissions changed!"

# Order: the SSH allow rule must come BEFORE the firewall is enabled
out=$(H --steps firewall --allow 80/tcp 2>&1)
l_ssh=$(grep -n 'ufw limit 22/tcp' <<<"$out" | head -1 | cut -d: -f1)
l_en=$(grep -n 'ufw --force enable' <<<"$out" | head -1 | cut -d: -f1)
[[ -n "$l_ssh" && -n "$l_en" && "$l_ssh" -lt "$l_en" ]] && ok "firewall: SSH rule comes before enable" || fail "firewall: wrong order" "$out"
has "$out" "ufw allow 80/tcp" && ok "firewall: --allow 80/tcp" || fail "firewall: --allow"
out=$(H --steps firewall --ssh-port 2222 2>&1)
has "$out" "ufw limit 2222/tcp" && ok "firewall: --ssh-port 2222" || fail "firewall: --ssh-port" "$out"
out=$(SSH_CONNECTION="1.2.3.4 5555 5.6.7.8 2200" H --steps firewall 2>&1)
has "$out" "ufw limit 2200/tcp" && ok "firewall: the current session's port is opened too" || fail "firewall: session port" "$out"

# Safeguard: password login can't be disabled without a key
r="$WORK/guard"; mkroot "$r"
out=$(ROOT_PREFIX="$r" H --apply -y --steps ssh --ssh-user "$me" 2>&1); rc=$?
[[ $rc -ne 0 ]] && ok "safeguard: ssh step fails without key/sudo" || fail "safeguard: it succeeded!" "$out"
[[ ! -e "$r/etc/ssh/sshd_config.d/00-hardening.conf" ]] && ok "safeguard: no file written" || fail "safeguard: file was written!"
has "$out" "authorized_keys" && ok "safeguard: the reason is explained" || fail "safeguard: no explanation" "$out"

# Safeguard: with a key, the outcome depends on sudo membership
if [[ -n "$home" ]]; then
    r="$WORK/guard2"; mkroot "$r"; mkdir -p "$r$home/.ssh"
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample" > "$r$home/.ssh/authorized_keys"
    out=$(ROOT_PREFIX="$r" H --apply -y --steps ssh --ssh-user "$me" 2>&1); rc=$?
    if user_in_sudo "$me"; then
        [[ $rc -eq 0 && -e "$r/etc/ssh/sshd_config.d/00-hardening.conf" ]] && ok "safeguard: key + sudo -> ssh step passes" || fail "safeguard: should have passed" "$out"
    else
        [[ $rc -ne 0 ]] && has "$out" "not in the sudo group" && ok "safeguard: rejects a user who is not in sudo" || fail "safeguard: sudo check" "$out"
    fi
fi

# --keep-password-auth doesn't need a key (only sudo is checked) -> without sudo it is refused
# It must stop on a system with no Include line
r="$WORK/noinc"; mkroot "$r"; echo "PermitRootLogin yes" > "$r/etc/ssh/sshd_config"
out=$(ROOT_PREFIX="$r" H --apply -y --steps ssh --ssh-user "$me" --skip-checks 2>&1); rc=$?
[[ $rc -ne 0 ]] && has "$out" "Include" && ok "ssh step stops when there is no Include line" || fail "Include check" "$out"
[[ ! -e "$r/etc/ssh/sshd_config.d/00-hardening.conf" ]] && ok "no Include: no file written" || fail "no Include: file was written"

# Full apply (in the fake root)
r="$WORK/full"; mkroot "$r"
out=$(ROOT_PREFIX="$r" H --apply -y --ssh-user "$me" --skip-checks 2>&1); rc=$?
[[ $rc -eq 0 ]] && ok "apply: exit code 0" || fail "apply: exit code $rc" "$out"
conf="$r/etc/ssh/sshd_config.d/00-hardening.conf"
[[ -e "$conf" ]] && grep -q '^PermitRootLogin no' "$conf" && grep -q '^PasswordAuthentication no' "$conf" && ok "apply: 00-hardening.conf is correct" || fail "apply: 00-hardening.conf"
[[ -e "$r/etc/sysctl.d/99-hardening.conf" ]] && ok "apply: sysctl file written" || fail "apply: sysctl"
[[ -e "$r/etc/apt/apt.conf.d/20auto-upgrades" ]] && ok "apply: auto-upgrades file written" || fail "apply: 20auto-upgrades"
grep -qE '^PASS_MAX_DAYS[[:space:]]+90$' "$r/etc/login.defs" && ok "apply: PASS_MAX_DAYS 90" || fail "apply: PASS_MAX_DAYS"
grep -qE '^PASS_MIN_DAYS[[:space:]]+1$' "$r/etc/login.defs" && ok "apply: PASS_MIN_DAYS 1" || fail "apply: PASS_MIN_DAYS"
grep -qE '^PASS_WARN_AGE[[:space:]]+7$' "$r/etc/login.defs" && ok "apply: PASS_WARN_AGE added" || fail "apply: PASS_WARN_AGE"
for pair in "passwd:644" "group:644" "shadow:640" "gshadow:640" "ssh/sshd_config:600"; do
    f="${pair%%:*}"; m="${pair##*:}"
    [[ "$(mode "$r/etc/$f")" == "$m" ]] && ok "apply: /etc/$f -> $m" || fail "apply: /etc/$f has mode $(mode "$r/etc/$f"), expected $m"
done
bk=$(find "$r/var/backups" -path '*etc/login.defs' 2>/dev/null | head -1)
[[ -n "$bk" ]] && grep -q 'PASS_MAX_DAYS.*99999' "$bk" && ok "apply: original login.defs was backed up" || fail "apply: no backup"
[[ -s "$r/var/log/harden.log" ]] && ok "apply: log file written" || fail "apply: no log"

# Idempotency: a second run must give the same result and not create duplicates
out=$(ROOT_PREFIX="$r" H --apply -y --ssh-user "$me" --skip-checks 2>&1); rc=$?
[[ $rc -eq 0 ]] && ok "idempotent: second run succeeds" || fail "idempotent: rc=$rc"
[[ "$(grep -cE '^PASS_MAX_DAYS' "$r/etc/login.defs")" == "1" ]] && ok "idempotent: PASS_MAX_DAYS is not duplicated" || fail "idempotent: duplicate"
[[ "$(grep -c '^PermitRootLogin' "$conf")" == "1" ]] && ok "idempotent: drop-in is not duplicated" || fail "idempotent: drop-in"

# --------------------------------------------------------- argument checks
tn "args: unknown step"          H --steps foo
tn "args: bad --allow"           H --allow abc
tn "args: bad --ssh-port"        H --ssh-port 99999
tn "args: bad --create-user"     H --create-user "Bad Name"
tn "args: unknown option"        H --no-such-option
tn "args: --steps without value" H --steps
t  "args: --help"                H --help
if [[ $EUID -ne 0 ]]; then
    tn "--apply is refused without root" H --apply -y
else
    echo "skip - running as root, skipping the 'refused without root' test"
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]

