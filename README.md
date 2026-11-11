# server-hardening-script

A Bash script that hardens a fresh Ubuntu or Debian server in one run: SSH settings, the `ufw` firewall, a handful of kernel (sysctl) parameters, password aging, permissions on a few critical files, and automatic security updates.

It does a dry run by default. Nothing is changed unless you pass `--apply`.

This edits your SSH and firewall configuration, and a mistake there can lock you out of the machine. Snapshot the VM and try it there first. Don't close your current SSH session until you've logged in successfully from a second terminal.

## Works with hardening-checker

[hardening-checker](https://github.com/faridtagizada/hardening-checker) finds problems, and this script fixes the ones that are safe to fix automatically. On a fake, deliberately weak system (using only the checker's SSH, FILE and USR checks) the scores went like this:

| | Score | PASS | FAIL | WARN |
|---|---|---|---|---|
| Before | 9/100 | 0 | 9 | 4 |
| After | 78/100 | 11 | 2 | 0 |

The two FAILs that remain, an extra account with UID 0 and an account with an empty password, are left alone on purpose. Deleting or changing accounts automatically is risky, so that decision is yours.

## Safeguards

- Dry run is the default.
- Password login is only turned off if the user you name with `--ssh-user` already has a key in `authorized_keys`.
- Root login is only closed if there is a user with sudo rights. `--create-user` only counts for that when the `user` step runs in the same invocation and succeeds.
- An account created with `--create-user` has no password, so `sudo` does not work for it until you run `passwd NAME`. The script warns about this in the `user` step and again in the summary.
- After writing the SSH config the script runs `sshd -t` and `sshd -T` and looks at the effective values. If `sshd -t` fails, if another file overrides the setting, or if the reload fails, the change is rolled back.
- In `ufw` the SSH rules are added first, before the default-deny policy and before the firewall is enabled. Every port `sshd` listens on is allowed (read from `sshd -T` and from the listening sockets), and so is the port of your current session when `SSH_CONNECTION` is available. Plain `sudo` removes that variable, which is why the listening ports are checked as well.
- Every file it changes is copied to `/var/backups/harden-<date>/` first, and a step fails if that copy or the write itself fails. The `perms` step only changes modes and owners; it writes the previous values to `/var/log/harden.log`.
- Usernames, ports, SSH keys and `--allow` values are validated.
- Everything is logged to `/var/log/harden.log`.

### Why the drop-in is called 00-hardening.conf

In sshd the first value that gets set is the one that counts. On Ubuntu, `sshd_config` begins with `Include /etc/ssh/sshd_config.d/*.conf`, and cloud images often ship a `50-cloud-init.conf` containing `PasswordAuthentication yes`. A hardening file with a later name would lose to it. Naming ours `00-hardening.conf` makes it load first. The script then checks the effective values with `sshd -T` anyway, because what a file says and what is actually in force aren't always the same thing.

## Steps

| Step | What it does |
|---|---|
| `user` | With `--create-user`, creates a sudo user and optionally installs an SSH key |
| `ssh` | `PermitRootLogin no`, `PasswordAuthentication no`, `PermitEmptyPasswords no`, `X11Forwarding no`, `MaxAuthTries 3`, `LoginGraceTime 30`, `ClientAlive*` |
| `firewall` | `ufw`: deny incoming, allow outgoing, `ufw limit` on SSH (rate limiting against brute force), plus any extra ports |
| `sysctl` | SYN cookies, no ICMP redirects or source routing, `rp_filter`, `log_martians`, ASLR |
| `passwords` | `/etc/login.defs`: `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 7` |
| `perms` | `passwd` and `group` 644, `shadow` and `gshadow` 640, `sshd_config` 600 |
| `updates` | Installs and enables `unattended-upgrades` |

`net.ipv4.ip_forward` is deliberately not touched, since Docker, VPNs and routers may need it.

## Requirements

Ubuntu 22.04+ or Debian 12+ (it relies on `sshd_config.d`), Bash 4+, and root or sudo for `--apply`. On any other distribution `--apply` refuses to run.

## Usage

```bash
git clone https://github.com/faridtagizada/server-hardening-script.git
cd server-hardening-script
chmod +x harden.sh

# 1) Dry run first: shows what would happen, changes nothing
./harden.sh --ssh-user ali

# 2) New user + SSH key + web ports (paste your full public key)
./harden.sh --create-user ali --ssh-key "ssh-ed25519 AAAA... ali@laptop" \
            --allow 80/tcp --allow 443/tcp

# 3) Apply for real (snapshot first!)
sudo ./harden.sh --apply --ssh-user ali --allow 80/tcp --allow 443/tcp

# Only some of the steps
sudo ./harden.sh --apply --steps sysctl,perms,passwords
```

| Option | Description |
|---|---|
| `--apply` | Actually apply the changes |
| `-y, --yes` | Don't ask for confirmation |
| `--steps` | `user,ssh,firewall,sysctl,passwords,perms,updates` (default: all) |
| `--create-user NAME` / `--ssh-key "KEY"` | New sudo user and its key |
| `--ssh-user NAME` | The account you log in with, used by the safety checks |
| `--ssh-port N` | SSH port (default: every port found with `sshd -T` and `ss`, otherwise 22) |
| `--allow PORT[/proto]` | Open an extra port in the firewall (repeatable) |
| `--keep-password-auth` | Leave password login alone and only close root login |
| `--skip-checks` | Skip the SSH safety checks (dangerous, for testing only) |

### Dry run output

This is what example 2 above prints when it is given a real public key:

```
[INFO] DRY-RUN mode: nothing is changed. Use --apply to apply.

=== Step: user ===
[INFO] [DRY-RUN] adduser --disabled-password --gecos '' ali
[INFO] [DRY-RUN] usermod -aG sudo ali
[INFO] [DRY-RUN] ~/.ssh/authorized_keys will be created for ali
[WARN] ali is created WITHOUT a password, so sudo will not work for it yet.
[WARN] Set one before you close your root session: passwd ali

=== Step: ssh ===
[INFO] [DRY-RUN] File will be written: /etc/ssh/sshd_config.d/00-hardening.conf (mode 644)
         | # generated by harden.sh 1.1.0 (2026-11-11)
         | # The file name deliberately starts with "00-": in sshd the FIRST value set wins,
         | # and files such as "50-cloud-init.conf" can override this with PasswordAuthentication yes.
         | PermitRootLogin no
         | PasswordAuthentication no
         | PermitEmptyPasswords no
         | X11Forwarding no
         | MaxAuthTries 3
         | LoginGraceTime 30
         | ClientAliveInterval 300
         | ClientAliveCountMax 2
[INFO] [DRY-RUN] then: sshd -t, effective-value check with sshd -T, systemctl reload ssh

=== Step: firewall ===
[INFO] [DRY-RUN] env DEBIAN_FRONTEND=noninteractive apt-get update
[INFO] [DRY-RUN] env DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
[INFO] [DRY-RUN] ufw limit 22/tcp
[INFO] [DRY-RUN] ufw allow 80/tcp
[INFO] [DRY-RUN] ufw allow 443/tcp
[INFO] [DRY-RUN] ufw default deny incoming
[INFO] [DRY-RUN] ufw default allow outgoing
[INFO] [DRY-RUN] ufw --force enable
[INFO] Check with: sudo ufw status verbose

=== Step: sysctl ===
[INFO] [DRY-RUN] File will be written: /etc/sysctl.d/99-hardening.conf (mode 644)
         | # generated by harden.sh
         | # Note: net.ipv4.ip_forward is deliberately left alone (Docker/VPN/router setups may need it).
         | net.ipv4.tcp_syncookies = 1
         | net.ipv4.conf.all.accept_redirects = 0
         | net.ipv4.conf.default.accept_redirects = 0
         | net.ipv6.conf.all.accept_redirects = 0
         | net.ipv6.conf.default.accept_redirects = 0
         | net.ipv4.conf.all.send_redirects = 0
         | net.ipv4.conf.default.send_redirects = 0
         | net.ipv4.conf.all.accept_source_route = 0
         | net.ipv4.conf.all.rp_filter = 1
         | net.ipv4.conf.default.rp_filter = 1
         | net.ipv4.conf.all.log_martians = 1
         | net.ipv4.icmp_echo_ignore_broadcasts = 1
         | net.ipv4.icmp_ignore_bogus_error_responses = 1
         | kernel.randomize_va_space = 2
[INFO] [DRY-RUN] sysctl -p /etc/sysctl.d/99-hardening.conf

=== Step: passwords ===
[INFO] [DRY-RUN] /etc/login.defs: PASS_MAX_DAYS = 90
[INFO] [DRY-RUN] /etc/login.defs: PASS_MIN_DAYS = 1
[INFO] [DRY-RUN] /etc/login.defs: PASS_WARN_AGE = 7
[INFO] Note: this only affects NEW accounts. For an existing account: sudo chage --maxdays 90 <name>

=== Step: perms ===
[INFO] [DRY-RUN] chmod 644 /etc/passwd
[INFO] [DRY-RUN] chown root:root /etc/passwd
[INFO] [DRY-RUN] chmod 644 /etc/group
[INFO] [DRY-RUN] chown root:root /etc/group
[INFO] [DRY-RUN] chmod 640 /etc/shadow
[INFO] [DRY-RUN] chown root:shadow /etc/shadow
[INFO] [DRY-RUN] chmod 640 /etc/gshadow
[INFO] [DRY-RUN] chown root:shadow /etc/gshadow
[INFO] [DRY-RUN] chmod 600 /etc/ssh/sshd_config
[INFO] [DRY-RUN] chown root:root /etc/ssh/sshd_config

=== Step: updates ===
[INFO] [DRY-RUN] env DEBIAN_FRONTEND=noninteractive apt-get update
[INFO] [DRY-RUN] env DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
[INFO] [DRY-RUN] File will be written: /etc/apt/apt.conf.d/20auto-upgrades (mode 644)
         | APT::Periodic::Update-Package-Lists "1";
         | APT::Periodic::Unattended-Upgrade "1";

================ SUMMARY ================
Succeeded: user ssh firewall sysctl passwords perms updates
Failed   : (none)
WARNING  : 'ali' has no password, so it cannot use sudo yet.
           Run 'passwd ali' as root BEFORE you close this session.
Mode     : DRY-RUN (nothing was changed). Add --apply to apply.
```

## Rolling back

```bash
# the backups
ls /var/backups/harden-*/

# undo the SSH change
sudo rm /etc/ssh/sshd_config.d/00-hardening.conf
sudo sshd -t && sudo systemctl reload ssh

# undo the sysctl change
sudo rm /etc/sysctl.d/99-hardening.conf && sudo sysctl --system

# turn the firewall off
sudo ufw disable

# restore login.defs
sudo cp /var/backups/harden-<date>/etc/login.defs /etc/login.defs
```

If you do get locked out of SSH, log in from the VM console and run the commands above.

## Tests

```bash
bash tests/run_tests.sh      # 96 tests
shellcheck harden.sh tests/run_tests.sh
```

The tests run against a fake root directory (`ROOT_PREFIX`) and never touch the real system. They cover the validation functions, the fact that a dry run changes nothing, the order of the firewall commands, the SSH safeguards, backups, idempotency (a second run doesn't create duplicates), and the automatic rollback using a fake `sshd` and `systemctl` (failed check, `sshd -t` error, failed reload).

### What the tests don't cover

Real `ufw`, real `sshd` and real `systemctl` are not exercised by the automated tests, because that would change the machine they run on. Check those by hand on an Ubuntu VM:

```bash
./harden.sh --ssh-user $USER                       # 1. does the dry run work?
sudo ./harden.sh --apply --ssh-user $USER          # 2. apply
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication'   # 3. effective values
sudo ufw status verbose                            # 4. firewall rules
ssh $USER@<server-ip>                              # 5. does login work from a NEW terminal?
sudo ./harden.sh --apply --ssh-user $USER          # 6. run it again, nothing should be duplicated
```

## Limitations

- On Ubuntu 24.04 SSH may be started through `ssh.socket`. Changing the port then also means changing the `ssh.socket` configuration. The script reads the port from `sshd -T` but doesn't change it.
- `MaxAuthTries 3` can bite if your SSH agent holds many keys, because each key counts as an attempt. Use `ssh -o IdentitiesOnly=yes -i ...`.
- Docker can bypass `ufw` by adding its own iptables rules, so check container ports separately.
- Only tested with IPv4. `ufw` handles IPv6 by default, but that hasn't been tested.
- `PASS_MAX_DAYS` only applies to new accounts. Existing ones need `chage`.
- `rp_filter = 1` is strict reverse-path filtering. It can drop traffic on hosts with asymmetric routing, several uplinks or policy-routed VPNs (some WireGuard setups). If that is your case, change both `rp_filter` lines in `/etc/sysctl.d/99-hardening.conf` to `2` (loose mode).
- `Match` blocks in the SSH configuration are not evaluated. The script warns when it finds one; check a concrete case with `sshd -T -C user=NAME,host=HOST,addr=IP`.
- `KbdInteractiveAuthentication` is not changed, because some setups need it for 2FA. If it is still `yes` after the run, the script warns that passwords may still be accepted through PAM.
- Values set in `/etc/sysctl.conf` are applied after `99-hardening.conf` and win. The script warns when it finds one of its keys there.
- It covers the basics and is not a replacement for the full CIS Benchmark.

## Layout

```
server-hardening-script/
├── harden.sh                 # the script
└── tests/
    ├── run_tests.sh          # 96 tests
    └── fakebin/              # fake sshd and systemctl
```

## TODO

- an install step for `fail2ban` / `auditd`
- a `--rollback` command (restore from the latest backup)
- IPv6 and `nftables` support
- settings from a config file (YAML or env)

## License

MIT
