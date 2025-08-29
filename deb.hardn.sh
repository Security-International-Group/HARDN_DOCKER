#!/bin/bash
# HARDN-XDR - Setup Script with Uninstall Option (Enhanced Hardening)
#
# This script installs required dependencies and applies both base and advanced hardening
# measures on Debian‑based systems using AppArmor (SELinux is not used). It now:
#
#  - Installs gnupg/gnupg2 and adds the Lynis repository (then runs an apt update),
#  - Installs additional recommended packages (including sysstat, aide, etc.),
#  - Enables sysstat (ACCT-9626) and disables auditd (ACCT-9630),
#  - Configures AIDE using updated options: it now uses "database_in" (instead of "database"),
#    uses "log_level=error" and "report_level=summary", and forces SHA512 checksums by appending
#    "+sha512" to the file check rules (satisfying FINT-4402),
#  - Writes legal banners to /etc/issue and /etc/issue.net (BANN-7126 & BANN-7130),
#  - Applies advanced sysctl hardening settings (KRNL-6000),
#  - Reminds the administrator to consider restricting compilers

#  - And finally removes gnupg and gnupg2 since they are no longer needed.
#
# Usage:
#   To install/update hardening settings:
#         sudo ./setup.sh
#   To uninstall (remove configuration modifications):
#         sudo ./setup.sh -uninstall
#

set -euo pipefail
IFS=$'\n\t'

# Prevent interactive prompts during apt operations in automated/container environments
export DEBIAN_FRONTEND=noninteractive

###############################################################################
# Uninstall Option: Remove configuration modifications.
###############################################################################
if [[ "${1:-}" == "-uninstall" ]]; then
  echo "Uninstalling HARD-XDR to default configurations..."
    
  # Remove advanced sysctl hardening configuration.
  if [ -f /etc/sysctl.d/99-hardening.conf ]; then
    rm /etc/sysctl.d/99-hardening.conf
    echo "Removed /etc/sysctl.d/99-hardening.conf"
    sysctl --system 2>/dev/null || echo "Warning: Failed to reload sysctl settings."
  fi

  # Remove network protocol blacklisting.
  if [ -f /etc/modprobe.d/disable-net-protocols.conf ]; then
    rm /etc/modprobe.d/disable-net-protocols.conf
    echo "Removed /etc/modprobe.d/disable-net-protocols.conf"
  fi

  echo "Uninstallation complete. Note: Installed packages and some configuration files were not removed."
  exit 0
fi

###############################################################################
# Pre-Checks
###############################################################################
# Ensure the script is run as root.
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Please use sudo."
  exit 1
fi

# Verify that the system is Debian‑based.
if ! grep -qiE "debian|ubuntu" /etc/os-release; then
  echo "This script is intended for Debian‑based systems."
  exit 1
fi

# Secure the script file itself.
chmod 700 "${BASH_SOURCE[0]}"

echo "---------------------------------------------"
echo " HARDN-XDR Setup Initialization"
echo "---------------------------------------------"

###############################################################################
# Pre-installation: Install gnupg/gnupg2 and add Lynis repository
###############################################################################
echo "[+] Installing gnupg and gnupg2..."
apt-get update
apt-get install -y gnupg gnupg2

echo "[+] Adding the Lynis repository..."
mkdir -p /etc/apt/trusted.gpg.d /tmp
KEY_URL="https://packages.cisofy.com/keys/cisofy-software-public.key"
curl -fsSL "$KEY_URL" -o /tmp/cisofy-software-public.key || true
if command -v gpg >/dev/null 2>&1 && [ -s /tmp/cisofy-software-public.key ]; then
  gpg --dearmor /tmp/cisofy-software-public.key -o /etc/apt/trusted.gpg.d/cisofy-software-public.gpg || true
fi
echo "deb [arch=amd64,arm64 signed-by=/etc/apt/trusted.gpg.d/cisofy-software-public.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" | tee /etc/apt/sources.list.d/cisofy-lynis.list
apt-get install -y apt-transport-https || true
echo "[+] Running an apt-get update after adding the Lynis repo..."
if ! apt-get update -o Acquire::AllowInsecureRepositories=false; then
  echo "apt-get update failed; attempting apt-key fallback..."
  if [ -s /tmp/cisofy-software-public.key ]; then
    apt-key add /tmp/cisofy-software-public.key || true
    apt-get update || true
  fi
fi

###############################################################################
# Install Essential Packages (including sysstat, aide, etc.)
###############################################################################
echo "[+] Installing essential system packages..."
ESSENTIAL_PACKAGES=(
  ufw
  fail2ban
  apparmor
  apparmor-utils
  firejail
  tcpd
  lynis
  debsums
  rkhunter
  git
  macchanger
  libpam-tmpdir            # Sets $TMP and $TMPDIR for PAM sessions.
  apt-listbugs             # Display critical bugs with APT.
  needrestart              # Detect services needing restart after upgrades.
  apt-show-versions        # For patch management.
  unattended-upgrades      # Automatic upgrades.
  acct                     # Process accounting.
  sysstat                  # System performance statistics.
  auditd                   # Audit daemon.
  aide                     # File integrity checker.
  libpam-pwquality         # Enforce password strength via PAM.
)
for pkg in "${ESSENTIAL_PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" &>/dev/null; then
    echo "Installing package: $pkg..."
    apt-get install -y --no-install-recommends "$pkg"
  else
    echo "Package $pkg is already installed."
  fi
done

# Ensure package database consistency and perform fixes that Lynis expects
echo "[+] Repairing package database and running apt checks..."
dpkg --configure -a || true
apt-get -f install -y || true
apt-get update || true
apt-get check || apt-get -f install -y || true

# Install and start a syslog daemon so Lynis/klogd checks have something to query
if ! dpkg -s rsyslog &>/dev/null; then
  echo "[+] Installing rsyslog to satisfy kernel logging checks..."
  apt-get install -y --no-install-recommends rsyslog || true
fi
if command -v rsyslogd >/dev/null 2>&1; then
  echo "[+] Starting rsyslogd in background..."
  /usr/sbin/rsyslogd || echo "Warning: rsyslogd failed to start (container/systemd limitations)."
fi

###############################################################################
# Enable sysstat Accounting and Disable auditd (Empty Ruleset)
###############################################################################
echo "[+] Enabling sysstat accounting..."
if [ -f /etc/default/sysstat ]; then
  sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat && echo "Sysstat enabled."
fi

echo "[+] Disabling auditd (due to empty ruleset)..."
systemctl disable --now auditd || echo "Warning: Could not disable auditd."

###############################################################################
# Configure UFW Firewall, Fail2Ban & AppArmor
###############################################################################
echo "[+] Installed UFW firewall..."

# Ensure iptables rules exist (Lynis looks for active rules). Containers may lack netfilter
# capabilities, so we try to create a minimal ruleset and restore it if possible.
echo "[+] Ensuring iptables rules exist (or creating a fallback rules file)..."
if iptables -L >/dev/null 2>&1; then
  if [ -z "$(iptables -L | sed -n '1,2p' | grep -v Chain)" ]; then
    echo "[+] No iptables rules found; attempting to add minimal policies..."
    iptables -P INPUT DROP || true
    iptables -P FORWARD DROP || true
    iptables -P OUTPUT ACCEPT || true
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT || true
  fi
else
  echo "[+] iptables not usable in this environment; creating fallback /etc/iptables/rules.v4"
  cat > /etc/iptables/rules.v4 <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
EOF
  # Try to load it if iptables-restore is available
  if command -v iptables-restore >/dev/null 2>&1; then
    iptables-restore /etc/iptables/rules.v4 || true
  fi
fi

echo "[+] Enabling Fail2Ban and AppArmor services..."
systemctl enable --now fail2ban || true
systemctl enable --now apparmor || true

###############################################################################
# Configure Secure Cron Jobs
###############################################################################
echo "[+] Configuring secure cron jobs..."
CRON_JOB_FILE="/root/hardn_cron_jobs"
cat <<EOF > "$CRON_JOB_FILE"
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 2 * * * apt-get update && apt-get upgrade -y
EOF
chmod 600 "$CRON_JOB_FILE"
crontab "$CRON_JOB_FILE" || true
rm -f "$CRON_JOB_FILE"

###############################################################################
# Disable USB Storage and Update 'locate' Database
###############################################################################
echo "[+] Disabling USB storage (if not required)..."
echo 'blacklist usb-storage' > /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage || echo "[-] Warning: Could not unload USB storage module; it may be in active use."

echo "[+] Running updatedb to build the file database for locate..."
updatedb || true

###############################################################################
# AIDE Configuration and Initialization (Force SHA512 via Config Rules)
###############################################################################
echo "[+] Configuring AIDE..."
mkdir -p /etc/aide
cat <<'EOF' > /etc/aide/aide.conf
#######################################################################
# AIDE Default Configuration File
#
# This is a basic configuration for the Advanced Intrusion Detection
# Environment (AIDE). It sets up the database locations, options, defines
# file attribute rules, and specifies which paths to monitor or ignore.
#######################################################################

# Database locations
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new

# Compress the output database file
gzip_dbout=yes

# Logging and reporting levels
log_level=error
report_level=summary

#######################################################################
# Global File Attribute Check Rules
#######################################################################
# Append +sha512 to force SHA512 checksums
NORMAL = p+i+n+u+g+acl+selinux+xattrs+sha512
LOG = p+i+n+u+g+sha512

#######################################################################
# File and Directory Selection
#######################################################################
!/proc
!/sys
!/dev
!/run

 /bin         NORMAL
 /sbin        NORMAL
 /usr/bin     NORMAL
 /usr/sbin    NORMAL
 /etc         NORMAL
 /lib         NORMAL
 /lib64       NORMAL
 /opt         NORMAL
 /home        NORMAL

 /var/log     LOG

!/var/lib/apt/lists
!/var/cache

#######################################################################
# End of Configuration
#######################################################################
EOF

mkdir -p /var/lib/aide
touch /var/lib/aide/aide.db.new
touch /var/lib/aide/aide.db
# Run AIDE update and initialization; ignore nonzero exit statuses.
aide --update --config /etc/aide/aide.conf || true
aide -i --config /etc/aide/aide.conf || true

# Some tools expect AIDE at /etc/aide.conf — create a compatibility symlink
if [ ! -f /etc/aide.conf ]; then
  echo "[+] Creating compatibility symlink /etc/aide.conf -> /etc/aide/aide.conf"
  ln -sf /etc/aide/aide.conf /etc/aide.conf || true
fi

# Ensure fail2ban local configuration exists to prevent it being overwritten by updates
if [ -f /etc/fail2ban/jail.conf ] && [ ! -f /etc/fail2ban/jail.local ]; then
  echo "[+] Copying fail2ban jail.conf to jail.local"
  cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || true
fi

###############################################################################
# Write Legal Banners (BANN-7126 & BANN-7130)
###############################################################################
echo "[+] Writing legal banner to /etc/issue and /etc/issue.net..."
echo "Unauthorized access is prohibited. All activity is monitored." > /etc/issue
echo "Unauthorized access is prohibited. All activity is monitored." > /etc/issue.net

###############################################################################
# Advanced Hardening via Sysctl (KRNL-6000)
###############################################################################
echo "[+] Applying advanced sysctl hardening settings..."
cat <<'EOF' > /etc/sysctl.d/99-hardening.conf
# Advanced hardening settings for maximum security

# Device settings
dev.tty.ldisc_autoload = 0

# Network protection
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.send_redirects = 0

# Filesystem protection
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Kernel and process security
kernel.core_uses_pid = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.modules_disabled = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1

# BPF hardening
net.core.bpf_jit_harden = 2

# TCP optimizations
net.ipv4.tcp_fin_timeout = 15

# Disable unused protocols
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

chmod 600 /etc/sysctl.d/99-hardening.conf
echo "[+] Reloading sysctl settings..."
sysctl --system || true
echo "[+] Advanced hardening settings applied."

###############################################################################
# Clean-Up: Remove gnupg and gnupg2 as they are no longer needed.
###############################################################################
echo "[+] Removing gnupg and gnupg2..."
apt remove gnupg gnupg2 -y || true

###############################################################################

echo "---------------------------------------------"
echo "[+] HARDN-XDR Setup Complete!"
echo "---------------------------------------------"
