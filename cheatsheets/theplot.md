## This is a rough outline of what I've created.  If you want to cheat look here

**Overall Narrative Arc:**

You are a hacker operating on the fringes. You receive an encrypted message containing a download link for a VM image (`0xGhost.img`) and instructions. The sender is the infamous Zer0Frame (ZF), leader of the hacker collective Nu11Division (N1D). The message is brief: "0xGhost, one of ours, went dark investigating TargetCorp. He was working on something big - 'Project Chimera'. This is his work machine image. Analyze it. Find out how to get into TargetCorp's network using his tracks. Follow the trail, find what he found, figure out what happened to him. Prove you have the skills, submit flags as you find them via the method detailed in the image. Succeed, and you're in N1D. Fail, and you never heard from me."

Your goal is to piece together 0xGhost's work, retrace his steps into TargetCorp, uncover the truth behind Project Chimera and his disappearance, and report findings by submitting flags to an automated system.

**Phase 1: The Inheritance (Analyzing `0xGhost.img`)**

This phase focuses on digital forensics using the provided VM image.

*   **Key Discoveries & Actions:**
    1.  **File System Exploration:** Standard Linux home directory (`/home/ghost`). You find Documents, Downloads, Notes, Mail, .ssh, .config, .bash_history, etc.
    2.  **Shell History (`.bash_history`):** Reveals commands targeting `targetcorp.com`, internal IP `172.16.10.5`, `portal.targetcorp.com`. Mentions cloning git repos, using `nmap`, `gobuster`, `nc`, `zip`, trying to mount `/dev/sdb1`, using `proxychains`. Hints at password (`htpasswd`) or key usage (`ssh -i`).
    3.  **Notes (`~/Notes`, `~/Documents/research/project_chimera/notes`):**
        *   `README_ZF_CONTACT.txt`: Explicit instructions from ZF. Details the **flag submission method: `nc director.nulldivision.internal 9999`** (Hostname resolves only via VPN). Gives first contact flag: `FLAG{ZEROFRAME_INSTRUCTIONS_RECEIVED}`. Mentions VPN config and encrypted key password hint location. Mentions Canary email.
        *   `main_strategy.md`: Details Project Chimera targeting TargetCorp's "Project Griffin". Lists attack vectors (Web Portal, SSH `172.16.10.5`). Mentions KeePass DB `ghost_secrets.kdbx` with password `ChangeMe123!`. Gives explicit **hints for VPN key password** (`GhostInTheShell2077`) and **Zip password** (`ProjectChimera!`). Contains narrative flag: `FLAG{MAIN_STRATEGY_DOCUMENT_LOCATED}`.
        *   `. hidden config `: File starting with dot and ending with space contains dummy AWS keys and a flag: `FLAG{FOUND_HIDDEN_SPACED_FILE}`.
    4.  **Connectivity (`~/vpn_configs`, `~/.ssh`):**
        *   `Nu11Division_Ops.ovpn`: The OpenVPN config file needing a cert and an encrypted key. Points to `vpn.nulldivision.internal`. **This is required for Phase 2.**
        *   `id_rsa_ghost_encrypted` & `.pub`: The encrypted RSA key pair for the VPN. Requires password found via hint in `main_strategy.md`.
        *   `id_ed25519` & `.pub`: An *unencrypted* Ed25519 key pair, mentioned in `~/.ssh/config` for host `target_internal` (`172.16.10.5`). **This is one way into the target network after VPN.**
        *   `config`: Defines `target_internal` (172.16.10.5) using `id_ed25519`. Lists other potential targets (some may be rabbit holes).
    5.  **Credentials & Secrets:**
        *   `~/Documents/ghost_secrets.kdbx`: KeePass DB (password `ChangeMe123!`). Contains mostly test/old creds, but might include `ghost:password123` (weak password used elsewhere?). Flag inside placeholder/DB: `FLAG{ACCESSED_KEEPASS_PLACEHOLDER}`.
        *   `~/Downloads/chimera_backup.zip`: Encrypted zip (password `ProjectChimera!`). Contains research notes hinting at internal file server (`10.0.10.50`), mentioning Canary contact and DeltaCharlie protocol.
        *   `~/Pictures/sky.png`: Steganography image (password `steganography`). Contains flag: `FLAG{STEGO_SKY_IS_BLUE_...}`.
        *   `~/.config/some_app/config.ini`: Contains Base64 encoded flag: `FLAG{BASE64_HIDDEN_IN_CONFIG}`.
    6.  **Email (`~/Mail`):**
        *   `msg_from_ZF_01.eml`: Urges contact with Canary via `anonymous_canary@protonmail.com` using "DeltaCharlie" protocol hint for key exchange. Contains flag: `FLAG{CANARY_CONTACT_DETAILS_RECEIVED}`.
        *   `msg_hr_phish_test.eml`: Spam/phish test pointing to `portal.targetcorp.com`.
        *   `msg_to_ZF_concerns.eml`: Shows Ghost's paranoia, mentions WAF issues, using TOR.
    7.  **File Recovery/Trash (`~/.local/share/Trash`, requiring tools):** Recovered `Nul1Div_comms_leak_analysis.txt` hints at internal N1D issues and a mole named "Canary" (conflicting info - is Canary mole or contact?). `todo.txt` pointed here.

*   **Outcome:** Player should have VPN credentials (config, decrypted key), target domain/IPs, understanding of flag submission, context about Project Chimera/Griffin/Canary, and several introductory flags.

**Phase 2: Breaching TargetCorp**

Player connects to the N1D Ops VPN (`vpn.nulldivision.internal`). The `director.nulldivision.internal` host is now reachable for flag submission. `targetcorp.com` DNS might resolve externally, but key targets `172.16.10.5` and potentially internal names (`*.targetcorp.local`) require the VPN connection (or `/etc/hosts` entries based on findings).

*   **Target Network Layout:**
    *   **VPN Entry Point (Managed by Director)**
    *   **DMZ Network (Simulated - 172.16.10.0/24):**
        *   `web-dmz` (172.16.10.100): Public Website (Container)
        *   `portal-dmz` (portal.targetcorp.com / 172.16.10.105): Login Portal (Container)
        *   `ssh-jump` (172.16.10.5): SSH Jumpbox (VM) - *This is the primary pivot point.*
    *   **Internal Network 1 (Internal LAN - 10.0.10.0/24):**
        *   `fileserv` (fileserv.targetcorp.local / 10.0.10.50): File Server (Windows VM or Samba)
        *   `db-internal` (db.targetcorp.local / 10.0.10.200): Database Server (Container)
        *   `dev-wiki` (dev-wiki.targetcorp.local / 10.0.10.150): Dev Wiki Server (Container)
        *   **Rabbit Hole:** `test-server` (10.0.10.250): Old test server, few services, nothing useful (Container).
    *   **Internal Network 2 (High Security Zone - 10.0.50.0/24 - Initially Unreachable):**
        *   `qec-sim` (qec-sim.targetcorp.internal / 10.0.50.50): Project Griffin Simulation Server (VM)

*   **Machine Breakdown & Path:**

    1.  **`ssh-jump` (172.16.10.5)**
        *   **Access:** SSH as `ghost` using the *unencrypted* `id_ed25519` key found on the Ghost image. (Alternatively, if KeePass contained `ghost:password123`, that might also work).
        *   **Purpose:** Bastion host / SSH jump box. Limited tools installed. Can reach DMZ and Internal Network 1 (10.0.10.0/24).
        *   **Clues/Flags:**
            *   `~/.bash_history`: Shows connections to `fileserv` (`smbclient //fileserv/...`) and `db-internal` (`mysql -h db.targetcorp.local ...`).
            *   `~/scripts/check_connections.sh`: A script that runs `netstat` or `ss`, revealing active connections to `db-internal` on port 3306.
            *   User `ghost` has specific `sudo` right: `sudo /usr/sbin/tcpdump -i eth1 port 3306`. Running this while `web-dmz` connects to the DB (may require triggering activity or waiting) could reveal **plaintext DB credentials `web_user:SimplePassw0rd`** in the packet capture. (*This is a harder path*).
            *   **FLAG{JUMPBOX_ACCESS_GHOST}**.
        *   **Rabbit Hole:** Crontab entry runs a backup script that targets a non-existent server. `/etc/hosts` has entries for many internal servers that don't respond.

    2.  **`web-dmz` (172.16.10.100)**
        *   **Access:** Standard HTTP/S access.
        *   **Purpose:** Basic corporate website. Mostly static info.
        *   **Clues/Flags:**
            *   `/robots.txt`: Disallows `/dev-backup/`.
            *   `/dev-backup/`: Contains `db_config.php.bak` (readable text file) with database credentials: `define('DB_USER', 'web_user'); define('DB_PASSWORD', 'SimplePassw0rd'); define('DB_HOST', 'db.targetcorp.local');`. **This is the easier path to DB creds.**
            *   **FLAG{WEBSERVER_DB_CREDS_LEAKED}**.
        *   **Rabbit Hole:** Contact form goes nowhere. "Client Login" link points to `portal.targetcorp.com`. Outdated news articles.

    3.  **`portal-dmz` (portal.targetcorp.com / 172.16.10.105)**
        *   **Access:** HTTP/S. Potential for limited SSH if a vuln is found.
        *   **Purpose:** Employee login portal.
        *   **Clues/Flags:**
            *   **Vulnerability:** Login page is vulnerable to basic SQL Injection: Username: `' OR '1'='1 --`, Password: `any`. This logs you in as the first user in the DB (e.g., `admin`).
            *   The admin dashboard (visible after SQLi login) shows system status and lists key internal servers: "File Server: fileserv.targetcorp.local (10.0.10.50)", "Database: db.targetcorp.local (10.0.10.200)".
            *   **FLAG{PORTAL_ACCESS_VIA_SQLI}**.
            *   *(Alternative Vuln):* Maybe a file upload vulnerability leading to webshell (harder path). If webshell gained: **FLAG{WEBSHELL_ON_PORTAL}**. Shell would be as `www-data`, limited user.
        *   **Rabbit Hole:** Password reset doesn't work. Pages for "Benefits", "HR Forms" require further login which isn't implemented/vulnerable.

    4.  **`db-internal` (db.targetcorp.local / 10.0.10.200)**
        *   **Access:** From `ssh-jump` (or other internal machines) using MySQL client and credentials `web_user:SimplePassw0rd` found via `web-dmz` leak or `tcpdump`.
        *   **Purpose:** Internal database server.
        *   **Clues/Flags:**
            *   Database `targetcorp_db`: Table `employees` has usernames, emails, job titles (useful for guessing/phishing if that were allowed). Table `projects` explicitly mentions "Project Griffin" is hosted on `dev-wiki.targetcorp.local` (10.0.10.150). Table `portal_users` contains password hashes for portal users (could try cracking `admin` hash?). Table `ghost_activity_log` shows 0xGhost's internal VPN IP accessing `ssh-jump`, `fileserv`, and attempting connection to `qec-sim` just before logs stop.
            *   **FLAG{DB_ACCESS_PROJECT_GRIFFIN_MENTIONED}**.
        *   **Rabbit Hole:** Multiple other databases (`test_db`, `backup_db`) with junk data. Large log tables unrelated to the main objective.

    5.  **`fileserv` (fileserv.targetcorp.local / 10.0.10.50)**
        *   **Access:** From `ssh-jump` or other internal machines using SMB client (`smbclient`, Windows Explorer). Allows anonymous listing OR requires authentication (e.g., `ghost:password123` if found/cracked from KeePass).
        *   **Purpose:** Internal file sharing.
        *   **Clues/Flags:**
            *   Share `Public`: Contains general documents, maybe an outdated network map diagram.
            *   Share `HR_Shared`: Contains `employee_roster.xlsx`. Maybe accessible by any authenticated user.
            *   Share `ghost_data`: Accessible only by `ghost`. Contains `research_fragment.txt`: "Griffin details must be on the dev wiki (dev-wiki.targetcorp.local). Found potential creds from an old commit: `dev_user:WikiPa55!`. Need to verify."
            *   **FLAG{FILESERV_ACCESS_DEVWIKI_CREDS}**.
        *   **Rabbit Hole:** Share `Dev_Builds` full of old compiled binaries. Share `Marketing_Assets` full of images/videos. Access denied messages for shares like `Admin_Backups`.

    6.  **`dev-wiki` (dev-wiki.targetcorp.local / 10.0.10.150)**
        *   **Access:** HTTP/S from internal network. Login using `dev_user:WikiPa55!` found on `fileserv`. Potentially SSH access later.
        *   **Purpose:** Internal Wiki for developers.
        *   **Clues/Flags:**
            *   **Wiki Content:** Page "Project Griffin" describes the project as an "Advanced Simulation Core". Mentions it runs on dedicated hardware simulated by `qec-sim.targetcorp.internal (10.0.50.50)`. *Crucially, it notes this server is on a separate, firewalled network segment.* Page "Deployment Procedures" contains an accidentally pasted **SSH private key (`id_rsa_svc_deploy`)** for the `svc_deploy` user, intended for deploying code *to qec-sim*.
            *   *(Alternative Vuln):* The wiki software itself might have a known CVE (e.g., plugin vulnerability) allowing RCE, gaining a shell as the web user (`www-data` or similar). This shell could find the SSH key in config files.
            *   **Firewall Rule Trigger:** Finding the `svc_deploy` key and submitting **FLAG{SVC_DEPLOY_SSH_KEY_FOUND}** triggers the Director: a new message appears (`/home/ghost/messages/zf_msg_03.txt` on jumpbox?) "Good find. Opening a pinhole in the firewall from jumpbox (172.16.10.5) to qec-sim (10.0.50.50) on port 22 only. Be careful in there."
            *   **FLAG{WIKI_ACCESS_GRIFFIN_DETAILS}**.
        *   **Rabbit Hole:** Many outdated pages, broken links. Discussions about features never implemented. Internal blog posts about company picnics.

    7.  **`qec-sim` (qec-sim.targetcorp.internal / 10.0.50.50)**
        *   **Access:** From `ssh-jump` *only after firewall rule is opened by Director*. SSH as `svc_deploy` using the private key found on `dev-wiki`.
        *   **Purpose:** Secure simulation server for the core of Project Griffin. Minimal installation.
        *   **Privilege Escalation:** User `svc_deploy` is restricted. Need root.
            *   **Method 1 (SUID):** `find / -perm -4000 -type f 2>/dev/null` reveals a custom SUID binary `/usr/local/bin/qec_control`. It might have a command injection vulnerability or read arbitrary files as root.
            *   **Method 2 (Kernel Exploit):** `uname -a` shows an old, vulnerable kernel version. Player needs to find/use an appropriate kernel exploit (e.g., Dirty COW).
            *   **Method 3 (Password in Config):** `/opt/qec/config.xml` (readable by `svc_deploy`) contains `<root_password>SuperSecureRootPass1!</root_password>` allowing `su`.
        *   **Clues/Flags (As Root):**
            *   `/root/ghost_warning.txt`: Note from Canary: "Ghost - They know. Internal sec flagged your access here. I tried to mask it. The final payload package is in `/opt/qec/payload/final_package.enc`. Decryption key relates to our first agreed signal ('DeltaCharlie'?). Get it and get out. I can't help further. -C". **FLAG{QEC_ROOT_ACCESS_GHOST_WARNING}**.
            *   `/opt/qec/payload/final_package.enc`: The encrypted file 0xGhost was after. **FLAG{FINAL_PAYLOAD_PACKAGE_FOUND}**.
            *   `/var/log/secure` or `auth.log`: Shows `svc_deploy` logins, failed root login attempts, successful root login (via chosen privesc method), and *before that*, shows 0xGhost's internal IP successfully logging in as root, then abrupt disconnection, followed by scans from internal security IPs (e.g., 10.0.1.5).

**Phase 3: The Revelation (Decrypting the Payload)**

*   **Action:** Player needs to get `final_package.enc` off `qec-sim` (back to `ssh-jump`, then maybe SCP/HTTP out via `web-dmz` if egress is allowed, or just analyze on `ssh-jump`).
*   **Decryption:** The key hint was "DeltaCharlie" (from Canary email via Ghost's machine & warning note). Player needs to use `openssl` or similar tool to decrypt the file, likely AES encrypted: `openssl enc -d -aes-256-cbc -in final_package.enc -out final_package.txt -k DeltaCharlie` (or similar syntax depending on how it was encrypted).
*   **The Truth:** `final_package.txt` contains 0xGhost's final report. Project Griffin isn't just a simulation; it's a nascent AI core designed by TargetCorp to automate cyber warfare, capable of finding zero-days and deploying payloads autonomously. 0xGhost realised the catastrophic potential if it fell into the wrong hands or went rogue. He believed TargetCorp was about to sell it or unleash it. The file contains technical details, ethical concerns, and the final flag: **FLAG{PROJECT_GRIFFIN_UNCOVERED_AI_DANGER}**.
*   **Conclusion:** Submitting the final flag triggers the Director one last time. A file `zer0frame_final.txt` appears: "Impressive work. You got further than Ghost did before they caught him. TargetCorp internal security snagged him right after he accessed QEC-Sim; he's likely black-bagged. Your findings on Griffin... troubling. Valuable. You're in Nu11Division. Lay low. New assignment soon. -ZF"

This provides a detailed path with interwoven narrative, technical challenges, clues, red herrings, and clear progression milestones marked by flags, all manageable by an autonomous Director system.