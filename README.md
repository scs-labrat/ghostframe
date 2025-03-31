![](ghostframe.png) 
# GhostFrame CTF: Automated Setup

This repository contains the automated setup script (`master_deploy_ghostframe.sh`) for the GhostFrame RPG CTF environment. This is a narrative-driven hacking challenge where the player simulates analyzing the compromised machine of a hacker named "0xGhost" to uncover clues and infiltrate a target network ("TargetCorp").

**Uniquely, this script modifies the host Kali Linux system it is run on to *become* the simulated "0xGhost" machine.** The target network and support services are then deployed using Docker and Docker Compose on the same host.

---

## ☢️ HIGH RISK WARNING ☢️

> **THIS SCRIPT IS DANGEROUS AND MAKES SIGNIFICANT, POTENTIALLY IRREVERSIBLE CHANGES TO THE HOST OPERATING SYSTEM.**
>
> *   It **MUST** be run with `sudo` privileges.
> *   It **WILL** install packages, create users (`ghost`), modify system files, create numerous files and directories in `/home/ghost/`, alter shell history, and deploy Docker containers.
> *   It is **DESIGNED EXPLICITELY FOR A FRESH, DEDICATED, DISPOSABLE KALI LINUX INSTALLATION** (preferably a Virtual Machine that you can snapshot and easily revert or delete).
> *   **DO NOT RUN THIS SCRIPT ON YOUR PRIMARY MACHINE, A SYSTEM WITH IMPORTANT DATA, OR ANY NON-KALI LINUX SYSTEM.**
> *   The creators assume **NO RESPONSIBILITY** for any damage caused by running this script. **USE AT YOUR OWN EXTREME RISK.**

---

## Prerequisites

Before running the `master_deploy_ghostframe.sh` script, ensure the following are installed and configured on your **dedicated Kali Linux system**:

1.  **Operating System:** Kali Linux (tested on recent versions, e.g., 2023.x, 2024.x).
2.  **Root Access:** You must be able to run commands with `sudo`.
3.  **Internet Connection:** Required during setup to download packages and Docker images.
4.  **Core System Utilities:** `sudo`, `bash`, standard coreutils (`apt`, `dpkg`, `cat`, `cp`, `chmod`, `mkdir`, `rm`, `echo`, `base64`, `fallocate`, etc.) - *These should be present by default on Kali.*
5.  **Docker:**
    *   `docker`: The Docker engine itself.
    *   `docker-compose`: The tool for defining and running multi-container Docker applications (v1 or v2 syntax).
    *   **Installation:**
        ```bash
        sudo apt update
        sudo apt install -y docker.io docker-compose
        sudo systemctl start docker
        sudo systemctl enable docker
        # Optional: Add your regular user to the docker group to avoid using sudo for docker commands later
        # sudo usermod -aG docker $USER
        # newgrp docker # Apply group change in current shell (or log out/in)
        ```
    *   **Verification:** Ensure the Docker service is running (`sudo systemctl status docker`).
6.  **OpenVPN Client:**
    *   `openvpn`: The client needed to connect to the CTF network from the host machine.
    *   **Installation:**
        ```bash
        sudo apt install -y openvpn
        ```
7.  **Cryptography & Keys:**
    *   `openssl`: For encryption/decryption tasks and certificate generation.
    *   `ssh-keygen`: For generating SSH keys.
    *   **Installation:** Usually pre-installed on Kali. `sudo apt install -y openssl ssh` if missing.
8.  **Archiving:**
    *   `zip`: For creating the encrypted archive clue.
    *   **Installation:** `sudo apt install -y zip`
9.  **Steganography:**
    *   `steghide`: For hiding data within images.
    *   **Installation:** `sudo apt install -y steghide`
10. **Image Manipulation:**
    *   `imagemagick`: Provides the `convert` command for creating dummy images.
    *   **Installation:** `sudo apt install -y imagemagick`
11. **Build Tools:**
    *   `build-essential`: Needed for compiling the SUID binary during the Docker build phase.
    *   **Installation:** `sudo apt install -y build-essential`
12. **Other Utilities:**
    *   `git`: Simulates commands in shell history.
    *   `tree`: Useful utility sometimes used.
    *   `keepassxc`: (Optional) Mentioned for manual DB creation. Not installed by script.
    *   `apache2-utils`: Provides `htpasswd`.
    *   `curl`, `wget`, `jq`, `python3-pip`: General purpose tools potentially used or mentioned.
    *   `filezilla`: (Optional) GUI tool mentioned. Not installed by script.
    *   `proxychains`: Network proxy tool configured for `ghost`.
    *   `libimage-exiftool-perl`: Sometimes needed by image tools.
    *   `net-tools`, `dnsutils`, `netcat`: Common networking utilities.
    *   **Installation (Combined):**
        ```bash
        sudo apt install -y git tree apache2-utils curl wget jq python3-pip proxychains libimage-exiftool-perl net-tools dnsutils netcat
        ```

*Note: The master script includes `check_dep` functions that attempt to install missing dependencies via `apt`, but pre-installing them manually is recommended.*

---

## Setup Instructions

**ON YOUR DEDICATED, DISPOSABLE KALI VM:**

1.  **Clone Repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
2.  **Review Script (Recommended):** Understand what `master_deploy_ghostframe.sh` does before running it.
3.  **Prepare Optional Resources:** If you have custom vulnerable PHP code for the portal, place `index.php`, `dashboard.php`, and `logout.php` inside a directory named `resources/portal/` within the cloned repository directory. Otherwise, the script will create dummy files.
4.  **Make Executable:**
    ```bash
    chmod +x master_deploy_ghostframe.sh
    ```
5.  **Run with Sudo:**
    ```bash
    sudo ./master_deploy_ghostframe.sh
    ```
6.  **Heed the Warning:** Read the confirmation prompt carefully. Type `y` and press Enter ONLY if you understand and accept the risks on this disposable system.
7.  **Wait:** The script will perform all setup steps:
    *   Install/check dependencies.
    *   Modify the host system (create `ghost` user, populate home directory).
    *   Set up the Docker project in `/opt/ghostframe_ctf/`.
    *   Generate keys and configurations.
    *   Generate VPN files (including `/home/ghost/player-ghostframe.ovpn`).
    *   Build Docker images.
    *   Start Docker containers via `docker-compose`.
8.  **Monitor:** Watch the script output for any errors, especially during package installation or Docker operations.

---

## Gameplay Instructions

1.  **Log In as Ghost:** Once the setup script completes successfully, **log out** of your current Kali session and **log back in** using the username `ghost` and the password `password123`. This ensures you are operating within the fully configured "Ghost environment".
2.  **Connect to VPN:** Open a terminal *as the `ghost` user*. Find the OpenVPN client configuration file in your home directory (`~/player-ghostframe.ovpn`). Connect using:
    ```bash
    sudo openvpn --config ~/player-ghostframe.ovpn --daemon
    ```
    Enter the `ghost` user password (`password123`) when prompted for `sudo`. The `--daemon` flag runs it in the background. Verify connection (`ip a show tun0`).
3.  **Explore Ghost's Machine:** Your current environment *is* the simulated compromised machine. Start exploring `/home/ghost/`. Look through:
    *   Notes (`~/Notes`, `~/Documents`)
    *   Shell History (`history` command or `~/.bash_history`)
    *   Emails (`~/Mail`)
    *   Configs (`~/.ssh/config`, `~/.proxychains/proxychains.conf`)
    *   Downloads (`~/Downloads`)
    *   Pictures (`~/Pictures`)
    *   Trash (`~/.local/share/Trash`)
4.  **Analyze Clues:** Find password hints, target IP addresses, SSH keys (`~/.ssh/`), VPN details, the flag submission method, project names ("Chimera", "Griffin"), and narrative context. Use standard Kali tools for forensics (strings, file, binwalk, steghide, zip password crackers if needed, KeePassXC for the `.kdbx` file).
5.  **Infiltrate Target Network:** Use the clues (keys, IPs, vulnerabilities described) and the active VPN connection to access and exploit the services running in the Docker containers (ssh-jump, web-dmz, portal-dmz, etc.). The target IPs are defined in the setup script and referenced in clues.
6.  **Submit Flags:** As you find flags (strings formatted like `FLAG{...}`), submit them to the automated "Director" service via netcat:
    ```bash
    nc 192.168.200.2 9999
    ```
    Paste the flag and press Enter. You can also use the alias defined in `~/.ssh/config`:
    ```bash
    nc director 9999
    ```
    The Director will respond with `VALID FLAG ACCEPTED`, `FLAG ALREADY SUBMITTED`, or `INVALID FLAG`. Valid flags may trigger events in the environment (like opening firewall access).

---

## Docker Environment Management

The target network runs inside Docker containers managed by Docker Compose. You may need these commands (run from `/opt/ghostframe_ctf/` with `sudo`):

*   **Stop Environment:** `sudo docker-compose down`
*   **Stop & Remove Data Volumes (DB data, etc.):** `sudo docker-compose down -v`
*   **Start Environment:** `sudo docker-compose up -d`
*   **View Container Status:** `sudo docker-compose ps`
*   **View Logs (e.g., for the director):** `sudo docker-compose logs -f flag_director`
*   **Restart a Service:** `sudo docker-compose restart <service_name>` (e.g., `ssh-jump`)

---

## Troubleshooting

*   **Docker Service:** Ensure the Docker daemon is running (`sudo systemctl status docker`).
*   **Port Conflicts:** The VPN uses UDP port 1194. Ensure nothing else on your host is using this port. Web services use ports 80/443 within Docker, but aren't exposed directly to the host by default.
*   **Permissions:** Docker setup can sometimes run into permission issues, especially related to `/var/run/docker.sock`. Running docker-compose with `sudo` usually resolves this for the setup phase. Volume mounts defined in `docker-compose.yml` should handle internal container permissions.
*   **Network Issues:** Verify the VPN connects successfully (`ip a show tun0`). Use `ping` or `nmap` from the host (acting as Ghost) to test connectivity to container IPs (e.g., `ping 172.16.10.5`) *after* the VPN is up. Ensure Docker networks were created (`sudo docker network ls`).
*   **Build Failures:** If `docker-compose build` fails, check the output for errors in the Dockerfiles (missing packages, command failures). Ensure `build-essential` is installed on the host.

---

## Disclaimer

This project is intended for educational and recreational purposes within a controlled environment. Modifying your host system is inherently risky. The authors provide this script "as is" without warranty of any kind. Use responsibly and ethically.