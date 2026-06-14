# 🔍 System Debug & Security Audit Script

A comprehensive system debugging tool with network device discovery, anomaly detection, and security auditing capabilities.

## Features

| Category | Checks |
|----------|--------|
| **Network** | Active connections, listening ports, ARP cache, DNS config, firewall status |
| **Security** | SUID binaries, SSH keys, cron jobs, sudoers, world-writable files |
| **System** | CPU/Memory/Disk usage, top processes, load average, kernel messages |
| **Threat Detection** | Suspicious ports, ARP spoofing, hidden files, processes from /tmp |


Requirements
OS: Linux (Ubuntu, Debian, RHEL, Arch) or macOS

Privileges: Root/sudo recommended for full access

Dependencies: ss, ip, arp, lsof (installed by default on most systems)


What It Detects

🚨 Suspicious listening ports (backdoors, trojans)

🚨 Processes running from /tmp or /dev/shm

🚨 ARP spoofing attempts

🚨 Unauthorized SUID/SGID binaries

🚨 Suspicious cron jobs

🚨 World-writable files

🚨 Hidden executables in home directories

🚨 Passwordless sudo rules

🚨 High CPU/memory usage

🚨 Failed login attempts (brute force)




## Alternative: Create a Collapsible Gallery


```markdown
<details>
<summary>📸 Click to view screenshots</summary>

| Section | Screenshot |
|---------|------------|
| System Overview | ![Overview](images/overview.png) |
| Network Analysis | ![Network](images/network.png) |
| Listening Ports | ![Listening](images/listening.png) |
| Firewall Status | ![Firewall](images/firewall.png) |
| Process Monitor | ![Process](images/process.png) |
| Login History | ![History](images/history.png) |
| Cron Jobs | ![Crontab](images/crontab.png) |

</details>





Disclaimer
This script performs read-only system inspection. It does not modify any files. Run with root privileges for complete access to all system information.



### 5. Create a `.gitignore`

```bash
nano .gitignore

# Logs
*.log

# OS files
.DS_Store
Thumbs.db

# Editor files
.swp
.swo
*~




## Quick Start

```bash
# Clone the repository
git clone https://github.com/Kal1010101/sysdebug.git
cd sysdebug

# Run as root (required for full access)
sudo ./sysdebug.sh

# Quick mode (skips slow checks)
sudo ./sysdebug.sh --quick

# Plain text output (no colors)
sudo ./sysdebug.sh --no-color
