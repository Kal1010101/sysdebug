#!/usr/bin/env bash
#
# =============================================================================
#  SYSTEM DEBUG & SECURITY AUDIT SCRIPT
#  Network Device Discovery | Anomaly Detection | Security Hardening Audit
# =============================================================================
#  Version: 1.0
#  Author: Kal1010101
#  Usage: sudo ./sysdebug.sh [--no-color] [--quick]
# =============================================================================

# Color definitions
if [[ -t 1 ]] && [[ -z "$NO_COLOR" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    NC='\033[0m'
    BOLD='\033[1m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; NC=''; BOLD=''
fi

# Abnormality counters
TOTAL_ABNORMALITIES=0
ABNORMALITIES=()

# Configurable thresholds (override via environment if needed)
SSH_KEY_WARNING_THRESHOLD=${SSH_KEY_WARNING_THRESHOLD:-3}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get OS type
OS_TYPE="$(uname -s)"

# Known legitimate ports for privacy tools (WHITELIST)
declare -A LEGIT_PORTS=(
    ["6668"]="i2pd-irc"
    ["6667"]="i2pd-irc-alt"
    ["6669"]="i2pd-irc-alt"
    ["4444"]="i2pd-http"
    ["4445"]="i2pd-https"
    ["4447"]="i2pd-socks"
    ["7070"]="i2pd-console"
    ["7656"]="i2pd-sam"
    ["7654"]="i2p-i2cp"
    ["7657"]="i2p-console"
    ["9050"]="tor-socks"
    ["9051"]="tor-control"
    ["9150"]="tor-browser"
    ["8118"]="privoxy"
    ["2222"]="ssh-alt"
)

print_header() {
    echo -e "\n${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║  🔍 SYSTEM DEBUG - $(date)  ║${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${NC}\n"
}

print_section() {
    echo -e "\n${BOLD}${YELLOW}$1${NC}"
    echo -e "${BLUE}──────────────────────────────────────────────────────────────${NC}"
}

add_abnormality() {
    TOTAL_ABNORMALITIES=$((TOTAL_ABNORMALITIES + 1))
    ABNORMALITIES+=("$1")
    echo -e "${RED}⚠️  ABNORMALITY DETECTED: $1${NC}"
}

network_connections() {
    print_section "🔌 ACTIVE NETWORK CONNECTIONS"

    # Truly suspicious ports (actual malware/backdoor ports)
    truly_suspicious=("31337" "12345" "54321" "27374" "6666" "6665" "1234" "9999")

    # Active Internet connections
    if command_exists ss; then
        echo -e "${GREEN}Established Connections:${NC}"
        while read line; do
            echo "  $line"
            # Check for connections to public internet
            if [[ $line =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+: ]]; then
                ip=$(echo $line | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1)
                if [[ ! $ip =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.) ]]; then
                    echo -e "    ${YELLOW}(Public internet connection)${NC}"
                fi
            fi
        done < <(ss -tunap 2>/dev/null | grep ESTAB | head -20)

        echo -e "\n${GREEN}Listening Ports:${NC}"
        while read line; do
            port=$(echo "$line" | grep -oE ':[0-9]+' | head -1 | cut -d':' -f2)
            echo "  $line"

            # Check if it's a known legitimate port
            if [[ -n "$port" ]] && [[ -n "${LEGIT_PORTS[$port]}" ]]; then
                echo -e "    ${GREEN}✓ Legitimate ${LEGIT_PORTS[$port]} port${NC}"
            # Check truly suspicious ports list
            elif [[ " ${truly_suspicious[@]} " =~ " ${port} " ]]; then
                add_abnormality "Suspicious port $port listening (possible backdoor/trojan)"
            # Check for high ports (above 49152 - dynamic/private ports)
            elif [[ -n "$port" ]] && [[ "$port" -gt 49152 ]]; then
                if command_exists lsof; then
                    proc_name=$(lsof -i :"$port" -sTCP:LISTEN -Fc 2>/dev/null | head -1 | cut -c2-)
                    if [[ -n "$proc_name" ]]; then
                        echo -e "    ${YELLOW}(High port - used by: $proc_name)${NC}"
                    else
                        echo -e "    ${YELLOW}(High port number - verify service)${NC}"
                    fi
                else
                    echo -e "    ${YELLOW}(High port number - verify service)${NC}"
                fi
            fi
        done < <(ss -tlnp 2>/dev/null | grep LISTEN)
    elif command_exists netstat; then
        echo -e "${GREEN}Established Connections:${NC}"
        netstat -tunap 2>/dev/null | grep ESTABLISHED | head -20

        echo -e "\n${GREEN}Listening Ports:${NC}"
        netstat -tlnp 2>/dev/null | grep LISTEN | head -20
    fi
}

network_devices() {
    print_section "🌐 NETWORK DEVICES & CONNECTIONS"

    # Local IP Addresses
    echo -e "${GREEN}Local IP Addresses:${NC}"
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        if command_exists ifconfig; then
            ifconfig | grep -E 'inet.[0-9]' | grep -v '127.0.0.1' | awk '{print $2}' | while read ip; do
                echo "  • $ip"
            done
        fi
    else
        if command_exists ip; then
            ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | while read ip; do
                if [[ $ip =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
                    echo -e "  • $ip ${GREEN}(Private IP)${NC}"
                else
                    echo -e "  • $ip ${YELLOW}(Public IP - exposed to internet)${NC}"
                fi
            done
        elif command_exists ifconfig; then
            ifconfig | grep -E 'inet.[0-9]' | grep -v '127.0.0.1' | awk '{print $2}' | while read ip; do
                echo "  • $ip"
            done
        fi
    fi

    # Network Interfaces
    echo -e "\n${GREEN}Network Interfaces:${NC}"
    if command_exists ip; then
        while read iface_line; do
            iface_name=$(echo "$iface_line" | awk -F': ' '{print $2}' | awk '{print $1}')
            echo "  • $iface_name"
            if ip link show "$iface_name" 2>/dev/null | grep -q "PROMISC"; then
                add_abnormality "Interface $iface_name is in PROMISCUOUS mode (possible packet sniffing)"
            fi
        done < <(ip link show | grep -E '^[0-9]')
    elif command_exists ifconfig; then
        ifconfig -a 2>/dev/null | grep -E '^[a-z0-9]' | awk '{print "  • " $1}'
    fi

    # ARP Cache (Connected Devices)
    echo -e "\n${GREEN}Connected Devices (ARP Cache):${NC}"
    if command_exists arp; then
        while read line; do
            if [[ $line =~ "incomplete" ]]; then
                echo -e "  ${YELLOW}$line (Incomplete - possible scan)${NC}"
            else
                echo "  $line"
            fi
        done < <(arp -a 2>/dev/null | head -15)
    elif [ -f /proc/net/arp ]; then
        while read line; do
            ip=$(echo "$line" | awk '{print $1}')
            hw=$(echo "$line" | awk '{print $4}')
            if [[ "$hw" == "00:00:00:00:00:00" ]]; then
                add_abnormality "Incomplete ARP entry for $ip (possible network scan)"
            fi
            echo "  $ip - $hw"
        done < <(tail -n +2 /proc/net/arp | head -10)

        # Check for ARP spoofing
        echo -e "\n${GREEN}Checking for ARP Spoofing:${NC}"
        while read ip; do
            macs=$(grep "$ip " /proc/net/arp | awk '{print $4}' | sort -u | grep -v "^00:00:00:00:00:00$")
            mac_count=$(echo "$macs" | grep -c .)
            if [[ "$mac_count" -gt 1 ]]; then
                mac_list=$(echo "$macs" | tr '\n' ' ')
                add_abnormality "Possible ARP spoofing: IP $ip resolves to multiple MACs: $mac_list"
            fi
        done < <(tail -n +2 /proc/net/arp | awk '{print $1}' | sort -u)
    fi
}

firewall_status() {
    print_section "🛡️ FIREWALL STATUS"

    if command_exists iptables; then
        if sudo iptables -L 2>/dev/null | grep -q "Chain"; then
            rules=$(sudo iptables -L | grep -c "ACCEPT\|DROP\|REJECT")
            echo -e "${GREEN}✅ iptables active ($rules rules)${NC}"

            if sudo iptables -L INPUT -n 2>/dev/null | grep -q "ACCEPT.*0.0.0.0/0"; then
                add_abnormality "Firewall allows ALL incoming connections (INPUT chain ACCEPT policy)"
            fi
        else
            echo -e "${RED}❌ iptables not configured or inactive${NC}"
            add_abnormality "No iptables firewall rules detected"
        fi
    fi

    if command_exists ufw; then
        ufw status | head -5
    fi

    if command_exists firewall-cmd; then
        firewall-cmd --state 2>/dev/null
    fi
}

dns_config() {
    print_section "📖 DNS CONFIGURATION"

    if [ -f /etc/resolv.conf ]; then
        echo -e "${GREEN}DNS Servers:${NC}"
        grep "nameserver" /etc/resolv.conf | while read line; do
            echo "  $line"
            dns_ip=$(echo $line | awk '{print $2}')
            if [[ "$dns_ip" =~ ^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|9\.9\.9\.9)$ ]]; then
                echo -e "    ${GREEN}(Public DNS)${NC}"
            elif [[ "$dns_ip" =~ ^(208\.67\.222\.222|208\.67\.220\.220)$ ]]; then
                echo -e "    ${GREEN}(OpenDNS)${NC}"
            elif [[ ! "$dns_ip" =~ ^(192\.168\.|10\.|172\.) ]]; then
                echo -e "    ${YELLOW}(External DNS - verify)${NC}"
            fi
        done

        if grep -q "127.0.0.1" /etc/resolv.conf && ! ss -lnup 2>/dev/null | grep -q ':53\b'; then
            add_abnormality "DNS points to localhost but no local DNS listener found (possible DNS hijacking)"
        fi
    fi

    if [ -f /etc/hosts ]; then
        suspicious_hosts=$(grep -E "127\.0\.0\.1.*(facebook|google|youtube|twitter|bank|paypal)" /etc/hosts | wc -l)
        if [[ $suspicious_hosts -gt 0 ]]; then
            add_abnormality "Hosts file contains redirections for common sites (possible malware)"
        fi
    fi
}

system_overview() {
    print_section "📋 SYSTEM OVERVIEW"

    hostname=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
    kernel=$(uname -r 2>/dev/null || echo "unknown")

    if [[ "$hostname" =~ ^(localhost|ubuntu|debian|fedora|centos|arch)$ ]] || [[ "$hostname" =~ ^[a-f0-9]{12}$ ]]; then
        add_abnormality "Default/generic hostname detected: $hostname"
    fi

    if [[ "$OS_TYPE" == "Linux" ]]; then
        if [ -f /etc/os-release ]; then
            os_name=$(grep "^PRETTY_NAME" /etc/os-release | cut -d'"' -f2)
        else
            os_name="Linux"
        fi
    elif [[ "$OS_TYPE" == "Darwin" ]]; then
        os_name="macOS $(sw_vers -productVersion 2>/dev/null)"
    else
        os_name="$OS_TYPE"
    fi

    uptime_info=$(uptime | awk -F'up' '{print $2}' | awk -F',' '{print $1}' | xargs)
    users=$(who | wc -l | xargs)

    printf "${GREEN}Hostname:${NC} %-25s ${GREEN}OS:${NC} %s\n" "$hostname" "$os_name"
    printf "${GREEN}Kernel:${NC} %-25s ${GREEN}Uptime:${NC} %s\n" "$kernel" "$uptime_info"
    printf "${GREEN}Users:${NC} %-25s\n" "$users"
}

memory_usage() {
    print_section "💾 MEMORY USAGE"

    if command_exists free; then
        while read line; do
            if [[ $line == *"Mem:"* ]]; then
                used=$(echo "$line" | awk '{print $3}')
                total=$(echo "$line" | awk '{print $2}')
                if command_exists bc && [[ -n "$used" ]] && [[ -n "$total" ]] && [[ "$total" != "0" ]]; then
                    usage_percent=$(echo "scale=2; $used / $total * 100" | bc 2>/dev/null)
                    if (( $(echo "$usage_percent > 90" | bc -l 2>/dev/null) )); then
                        echo -e "${RED}$line (${usage_percent}% used)${NC}"
                        add_abnormality "Memory usage critical: ${usage_percent}%"
                    elif (( $(echo "$usage_percent > 75" | bc -l 2>/dev/null) )); then
                        echo -e "${YELLOW}$line (${usage_percent}% used)${NC}"
                    else
                        echo -e "${GREEN}$line (${usage_percent}% used)${NC}"
                    fi
                else
                    echo -e "$line"
                fi
            else
                echo -e "$line"
            fi
        done < <(free -m | awk 'NR==1{printf "%-10s %-8s %-8s %-8s %-8s %-8s\n", $1, $2, $3, $4, $5, $6}
                       NR==2{printf "%-10s %-8s %-8s %-8s %-8s %-8s\n", $1, $2, $3, $4, $5, $6}')
    fi
}

disk_usage() {
    print_section "💿 DISK USAGE"

    if command_exists df; then
        while read line; do
            if [[ $line == *"Filesystem"* ]]; then
                echo -e "${CYAN}$line${NC}"
            elif [[ $line == *"100%"* ]] || [[ $line == *"9"?"%"* ]]; then
                echo -e "${RED}$line${NC}"
                add_abnormality "Disk partition nearly full: $line"
            elif [[ $line == *"8"?"%"* ]] || [[ $line == *"7"?"%"* ]]; then
                echo -e "${YELLOW}$line${NC}"
            else
                echo -e "${GREEN}$line${NC}"
            fi
        done < <(df -h 2>/dev/null | grep -E "^(/dev/|Filesystem|/)" | awk '{printf "%-20s %-8s %-8s %-8s %-6s %s\n", $1, $2, $3, $4, $5, $6}')
    fi
}

top_processes() {
    print_section "🔥 TOP CPU PROCESSES"

    if command_exists ps; then
        if [[ "$OS_TYPE" == "Darwin" ]] || [[ "$OS_TYPE" == "FreeBSD" ]]; then
            while read line; do
                pid=$(echo "$line" | awk '{print $2}')
                cpu=$(echo "$line" | awk '{print $3}')
                cmd=$(echo "$line" | awk '{print $11}')
                echo -e "$line"

                if command_exists bc && [[ $cpu =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( $(echo "$cpu > 50" | bc -l 2>/dev/null) )); then
                    # Exclude ps itself and the debug script — they spike briefly during collection
                    if [[ "$cmd" != "ps" ]] && [[ "$cmd" != "bash" ]]; then
                        add_abnormality "Process $pid ($cmd) using >50% CPU"
                    fi
                fi
            done < <(ps auxr | head -11 | tail -10)
        else
            while read line; do
                pid=$(echo "$line" | awk '{print $2}')
                cpu=$(echo "$line" | awk '{print $3}')
                cmd=$(echo "$line" | awk '{print $11}')
                echo -e "$line"

                if command_exists bc && [[ $cpu =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( $(echo "$cpu > 50" | bc -l 2>/dev/null) )); then
                    # Exclude ps itself and the debug script — they spike briefly during collection
                    if [[ "$cmd" != "ps" ]] && [[ "$cmd" != "bash" ]]; then
                        add_abnormality "Process $pid ($cmd) using >50% CPU"
                    fi
                fi
            done < <(ps aux --sort=-%cpu 2>/dev/null | head -11 | tail -10)
        fi
    fi
}

load_average() {
    print_section "📈 LOAD AVERAGE"

    if command_exists uptime; then
        load=$(uptime | awk -F'load average:' '{print $2}' | xargs)

        if [[ "$OS_TYPE" == "Darwin" ]]; then
            cores=$(sysctl -n hw.ncpu 2>/dev/null)
        elif [[ "$OS_TYPE" == "Linux" ]]; then
            cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null)
        else
            cores="N/A"
        fi

        printf "${GREEN}Load Average (1,5,15 min):${NC} %s\n" "$load"
        printf "${GREEN}CPU Cores:${NC} %s\n" "$cores"

        if [[ "$cores" != "N/A" ]] && [[ "$cores" =~ ^[0-9]+$ ]] && command_exists bc; then
            load1=$(echo $load | awk -F', ' '{print $1}' | sed 's/ //g')
            if (( $(echo "$load1 > $cores * 1.5" | bc -l 2>/dev/null) )); then
                echo -e "${RED}⚠️  CRITICAL: High system load detected!${NC}"
                add_abnormality "System load critically high: $load1 (cores: $cores)"
            elif (( $(echo "$load1 > $cores" | bc -l 2>/dev/null) )); then
                echo -e "${YELLOW}⚠️  Warning: Moderate system load detected${NC}"
            fi
        fi
    fi
}

kernel_messages() {
    print_section "📌 KERNEL MESSAGES (last 10)"

    if command_exists dmesg; then
        while read line; do
            if [[ $line == *"error"* ]] || [[ $line == *"fail"* ]] || [[ $line == *"Error"* ]]; then
                echo -e "${RED}$line${NC}"
                add_abnormality "Error in kernel messages: $line"
            else
                echo -e "${WHITE}$line${NC}"
            fi
        done < <(dmesg -T 2>/dev/null | tail -10)
    fi
}

wifi_networks() {
    if command_exists iwconfig; then
        print_section "📡 WIFI INFORMATION"

        iwconfig 2>/dev/null | grep -E "ESSID|Mode|Frequency|Quality" | while read line; do
            echo "  $line"
        done
    fi
}

check_suid_binaries() {
    print_section "🔑 SUID/SGID BINARY AUDIT"

    echo -e "${GREEN}Scanning for SUID/SGID binaries...${NC}"
    # Exclude: /timeshift/ (backup snapshots of live system), /opt (browser sandboxes like chrome-sandbox are legitimate)
    local suspicious_paths=()
    while read -r file; do
        dir=$(dirname "$file")
        if [[ ! "$dir" =~ ^(/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib|/usr/libexec|/usr/local/bin|/usr/local/sbin|/opt) ]]; then
            echo -e "  ${RED}⚠️  Suspicious SUID/SGID: $file${NC}"
            add_abnormality "Suspicious SUID/SGID binary outside standard path: $file"
        else
            echo -e "  ${GREEN}✓ $file${NC}"
        fi
    done < <(find / -xdev -perm /6000 -type f 2>/dev/null | grep -v "^/timeshift/\|^/var/lib/containerd/\|^/var/lib/docker/\|^/var/lib/snapd/\|^/usr/share/code/")
}

check_crontabs() {
    print_section "⏰ CRONTAB INSPECTION (ALL USERS)"

    # System-wide cron files
    echo -e "${GREEN}System cron jobs:${NC}"
    for cronfile in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        if [ -f "$cronfile" ]; then
            entries=$(grep -v "^#\|^$" "$cronfile" 2>/dev/null)
            if [[ -n "$entries" ]]; then
                echo -e "  ${CYAN}[$cronfile]${NC}"
                while read -r entry; do
                    echo "    $entry"
                    # Flag lines that actually execute suspicious commands (not just check if tools exist with -x/-f)
                    if [[ "$entry" =~ (wget[[:space:]]+http|curl[[:space:]]+-[a-zA-Z]*[oO][[:space:]]|[[:space:]]/tmp/[^[:space:]]|[[:space:]]/dev/shm/[^[:space:]]|bash[[:space:]]+-i|nc[[:space:]]+-e|ncat[[:space:]]+-e|python[0-9.]*[[:space:]]+-c[[:space:]]|perl[[:space:]]+-e[[:space:]].*socket) ]]; then
                        add_abnormality "Suspicious cron entry in $cronfile: $entry"
                        echo -e "    ${RED}⚠️  Suspicious command detected!${NC}"
                    fi
                done <<< "$entries"
            fi
        fi
    done

    # Per-user crontabs
    echo -e "\n${GREEN}User crontabs:${NC}"
    while read -r user; do
        cron_out=$(crontab -u "$user" -l 2>/dev/null | grep -v "^#\|^$")
        if [[ -n "$cron_out" ]]; then
            echo -e "  ${CYAN}[$user]${NC}"
            while read -r entry; do
                echo "    $entry"
                if [[ "$entry" =~ (wget[[:space:]]+http|curl[[:space:]]+-[a-zA-Z]*[oO][[:space:]]|[[:space:]]/tmp/[^[:space:]]|[[:space:]]/dev/shm/[^[:space:]]|bash[[:space:]]+-i|nc[[:space:]]+-e|ncat[[:space:]]+-e|python[0-9.]*[[:space:]]+-c[[:space:]]|perl[[:space:]]+-e[[:space:]].*socket) ]]; then
                    add_abnormality "Suspicious cron entry for user $user: $entry"
                    echo -e "    ${RED}⚠️  Suspicious command detected!${NC}"
                fi
            done <<< "$cron_out"
        fi
    done < <(cut -f1 -d: /etc/passwd)
}

check_tmp_processes() {
    print_section "👻 PROCESSES RUNNING FROM SUSPICIOUS LOCATIONS"

    echo -e "${GREEN}Checking process binary locations...${NC}"
    found=0
    while read -r procpath; do
        if [ -L "$procpath" ]; then
            target=$(readlink -f "$procpath" 2>/dev/null)
            pid=$(echo "$procpath" | grep -oE '[0-9]+')
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 80)

            if [[ "$target" =~ ^(/tmp|/dev/shm|/var/tmp) ]] || [[ "$target" == *"(deleted)"* ]]; then
                echo -e "  ${RED}⚠️  PID $pid binary: $target${NC}"
                echo -e "     CMD: $cmdline"
                add_abnormality "Process PID $pid running from suspicious location: $target"
                found=1
            fi
        fi
    done < <(ls /proc/*/exe 2>/dev/null)

    # Also check /dev/shm and memfd (fileless malware)
    echo -e "\n${GREEN}Checking /dev/shm for executables:${NC}"
    while read -r f; do
        echo -e "  ${RED}⚠️  Executable in /dev/shm: $f${NC}"
        add_abnormality "Executable found in /dev/shm: $f"
        found=1
    done < <(find /dev/shm /run/shm 2>/dev/null -type f -executable)

    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✓ No suspicious processes found${NC}"
    fi
}

check_ssh_keys() {
    print_section "🔐 SSH AUTHORIZED KEYS AUDIT"

    echo -e "${GREEN}Scanning authorized_keys files...${NC}"
    found=0
    while read -r keyfile; do
        if [[ "$OS_TYPE" == "Darwin" ]]; then
            owner=$(stat -f '%Su' "$keyfile" 2>/dev/null)
        else
            owner=$(stat -c '%U' "$keyfile" 2>/dev/null)
        fi
        key_count=$(grep -c "ssh-" "$keyfile" 2>/dev/null)
        key_count=${key_count:-0}
        echo -e "  ${CYAN}$keyfile${NC} (owner: $owner, keys: $key_count)"

        if [[ "$key_count" -gt "$SSH_KEY_WARNING_THRESHOLD" ]]; then
            add_abnormality "Large number of SSH keys ($key_count) in $keyfile"
            echo -e "    ${YELLOW}⚠️  Unusually high number of keys${NC}"
        fi

        # Flag command= overrides and unusual options
        while read -r keyline; do
            if [[ "$keyline" =~ ^(command=|permitopen=|tunnel=) ]]; then
                echo -e "    ${YELLOW}⚠️  Restricted key with command override: ${keyline:0:60}...${NC}"
                add_abnormality "SSH key with command restriction in $keyfile (possible backdoor)"
            fi
        done < <(grep -v "^#\|^$" "$keyfile" 2>/dev/null)
        found=1
    done < <(find /home /root /etc/ssh 2>/dev/null -name "authorized_keys" -type f)

    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✓ No authorized_keys files found${NC}"
    fi
}

check_passwd_integrity() {
    print_section "👤 PASSWD & SUDOERS INTEGRITY"

    # Check for extra UID 0 accounts
    echo -e "${GREEN}UID 0 (root-equivalent) accounts:${NC}"
    found_uid0=0
    while read -r line; do
        uname=$(echo "$line" | cut -d: -f1)
        if [[ "$uname" != "root" ]]; then
            echo -e "  ${RED}⚠️  Non-root UID 0 account: $uname${NC}"
            add_abnormality "Unexpected UID 0 account found: $uname"
            found_uid0=1
        else
            echo -e "  ${GREEN}✓ $uname (expected)${NC}"
        fi
    done < <(awk -F: '($3 == 0) {print}' /etc/passwd)
    [[ $found_uid0 -eq 0 ]] && echo -e "  ${GREEN}✓ Only root has UID 0${NC}"

    # Check for accounts with no password (empty hash)
    echo -e "\n${GREEN}Accounts with no password:${NC}"
    found_nopass=0
    while read -r line; do
        uname=$(echo "$line" | cut -d: -f1)
        hash=$(echo "$line" | cut -d: -f2)
        if [[ "$hash" == "" ]] || [[ "$hash" == "::" ]]; then
            echo -e "  ${RED}⚠️  No password set for: $uname${NC}"
            add_abnormality "Account with no password: $uname"
            found_nopass=1
        fi
    done < <(cat /etc/shadow 2>/dev/null || awk -F: '{print $1":"$2}' /etc/passwd)
    [[ $found_nopass -eq 0 ]] && echo -e "  ${GREEN}✓ All accounts have passwords${NC}"

    # Sudoers check
    echo -e "\n${GREEN}Sudo privileges:${NC}"
    if [ -f /etc/sudoers ]; then
        while read -r line; do
            echo "  $line"
            # NOPASSWD: skip if it's a known safe system path (Mint/Ubuntu system tools)
            if [[ "$line" =~ NOPASSWD ]] && [[ ! "$line" =~ ^# ]]; then
                if [[ ! "$line" =~ (mintdrivers|mintupdate|mint-refresh-cache|dpkg_lock_check|kdesu_stub) ]]; then
                    echo -e "  ${YELLOW}⚠️  NOPASSWD sudo rule detected${NC}"
                    add_abnormality "Passwordless sudo rule: $line"
                fi
            fi
            # ALL=(ALL) ALL: skip standard %sudo and %admin groups — these are default on Ubuntu/Mint
            if [[ "$line" =~ ALL.*ALL.*ALL ]] && [[ ! "$line" =~ ^(root|#|%sudo|%admin) ]]; then
                add_abnormality "Unrestricted sudo ALL rule for non-root: $line"
                echo -e "  ${RED}⚠️  Unrestricted sudo ALL rule!${NC}"
            fi
        done < <(grep -v "^#\|^$" /etc/sudoers 2>/dev/null)
    fi
    # Also check sudoers.d
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            [ -f "$f" ] || continue
            echo -e "  ${CYAN}[sudoers.d: $(basename "$f")]${NC}"
            while read -r line; do
                echo "    $line"
                # Whitelist known Linux Mint system NOPASSWD rules and standard Defaults entries
                if [[ "$line" =~ NOPASSWD|ALL.*ALL ]]; then
                    if [[ ! "$line" =~ (mintdrivers|mintupdate|mint-refresh-cache|dpkg_lock_check|kdesu_stub|pwfeedback|use_pty) ]]; then
                        add_abnormality "Suspicious sudoers.d rule in $f: $line"
                        echo -e "    ${RED}⚠️  Suspicious rule!${NC}"
                    fi
                fi
            done < <(grep -v "^#\|^$" "$f" 2>/dev/null)
        done
    fi
}

check_recent_modifications() {
    print_section "📝 RECENTLY MODIFIED SYSTEM BINARIES"

    # Use the last apt/dpkg run as baseline — binaries newer than that are suspicious.
    # Fall back to 24 hours if no apt log found, to avoid mass false positives after updates.
    local baseline=""
    local baseline_desc=""

    if [ -f /var/log/apt/history.log ]; then
        # Get timestamp of last apt install/upgrade operation
        last_apt=$(grep "^End-Date:" /var/log/apt/history.log | tail -1 | awk '{print $2, $3}')
        if [[ -n "$last_apt" ]]; then
            baseline_desc="since last apt operation ($last_apt)"
            # Find binaries modified more recently than the apt log itself
            baseline="-newer /var/log/apt/history.log"
        fi
    fi

    if [[ -z "$baseline" ]]; then
        baseline_desc="in last 24 hours"
        baseline="-mmin -1440"
    fi

    # Build a deduplicated list of search dirs (handles merged-usr systems
    # where /bin -> /usr/bin and /sbin -> /usr/sbin, which would otherwise
    # cause the same binary to be reported twice)
    local search_dirs=()
    for d in /usr/bin /usr/sbin /bin /sbin; do
        [ -d "$d" ] || continue
        real=$(readlink -f "$d" 2>/dev/null || echo "$d")
        skip=0
        for existing in "${search_dirs[@]}"; do
            [[ "$existing" == "$real" ]] && skip=1 && break
        done
        [[ $skip -eq 0 ]] && search_dirs+=("$real")
    done

    echo -e "${GREEN}Checking for modified binaries $baseline_desc...${NC}"
    found=0
    while read -r file; do
        if [[ "$OS_TYPE" == "Darwin" ]]; then
            mod_time=$(stat -f '%Sm' "$file" 2>/dev/null)
        else
            mod_time=$(stat -c '%y' "$file" 2>/dev/null | cut -d'.' -f1)
        fi
        echo -e "  ${RED}⚠️  Modified: $file ($mod_time)${NC}"
        add_abnormality "System binary recently modified: $file"
        found=1
    done < <(find "${search_dirs[@]}" $baseline -type f 2>/dev/null)

    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✓ No recently modified system binaries${NC}"
    fi
}

check_login_history() {
    print_section "🕵️  LOGIN HISTORY & ANOMALIES"

    echo -e "${GREEN}Recent successful logins:${NC}"
    while read -r line; do
        # Flag logins from public IPs
        ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [[ -n "$ip" ]] && [[ ! "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.) ]]; then
            echo -e "  ${YELLOW}⚠️  Login from public IP: $line${NC}"
            add_abnormality "Login from public IP detected: $ip"
        else
            echo "  $line"
        fi
    done < <(last -n 15 2>/dev/null | head -15)

    # Failed logins (brute force indicator)
    echo -e "\n${GREEN}Recent failed logins:${NC}"
    if command_exists lastb; then
        fail_count=$(lastb -n 20 2>/dev/null | grep -c "^[a-zA-Z]")
        fail_count=${fail_count:-0}
    else
        fail_count=0
    fi
    if [[ "$fail_count" -gt 10 ]]; then
        echo -e "  ${RED}⚠️  High number of failed logins: $fail_count (possible brute force)${NC}"
        add_abnormality "High failed login count: $fail_count attempts"
        lastb -n 10 2>/dev/null | head -10 | while read -r line; do
            echo "  $line"
        done
    elif [[ "$fail_count" -gt 0 ]]; then
        echo -e "  ${YELLOW}$fail_count failed attempts (last 20 records)${NC}"
        lastb -n 5 2>/dev/null | head -5 | while read -r line; do
            echo "  $line"
        done
    else
        echo -e "  ${GREEN}✓ No recent failed logins${NC}"
    fi

    # Currently logged in users
    echo -e "\n${GREEN}Currently logged in:${NC}"
    who | while read -r line; do
        echo "  $line"
    done
}

check_world_writable() {
    print_section "🌍 WORLD-WRITABLE FILES (outside /tmp & /proc)"

    echo -e "${GREEN}Scanning for world-writable files...${NC}"
    found=0
    while read -r file; do
        echo -e "  ${YELLOW}⚠️  World-writable: $file${NC}"
        add_abnormality "World-writable file found: $file"
        found=1
    done < <(find / -xdev -type f -perm -0002 2>/dev/null | grep -v "^/tmp\|^/proc\|^/sys\|^/dev\|^/home/.*\.ecryptfs\|^/home/.*\.Private\|^/var/lib/containerd/\|^/var/lib/docker/\|^/var/ossec/")

    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✓ No suspicious world-writable files found${NC}"
    fi
}

check_hidden_files() {
    print_section "🫥 HIDDEN FILES IN SUSPICIOUS LOCATIONS"

    echo -e "${GREEN}Scanning /tmp, /var/tmp, /dev/shm for hidden files...${NC}"
    found=0
    # Exclude normal X11/display manager socket files which legitimately live as hidden files in /tmp
    while read -r file; do
        echo -e "  ${RED}⚠️  Hidden file: $file${NC}"
        add_abnormality "Hidden file in temp directory: $file"
        found=1
    done < <(find /tmp /var/tmp /dev/shm 2>/dev/null -name ".*" -not -name ".." -not -name "." \
        | grep -v "^/tmp/\.X[0-9]*-lock$\|^/tmp/\.X11-unix\|^/tmp/\.XIM-unix\|^/tmp/\.ICE-unix\|^/tmp/\.font-unix")

    echo -e "\n${GREEN}Scanning home directories for unexpected hidden executables:${NC}"
    while read -r file; do
        echo -e "  ${YELLOW}⚠️  Hidden executable: $file${NC}"
        add_abnormality "Hidden executable in home directory: $file"
        found=1
    done < <(find /home /root -maxdepth 4 -name ".*" -type f -executable 2>/dev/null | grep -v ".bashrc\|.bash_profile\|.profile\|.bash_logout\|.ssh\|.gnupg\|.config")

    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✓ No suspicious hidden files found${NC}"
    fi
}

print_summary() {
    echo -e "\n${BOLD}${MAGENTA}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${MAGENTA}  📊 ABNORMALITY SUMMARY${NC}"
    echo -e "${BOLD}${MAGENTA}════════════════════════════════════════════════════════════${NC}"

    if [[ $TOTAL_ABNORMALITIES -eq 0 ]]; then
        echo -e "${GREEN}✅ No abnormalities detected - System appears healthy${NC}"
    else
        echo -e "${RED}⚠️  Found $TOTAL_ABNORMALITIES abnormalities:${NC}\n"
        for i in "${!ABNORMALITIES[@]}"; do
            echo -e "  $((i+1)). ${RED}${ABNORMALITIES[$i]}${NC}"
        done
    fi
}

# Main execution
main() {
    print_header
    system_overview
    load_average
    memory_usage
    disk_usage
    top_processes
    network_devices
    network_connections
    firewall_status
    dns_config
    kernel_messages
    wifi_networks
    check_suid_binaries
    check_crontabs
    check_tmp_processes
    check_ssh_keys
    check_passwd_integrity
    check_recent_modifications
    check_login_history
    check_world_writable
    check_hidden_files

    print_summary

    echo -e "\n${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}✅ Debug scan complete - $(date)${NC}\n"
}

# Run main function
main "$@"
