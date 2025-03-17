#!/bin/bash

# -----------------------------------------------------------
# 自动化 Nmap 扫描脚本：主机发现、端口枚举、服务版本检测、漏洞扫描
# Author: https://github.com/Yanxinwu946/
# -----------------------------------------------------------

# 颜色定义
greenColour="\e[0;32m\033[1m"
redColour="\e[0;31m\033[1m"
yellowColour="\e[0;33m\033[1m"
endColour="\033[0m\e[0m"

# 使用说明
usage() {
    echo -e "${greenColour}Usage:${endColour} $0 [-i <IP>] [-f <file>] [-s <subnet>]"
    echo -e "  -i <IP>       : Scan a single IP (e.g., 192.168.56.10)"
    echo -e "  -f <file>     : Scan IPs from a file (one IP per line)"
    echo -e "  -s <subnet>   : Discover and scan hosts in a subnet (e.g., 192.168.1.0/24)"
    echo -e "Example:"
    echo -e "  $0 -i 192.168.56.10"
    echo -e "  $0 -f targets.txt"
    echo -e "  $0 -s 192.168.1.0/24"
    exit 1
}

# 捕获 Ctrl+C
sigint() {
    echo -e "\n\n${redColour}[*] Exiting${endColour}"
    tput cnorm
    rm -f alive_hosts.txt 2>/dev/null
    exit 1
}
trap sigint INT

# 检查工具可用性
check_tools() {
    if ! command -v nmap >/dev/null 2>&1; then
        echo -e "${redColour}Error: 'nmap' is required but not installed. Please install it.${endColour}"
        exit 1
    fi

    if ! command -v grc >/dev/null 2>&1; then
        echo -e "${yellowColour}Warning: 'grc' not found. Output will not be colorized. Install with 'sudo apt install grc' or equivalent.${endColour}"
    fi
}

# 函数：运行 Nmap 扫描
run_nmap() {
    local ip="$1"
    local cmd="$2"
    local output="$3"
    echo -e "${yellowColour}Running on $ip: $cmd${endColour}"
    if command -v grc >/dev/null 2>&1; then
        eval "grc $cmd"
    else
        eval "$cmd"
    fi
    if [ $? -eq 0 ]; then
        echo -e "${greenColour}Scan completed for $ip, output saved to $output${endColour}"
    else
        echo -e "${redColour}Error: Scan failed for $ip: $cmd${endColour}"
    fi
    echo "----------------------------------------"
}

# 函数：扫描单个IP
scan_ip() {
    local IP="$1"
    local OUTPUT_DIR="enum_$IP"
    mkdir -p "$OUTPUT_DIR"

    # 全端口扫描
    run_nmap "$IP" "nmap -p- --min-rate 5000 -T4 -Pn -n -v -oN $OUTPUT_DIR/ports $IP" "$OUTPUT_DIR/ports"

    # 提取开放端口
    PORT=$(grep '^[0-9]' "$OUTPUT_DIR/ports" | cut -d '/' -f1 | tr '\n' ',' | sed 's/,$//')
    if [ -z "$PORT" ]; then
        echo -e "${yellowColour}Warning: No open ports found on $IP, skipping detailed scans${endColour}"
        return
    fi
    echo -e "${greenColour}Open ports on $IP: $PORT${endColour}"

    # 服务版本和操作系统检测
    run_nmap "$IP" "nmap -T4 -Pn -n -sCV -O -p$PORT -oN $OUTPUT_DIR/detail.nmap $IP" "$OUTPUT_DIR/detail.nmap"

    # UDP 扫描（前 20 端口）
    run_nmap "$IP" "nmap -sU -sV -Pn --top-ports 20 --version-intensity 0 -oN $OUTPUT_DIR/udp.nmap $IP" "$OUTPUT_DIR/udp.nmap"

    # 漏洞扫描
    run_nmap "$IP" "nmap -Pn -p$PORT --script=vuln -oN $OUTPUT_DIR/vuln.nmap $IP" "$OUTPUT_DIR/vuln.nmap"

    # 检查 SMB 并运行相关扫描
    if echo "$PORT" | grep -E '139|445' >/dev/null; then
        echo -e "${yellowColour}SMB ports (139/445) detected on $IP, running SMB vulnerability scan${endColour}"
        run_nmap "$IP" "nmap -Pn --script=smb-vuln* -p 139,445 -oN $OUTPUT_DIR/smbvuln.nmap $IP" "$OUTPUT_DIR/smbvuln.nmap"
    else
        echo -e "${yellowColour}No SMB ports (139/445) detected on $IP${endColour}"
    fi
}

# 函数：主机发现 (使用 nmap -sn)
discover_hosts() {
    local SUBNET="$1"
    echo -e "${yellowColour}Discovering hosts in $SUBNET...${endColour}"
    nmap -sn "$SUBNET" -oG - | grep "Up" | awk '{print $2}' > alive_hosts.txt
    if [ -s alive_hosts.txt ]; then
        echo -e "${greenColour}Found $(wc -l < alive_hosts.txt) alive hosts:${endColour}"
        cat alive_hosts.txt
    else
        echo -e "${redColour}No alive hosts found in $SUBNET${endColour}"
        rm -f alive_hosts.txt
        exit 1
    fi
}

# 函数：用户选择扫描目标
select_scan_targets() {
    local ips=()
    while IFS= read -r ip; do
        ips+=("$ip")
    done < alive_hosts.txt

    echo -e "${yellowColour}Host discovery completed. Select scanning option:${endColour}"
    echo -e "  - Enter IPs separated by commas to scan specific hosts (e.g., ${ips[0]},${ips[1]})"
    echo -e "  - Press Enter to scan all discovered hosts"
    echo -e "  - Press Ctrl+C to exit"
    read -p "Your choice: " choice

    if [ -z "$choice" ]; then
        echo -e "${greenColour}Scanning all discovered hosts:${endColour}"
        for ip in "${ips[@]}"; do
            scan_ip "$ip"
        done
    else
        IFS=',' read -r -a selected_ips <<< "$choice"
        local valid_ips=()
        local invalid_ips=()

        for input_ip in "${selected_ips[@]}"; do
            input_ip=$(echo "$input_ip" | tr -d '[:space:]')
            if echo "${ips[@]}" | grep -w "$input_ip" >/dev/null; then
                valid_ips+=("$input_ip")
            else
                invalid_ips+=("$input_ip")
            fi
        done

        if [ ${#invalid_ips[@]} -gt 0 ]; then
            echo -e "${redColour}Error: The following IPs are not in the discovered hosts list: ${invalid_ips[*]}${endColour}"
        fi

        if [ ${#valid_ips[@]} -gt 0 ]; then
            echo -e "${greenColour}Scanning selected IPs: ${valid_ips[*]}${endColour}"
            for ip in "${valid_ips[@]}"; do
                scan_ip "$ip"
            done
        fi
    fi
    rm -f alive_hosts.txt
}

# 主逻辑：解析参数
check_tools
MODE=""
TARGET=""

while getopts "i:f:s:" opt; do
    case $opt in
        i) MODE="single"; TARGET="$OPTARG" ;;
        f) MODE="file"; TARGET="$OPTARG" ;;
        s) MODE="subnet"; TARGET="$OPTARG" ;;
        ?) usage ;;
    esac
done

if [ -z "$MODE" ]; then
    echo -e "${redColour}Error: No mode specified${endColour}"
    usage
fi

# 执行扫描
case "$MODE" in
    single)
        echo -e "${greenColour}Scanning single IP: $TARGET${endColour}"
        scan_ip "$TARGET"
        ;;
    file)
        if [ ! -f "$TARGET" ]; then
            echo -e "${redColour}Error: File $TARGET not found${endColour}"
            exit 1
        fi
        echo -e "${greenColour}Scanning IPs from file: $TARGET${endColour}"
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            scan_ip "$ip"
        done < "$TARGET"
        ;;
    subnet)
        discover_hosts "$TARGET"
        select_scan_targets
        ;;
esac

echo -e "${greenColour}All scans completed!${endColour}"
exit 0
