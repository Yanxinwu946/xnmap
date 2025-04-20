#!/bin/bash

# -----------------------------------------------------------
# 自动化 Nmap 扫描脚本：主机发现、端口枚举、服务版本检测、漏洞扫描、HTTP目录扫描
# Author: https://github.com/Yanxinwu946/
# -----------------------------------------------------------

# 颜色定义
greenColour="\e[0;32m\033[1m"
redColour="\e[0;31m\033[1m"
yellowColour="\e[0;33m\033[1m"
endColour="\033[0m\e[0m"

# 使用说明
usage() {
    echo -e "${greenColour}Usage:${endColour} $0 [-i <IP>] [-f <file>] [-s <subnet>] [-l] [-m]"
    echo -e "  -i <IP>       : Scan a single IP (e.g., 192.168.56.10)"
    echo -e "  -f <file>     : Scan IPs from a file (one IP per line)"
    echo -e "  -s <subnet>   : Discover and scan hosts in a subnet (e.g., 192.168.1.0/24)"
    echo -e "  -l            : Lightweight scan (full ports only)"
    echo -e "  -m            : Slow mode (min-rate 2000, T3 timing)"
    echo -e "Example:"
    echo -e "  $0 -i 192.168.56.10"
    echo -e "  $0 -f targets.txt"
    echo -e "  $0 -s 192.168.1.0/24 -l -m"
    exit 1
}

# 捕获 Ctrl+C
sigint() {
    echo -e "\n${redColour}[*] Exiting${endColour}"
    tput cnorm
    rm -f alive_hosts.txt 2>/dev/null
    exit 1
}
trap sigint INT

# 检查工具可用性
check_tools() {
    local tools=("nmap" "gobuster")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${redColour}Error: '$tool' is required but not installed. Please install it.${endColour}"
            exit 1
        fi
    done
    if ! command -v grc >/dev/null 2>&1; then
        echo -e "${yellowColour}Warning: 'grc' not found. Output will not be colorized. Install with 'sudo apt install grc'.${endColour}"
    fi
    if [ ! -f "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" ]; then
        echo -e "${yellowColour}Warning: 'seclists' wordlist not found. Install with 'sudo apt install seclists'.${endColour}"
    fi
}

# 函数：运行命令（支持 grc）
run_cmd() {
    local cmd="$1"
    local output="$2"
    echo -e "${yellowColour}Executing: $cmd${endColour}"
    if command -v grc >/dev/null 2>&1; then
        grc $cmd
    else
        eval "$cmd"
    fi
    local status=$?
    if [ $status -eq 0 ]; then
        echo -e "${greenColour}Completed, output saved to $output${endColour}"
    else
        echo -e "${redColour}Error: Command failed${endColour}"
    fi
    echo "----------------------------------------"
    return $status
}

# 函数：轻量化扫描
lightweight_scan() {
    local ip="$1"
    local output_dir="enum_${ip//./_}"
    mkdir -p "$output_dir"
    local timing=""
    [ "$SLOW_MODE" = true ] && timing="-T3"
    local nmap_cmd="nmap -p- --min-rate $MIN_RATE $timing -Pn -n -v -oN $output_dir/ports $ip"
    run_cmd "$nmap_cmd" "$output_dir/ports"
}

# 函数：完整扫描
full_scan() {
    local ip="$1"
    local output_dir="enum_${ip//./_}"
    mkdir -p "$output_dir"

    # 全端口扫描（优化 T4 性能）
    local timing=""
    [ "$SLOW_MODE" = true ] && timing="-T3" || timing="-T4 --defeat-rst-ratelimit"
    local nmap_cmd="nmap -p- --min-rate $MIN_RATE $timing -Pn -n -v -oN $output_dir/ports $ip"
    run_cmd "$nmap_cmd" "$output_dir/ports" || return 1

    # 提取开放端口
    local ports
    ports=$(grep '^[0-9]' "$output_dir/ports" | cut -d '/' -f1 | tr '\n' ',' | sed 's/,$//')
    if [ -z "$ports" ]; then
        echo -e "${yellowColour}Warning: No open ports found on $ip, skipping detailed scans${endColour}"
        return
    fi
    echo -e "${greenColour}Open ports on $ip: $ports${endColour}"

    # 服务版本和操作系统检测
    local detail_cmd="nmap $timing -Pn -n -sCV -O -p$ports -oN $output_dir/detail.nmap $ip"
    run_cmd "$detail_cmd" "$output_dir/detail.nmap"

    # UDP 扫描（限制为高频端口）
    local udp_cmd="nmap -sU -sV -Pn --top-ports 20 --version-intensity 0 -oN $output_dir/udp.nmap $ip"
    run_cmd "$udp_cmd" "$output_dir/udp.nmap"

    # 漏洞扫描（仅常见端口）
    local common_ports="21,22,23,25,80,110,143,443,445,3389"
    local vuln_ports=$(echo "$ports" | tr ',' '\n' | awk -v common="$common_ports" 'BEGIN {split(common, arr, ","); for (i in arr) common_set[arr[i]]} $1 in common_set {print $1}' | paste -sd,)
    if [ -n "$vuln_ports" ]; then
        echo -e "${yellowColour}Running vulnerability scan on ports: $vuln_ports${endColour}"
        local vuln_cmd="nmap -Pn -p$vuln_ports --script=vuln --min-rate $MIN_RATE -oN $output_dir/vuln.nmap $ip"
        run_cmd "$vuln_cmd" "$output_dir/vuln.nmap"
    else
        echo -e "${yellowColour}No common ports open for vulnerability scan on $ip${endColour}"
    fi

    # HTTP 端口的 Gobuster 目录扫描
    local http_ports
    http_ports=$(grep -h "^[0-9].*http" "$output_dir/detail.nmap" | cut -d "/" -f 1 | sort -u)
    if [ -n "$http_ports" ]; then
        echo -e "${yellowColour}Detected HTTP ports: $http_ports${endColour}"
        local wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        [ ! -f "$wordlist" ] && wordlist="/usr/share/wordlists/dirb/common.txt"
        for port in $http_ports; do
            echo -e "${greenColour}[*] Starting GoBuster on $ip:$port${endColour}"
            local gobuster_cmd="gobuster dir -t 50 -ekq -u http://$ip:$port/ -w $wordlist -o $output_dir/godir$port.txt"
            run_cmd "$gobuster_cmd" "$output_dir/godir$port.txt"
        done
    else
        echo -e "${yellowColour}[!] No HTTP ports found for $ip${endColour}"
    fi
}

# 函数：主机发现
discover_hosts() {
    local subnet="$1"
    echo -e "${yellowColour}Discovering hosts in $subnet...${endColour}"
    nmap -sn --min-rate 1000 "$subnet" -oG - | grep "Up" | awk '{print $2}' | sort -u > alive_hosts.txt
    if [ -s alive_hosts.txt ]; then
        echo -e "${greenColour}Found $(wc -l < alive_hosts.txt) alive hosts:${endColour}"
        cat alive_hosts.txt
    else
        echo -e "${redColour}No alive hosts found in $subnet${endColour}"
        rm -f alive_hosts.txt
        exit 1
    fi
}

# 函数：用户选择扫描目标
select_scan_targets() {
    local scan_func="$1"
    local ips=()
    readarray -t ips < alive_hosts.txt

    echo -e "${yellowColour}Host discovery completed. Select scanning option:${endColour}"
    echo -e "  - Enter IPs separated by commas (e.g., ${ips[0]},${ips[1]})"
    echo -e "  - Press Enter to scan all discovered hosts"
    echo -e "  - Press Ctrl+C to exit"
    read -p "Your choice: " choice

    if [ -z "$choice" ]; then
        echo -e "${greenColour}Scanning all discovered hosts:${endColour}"
        for ip in "${ips[@]}"; do
            $scan_func "$ip"
        done
    else
        IFS=',' read -r -a selected_ips <<< "$choice"
        local valid_ips=()
        for input_ip in "${selected_ips[@]}"; do
            input_ip=$(echo "$input_ip" | tr -d '[:space:]')
            if [[ "${ips[*]}" =~ (^|[[:space:]])$input_ip($|[[:space:]]) ]]; then
                valid_ips+=("$input_ip")
            fi
        done
        if [ ${#valid_ips[@]} -eq 0 ]; then
            echo -e "${redColour}Error: No valid IPs selected${endColour}"
            rm -f alive_hosts.txt
            exit 1
        fi
        echo -e "${greenColour}Scanning selected IPs: ${valid_ips[*]}${endColour}"
        for ip in "${valid_ips[@]}"; do
            $scan_func "$ip"
        done
    fi
    rm -f alive_hosts.txt
}

# 主逻辑：解析参数
check_tools
MODE=""
TARGET=""
LIGHTWEIGHT=false
SLOW_MODE=false
MIN_RATE=5000

while getopts "i:f:s:lm" opt; do
    case $opt in
        i) MODE="single"; TARGET="$OPTARG" ;;
        f) MODE="file"; TARGET="$OPTARG" ;;
        s) MODE="subnet"; TARGET="$OPTARG" ;;
        l) LIGHTWEIGHT=true ;;
        m) SLOW_MODE=true; MIN_RATE=2000 ;;
        ?) usage ;;
    esac
done

if [ -z "$MODE" ]; then
    echo -e "${redColour}Error: No mode specified${endColour}"
    usage
fi

# 选择扫描函数
scan_func="full_scan"
[ "$LIGHTWEIGHT" = true ] && scan_func="lightweight_scan"

# 执行扫描
case "$MODE" in
    single)
        echo -e "${greenColour}Scanning single IP: $TARGET${endColour}"
        $scan_func "$TARGET"
        ;;
    file)
        if [ ! -f "$TARGET" ]; then
            echo -e "${redColour}Error: File $TARGET not found${endColour}"
            exit 1
        fi
        echo -e "${greenColour}Scanning IPs from file: $TARGET${endColour}"
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            $scan_func "$ip"
        done < "$TARGET"
        ;;
    subnet)
        discover_hosts "$TARGET"
        select_scan_targets "$scan_func"
        ;;
esac

echo -e "${greenColour}All scans completed!${endColour}"
exit 0
