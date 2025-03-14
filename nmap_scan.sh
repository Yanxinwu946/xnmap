#!/bin/bash

# -----------------------------------------------------------
# 自动化 Nmap 扫描脚本：端口枚举、服务版本检测、漏洞扫描
# Author: https://github.com/Yanxinwu946/
# -----------------------------------------------------------

# 颜色定义
greenColour="\e[0;32m\033[1m"
redColour="\e[0;31m\033[1m"
yellowColour="\e[0;33m\033[1m"
endColour="\033[0m\e[0m"

# 使用说明
usage() {
    echo -e "${greenColour}Usage:${endColour} $0 <IP>"
    echo -e "Example: $0 192.168.56.10"
    exit 1
}

# 捕获 Ctrl+C
sigint() {
    echo -e "\n\n${redColour}[*] Exiting${endColour}"
    tput cnorm
    exit 1
}
trap sigint INT

# 检查是否提供了 IP 参数
if [ -z "$1" ]; then
    echo -e "${redColour}Error: IP address not provided${endColour}"
    usage
fi

IP="$1"
OUTPUT_DIR="enum"
SEPARATOR="----------------------------------------"

# 创建输出目录
if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
fi

# 检查工具可用性
if ! command -v nmap >/dev/null 2>&1; then
    echo -e "${redColour}Error: 'nmap' command not found. Please install nmap.${endColour}"
    exit 1
fi

# 函数：运行 Nmap 扫描
run_nmap() {
    local cmd="$1"
    local output="$2"
    echo -e "${yellowColour}Running: $cmd${endColour}"
    eval "$cmd"
    if [ $? -eq 0 ]; then
        echo -e "${greenColour}Scan completed, output saved to $output${endColour}"
    else
        echo -e "${redColour}Error: Scan failed for $cmd${endColour}"
    fi
    echo "$SEPARATOR"
}

# 1. 全端口扫描
run_nmap "grc nmap -p- --min-rate 5000 -T4 -Pn -n -v -oN $OUTPUT_DIR/ports $IP" "$OUTPUT_DIR/ports"

# 提取开放端口
PORT=$(cat "$OUTPUT_DIR/ports" | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed 's/,$//')
if [ -z "$PORT" ]; then
    echo -e "${yellowColour}Warning: No open ports found, skipping detailed scans${endColour}"
    echo -e "${greenColour}Initial scan completed!${endColour}"
    exit 0
fi
echo -e "${greenColour}Open ports: $PORT${endColour}"

# 2. 服务版本和操作系统检测
run_nmap "grc nmap -T4 -Pn -n -sCV -O -p$PORT -oN $OUTPUT_DIR/detail.nmap $IP" "$OUTPUT_DIR/detail.nmap"

# 3. UDP 扫描（前 20 端口）
run_nmap "grc nmap -sU -sV -Pn --top-ports 20 --version-intensity 0 -oN $OUTPUT_DIR/udp.nmap $IP" "$OUTPUT_DIR/udp.nmap"

# 4. 漏洞扫描
run_nmap "grc nmap -Pn -p$PORT --script=vuln -oN $OUTPUT_DIR/vuln.nmap $IP" "$OUTPUT_DIR/vuln.nmap"

# 5. 检查 SMB 并运行相关扫描
if echo "$PORT" | grep -E '139|445' >/dev/null; then
    echo -e "${yellowColour}SMB ports (139/445) detected, running SMB vulnerability scan${endColour}"
    run_nmap "grc nmap -Pn --script=smb-vuln* -p 139,445 -oN $OUTPUT_DIR/smbvuln.nmap $IP" "$OUTPUT_DIR/smbvuln.nmap"
else
    echo -e "${yellowColour}No SMB ports (139/445) detected, skipping SMB scan${endColour}"
    echo "$SEPARATOR"
fi

echo -e "${greenColour}All scans completed!${endColour}"

exit 0
