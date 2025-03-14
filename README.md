## 项目介绍
该脚本是一款强大且高效的 Bash 脚本，专为自动化 Nmap 扫描设计，能够完成端口枚举、服务版本检测、操作系统识别、漏洞扫描等关键安全评估任务。其开发灵感来源于个人打靶机实战经验，旨在提升渗透测试效率，并为通过 OSCP 认证考试提供便利。

## 功能特点
- **全端口扫描**：快速识别目标主机的所有开放端口。
- **服务版本检测**：获取运行在端口上的服务版本信息。
- **操作系统识别**：尝试识别目标主机的操作系统。
- **UDP 端口扫描**：检测目标主机的前 20 个常见 UDP 端口。
- **漏洞扫描**：利用 Nmap 内置的 `vuln` 脚本检测已知漏洞。
- **SMB 漏洞扫描**：针对开放 139/445 端口的目标，自动进行 SMB 相关漏洞检测。
- **自动输出结果**：所有扫描结果保存在 `enum/` 目录，方便分析。

## 安装指南
### 依赖项
本脚本依赖以下工具，请确保它们已正确安装：
- `nmap` (端口扫描工具)
- `grc` (使 Nmap 输出变得多彩🥰)

在 Debian/Ubuntu 系统上，你可以使用以下命令安装依赖：
```bash
sudo apt update && sudo apt install -y nmap grc
```

### 复制脚本到 `/usr/local/bin/`
```bash
git clone https://github.com/Yanxinwu946/xnmap.git
sudo cp xnmap/nmap_scan.sh /usr/local/bin/xnmap
sudo chmod +x /usr/local/bin/xnmap
```

## 使用方法
### 运行脚本
```bash
xnmap <目标 IP>
```
示例：
```bash
xnmap 192.168.56.10
```

### 结果输出
所有扫描结果将保存在 `enum/` 目录下，包括：
- `ports`：全端口扫描结果
- `detail.nmap`：详细服务和 OS 识别信息
- `udp.nmap`：UDP 端口扫描结果
- `vuln.nmap`：漏洞扫描结果
- `smbvuln.nmap`：SMB 相关漏洞扫描（仅当目标开放 139/445 端口时生成）

## 工作流程
1. **全端口扫描**：
   ```bash
   nmap -p- --min-rate 5000 -T4 -Pn -n -v -oN enum/ports <IP>
   ```
2. **解析开放端口**，如果没有端口开放，则终止扫描。
3. **详细扫描（版本/OS 识别）**：
   ```bash
   nmap -T4 -Pn -n -sCV -O -p<端口列表> -oN enum/detail.nmap <IP>
   ```
4. **UDP 端口扫描**（前 20 端口）：
   ```bash
   nmap -sU -sV -Pn --top-ports 20 --version-intensity 0 -oN enum/udp.nmap <IP>
   ```
5. **漏洞扫描**：
   ```bash
   nmap -Pn -p<端口列表> --script=vuln -oN enum/vuln.nmap <IP>
   ```
6. **SMB 漏洞扫描**（仅在 139/445 端口开放时执行）：
   ```bash
   nmap -Pn --script=smb-vuln* -p 139,445 -oN enum/smbvuln.nmap <IP>
   ```

## 注意事项
- 请确保在合法授权的情况下使用本脚本，避免对未授权目标进行扫描。
- 由于部分扫描（如 `vuln`）涉及漏洞利用检测，可能会被防火墙拦截或影响目标系统稳定性，请谨慎使用。
- 运行本脚本时请使用 `sudo` 以便执行特权扫描（如 UDP 扫描）。

## 许可证
本项目基于 MIT 许可证开源，欢迎 Fork 和贡献改进！
