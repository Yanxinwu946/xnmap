## 项目介绍
该脚本是一款强大且高效的 Bash 脚本，专为自动化 Nmap 扫描设计，能够完成主机发现、端口枚举、服务版本检测、操作系统识别、漏洞扫描等关键安全评估任务。其开发灵感来源于个人打靶机实战经验，旨在提升渗透测试效率，并为通过 OSCP 认证考试提供便利。

## 功能特点
- **主机发现**：通过 `nmap -sn` 快速扫描子网，识别存活主机。
- **多模式支持**：
  - 单IP扫描：针对单一目标执行完整扫描。
  - 列表扫描：从文件中读取IP列表进行批量扫描。
  - 子网扫描：自动发现并扫描子网中的存活主机。
- **全端口扫描**：快速识别目标主机的所有开放端口。
- **服务版本检测**：获取运行在端口上的服务版本信息。
- **操作系统识别**：尝试识别目标主机的操作系统。
- **UDP 端口扫描**：检测目标主机的前 20 个常见 UDP 端口。
- **漏洞扫描**：利用 Nmap 内置的 `vuln` 脚本检测已知漏洞。
- **SMB 漏洞扫描**：针对开放 139/445 端口的目标，自动进行 SMB 相关漏洞检测。
- **多彩输出**：通过 `grc` 为 Nmap 输出添加颜色高亮，提升可读性。
- **自动输出结果**：扫描结果按目标IP保存在独立目录（如 `enum_<IP>`），便于分析。

## 安装指南
### 依赖项
本脚本依赖以下工具，请确保它们已正确安装：
- `nmap`（端口扫描工具，必需）
- `grc`（使 Nmap 输出变得多彩🥰，可选）

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
脚本支持以下三种模式：
1. **单IP扫描**
   ```bash
   xnmap -i <目标 IP>
   ```
   示例：
   ```bash
   xnmap -i 192.168.56.10
   ```

2. **列表扫描（从文件读取IP）**
   ```bash
   xnmap -f <IP列表文件>
   ```
   示例：
   ```bash
   echo -e "192.168.56.10\n192.168.56.11" > targets.txt
   xnmap -f targets.txt
   ```

3. **子网扫描（主机发现+扫描）**
   ```bash
   xnmap -s <子网>
   ```
   示例：
   ```bash
   xnmap -s 192.168.1.0/24
   ```

### 结果输出
所有扫描结果将保存在以目标IP命名的目录下（如 `enum_192.168.56.10/`），包括：
- `ports`：全端口扫描结果
- `detail.nmap`：详细服务和操作系统识别信息
- `udp.nmap`：UDP 端口扫描结果
- `vuln.nmap`：漏洞扫描结果
- `smbvuln.nmap`：SMB 相关漏洞扫描结果（仅当目标开放 139/445 端口时生成）

## 工作流程
1. **主机发现**（仅子网模式）：
   ```bash
   nmap -sn <subnet> -oG -
   ```
   输出解析后提取存活主机的 IP。
2. **全端口扫描**：
   ```bash
   nmap -p- --min-rate 5000 -T4 -Pn -n -v -oN enum_<IP>/ports <IP>
   ```
3. **解析开放端口**：如果没有端口开放，则跳过后续扫描。
4. **详细扫描（版本/OS 识别）**：
   ```bash
   nmap -T4 -Pn -n -sCV -O -p<端口列表> -oN enum_<IP>/detail.nmap <IP>
   ```
5. **UDP 端口扫描**（前 20 端口）：
   ```bash
   nmap -sU -sV -Pn --top-ports 20 --version-intensity 0 -oN enum_<IP>/udp.nmap <IP>
   ```
6. **漏洞扫描**：
   ```bash
   nmap -Pn -p<端口列表> --script=vuln -oN enum_<IP>/vuln.nmap <IP>
   ```
7. **SMB 漏洞扫描**（仅在 139/445 端口开放时执行）：
   ```bash
   nmap -Pn --script=smb-vuln* -p 139,445 -oN enum_<IP>/smbvuln.nmap <IP>
   ```

## 注意事项
- **合法性**：请确保在合法授权的情况下使用本脚本，避免对未授权目标进行扫描。
- **权限**：运行脚本时建议使用 `sudo`，因为某些 `nmap` 扫描（如 UDP 或全端口扫描）需要 root 权限。
- **防火墙**：部分扫描（如 `vuln` 或 UDP）可能被防火墙拦截，或对目标系统造成影响，请谨慎使用。
- **依赖检查**：若缺少 `grc`，脚本仍可运行，但输出不会高亮；若缺少 `nmap`，脚本将退出并提示安装。

## 许可证
本项目基于 MIT 许可证开源，欢迎 Fork 和贡献改进！
