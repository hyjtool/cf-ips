#!/usr/bin/env python3
"""
Cloudflare 优选 IP 自动化工具 
"""

import sys
# 强制 Windows 终端使用 UTF-8 编码
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

import asyncio
import base64
import json
import os
import smtplib
import ssl
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from email.header import Header
from email.mime.text import MIMEText
from pathlib import Path

# ================= 根目录绝对路径绑定 =================
BASE_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = Path(__file__).resolve()
BEST_OUTPUT = BASE_DIR / "best_ips.txt"

# ================= 默认全局配置 =================
DEFAULT_CONFIG = {
    "DEFAULT_MODE": "cloud",
    "USE_GH": "false",
    "USE_R2": "false",
    "USE_TG": "false",
    "USE_MAIL": "false",
    "INPUT_URL": "https://zip.cm.edu.kg/all.txt",
    "DOWNLOAD_TIMEOUT": "60.0",
    "MAX_NODES": "1000000",
    "TCP_WORKERS": "400",
    "TCP_TIMEOUT": "1.5",
    "SPEED_WORKERS": "12",
    "SPEED_TIMEOUT": "6.0",
    "SPEED_MIN": "5.0",
    "TOP_PER_REGION": "8",
    "CF_ACCOUNT_ID": "",
    "CF_ACCESS_KEY": "",
    "CF_SECRET_KEY": "",
    "CF_BUCKET_NAME": "",
    "GH_SYNC_MODE": "api",
    "GH_OWNER": "",
    "GH_REPO_NAME": "",
    "GH_TOKEN": "",
    "TG_BOT_TOKEN": "",
    "TG_CHAT_ID": "",
    "MAIL_HOST": "smtp.qq.com",
    "MAIL_USER": "",
    "MAIL_PASS": "",
    "MAIL_TO": "",
}

SPEED_DOMAIN = "speed.cloudflare.com"
SPEED_PATH = "/__down"
SPEED_BYTES = 2 * 1024 * 1024


# ================= 配置加载与 Base64 自固化保存 =================
def load_config():
    config = DEFAULT_CONFIG.copy()
    try:
        if SCRIPT_PATH.exists():
            content = SCRIPT_PATH.read_text(encoding="utf-8")
            for line in content.splitlines():
                if line.strip().startswith("# CONFIG_B64:"):
                    b64_data = line.strip().split(":", 1)[1].strip()
                    json_str = base64.b64decode(b64_data.encode("utf-8")).decode("utf-8")
                    saved_cfg = json.loads(json_str)
                    config.update(saved_cfg)
                    break
    except Exception:
        pass
    return config


def save_config_to_self(cfg):
    try:
        content = SCRIPT_PATH.read_text(encoding="utf-8")
        json_str = json.dumps(cfg, ensure_ascii=False)
        b64_data = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
        new_line = f"# CONFIG_B64: {b64_data}"

        lines = content.splitlines()
        cleaned_lines = [l for l in lines if not l.strip().startswith("# CONFIG_B64:")]
        cleaned_lines.append(new_line)
        
        SCRIPT_PATH.write_text("\n".join(cleaned_lines) + "\n", encoding="utf-8")
        return True
    except Exception as e:
        print(f"\n⚠️ 自固化配置失败: {e}")
        return False


def mask_str(s):
    """敏感信息打码显示"""
    if not s:
        return "[未配置]"
    if len(s) <= 6:
        return "***"
    return s[:4] + "***" + s[-2:]


@dataclass(frozen=True)
class Node:
    ip: str
    port: int
    region: str

    @property
    def raw(self) -> str:
        return f"{self.ip}:{self.port}#{self.region}"


# ================= 跨平台 ESC 键捕获与监听函数 =================
def wait_for_esc(prompt):
    """阻塞等待用户按下 ESC 键"""
    print(prompt, end='', flush=True)
    if sys.platform == "win32":
        import msvcrt
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch == b'\x1b':  # ESC 键
                    print()
                    return
            else:
                time.sleep(0.05)
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch == '\x1b':  # ESC 键
                    print('\r\n', end='')
                    return
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def get_input_with_esc(prompt):
    """跨平台实时监听输入，支持按 ESC 键随时取消并返回"""
    print(prompt, end='', flush=True)
    chars = []
    
    if sys.platform == "win32":
        import msvcrt
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch == b'\x1b':  # ESC 键
                    print()
                    return None
                elif ch in (b'\r', b'\n'):  # 回车键
                    print()
                    return "".join(chars)
                elif ch == b'\x08':  # 退格键
                    if chars:
                        chars.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                elif ch in (b'\x00', b'\xe0'):
                    msvcrt.getch()  # 过滤组合键
                else:
                    try:
                        decoded = ch.decode('utf-8', errors='ignore')
                        chars.append(decoded)
                        sys.stdout.write(decoded)
                        sys.stdout.flush()
                    except:
                        pass
            else:
                time.sleep(0.02)
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch == '\x1b':  # ESC 键
                    print('\r\n', end='')
                    return None
                elif ch in ('\r', '\n'):  # 回车键
                    print('\r\n', end='')
                    return "".join(chars)
                elif ch in ('\x7f', '\b'):  # 退格键
                    if chars:
                        chars.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                else:
                    chars.append(ch)
                    sys.stdout.write(ch)
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# ================= 内置原生进度条 =================
class SimpleProgressBar:
    def __init__(self, total, desc="处理中"):
        self.total = total
        self.current = 0
        self.desc = desc
        self.start_time = time.time()
        self.lock = asyncio.Lock()

    async def update(self, n=1):
        async with self.lock:
            self.current += n
            self._print()

    def _print(self):
        if self.total <= 0:
            percent = 100.0
            filled = 30
        else:
            percent = min(100.0, (self.current / self.total) * 100)
            filled = int(30 * self.current // self.total)
        
        bar = "█" * filled + "-" * (30 - filled)
        elapsed = time.time() - self.start_time
        sys.stdout.write(f"\r{self.desc}: |{bar}| {self.current}/{self.total} [{percent:5.1f}%] 耗时: {elapsed:.1f}s")
        sys.stdout.flush()

    def close(self):
        sys.stdout.write("\n")
        sys.stdout.flush()


# ================= 核心测速与内存解析引擎 =================
def fetch_ips_content(url, timeout):
    if "://" not in url:
        url = f"http://{url}"
    print(f"🌐 正在从云端拉取 IP 列表: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8-sig", errors="ignore")
    except Exception as e:
        print(f"⚠️ 下载 IP 列表失败: {e}")
    return None


def parse_nodes_from_text(text, max_nodes):
    nodes, seen = [], set()
    if not text:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line or "#" not in line:
            continue
        try:
            addr, reg = line.split("#", 1)
            ip, port = addr.rsplit(":", 1)
            n = Node(ip.strip(), int(port), reg.strip())
            if n not in seen:
                seen.add(n)
                nodes.append(n)
        except Exception:
            continue
    return nodes[:max_nodes]


async def tcping(node: Node, timeout: float):
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(node.ip, node.port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return round((time.perf_counter() - start) * 1000, 2)
    except Exception:
        return None


async def measure_speed_async(node: Node, timeout: float):
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    start_time = time.perf_counter()
    total_received = 0
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                node.ip,
                node.port,
                ssl=ssl_context,
                server_hostname=SPEED_DOMAIN,
            ),
            timeout=3.0,
        )

        request = (
            f"GET {SPEED_PATH}?bytes={SPEED_BYTES} HTTP/1.1\r\n"
            f"Host: {SPEED_DOMAIN}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode("utf-8"))
        await writer.drain()

        while True:
            if time.perf_counter() - start_time > timeout:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(16384), timeout=2.0)
                if not chunk:
                    break
                total_received += len(chunk)
            except asyncio.TimeoutError:
                break

        writer.close()
        await writer.wait_closed()

        duration = time.perf_counter() - start_time
        if duration <= 0 or total_received < 1024:
            return 0.0

        mbps = round((total_received * 8) / (duration * 1_000_000), 2)
        return mbps if mbps <= 1000 else 0.0
    except Exception:
        return 0.0


# ================= 云端上传与通知模块 =================
def upload_to_r2(cfg):
    if cfg["USE_R2"] != "true":
        return "🚫 已禁用"
    print("☁️ 正在上传 best_ips.txt 至 Cloudflare R2...")
    try:
        import boto3
        s3 = boto3.client(
            's3',
            endpoint_url=f"https://{cfg['CF_ACCOUNT_ID']}.r2.cloudflarestorage.com",
            aws_access_key_id=cfg['CF_ACCESS_KEY'],
            aws_secret_access_key=cfg['CF_SECRET_KEY']
        )
        if BEST_OUTPUT.exists():
            s3.upload_file(str(BEST_OUTPUT), cfg['CF_BUCKET_NAME'], 'best_ips.txt', ExtraArgs={'ContentType': 'text/plain'})
        print("    └─ ✅ R2 上传成功")
        return "✅ 成功"
    except Exception as e:
        print(f"    └─ ❌ R2 上传失败: {e}")
        return "❌ 失败"


def upload_to_github(cfg, top_ip):
    if cfg["USE_GH"] != "true":
        return "🚫 已禁用"
    print("🐙 正在通过 API 同步 best_ips.txt 至 GitHub 仓库...")
    
    token = cfg["GH_TOKEN"]
    owner = cfg["GH_OWNER"]
    repo = cfg["GH_REPO_NAME"]
    file = "best_ips.txt"
    
    if not BEST_OUTPUT.exists():
        return "❌ 失败 (本地文件不存在)"
        
    api_base = f"https://api.github.com/repos/{owner}/{repo}/contents/{file}"
    
    # 构建高度兼容的 SSL 上下文，防止代理或握手中断
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # 最多重试 3 次，防止网络波动导致偶尔 EOF 报错
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(api_base, headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "Mozilla/5.0"
            })
            sha = ""
            try:
                with urllib.request.urlopen(req, context=ssl_context, timeout=15) as resp:
                    data = json.loads(resp.read().decode())
                    sha = data.get("sha", "")
            except Exception:
                pass

            content_b64 = base64.b64encode(BEST_OUTPUT.read_bytes()).decode()
            payload = {
                "message": f"Update best_ips.txt: {top_ip}",
                "content": content_b64
            }
            if sha:
                payload["sha"] = sha

            put_req = urllib.request.Request(api_base, data=json.dumps(payload).encode(), headers={
                "Authorization": f"token {token}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
                "User-Agent": "Mozilla/5.0"
            }, method="PUT")
            
            with urllib.request.urlopen(put_req, context=ssl_context, timeout=15) as resp:
                if resp.status in (200, 201):
                    print("    └─ ✅ GitHub 同步成功")
                    return "✅ 成功 (API)"
        except Exception as e:
            if attempt < 3:
                print(f"    └─ ⚠️ GitHub 同步第 {attempt} 次尝试遇到网络波动，正在重试... ({e})")
                time.sleep(2)
            else:
                print(f"    └─ ❌ GitHub 同步最终失败: {e}")
                return "❌ 失败"
    return "❌ 失败"


def send_telegram(cfg, fast_count, top_ip, r2_msg, gh_msg):
    if cfg["USE_TG"] != "true":
        return
    print("📢 正在发送 Telegram 通知...")
    msg_text = (
        f"<b>📊 IP 优选战报</b>\n"
        f"----------------------------\n"
        f"✨ <b>优选任务已完成</b>\n"
        f"🏆 <b>达标优选</b>: <code>{fast_count}</code>\n"
        f"💡 <b>最快 IP</b>: <code>{top_ip}</code>\n"
        f"----------------------------\n"
        f"☁️ <b>Cloudflare R2</b>: {r2_msg}\n"
        f"🐙 <b>GitHub 同步</b>: {gh_msg}\n"
        f"⏰ <b>时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
    )
    url = f"https://api.telegram.org/bot{cfg['TG_BOT_TOKEN']}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": cfg["TG_CHAT_ID"],
        "parse_mode": "HTML",
        "text": msg_text
    }).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("    └─ ✅ Telegram 通知已发送")
    except Exception as e:
        print(f"    └─ ❌ Telegram 发送失败: {e}")


def send_email(cfg, fast_count, top_ip, r2_msg, gh_msg):
    if cfg["USE_MAIL"] != "true":
        return
    print("📧 正在发送 Email 邮件通知...")
    try:
        html_body = (
            f"<b>📊 优选 IP 战报</b><br>"
            f"达标优选数量: {fast_count}<br>"
            f"最快 IP: {top_ip}<br>"
            f"R2存储: {r2_msg} | GitHub: {gh_msg}<br>"
            f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        msg = MIMEText(html_body, 'html', 'utf-8')
        msg['From'] = f"{Header('Cloudflare Bot', 'utf-8')} <{cfg['MAIL_USER']}>"
        msg['To'] = cfg['MAIL_TO']
        msg['Subject'] = Header("🚀 IP 优选战报通知", 'utf-8')

        server = smtplib.SMTP_SSL(cfg['MAIL_HOST'], 465, timeout=15)
        server.login(cfg['MAIL_USER'], cfg['MAIL_PASS'])
        server.sendmail(cfg['MAIL_USER'], [cfg['MAIL_TO']], msg.as_string())
        server.quit()
        print("    └─ ✅ 邮件发送成功")
    except Exception as e:
        print(f"    └─ ❌ 邮件发送失败: {e}")


# ================= 主流程与进度条测速逻辑 =================
async def run_speedtest(cfg):
    start_time = time.time()
    
    raw_content = fetch_ips_content(cfg["INPUT_URL"], float(cfg["DOWNLOAD_TIMEOUT"]))
    if not raw_content:
        print("❌ 错误: 无法从云端下载 IP 资源！")
        return False

    nodes = parse_nodes_from_text(raw_content, int(cfg["MAX_NODES"]))
    total_nodes = len(nodes)
    if total_nodes == 0:
        print("❌ 错误: 解析到的可用节点数为 0！")
        return False

    tcp_workers = int(cfg["TCP_WORKERS"])
    tcp_timeout = float(cfg["TCP_TIMEOUT"])
    print(f"🚀 开始 TCP 延迟测试：并发 {tcp_workers}, 限时 {tcp_timeout}s, 总节点数 {total_nodes}")

    tcp_results = []
    sem = asyncio.Semaphore(tcp_workers)

    async def t_task(n, pbar):
        async with sem:
            lat = await tcping(n, tcp_timeout)
            if lat:
                tcp_results.append((n, lat))
            await pbar.update(1)

    speed_results = []
    speed_min = float(cfg["SPEED_MIN"])

    try:
        pbar_tcp = SimpleProgressBar(total_nodes, desc="TCP 延迟测试")
        await asyncio.gather(*(t_task(n, pbar_tcp) for n in nodes))
        pbar_tcp.close()

        groups = defaultdict(list)
        top_per_region = int(cfg["TOP_PER_REGION"])
        for n, lat in tcp_results:
            groups[n.region].append((n, lat))
        candidates = []
        for reg in groups:
            candidates.extend(sorted(groups[reg], key=lambda x: x[1])[:top_per_region])

        speed_workers = int(cfg["SPEED_WORKERS"])
        speed_timeout = float(cfg["SPEED_TIMEOUT"])
        print(f"📢 开始下载带宽测试：并发 {speed_workers}, 最低要求 {speed_min} Mbps, 候选数 {len(candidates)}")

        sem_s = asyncio.Semaphore(speed_workers)

        async def s_task(n, lat, pbar_s):
            async with sem_s:
                s = await measure_speed_async(n, speed_timeout)
                speed_results.append((n, lat, s))
                await pbar_s.update(1)

        pbar_speed = SimpleProgressBar(len(candidates), desc="带宽测速中")
        await asyncio.gather(*(s_task(n, lat, pbar_speed) for n, lat in candidates))
        pbar_speed.close()

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n\n⚠️ 检测到用户手动中断，正在紧急保存已测出的成果...")
    except Exception as e:
        print(f"\n\n⚠️ 发生异常中断: {e}，正在紧急保存已测出的成果...")

    if speed_results:
        speed_results.sort(key=lambda x: (x[1], -x[2]))
        fast_count = 0
        with BEST_OUTPUT.open("w", encoding="utf-8") as f2:
            for n, lat, s in speed_results:
                is_fast = s >= speed_min
                if is_fast:
                    line = f"{n.raw} [{lat}ms {s}Mbps]\n"
                    f2.write(line)
                    fast_count += 1

        duration = int(time.time() - start_time)
        print("\n" + "=" * 40)
        print(f"✨ 优选任务结束！总耗时: {duration}s")
        print(f"📊 已完成测速节点数: {len(speed_results)}")
        print(f"🏆 达标优选 IP 数量 (best_ips.txt): {fast_count}")
        print("=" * 40 + "\n")

        top_ip = "N/A"
        if BEST_OUTPUT.exists():
            try:
                lines = BEST_OUTPUT.read_text(encoding="utf-8").splitlines()
                if lines:
                    top_ip = lines[0].split()[0]
            except Exception:
                pass

        r2_msg = upload_to_r2(cfg)
        gh_msg = upload_to_github(cfg, top_ip)
        send_telegram(cfg, fast_count, top_ip, r2_msg, gh_msg)
        send_email(cfg, fast_count, top_ip, r2_msg, gh_msg)

        return True
    else:
        print("💡 尚未完成任何节点的测速，未生成结果文件。")
        return False


# ================= 辅助函数：带 ESC 返回的数值输入校验 =================
def prompt_number(prompt_title, current_val, is_float=False):
    while True:
        msg = f"{prompt_title} (当前: {current_val}) [按 ESC 返回]: "
        val = get_input_with_esc(msg)
        if val is None:
            print("🔙 已按下 ESC，返回上一页。")
            return None
        val = val.strip()
        if not val:
            return current_val  # 直接回车保持不变
        try:
            if is_float:
                num = float(val)
                if num < 0:
                    print("❌ 数值不能为负数，请重新输入！")
                    continue
                return str(num)
            else:
                num = int(val)
                if num <= 0:
                    print("❌ 请输入大于 0 的正整数！")
                    continue
                return str(num)
        except ValueError:
            print("❌ 格式错误：请输入有效的数值（例如纯数字）！")


# ================= 云服务独立配置子菜单 =================
def config_r2_menu(cfg):
    while True:
        print("\n☁️  [ Cloudflare R2 存储配置与详情 ]")
        print("=" * 45)
        print(f" 1. 启停开关 (USE_R2)   --> [{cfg['USE_R2']}]")
        print(f" 2. 账户 ID (Account ID) --> [{cfg['CF_ACCOUNT_ID'] or '[未设置]'}]")
        print(f" 3. Access Key ID       --> [{mask_str(cfg['CF_ACCESS_KEY'])}]")
        print(f" 4. Secret Access Key   --> [{mask_str(cfg['CF_SECRET_KEY'])}]")
        print(f" 5. 存储桶名 (Bucket)   --> [{cfg['CF_BUCKET_NAME'] or '[未设置]'}]")
        print(" ---------------------------------------------")
        print(" 0. 返回上级菜单")
        print("=" * 45)
        choice = input("请选择要修改的 R2 项目编号: ").strip()
        if choice == "1":
            cfg["USE_R2"] = "false" if cfg["USE_R2"] == "true" else "true"
            print(f"✅ R2 开关已切换为: {cfg['USE_R2']}")
        elif choice == "2":
            val = get_input_with_esc(f"输入新的账户 ID (当前: {cfg['CF_ACCOUNT_ID']}) [按 ESC 返回]: ")
            if val is not None: cfg["CF_ACCOUNT_ID"] = val.strip(); print("✅ 已更新。")
        elif choice == "3":
            val = get_input_with_esc("输入新的 Access Key [按 ESC 返回]: ")
            if val is not None: cfg["CF_ACCESS_KEY"] = val.strip(); print("✅ 已更新。")
        elif choice == "4":
            val = get_input_with_esc("输入新的 Secret Key [按 ESC 返回]: ")
            if val is not None: cfg["CF_SECRET_KEY"] = val.strip(); print("✅ 已更新。")
        elif choice == "5":
            val = get_input_with_esc(f"输入新的 Bucket Name (当前: {cfg['CF_BUCKET_NAME']}) [按 ESC 返回]: ")
            if val is not None: cfg["CF_BUCKET_NAME"] = val.strip(); print("✅ 已更新。")
        elif choice == "0":
            break
        else:
            print("❌ 无效选项。")
        save_config_to_self(cfg)


def config_github_menu(cfg):
    while True:
        print("\n🐙  [ GitHub 仓库同步配置与详情 ]")
        print("=" * 45)
        print(f" 1. 启停开关 (USE_GH)   --> [{cfg['USE_GH']}]")
        print(f" 2. 用户名/组织 (Owner) --> [{cfg['GH_OWNER'] or '[未设置]'}]")
        print(f" 3. 仓库名称 (Repo)     --> [{cfg['GH_REPO_NAME'] or '[未设置]'}]")
        print(f" 4. 访问令牌 (Token)    --> [{mask_str(cfg['GH_TOKEN'])}]")
        print(" ---------------------------------------------")
        print(" 0. 返回上级菜单")
        print("=" * 45)
        choice = input("请选择要修改的 GitHub 项目编号: ").strip()
        if choice == "1":
            cfg["USE_GH"] = "false" if cfg["USE_GH"] == "true" else "true"
            print(f"✅ GitHub 开关已切换为: {cfg['USE_GH']}")
        elif choice == "2":
            val = get_input_with_esc(f"输入新的 GitHub 用户名/组织 (当前: {cfg['GH_OWNER']}) [按 ESC 返回]: ")
            if val is not None: cfg["GH_OWNER"] = val.strip(); print("✅ 已更新。")
        elif choice == "3":
            val = get_input_with_esc(f"输入新的 GitHub 仓库名 (当前: {cfg['GH_REPO_NAME']}) [按 ESC 返回]: ")
            if val is not None: cfg["GH_REPO_NAME"] = val.strip(); print("✅ 已更新。")
        elif choice == "4":
            val = get_input_with_esc("输入新的 GitHub Token (classic) [按 ESC 返回]: ")
            if val is not None: cfg["GH_TOKEN"] = val.strip(); print("✅ 已更新。")
        elif choice == "0":
            break
        else:
            print("❌ 无效选项。")
        save_config_to_self(cfg)


def config_telegram_menu(cfg):
    while True:
        print("\n📢  [ Telegram 通知配置与详情 ]")
        print("=" * 45)
        print(f" 1. 启停开关 (USE_TG)   --> [{cfg['USE_TG']}]")
        print(f" 2. Bot Token          --> [{mask_str(cfg['TG_BOT_TOKEN'])}]")
        print(f" 3. 接收 Chat ID        --> [{cfg['TG_CHAT_ID'] or '[未设置]'}]")
        print(" ---------------------------------------------")
        print(" 0. 返回上级菜单")
        print("=" * 45)
        choice = input("请选择要修改的 Telegram 项目编号: ").strip()
        if choice == "1":
            cfg["USE_TG"] = "false" if cfg["USE_TG"] == "true" else "true"
            print(f"✅ Telegram 开关已切换为: {cfg['USE_TG']}")
        elif choice == "2":
            val = get_input_with_esc("输入新的 Telegram Bot Token [按 ESC 返回]: ")
            if val is not None: cfg["TG_BOT_TOKEN"] = val.strip(); print("✅ 已更新。")
        elif choice == "3":
            val = get_input_with_esc(f"输入新的 Chat ID (当前: {cfg['TG_CHAT_ID']}) [按 ESC 返回]: ")
            if val is not None: cfg["TG_CHAT_ID"] = val.strip(); print("✅ 已更新。")
        elif choice == "0":
            break
        else:
            print("❌ 无效选项。")
        save_config_to_self(cfg)


def config_email_menu(cfg):
    while True:
        print("\n📧  [ Email 邮件通知配置与详情 ]")
        print("=" * 45)
        print(f" 1. 启停开关 (USE_MAIL) --> [{cfg['USE_MAIL']}]")
        print(f" 2. SMTP 服务器         --> [{cfg['MAIL_HOST']}]")
        print(f" 3. 发件人邮箱          --> [{cfg['MAIL_USER'] or '[未设置]'}]")
        print(f" 4. 邮箱授权码/密码     --> [{mask_str(cfg['MAIL_PASS'])}]")
        print(f" 5. 收件人邮箱          --> [{cfg['MAIL_TO'] or '[未设置]'}]")
        print(" ---------------------------------------------")
        print(" 0. 返回上级菜单")
        print("=" * 45)
        choice = input("请选择要修改的 Email 项目编号: ").strip()
        if choice == "1":
            cfg["USE_MAIL"] = "false" if cfg["USE_MAIL"] == "true" else "true"
            print(f"✅ Email 开关已切换为: {cfg['USE_MAIL']}")
        elif choice == "2":
            val = get_input_with_esc(f"输入新的 SMTP 服务器 (当前: {cfg['MAIL_HOST']}) [按 ESC 返回]: ")
            if val is not None: cfg["MAIL_HOST"] = val.strip() or "smtp.qq.com"; print("✅ 已更新。")
        elif choice == "3":
            val = get_input_with_esc(f"输入新的发件人邮箱 (当前: {cfg['MAIL_USER']}) [按 ESC 返回]: ")
            if val is not None: cfg["MAIL_USER"] = val.strip(); print("✅ 已更新。")
        elif choice == "4":
            val = get_input_with_esc("输入新的邮箱授权码 [按 ESC 返回]: ")
            if val is not None: cfg["MAIL_PASS"] = val.strip(); print("✅ 已更新。")
        elif choice == "5":
            val = get_input_with_esc(f"输入新的收件人邮箱 (当前: {cfg['MAIL_TO']}) [按 ESC 返回]: ")
            if val is not None: cfg["MAIL_TO"] = val.strip(); print("✅ 已更新。")
        elif choice == "0":
            break
        else:
            print("❌ 无效选项。")
        save_config_to_self(cfg)


# ================= 参数设置子菜单（主设置界面） =================
def settings_menu():
    cfg = load_config()
    while True:
        try:
            print("\n⚙️  [ 参数与云端服务设置  ]")
            print("=" * 50)
            print(" --- 【测速及筛选参数】 ---")
            print(f" 1. TCP 测速并发线程  --> [{cfg['TCP_WORKERS']}]")
            print(f" 2. TCP 延迟上限超时  --> [{cfg['TCP_TIMEOUT']}s]")
            print(f" 3. 下载测速并发线程  --> [{cfg['SPEED_WORKERS']}]")
            print(f" 4. 下载测速超时时间  --> [{cfg['SPEED_TIMEOUT']}s]")
            print(f" 5. 最低达标速度下限  --> [{cfg['SPEED_MIN']} Mbps]")
            print(f" 6. 每个地区 IP 保留数 --> [{cfg['TOP_PER_REGION']} 个]")
            print(f" 7. IP 来源链接地址   --> [{cfg['INPUT_URL']}]")
            print(" --- 【云端上传与通知服务 】 ---")
            print(f" 8. Cloudflare R2 设置  --> [{cfg['USE_R2']}]")
            print(f" 9. GitHub 仓库同步设置 --> [{cfg['USE_GH']}]")
            print(f" 10. Telegram 通知设置  --> [{cfg['USE_TG']}]")
            print(f" 11. Email 邮件通知设置 --> [{cfg['USE_MAIL']}]")
            print(" --------------------------------------------------")
            print(" 0. 保存所有修改并返回主菜单")
            print("=" * 50)
            choice = input("请选择功能编号: ").strip()

            if choice == "1":
                res = prompt_number("输入新的 TCP 测速并发线程", cfg['TCP_WORKERS'], is_float=False)
                if res is not None: cfg["TCP_WORKERS"] = res
            elif choice == "2":
                res = prompt_number("输入新的 TCP 延迟上限超时", cfg['TCP_TIMEOUT'], is_float=True)
                if res is not None: cfg["TCP_TIMEOUT"] = res
            elif choice == "3":
                res = prompt_number("输入新的下载测速并发线程", cfg['SPEED_WORKERS'], is_float=False)
                if res is not None: cfg["SPEED_WORKERS"] = res
            elif choice == "4":
                res = prompt_number("输入新的下载测速超时时间", cfg['SPEED_TIMEOUT'], is_float=True)
                if res is not None: cfg["SPEED_TIMEOUT"] = res
            elif choice == "5":
                res = prompt_number("输入新的最低达标速度 Mbps", cfg['SPEED_MIN'], is_float=True)
                if res is not None: cfg["SPEED_MIN"] = res
            elif choice == "6":
                res = prompt_number("输入每个地区保留的 IP 数量", cfg['TOP_PER_REGION'], is_float=False)
                if res is not None: cfg["TOP_PER_REGION"] = res
            elif choice == "7":
                val = get_input_with_esc(f"输入新的 IP 来源 URL (当前: {cfg['INPUT_URL']}) [按 ESC 返回]: ")
                if val is None:
                    print("🔙 已按下 ESC，返回上一页。")
                elif val.strip():
                    cfg["INPUT_URL"] = val.strip()
            elif choice == "8":
                config_r2_menu(cfg)
            elif choice == "9":
                config_github_menu(cfg)
            elif choice == "10":
                config_telegram_menu(cfg)
            elif choice == "11":
                config_email_menu(cfg)
            elif choice == "0":
                if save_config_to_self(cfg):
                    print("💾 参数已成功固化写入脚本并返回主菜单！")
                else:
                    print("⚠️ 固化保存失败。")
                break
            else:
                print("❌ 无效的选项，请重新输入。")
                continue
            
            # 实时固化到脚本自身
            save_config_to_self(cfg)
            print("✅ 修改已自动固化保存。")

        except (KeyboardInterrupt, EOFError):
            print("\n🔙 已取消修改并返回主菜单。")
            break
        except Exception as e:
            print(f"\n⚠️ 设置出错: {e}")
            break


# ================= 主程序入口（主菜单） =================
def main():
    while True:
        cfg = load_config()
        print("\n" + "=" * 45)
        print(" 🚀 智能优选Cloudflare IP")
        print("=" * 45)
        print(" 1. 立即运行测速")
        print(" 2. 参数与云端服务设置 ")
        print(" 0. 退出程序")
        print("=" * 45)
        try:
            choice = input("请输入功能编号: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n再见！")
            break

        if choice == "1":
            try:
                asyncio.run(run_speedtest(cfg))
            except KeyboardInterrupt:
                print("\n操作已取消。")
            
            # 测速完成后，按 ESC 键返回主菜单
            wait_for_esc("\n✨ 测速已完成，按 ESC 键返回主菜单...")
            
        elif choice == "2":
            settings_menu()
        elif choice == "0":
            print("再见！")
            break
        else:
            print("❌ 输入错误，请重新选择。")


if __name__ == "__main__":
    main()
