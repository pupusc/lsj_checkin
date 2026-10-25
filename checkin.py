#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
司机社（Discuz + k_misign 签到插件）每日签到 —— GitHub Actions / 本地 Python 版

零依赖：仅用 Python 标准库（urllib），Python 3.8+ 直接运行，无需 pip install。

流程：候选地址测速选最快 → 登录 → 每日签到 → 校验结果

配置（环境变量，GitHub 上放 Secrets）：
  SIJISHE_USER    账号
  SIJISHE_PASS    密码
  SIJISHE_COOKIE  可选。从浏览器复制的论坛 Cookie（需含 *_auth 和 *_saltkey 两项），
                  提供后优先使用，可避免频繁账密登录触发风控。

本地运行：  SIJISHE_USER=xxx SIJISHE_PASS=xxx python checkin.py
GitHub：    见 README.md（配置 Secrets 后由 Actions 每天定时运行）
"""

import hashlib
import os
import re
import ssl
import sys
import time
from http import cookiejar
from urllib import error as urlerror, parse, request as urlrequest

PUBLISH_URL = "https://www.47447.net/"          # 官方发布页（拦截非浏览器请求，失败自动跳过）
CANDIDATES = [                                   # 兜底地址列表，请与发布页保持一致
    "https://dlsjs.com",
    "https://dlsjs.net",
    "https://sjs96.com",
    "https://xsijishe.net",
]
SIGN_PAGE = "/k_misign-sign.html"
LOGIN_PAGE = "/member.php?mod=logging&action=login"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
PING_ROUNDS = 3
PING_TIMEOUT = 8

USERNAME = os.environ.get("SIJISHE_USER", "").strip()
PASSWORD = os.environ.get("SIJISHE_PASS", "").strip()
RAW_COOKIE = os.environ.get("SIJISHE_COOKIE", "").strip()

JAR = cookiejar.CookieJar()
VERIFY_SSL = True
OPENER = None


def build_opener(verify=True):
    handlers = [urlrequest.HTTPCookieProcessor(JAR)]
    if not verify:
        handlers.append(urlrequest.HTTPSHandler(
            context=ssl._create_unverified_context()))
    op = urlrequest.build_opener(*handlers)
    op.addheaders = [("User-Agent", UA), ("Accept-Language", "zh-CN,zh;q=0.9")]
    return op


def _is_ssl_error(exc):
    reason = getattr(exc, "reason", None)
    return isinstance(reason, ssl.SSLError) or "CERTIFICATE" in str(reason).upper()


def open_with_challenge(url, data=None, referer=None, timeout=30, tries=3):
    """打开请求并自动通过站点防护挑战。

    站点（Cloudflare/WAF）对无 Cookie 的首次请求返回 403 挑战页，
    但挑战 Cookie 会随响应的 Set-Cookie 下发（无需执行其 JS），
    因此 403 后带着 CookieJar 里的新 Cookie 重试即可通过。
    返回响应对象；调用方自行 read()。
    """
    global VERIFY_SSL, OPENER
    last_err = None
    for _ in range(tries):
        body = parse.urlencode(data).encode("utf-8") if isinstance(data, dict) else data
        req = urlrequest.Request(url, data=body)
        if referer:
            req.add_header("Referer", referer)
        try:
            return OPENER.open(req, timeout=timeout)
        except urlerror.HTTPError as e:
            if e.code == 403:
                last_err = e
                time.sleep(0.6)
                continue
            raise
        except urlrequest.URLError as e:
            if _is_ssl_error(e) and VERIFY_SSL:
                print("  ⚠ 证书校验异常，本次运行改为跳过证书校验")
                VERIFY_SSL = False
                OPENER = build_opener(verify=False)
                last_err = e
                continue
            raise
    raise RuntimeError("请求失败（403 挑战重试 %d 次仍未通过）：%s" % (tries, url))


def http(url, data=None, referer=None, timeout=30):
    """GET（或表单 POST，data 传 dict），返回解码后的响应文本"""
    resp = open_with_challenge(url, data=data, referer=referer, timeout=timeout)
    raw = resp.read()
    m = re.search(r"charset=([\w-]+)", resp.headers.get("Content-Type", ""))
    charset = m.group(1) if m else "utf-8"
    try:
        return raw.decode(charset, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def has_auth_cookie():
    return any(c.name.endswith("_auth") for c in JAR)


def looks_logged_in(html):
    """页头有退出链接即视为已登录（游客页面也会出现 uid 主页链接，不可作为依据）"""
    return "action=logout" in html


# ──────────────── 测速选站 ────────────────

def parse_publish_lines():
    """尽力从发布页解析最新地址列表（非浏览器客户端可能被 403，失败则忽略）"""
    try:
        html = http(PUBLISH_URL, timeout=10)
        m = re.search(r"lines:\s*\[([\s\S]*?)\]", html)
        if m:
            urls = re.findall(r"url:\s*[\"']([^\"']+)[\"']", m.group(1))
            out = [u if u.lower().startswith("http") else "https://" + u for u in urls]
            if out:
                return out
    except Exception:
        pass
    return None


def ping_once(base):
    t0 = time.perf_counter()
    open_with_challenge(base + "/?_ping=" + str(int(time.time() * 1000)),
                        timeout=PING_TIMEOUT).close()  # 拿到响应头即计时，不下载页面
    return (time.perf_counter() - t0) * 1000


def pick_best(candidates):
    print("[1/3] 测速（每地址 %d 轮取最小，超时 %ds）" % (PING_ROUNDS, PING_TIMEOUT))
    results = []
    for c in candidates:
        best = None
        for i in range(PING_ROUNDS):
            try:
                ms = ping_once(c)
                best = ms if best is None else min(best, ms)
            except Exception:
                pass
            time.sleep(0.1)
        results.append((c, best))
        print("    %-30s%s" % (c, "超时" if best is None else "%.0f ms" % best))
    ok = sorted([r for r in results if r[1] is not None], key=lambda x: x[1])
    if not ok:
        raise RuntimeError("所有候选地址均无法连接"
                           "（若在 GitHub 上运行，可能是站点屏蔽了数据中心 IP）")
    print("    ✅ 选用：%s（%.0f ms）" % ok[0])
    return ok[0][0]


# ──────────────── 登录 ────────────────

def do_login(base, password):
    """POST 登录表单；返回 (是否成功, 错误信息)"""
    html = http(base + LOGIN_PAGE, referer=base + "/")
    m = re.search(r'<form[^>]*name="login"[^>]*action="([^"]+)"', html)
    if not m:
        return False, "登录页解析失败：未找到登录表单"
    action = parse.urljoin(base + "/", m.group(1).replace("&amp;", "&"))
    fh = re.search(r'name="formhash"\s+value="([a-f0-9]{8})"', html)
    data = {
        "formhash": fh.group(1) if fh else "",
        "referer": base + "/",
        "username": USERNAME,
        "password": password,
        "questionid": "0",
        "answer": "",
        "cookietime": "2592000",
        "loginsubmit": "true",
    }
    resp_html = http(action, data=data, referer=base + LOGIN_PAGE)
    if has_auth_cookie():
        return True, ""
    msg = re.search(r"<!\[CDATA\[([\s\S]*?)\]\]>", resp_html)
    return False, (msg.group(1).strip() if msg else resp_html[:120])


# ──────────────── 签到 ────────────────

def extract_rank(html):
    m = re.search(r"您的签到排名[：:]\s*(\d+)", html)
    return ("签到排名 " + m.group(1)) if m else ""


def do_sign(base):
    """返回 (状态, 附加信息)；状态: signed=本次签到成功 / already=今天已签到"""
    html = http(base + SIGN_PAGE, referer=base + "/")
    if not (looks_logged_in(html) and has_auth_cookie()):
        raise RuntimeError("签到页显示未登录，登录流程未生效")
    if "您今天还没有签到" not in html:
        return "already", extract_rank(html)

    m = (re.search(r'id="JD_sign"[^>]*href="([^"]*)"', html)
         or re.search(r'href="([^"]*)"[^>]*id="JD_sign"', html)
         or re.search(r'href="(plugin\.php\?id=k_misign:sign[^"]*operation=qiandao[^"]*)"', html))
    if not m:
        raise RuntimeError("签到页解析失败：未找到签到按钮链接")
    api = parse.urljoin(base + "/", m.group(1).replace("&amp;", "&"))
    api_body = http(api, referer=base + SIGN_PAGE)[:150]

    html2 = http(base + SIGN_PAGE, referer=base + "/")
    if "您今天还没有签到" in html2:
        raise RuntimeError("调用签到接口后页面仍显示未签到（接口返回：%s）" % api_body)
    return "signed", extract_rank(html2)


# ──────────────── 主流程 ────────────────

def load_cookie(base):
    """把浏览器导出的 Cookie 字符串塞进 CookieJar"""
    host = parse.urlparse(base).hostname
    for kv in RAW_COOKIE.split(";"):
        if "=" not in kv:
            continue
        k, v = kv.strip().split("=", 1)
        JAR.set_cookie(cookiejar.Cookie(
            version=0, name=k, value=v, port=None, port_specified=False,
            domain=host, domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False, expires=None,
            discard=False, comment=None, comment_url=None, rest={}, rfc2109=False))


def main():
    print("🚗 司机社每日签到（Python 版）")
    print("─" * 46)
    if not (USERNAME and PASSWORD) and not RAW_COOKIE:
        print("❌ 未配置账号：请设置环境变量 SIJISHE_USER / SIJISHE_PASS（或 SIJISHE_COOKIE）")
        return 1

    addrs = parse_publish_lines() or CANDIDATES
    print("[0/3] 候选地址（来源：%s）：%s"
          % ("发布页" if addrs != CANDIDATES else "内置列表", ", ".join(addrs)))
    base = pick_best(addrs).rstrip("/")
    print("[2/3] 登录态…")
    if RAW_COOKIE:
        load_cookie(base)
        print("    已加载 SIJISHE_COOKIE")

    probe = http(base + SIGN_PAGE)
    if not (has_auth_cookie() and looks_logged_in(probe)):  # 未登录（auth Cookie 是硬指标）
        if not (USERNAME and PASSWORD):
            print("❌ Cookie 无效且未配置账号密码")
            return 1
        print("    账密登录 %s（账号：%s）…" % (parse.urlparse(base).hostname, USERNAME))
        # 该站前端登录时会把密码转成 MD5 提交（浏览器实测确认），故先试 MD5 再试明文
        md5pw = hashlib.md5(PASSWORD.encode("utf-8")).hexdigest()
        ok, err = do_login(base, md5pw)
        if not ok and md5pw != PASSWORD:
            ok, err2 = do_login(base, PASSWORD)
            err = err or err2
        if not ok or not has_auth_cookie():
            print("❌ 登录失败：%s" % (err or "未获取到登录态 Cookie"))
            return 1
    print("    ✅ 已登录")

    print("[3/3] 执行每日签到…")
    status, extra = do_sign(base)
    if status == "already":
        print("    ✅ 今天已签到过啦%s" % (("（%s）" % extra) if extra else ""))
    else:
        print("    🎉 签到成功！%s" % extra)
    print("\n🎉 全部完成。")
    return 0


if __name__ == "__main__":
    OPENER = build_opener()
    try:
        sys.exit(main())
    except Exception as e:
        print("❌ 失败：%s" % e)
        sys.exit(1)
