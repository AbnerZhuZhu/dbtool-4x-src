# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         __init__.py
# Description:  
# Author:       xaoyaoo
# Date:         2023/12/14
# -------------------------------------------------------------------------------
import os
import subprocess
import sys
import time
import uvicorn
import mimetypes
import logging
from logging.handlers import RotatingFileHandler

from uvicorn.config import LOGGING_CONFIG
from fastapi import FastAPI, Request, Path, Query
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse, FileResponse

from .utils import gc, is_port_in_use, server_loger
from .rjson import ReJson
from .remote_server import rs_api
from .local_server import ls_api

from pywxdump import __version__


def gen_fastapi_app(handler, origins=None):
    app = FastAPI(title="wxdump", description="微信工具", version=__version__,
                  terms_of_service="https://github.com/xaoyaoo/pywxdump",
                  contact={"name": "xaoyaoo", "url": "https://github.com/xaoyaoo/pywxdump"},
                  license_info={"name": "MIT License",
                                "url": "https://github.com/xaoyaoo/PyWxDump/blob/master/LICENSE"})

    web_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "web")  # web文件夹路径
    # 跨域
    if not origins:
        origins = [
            "http://localhost:5000",
            "http://127.0.0.1:5000",
            "http://localhost:8080",  # 开发环境的客户端地址"
            # "http://0.0.0.0:5000",
            # "*"
        ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,  # 允许所有源
        allow_credentials=True,
        allow_methods=["*"],  # 允许所有方法
        allow_headers=["*"],  # 允许所有头
    )

    @app.on_event("startup")
    async def startup_event():
        logger = logging.getLogger("uvicorn")
        logger.addHandler(handler)

    # 错误处理
    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
        # print(request.body)
        return ReJson(1002, {"detail": exc.errors()})

    # 首页
    @app.get("/")
    @app.get("/index.html")
    async def index():
        response = RedirectResponse(url="/s/index.html", status_code=307)
        return response

    # 路由挂载
    app.include_router(rs_api, prefix='/api/rs', tags=['远程api'])
    app.include_router(ls_api, prefix='/api/ls', tags=['本地api'])

    # 根据文件类型，设置mime_type，返回文件
    @app.get("/s/{filename:path}")
    async def serve_file(filename: str):
        # 构建完整的文件路径
        file_path = os.path.join(web_path, filename)
        file_path = os.path.abspath(file_path)

        # 检查文件是否存在
        if os.path.isfile(file_path):
            # 获取文件 MIME 类型
            mime_type, _ = mimetypes.guess_type(file_path)
            # 如果 MIME 类型为空，则默认为 application/octet-stream
            if mime_type is None:
                mime_type = "application/octet-stream"
                server_loger.warning(f"[+] 无法获取文件 MIME 类型，使用默认值：{mime_type}")
            if file_path.endswith(".js"):
                mime_type = "text/javascript"
            server_loger.info(f"[+] 文件 {file_path} MIME 类型：{mime_type}")
            # 返回文件
            return FileResponse(file_path, media_type=mime_type)

        # 如果文件不存在，返回 404
        return {"detail": "Not Found"}, 404

    # 静态文件挂载
    # if os.path.exists(os.path.join(web_path, "index.html")):
    #     app.mount("/s", StaticFiles(directory=web_path), name="static")

    return app


def find_free_port(host, start_port, max_try=50):
    """从 start_port 开始找一个能绑上的端口；找不到返回 None"""
    import socket
    for p in range(int(start_port), int(start_port) + max_try):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
                return p
            except socket.error:
                continue
    return None


def find_port_pids(port):
    """
    找出正在监听某个端口的进程 [(pid, 进程名, 命令行), ...]（纯查询，不做任何处理）。

    优先用 `netstat -ano`：本机实测 psutil.net_connections() 要 15 秒以上（它枚举全部连接），
    放在启动路径上会把「端口被占用」这件事变成卡死；netstat 一般 1 秒内出结果。
    """
    pids = set()
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=8,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
        for line in out.splitlines():
            f = line.split()
            if len(f) < 5 or f[0].upper() != "TCP":
                continue
            if f[1].endswith(f":{port}") and f[3].upper() == "LISTENING" and f[4].isdigit():
                pids.add(int(f[4]))
    except Exception:
        pass

    if not pids:  # 兜底（netstat 不可用或输出解析不到）
        try:
            import psutil
            for c in psutil.net_connections(kind="inet"):
                if c.laddr and getattr(c.laddr, "port", None) == int(port) and c.pid:
                    pids.add(c.pid)
        except Exception:
            pass

    result = []
    for pid in pids:
        if pid == os.getpid():
            continue  # 别把自己算进去
        name, cmdline = "?", ""
        try:
            import psutil
            proc = psutil.Process(pid)
            name, cmdline = proc.name(), " ".join(proc.cmdline() or [])[:200]
        except Exception:
            pass
        result.append((pid, name, cmdline))
    return result


def free_port(host, port, kill_port=False):
    """
    端口被占用时的处理：
      1. 先打印是谁占着（pid / 进程名 / 命令行）
      2. kill_port=True 且占用者是【本程序自己的 wxdump / uvicorn】时，结束它并复用原端口
      3. 其他情况（或杀不掉）自动换一个空闲端口，保证服务一定起得来
    返回最终要用的端口
    """
    if not is_port_in_use(host, port):
        return port

    holders = find_port_pids(port)
    print(f"[!] 端口 {port} 已被占用：")
    for pid, name, cmdline in holders:
        print(f"    pid={pid}  name={name}  cmd={cmdline}")
    if not holders:
        print("    （未能查到占用进程，可能是别的用户/更高权限的进程）")

    if kill_port and holders:
        import psutil
        killed = []
        for pid, name, cmdline in holders:
            low = cmdline.lower()
            # 只结束「一看就是上一次没退干净的 PyWxDump / uvicorn」的进程，避免误杀用户自己的程序
            if name.lower() in ("python.exe", "pythonw.exe", "wxdump.exe") and ("wxdump" in low or "uvicorn" in low):
                try:
                    psutil.Process(pid).terminate()
                    killed.append(pid)
                except Exception as e:
                    print(f"[!] 结束 pid={pid} 失败：{e}")
        if killed:
            time.sleep(1.5)
            print(f"[+] 已结束占用进程 {killed}")
            if not is_port_in_use(host, port):
                print(f"[+] 端口 {port} 已释放，继续使用 {port}")
                return port

    new_port = find_free_port(host, port)
    if new_port is None:
        print(f"[-] 从 {port} 起找了 50 个端口都被占用，请手动用 -p 指定一个空闲端口后重试")
        return None
    print(f"[+] 自动改用空闲端口 {new_port}（也可以用 -p {new_port} 固定下来）")
    return new_port


def start_server(port=5000, online=False, debug=False, isopenBrowser=True,
                 merge_path="", wx_path="", my_wxid="", kill_port=False,
                 key_file="", mode="auto", decrypted_dir="",
                 no_decrypt=False, force_decrypt=False):
    """
    启动flask
    :param port:  端口号
    :param online:  是否在线查看(局域网查看)
    :param debug:  是否开启debug模式
    :param isopenBrowser:  是否自动打开浏览器
    :param key_file:  【4.x】本地密钥文件（默认自动找 ~/.wechat-cli/all_keys.json）
    :param mode:      【4.x】auto（默认，自动准备） / 3x（完全走 3.x 老逻辑，不做 4.x 准备）
    :param decrypted_dir: 【4.x】解密产物目录（默认复用已有解密库或 work_path/decrypted_wx4）
    :param no_decrypt:     【4.x】完全不解密，只用 decrypted_dir 里现成的库
    :param force_decrypt:  【4.x】把已存在但比原始库旧的库也重新解密一遍
    :return:
    """
    work_path = os.path.join(os.getcwd(), "wxdump_work")  # 临时文件夹,用于存放图片等    # 全局变量
    if not os.path.exists(work_path):
        os.makedirs(work_path, exist_ok=True)
        server_loger.info(f"[+] 创建临时文件夹：{work_path}")
        print(f"[+] 创建临时文件夹：{work_path}")

    # 日志处理，写入到文件
    log_format = '[{levelname[0]}] {asctime} [{name}:{levelno}] {pathname}:{lineno} {message}'
    log_datefmt = '%Y-%m-%d %H:%M:%S'
    log_file_path = os.path.join(work_path, "wxdump.log")
    file_handler = RotatingFileHandler(log_file_path, mode="a", maxBytes=10 * 1024 * 1024, backupCount=3)
    formatter = logging.Formatter(fmt=log_format, datefmt=log_datefmt, style='{')
    file_handler.setFormatter(formatter)

    wx_core_logger = logging.getLogger("wx_core")
    db_prepare = logging.getLogger("db_prepare")

    # 这几个日志处理器为本项目的日志处理器
    server_loger.addHandler(file_handler)
    wx_core_logger.addHandler(file_handler)
    db_prepare.addHandler(file_handler)

    conf_file = os.path.join(work_path, "conf_auto.json")  # 用于存放各种基础信息
    auto_setting = "auto_setting"
    env_file = os.path.join(work_path, ".env")  # 用于存放环境变量
    # set 环境变量
    os.environ["PYWXDUMP_WORK_PATH"] = work_path
    os.environ["PYWXDUMP_CONF_FILE"] = conf_file
    os.environ["PYWXDUMP_AUTO_SETTING"] = auto_setting

    with open(env_file, "w", encoding="utf-8") as f:
        f.write(f"PYWXDUMP_WORK_PATH = '{work_path}'\n")
        f.write(f"PYWXDUMP_CONF_FILE = '{conf_file}'\n")
        f.write(f"PYWXDUMP_AUTO_SETTING = '{auto_setting}'\n")

    if merge_path and os.path.exists(merge_path):
        my_wxid = my_wxid if my_wxid else "wxid_dbshow"
        gc.set_conf(my_wxid, "wxid", my_wxid)  # 初始化wxid
        gc.set_conf(my_wxid, "merge_path", merge_path)  # 初始化merge_path
        gc.set_conf(my_wxid, "wx_path", wx_path)  # 初始化wx_path
        db_config = {"key": my_wxid, "type": "sqlite", "path": merge_path}
        gc.set_conf(my_wxid, "db_config", db_config)  # 初始化db_config
        gc.set_conf(auto_setting, "last", my_wxid)  # 初始化last

    # ---------------- 【4.x 改造 · 第三步】启动即自动准备 ----------------
    #   读本地密钥文件 → 用密钥 page1 HMAC 校验定位账号目录 → 增量解密 → 写好 conf。
    #   写完 conf 后：
    #     · /api/rs/is_init 会返回 True，前端不再跳「请先初始化数据」，也不需要填
    #       merge_all.db / 微信文件夹路径，直接进会话页；
    #     · /api/rs/* 这些接口都按 conf 里的 last + db_config 取库，这里已经指向 4.x 解密库。
    #   mode=3x 时整块跳过，3.x 老逻辑（上面的 merge_path / 界面手动初始化）完全不变。
    if str(mode).lower() not in ("3x", "3"):
        try:
            from pywxdump.wx_core.wx4_prepare import prepare_wx4
            print("[+] 微信 4.x 自动准备：读密钥文件 → 定位账号目录 → 检查解密库……")
            wx4 = prepare_wx4(key_file=key_file or None, wx_path=wx_path or None,
                              decrypted_dir=decrypted_dir or None, my_wxid=my_wxid or None,
                              no_decrypt=bool(no_decrypt), force_decrypt=bool(force_decrypt),
                              work_path=work_path, log=print)
            if wx4.get("ok"):
                mid = wx4["my_wxid"] or "wxid_wx4"
                gc.set_conf(mid, "wxid", wx4["my_wxid"] or mid)
                gc.set_conf(mid, "my_wxid", wx4["my_wxid"] or mid)
                gc.set_conf(mid, "wx_path", wx4["wx_path"])
                gc.set_conf(mid, "key_file", wx4["key_file"])
                gc.set_conf(mid, "key", "")
                gc.set_conf(mid, "merge_path", wx4["primary_db"])
                gc.set_conf(mid, "db_config", {
                    "key": mid,            # 只作连接池缓存键，用 wxid 保证稳定
                    "type": "sqlite",
                    "path": wx4["primary_db"],
                    "my_wxid": wx4["my_wxid"] or mid,
                    "decrypted_dir": wx4["decrypted_dir"],   # side 库（contact/session/头像）在这
                })
                gc.set_conf(auto_setting, "last", mid)
                print(f"[+] 4.x 自动初始化完成：wxid={wx4['my_wxid'] or '(未识别，IsSender 可能不准)'}")
                print(f"    原始库目录：{wx4['db_storage']}")
                print(f"    解密库目录：{wx4['decrypted_dir']}")
                print(f"    主库      ：{wx4['primary_db']}")
                print(f"    {wx4['msg']}")
                print("[+] UI 会直接加载该账号的全部会话，无需在界面上填任何路径")
            else:
                print(f"[-] 4.x 自动准备未完成：{wx4.get('msg')}")
                print("    服务照常启动；可加 --key_file/--wx_path 后重启，或在界面手动初始化"
                      "（3.x 逻辑不受影响）")
        except Exception as e:
            print(f"[-] 4.x 自动准备异常（已忽略，不影响 3.x）：{e}")

    # 检查端口是否被占用
    if online:
        host = '0.0.0.0'
    else:
        host = "127.0.0.1"

    if is_port_in_use(host, port):
        # 原逻辑是直接 print + input() 后退出，所以会看到
        #   Port 5000 is already in use. Choose a different port.
        # 这里改成：打印占用者 -> 需要时结束残留的 wxdump 进程 -> 否则自动换空闲端口。
        new_port = free_port(host, port, kill_port=bool(kill_port))
        if new_port is None:
            return  # 实在找不到端口才退出
        port = new_port
    if isopenBrowser:
        try:
            # 自动打开浏览器
            url = f"http://127.0.0.1:{port}/"
            # 根据操作系统使用不同的命令打开默认浏览器
            if sys.platform.startswith('darwin'):  # macOS
                subprocess.call(['open', url])
            elif sys.platform.startswith('win'):  # Windows
                subprocess.call(['start', url], shell=True)
            elif sys.platform.startswith('linux'):  # Linux
                subprocess.call(['xdg-open', url])
            else:
                server_loger.error(f"Unsupported platform, can't open browser automatically.", exc_info=True)
                print("Unsupported platform, can't open browser automatically.")
        except Exception as e:
            server_loger.error(f"自动打开浏览器失败：{e}", exc_info=True)

    time.sleep(1)
    server_loger.info(f"启动flask服务，host:port：{host}:{port}")
    print(f"[+] 请使用浏览器访问 http://127.0.0.1:{port}/ 查看聊天记录")
    global app
    print(f"[+] 如需查看api文档，请访问 http://127.0.0.1:{port}/docs ")
    origins = [
        f"http://localhost:{port}",
        f"http://{host}:{port}",
        f"http://localhost:8080",  # 开发环境的客户端地址"
        # f"http://0.0.0.0:{port}",
        # "*"
    ]
    app = gen_fastapi_app(file_handler, origins)

    LOGGING_CONFIG["formatters"]["default"]["fmt"] = "[%(asctime)s] %(levelprefix)s %(message)s"
    LOGGING_CONFIG["formatters"]["access"][
        "fmt"] = '[%(asctime)s] %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'
    config = uvicorn.Config(app=app, host=host, port=port, reload=debug, log_level="info", workers=1, env_file=env_file)
    server = uvicorn.Server(config)
    server.run()
    # uvicorn.run(app=app, host=host, port=port, reload=debug, log_level="info", workers=1, env_file=env_file)


app = None

__all__ = ["start_server", "gen_fastapi_app"]
