# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         main.py.py
# Description:  
# Author:       xaoyaoo
# Date:         2023/10/14
# -------------------------------------------------------------------------------
import argparse
import os
import sys
import json

from pywxdump import *
import pywxdump
from pywxdump.wx_core.wx_info import read_wx4_keys_file
# 【第二步·4.x】BiasAddr 用于输出 4.x 进程基址信息 / 内存诊断；get_wx_processes 同时认 WeChat.exe 与 Weixin.exe
from pywxdump.wx_core.get_bias_addr import BiasAddr as BiasAddr4x, get_wx_processes

wxdump_ascii = r"""
██████╗ ██╗   ██╗██╗    ██╗██╗  ██╗██████╗ ██╗   ██╗███╗   ███╗██████╗ 
██╔══██╗╚██╗ ██╔╝██║    ██║╚██╗██╔╝██╔══██╗██║   ██║████╗ ████║██╔══██╗
██████╔╝ ╚████╔╝ ██║ █╗ ██║ ╚███╔╝ ██║  ██║██║   ██║██╔████╔██║██████╔╝
██╔═══╝   ╚██╔╝  ██║███╗██║ ██╔██╗ ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝ 
██║        ██║   ╚███╔███╔╝██╔╝ ██╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║     
╚═╝        ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     
"""
PYWXDUMP_VERSION = pywxdump.__version__

models = {}


def detect_wx_generation():
    """
    【4.0 默认行为】自动识别当前微信代次（用户不传 --mode 时用这个判断）：

      - 发现 Weixin.exe（微信 4.x）→ "4x"
      - 只有 WeChat.exe（微信 3.x）→ "3x"
      - 两个都没发现            → None

    :return: (mode, weixin_pids, wechat_pids)
    """
    try:
        procs = get_wx_processes()          # 名单 = WeChat.exe + Weixin.exe，返回带 is_wx4 标记
    except Exception:
        procs = []
    weixin_pids = [d["pid"] for d in procs if d.get("is_wx4")]
    wechat_pids = [d["pid"] for d in procs if not d.get("is_wx4")]
    if weixin_pids:
        return "4x", weixin_pids, wechat_pids
    if wechat_pids:
        return "3x", weixin_pids, wechat_pids
    return None, weixin_pids, wechat_pids


def auto_detect_mode_for(a: str, args, key_file=None, decrypted_dir=None):
    """
    【4.0】把 --mode 的 auto 解析成实际模式，并决定是否默认开内存取密钥。

    :param a:     "info" / "bias"，只用于打印提示
    :return: (mode, scan_mem, ok) —— ok=False 表示无法继续（调用方直接返回）
    """
    mode = (getattr(args, "wx_mode", "auto") or "auto").lower()
    no_scan_mem = bool(getattr(args, "no_scan_mem", False))
    scan_mem = bool(getattr(args, "scan_mem", False))

    if mode == "auto":
        det, weixin_pids, wechat_pids = detect_wx_generation()
        if det == "4x":
            mode = "4x"
            print(f"[*] 检测到微信 4.x 进程 Weixin.exe（pid {weixin_pids}）"
                  f"→ wxdump {a} 自动走 4.x 内存取密钥")
        elif det == "3x":
            mode = "3x"
            print(f"[*] 检测到微信 3.x 进程 WeChat.exe（pid {wechat_pids}）→ wxdump {a} 走 3.x 老逻辑")
        elif key_file or decrypted_dir:
            mode = "4x"
            print(f"[*] 没检测到微信进程，但给了密钥文件/解密库 → wxdump {a} 走 4.x 读库路线")
        else:
            print("[-] 没检测到微信进程：Weixin.exe（4.x）/ WeChat.exe（3.x）都没有")
            print(f"[-] 请先登录微信后重试 wxdump {a}")
            print("[-] 或直接读库：wxdump info -dd <解密库目录> ／ --key_file <all_keys.json>")
            return None, False, False

    # 4.x 且没给密钥文件时，内存取密钥默认开启（--no_scan_mem 可关）
    if mode == "4x" and not key_file and not no_scan_mem and not scan_mem:
        scan_mem = True
        print("[*] 4.x 默认开启只读内存取密钥（不需要密钥文件）；要关掉加 --no_scan_mem")
    return mode, scan_mem, True


def create_parser():
    class CustomArgumentParser(argparse.ArgumentParser):
        def format_help(self):
            # 首先显示软件简介
            # 定义软件简介文本并进行格式化
            line_len = 70
            PYWXDUMP_VERSION = pywxdump.__version__
            wxdump_line = '\n'.join([f'\033[36m{line:^{line_len}}\033[0m' for line in wxdump_ascii.split('\n') if line])
            first_line = f'\033[36m{" PyWxDump v" + PYWXDUMP_VERSION + " ":=^{line_len}}\033[0m'
            brief = ('PyWxDump v4.x 适配版：支持微信 4.x 内存取密钥（只读）、获取账号信息、解密数据库、'
                     '查看聊天记录、导出聊天记录为 html 等')
            other = ('\033[1m★ 微信 4.x（含 4.1.15.13）：直接执行 wxdump info / wxdump bias 即可，'
                     '自动走只读内存取密钥（无需再手输 --mode 4x --scan_mem）\033[0m\n'
                     '★ 只读扫描 Weixin.exe 内存：不注入 / 不 Hook / 不修改微信文件\n'
                     '更多详情请查看: \033[4m\033[1mhttps://github.com/xaoyaoo/PyWxDump\033[0m')

            separator = f'\033[36m{" options ":-^{line_len}}\033[0m'

            # 获取帮助信息并添加到软件简介下方
            help_text = super().format_help().strip()

            return f'\n{wxdump_line}\n\n{first_line}\n{brief}\n{separator}\n{help_text}\n{separator}\n{other}\n{first_line}\n'

    # 创建命令行参数解析器
    parser = CustomArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-V', '--version', action='version', version=f"PyWxDump v{PYWXDUMP_VERSION}")

    # 添加子命令解析器
    subparsers = parser.add_subparsers(dest="mode", help="""运行模式:""", required=True, metavar="mode")

    return parser, subparsers


main_parser, sub_parsers = create_parser()


class SubMainMetaclass(type):

    def is_implemented_method(cls, name: str, method: str):
        if not hasattr(cls, method) or not callable(getattr(cls, method)):
            raise NotImplementedError("{} NotImplemented [{}]".format(name, method))

    def __init__(cls, name, bases, kwargs):
        super(SubMainMetaclass, cls).__init__(name, bases, kwargs)

        if name in ["BaseSubMainClass"]:
            return

        mode = getattr(cls, "mode")
        if mode in models:
            raise TypeError("mode[{}] is used...".format(mode))

        cls.is_implemented_method(name, "init_parses")
        cls.is_implemented_method(name, "run")

        c = cls()
        models[mode] = c
        c.init_parses(sub_parsers.add_parser(mode, **getattr(c, "parser_kwargs")))


class BaseSubMainClass(metaclass=SubMainMetaclass):
    parser_kwargs = {}

    @property
    def mode(self) -> str:
        raise NotImplementedError()

    def init_parses(self, parser):
        raise NotImplementedError()

    def run(self, args: argparse.Namespace):
        raise NotImplementedError()


class MainBiasAddr(BaseSubMainClass):
    mode = "bias"
    parser_kwargs = {"help": "获取微信基址偏移（4.x：默认只读内存取密钥，输出 {库路径: 密钥}）"}

    def init_parses(self, parser):
        # 添加 'bias_addr' 子命令解析器
        # 注意：3.x 需要 --mobile/--name/--account 去内存里搜；4.x 完全不需要，
        #       所以这里把 required 去掉，只在真正走 3.x 内存路径时才要求。
        parser.add_argument("--mobile", type=str, help="(3.x)手机号", metavar="", required=False)
        parser.add_argument("--name", type=str, help="(3.x)微信昵称", metavar="", required=False)
        parser.add_argument("--account", type=str, help="(3.x)微信账号", metavar="", required=False)
        parser.add_argument("--key", type=str, metavar="", help="(可选)密钥")
        parser.add_argument("--db_path", type=str, metavar="", help="(可选)已登录账号的微信文件夹路径")
        parser.add_argument("-vlp", '--WX_OFFS_PATH', type=str, metavar="",
                            help="(可选)微信版本偏移文件路径,如有，则自动更新",
                            default=None)
        parser.add_argument("-dd", "--decrypted_dir", type=str, metavar="", default=None,
                            help="(4.x)已解密数据库目录；给了就完全跳过内存扫描，直接从库里读信息")
        parser.add_argument("--key_file", "--keys_file", dest="key_file", type=str, metavar="", default=None,
                            help="(4.x)本地密钥文件路径，形如 {库路径: {enc_key, salt}}，如 all_keys.json")
        parser.add_argument("--mode", dest="wx_mode", type=str, metavar="", default="auto",
                            choices=["auto", "3x", "4x"],
                            help="(4.x)auto/3x/4x；默认 auto=自动识别（发现 Weixin.exe 即走 4.x 内存取密钥）")
        parser.add_argument("--my_wxid", type=str, metavar="", default=None, help="(4.x)当前登录账号 wxid")
        parser.add_argument("--wx_path", type=str, metavar="", default=None,
                            help="(4.x)微信数据目录，如 D:\\xwechat_files\\wxid_xxx_abcd")
        parser.add_argument("--scan_mem", action="store_true",
                            help="(4.x)只读内存取密钥：形状预筛 + 真库 salt 反推 32 字节 XOR 掩码 + "
                                 "第 1 页 HMAC 校验；【4.x 未给 --key_file 时默认开启】")
        parser.add_argument("--no_scan_mem", action="store_true",
                            help="(4.x)关闭默认的只读内存取密钥，改走 --key_file / -dd")
        parser.add_argument("--no_sync_keys", action="store_true",
                            help="(4.x)本次【不】回写 all_keys.json、也不另存未匹配串（默认会回写+另存）")
        parser.add_argument("--extra_keys", type=str, metavar="", default=None,
                            help=r"(4.x)未匹配串另存路径，默认 C:\Users\Administrator\.wechat-cli\extra_mem_keys.json")
        parser.add_argument("--wx_root", type=str, metavar="", default=None,
                            help=r"(4.x)微信数据根目录，留空自动定位（回退 D:\xwechat_files，用于收集真库 salt 与第 1 页）")
        parser.add_argument("--mem_budget", type=float, metavar="", default=300,
                            help="(4.x)每个进程内存扫描时间上限（秒），默认 300")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # 从命令行参数获取值
        mobile = args.mobile
        name = args.name
        account = args.account
        key = args.key
        db_path = args.db_path
        vlp = args.WX_OFFS_PATH
        mode = (getattr(args, "wx_mode", "auto") or "auto").lower()
        decrypted_dir = getattr(args, "decrypted_dir", None)
        my_wxid = getattr(args, "my_wxid", None)
        wx_path = getattr(args, "wx_path", None)
        key_file = getattr(args, "key_file", None)
        scan_mem = bool(getattr(args, "scan_mem", False))
        # 【4.0】不传 --mode 时自动识别微信代次；4.x 自动开内存取密钥
        mode, scan_mem, ok = auto_detect_mode_for("bias", args, key_file=key_file,
                                                 decrypted_dir=decrypted_dir)
        if not ok:
            return None

        if mode == "4x" or key_file or scan_mem:
            # ---------- 4.x：密钥默认从内存取；给了密钥文件则以文件为准 ----------
            print("[*] 4.x 模式：跳过 3.x 的 WX_OFFS 固定偏移，改走 4.x 密钥获取流程")
            mem_report = None
            if scan_mem:
                # 【第三步·4.x】只读内存取密钥（形状预筛 + 真库 salt 反推 32 字节 XOR 掩码 + HMAC 校验）
                print("[*] --scan_mem：开始只读扫描 Weixin.exe 内存（不注入 / 不 Hook / 不改微信文件）")
                from pywxdump.wx_core.wx_info import _wx4_mem_keys_report
                mem_report = _wx4_mem_keys_report(
                    wx_root=getattr(args, "wx_root", None),
                    time_budget=float(getattr(args, "mem_budget", 300) or 300),
                    sync_store=not getattr(args, "no_sync_keys", False),
                    extra_file=getattr(args, "extra_keys", None))
                print("[*] 内存取密钥结束：拿到 "
                      f"{len((mem_report or {}).get('keys') or {})} 把通过真库 HMAC 校验的密钥")
            keymap = read_wx4_keys_file(key_file) if key_file else {}
            if not keymap and not key_file and mem_report and mem_report.get("keys"):
                keymap = dict(mem_report["keys"])
                print(f"[+] 密钥来源：Weixin.exe 只读内存扫描（{len(keymap)} 把，无需密钥文件）")
            if not keymap and decrypted_dir:
                for cand in ("all_keys.json", "keys.json"):
                    p = os.path.join(decrypted_dir, cand)
                    keymap = read_wx4_keys_file(p)
                    if keymap:
                        key_file = p
                        break
            if not keymap:
                print("[-] 没有从密钥文件里读到 4.x 形态的密钥")
                print('[-] 需要的格式：{"库路径": {"enc_key": "<64位hex>", "salt": "<32位hex>"}}')
                print(f"[-] 当前 --key_file：{key_file}")
                print("[-] 或者用 --scan_mem 直接只读扫描 Weixin.exe 内存取密钥")
                return None
            if key_file:
                print(f"[+] 密钥文件：{key_file}")
            print(f"[*] 共拿到 {len(keymap)} 个库的密钥")

            # 【第二步·4.x】bias 在 4.x 下改报「进程基址 + 内存统计」：
            #   3.x 的 [昵称,账号,手机号,邮箱,KEY] 五个偏移在 4.x 不存在
            #   （没有 WeChatWin.dll，WX_OFFS.json 的固定偏移已失效），
            #   所以这里给 Weixin.exe 的映像基址与可扫私有区段统计，配合下面的 库路径:密钥。
            try:
                procs = get_wx_processes()
                print("[*] 4.x 进程基址信息（Weixin.exe 映像基址 + 可扫私有区段）：")
                for d in procs:
                    try:
                        base = BiasAddr4x.wx4_module_base(d["pid"])
                    except Exception:
                        base = None
                    try:
                        regions = sum(1 for _ in BiasAddr4x("", "", "", "", None)
                                      ._iter_wx4_scannable_regions(d["pid"]))
                    except Exception:
                        regions = -1
                    print(f"    pid={d['pid']} {d['name']}  基址={hex(base) if base else 'None'}"
                          f"  私有内存={(d.get('private') or 0) / 1048576:.0f} MB  可扫区段={regions} 个")
                if not procs:
                    print("    （没找到 Weixin.exe 进程；密钥不受影响，仍从密钥文件读）")
                print("[*] 说明：4.x 不用 WX_OFFS.json 的固定偏移，"
                      "所以没有 3.x 那种 [昵称,账号,手机号,邮箱,KEY] 偏移量可报")
                print("[*]       4.x 默认已开启内存取密钥；要关掉加 --no_scan_mem")
            except Exception as e:
                print(f"[-] 4.x 进程基址信息获取失败（不影响密钥输出）：{e}")

            print("{库路径: 密钥}")
            print(keymap)
            return keymap

        if decrypted_dir:
            # ---------- 4.x：跳过内存扫描，直接读已解密数据库 ----------
            print("[*] 4.x 模式：跳过内存扫描，从已解密数据库读取微信信息")
            infos = get_wx_info_from_db(decrypted_dir=decrypted_dir, my_wxid=my_wxid,
                                        wx_path=wx_path, key_file=key_file, is_print=True)
            if not infos:
                return None
            print("[*] 说明：4.x 没有 WeChatWin.dll，3.x 的 base bias（内存偏移）机制不适用，")
            print("[*]       因此这里【不会写入/覆盖】WX_OFFS.json 里的偏移记录。")
            print("[*]       想拿 4.x 的密钥列表，请加 --key_file <all_keys.json>")
            return {infos[0].get("version") or "4.x": []}

        # ---------- 3.x：原逻辑完全不变（强制 mode="3x"，不再回落到 4.x 内存扫描）----------
        if not (mobile and name and account):
            print("[-] 3.x 模式需要同时提供 --mobile --name --account")
            print("[-] 若微信是 4.x：请用 wxdump bias --mode 4x --key_file <all_keys.json>")
            print("[-]     或 wxdump bias -dd <解密库目录>（只读已解密数据库）")
            return None
        # 调用 run 函数，并传入参数
        rdata = BiasAddr(account, mobile, name, key, db_path).run(True, vlp, mode="3x")
        if rdata is None:
            print("[-] 3.x 模式未成功：没找到 WeChat.exe（微信 3.x 进程）")
            print("[-] 微信是 4.x 的话，请用：wxdump bias --mode 4x --key_file <all_keys.json>")
        return rdata


class MainWxInfo(BaseSubMainClass):
    mode = "info"
    parser_kwargs = {"help": "获取微信信息（4.x：默认只读内存取密钥，输出账号信息 + 密钥）"}

    def init_parses(self, parser):
        # 添加 'wx_info' 子命令解析器
        parser.add_argument("-vlp", '--WX_OFFS_PATH', metavar="", type=str,
                            help="(可选)微信版本偏移文件路径", default=WX_OFFS_PATH)
        parser.add_argument("-s", '--save_path', metavar="", type=str, help="(可选)保存路径【json文件】")
        parser.add_argument("--mode", dest="wx_mode", type=str, metavar="", default="auto",
                            choices=["auto", "3x", "4x"],
                            help="(4.x)auto/3x/4x；默认 auto=自动识别（发现 Weixin.exe 即走 4.x 内存取密钥）")
        parser.add_argument("-dd", "--decrypted_dir", type=str, metavar="", default=None,
                            help="(4.x)已解密数据库目录；给了就优先从解密库读联系人信息")
        parser.add_argument("--key_file", "--keys_file", dest="key_file", type=str, metavar="", default=None,
                            help="(4.x)本地密钥文件路径，形如 {库路径: {enc_key, salt}}，如 all_keys.json")
        parser.add_argument("--my_wxid", type=str, metavar="", default=None, help="(4.x)当前登录账号 wxid")
        parser.add_argument("--wx_path", type=str, metavar="", default=None,
                            help="(4.x)微信数据目录，如 D:\\xwechat_files\\wxid_xxx_abcd")
        parser.add_argument("--scan_mem", action="store_true",
                            help="(4.x)只读内存取密钥：形状预筛 + 真库 salt 反推 32 字节 XOR 掩码 + "
                                 "第 1 页 HMAC 校验；【4.x 未给 --key_file 时默认开启】")
        parser.add_argument("--no_scan_mem", action="store_true",
                            help="(4.x)关闭默认的只读内存取密钥，回到 --key_file 路线")
        parser.add_argument("--no_sync_keys", action="store_true",
                            help="(4.x)本次【不】回写 all_keys.json、也不另存未匹配串（默认会回写+另存）")
        parser.add_argument("--extra_keys", type=str, metavar="", default=None,
                            help=r"(4.x)未匹配串另存路径，默认 C:\Users\Administrator\.wechat-cli\extra_mem_keys.json")
        parser.add_argument("--wx_root", type=str, metavar="", default=None,
                            help=r"(4.x)微信数据根目录，留空自动定位（回退 D:\xwechat_files，用于收集真库 salt 与第 1 页）")
        parser.add_argument("--mem_budget", type=float, metavar="", default=300,
                            help="(4.x)每个进程内存扫描时间上限（秒），默认 300")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # 读取微信各版本偏移
        path = args.WX_OFFS_PATH
        save_path = args.save_path
        mode = (getattr(args, "wx_mode", "auto") or "auto").lower()
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                WX_OFFS = json.load(f)
        else:
            if mode != "4x":
                print(f"[-] 偏移文件不存在/未指定：{path}（4.x 不需要偏移文件，可忽略）")
            WX_OFFS = {}
        key_file = getattr(args, "key_file", None)
        scan_mem = bool(getattr(args, "scan_mem", False))
        # 【4.0】不传 --mode 时自动识别微信代次；4.x 自动开内存取密钥
        mode, scan_mem, ok = auto_detect_mode_for("info", args, key_file=key_file,
                                                 decrypted_dir=getattr(args, "decrypted_dir", None))
        if not ok:
            return None
        result = get_wx_info(WX_OFFS, True, save_path,
                             decrypted_dir=getattr(args, "decrypted_dir", None),
                             my_wxid=getattr(args, "my_wxid", None),
                             wx_path=getattr(args, "wx_path", None),
                             key_file=key_file,
                             mode=mode,
                             scan_mem=scan_mem,
                             wx_root=getattr(args, "wx_root", None),
                             mem_time_budget=float(getattr(args, "mem_budget", 300) or 300),
                             sync_store=not getattr(args, "no_sync_keys", False),
                             extra_keys_file=getattr(args, "extra_keys", None))
        return result


class MainWxDbPath(BaseSubMainClass):
    mode = "wx_path"
    parser_kwargs = {"help": "获取微信文件夹路径"}

    def init_parses(self, parser):
        # 添加 'wx_db_path' 子命令解析器
        parser.add_argument("-r", "--db_types", type=str,
                            help="(可选)需要的数据库名称(eg: -r MediaMSG;MicroMsg;FTSMSG;MSG;Sns;Emotion )",
                            default=None, metavar="")
        # 【4.0】-wf/--wx_files（原版）+ --wx_path/-wf（4.x 习惯写法）；留空时自动定位
        parser.add_argument("-wf", "--wx_files", "--wx_path", "-wx_path",
                            dest="wx_files", type=str,
                            help="(可选)'WeChat Files' / 4.x 的 D:\\xwechat_files 或账号目录；留空自动定位",
                            default=None, metavar="")
        parser.add_argument("-id", "--wxid", type=str, help="(可选)wxid_,用于确认用户文件夹",
                            default=None, metavar="")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # 从命令行参数获取值
        db_types = args.db_types
        msg_dir = args.wx_files
        wxid = args.wxid
        if not msg_dir:
            print("[*] 未指定 --wx_files/--wx_path，自动定位微信数据目录（4.x 无需注册表）……")
        ret = get_wx_db(msg_dir=msg_dir, db_types=db_types, wxids=wxid)
        if not ret:
            print("[-] 没找到任何数据库。可以手动指定，例如：")
            print("[-]   4.x：python -m pywxdump wx_path --wx_path \"D:\\xwechat_files\"")
            print("[-]   4.x：python -m pywxdump wx_path --wx_path \"D:\\xwechat_files\\wxid_xxx_abcd\"")
            print("[-]   3.x：python -m pywxdump wx_path --wx_files \"C:\\Users\\xxx\\Documents\\WeChat Files\"")
        else:
            dirs = []
            for r in ret:
                d = r.get("wxid_dir")
                if d and d not in dirs:
                    dirs.append(d)
            print(f"[+] 共找到 {len(ret)} 个数据库文件，数据目录：")
            for d in dirs[:5]:
                print(f"     {d}")
            if len(dirs) > 5:
                print(f"     …… 以及另外 {len(dirs) - 5} 个目录（可用 -id <wxid> 缩小范围）")
        for i in ret: print(i)
        return ret


class MainDecrypt(BaseSubMainClass):
    mode = "decrypt"
    parser_kwargs = {"help": "解密微信数据库"}

    def init_parses(self, parser):
        # 添加 'decrypt' 子命令解析器
        parser.add_argument("-k", "--key", type=str, help="密钥", required=True, metavar="")
        parser.add_argument("-i", "--db_path", type=str, help="数据库路径(目录or文件)", required=True, metavar="")
        parser.add_argument("-o", "--out_path", type=str, default=os.path.join(os.getcwd(), "decrypted"),
                            help="输出路径(必须是目录)[默认为当前路径下decrypted文件夹]", required=False,
                            metavar="")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # 从命令行参数获取值
        key = args.key
        db_path = args.db_path
        out_path = args.out_path

        if not os.path.exists(db_path):
            print(f"[-] 数据库路径不存在：{db_path}")
            return

        if not os.path.exists(out_path):
            os.makedirs(out_path)
            print(f"[+] 创建输出文件夹：{out_path}")

        # 调用 decrypt 函数，并传入参数
        result = batch_decrypt(key, db_path, out_path, True)
        return result


class MainMerge(BaseSubMainClass):
    mode = "merge"
    parser_kwargs = {"help": "[测试功能]合并微信数据库(MSG.db or MediaMSG.db)"}

    def init_parses(self, parser):
        # 添加 'merge' 子命令解析器
        parser.add_argument("-i", "--db_path", type=str, help="数据库路径(文件路径，使用英文[,]分割)", required=True,
                            metavar="")
        parser.add_argument("-o", "--out_path", type=str, default=os.path.join(os.getcwd(), "decrypted"),
                            help="输出路径(目录或文件名)[默认为当前路径下decrypted文件夹下merge_***.db]",
                            required=False,
                            metavar="")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # 从命令行参数获取值
        db_path = args.db_path
        out_path = args.out_path

        db_path = db_path.split(",")
        db_path = [i.strip() for i in db_path]
        dbpaths = []
        for i in db_path:
            if not os.path.exists(i):  # 判断路径是否存在
                print(f"[-] 数据库路径不存在：{i}")
                return
            if os.path.isdir(i):  # 如果是文件夹，则获取文件夹下所有的db文件
                dbpaths += [os.path.join(i, j) for j in os.listdir(i) if j.endswith(".db")]
            else:  # 如果是文件，则直接添加
                dbpaths.append(i)

        if (not out_path.endswith(".db")) and (not os.path.exists(out_path)):
            os.makedirs(out_path)
            print(f"[+] 创建输出文件夹：{out_path}")

        print(f"[*] 合并中...（用时较久，耐心等待）")
        dbpaths = [{"db_path": i} for i in dbpaths if os.path.exists(i)]  # 去除不存在的路径
        result = merge_db(dbpaths, out_path)

        print(f"[+] 合并完成：{result}")
        return result


class MainShowChatRecords(BaseSubMainClass):
    mode = "dbshow"
    parser_kwargs = {"help": "聊天记录查看"}

    def init_parses(self, parser):
        # 添加 'dbshow' 子命令解析器
        # 【4.0】兼容多种写法：-merge/--merge_path（原版）+ --db_path/-db_path/--db/-db（大家习惯这么叫）
        parser.add_argument("-merge", "--merge_path", "--db_path", "-db_path", "--db", "-db",
                            dest="merge_path", type=str,
                            help="解密并合并后的 merge_all.db 的路径（别名：--db_path/--db）",
                            required=False, metavar="")
        parser.add_argument("-wid", "--wx_path", type=str,
                            help="(可选)微信文件夹的路径（用于显示图片）", required=False,
                            metavar="")
        parser.add_argument("-myid", "--my_wxid", type=str, help="(可选)微信账号(本人微信id)", required=False,
                            default="", metavar="")
        parser.add_argument("--online", action='store_true', help="(可选)是否在线查看(局域网查看)", required=False,
                            default=False)
        # parser.add_argument("-k", "--key", type=str, help="(可选)密钥", required=False, metavar="")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # (merge)和(msg_path,micro_path,media_path) 二选一
        # if not args.merge_path and not (args.msg_path and args.micro_path and args.media_path):
        #     print("[-] 请输入数据库路径（[merge_path] or [msg_path, micro_path, media_path]）")
        #     return

        # 目前仅能支持merge database
        if not args.merge_path:
            print("[-] 请输入数据库路径（[merge_path]）")
            print("[-] 正确用法：python -m pywxdump dbshow -merge \"D:\\merged.db\"")
            print("[-]       别名也支持：python -m pywxdump dbshow --db_path \"D:\\merged.db\"")
            print("[-]       可加 -wid <微信数据目录> 用于显示图片、-myid <本人wxid> 用于区分自己发的消息")
            return

        # 从命令行参数获取值
        merge_path = args.merge_path

        online = args.online

        if not os.path.exists(merge_path):
            print("[-] 输入数据库路径不存在")
            return

        start_server(merge_path=merge_path, wx_path=args.wx_path, my_wxid=args.my_wxid, online=online)


class MainExportChatRecords(BaseSubMainClass):
    mode = "export"
    parser_kwargs = {"help": "[已废弃]聊天记录导出为html"}

    def init_parses(self, parser):
        # 添加 'export' 子命令解析器
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        print("[+] export命令已废弃，请使用ui命令[wxdump ui]或api命令[wxdump api]启动服务")


class MainAll(BaseSubMainClass):
    mode = "all"
    parser_kwargs = {"help": "[已废弃]获取微信信息，解密微信数据库，查看聊天记录"}

    def init_parses(self, parser):
        # 添加 'all' 子命令解析器
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        print("[+] all命令已废弃，请使用ui命令[wxdump ui]或api命令[wxdump api]启动服务")


class MainUi(BaseSubMainClass):
    mode = "ui"
    parser_kwargs = {"help": "启动UI界面"}

    def init_parses(self, parser):
        # 添加 'ui' 子命令解析器
        parser.add_argument("-p", '--port', metavar="", type=int, help="(可选)端口号", default=5000)
        parser.add_argument("--online", help="(可选)是否在线查看(局域网查看)", default=False, action='store_true')
        parser.add_argument("--debug", help="(可选)是否开启debug模式", default=False, action='store_true')
        parser.add_argument("--noOpenBrowser", dest='isOpenBrowser', default=True, action='store_false',
                            help="(可选)用于禁用自动打开浏览器")
        parser.add_argument("--killPort", dest='kill_port', default=False, action='store_true',
                            help="(可选)端口被占用时，自动结束占用该端口的进程（默认不杀，自动换一个空闲端口）")
        # ---- 【4.x 改造 · 第三步】启动即自动准备：密钥文件 / 模式 / 解密目录 ----
        parser.add_argument("--key_file", "--keys_file", dest="key_file", metavar="", default="",
                            help="(可选·4.x)本地密钥文件，默认自动找 ~/.wechat-cli/all_keys.json")
        parser.add_argument("--mode", dest="wx_mode", metavar="", choices=["auto", "3x", "4x"], default="auto",
                            help="(可选)auto/4x=启动时自动准备 4.x（读密钥→解密→加载会话）；3x=完全走 3.x 老逻辑")
        parser.add_argument("--decrypted_dir", dest="decrypted_dir", metavar="", default="",
                            help="(可选·4.x)解密产物目录，默认复用已有解密库或 <工作目录>/decrypted_wx4")
        parser.add_argument("--no_decrypt", dest="no_decrypt", default=False, action="store_true",
                            help="(可选·4.x)完全不解密，只用 --decrypted_dir 里现成的库")
        parser.add_argument("--force_decrypt", dest="force_decrypt", default=False, action="store_true",
                            help="(可选·4.x)把已存在但比原始库旧的库也重新解密一遍")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # 从命令行参数获取值
        online = args.online
        port = args.port
        debug = args.debug
        isopenBrowser = args.isOpenBrowser

        start_server(port=port, online=online, debug=debug, isopenBrowser=isopenBrowser,
                     key_file=getattr(args, "key_file", "") or "",
                     mode=getattr(args, "wx_mode", "auto") or "auto",
                     decrypted_dir=getattr(args, "decrypted_dir", "") or "",
                     no_decrypt=bool(getattr(args, "no_decrypt", False)),
                     force_decrypt=bool(getattr(args, "force_decrypt", False)),
                     kill_port=getattr(args, "kill_port", False))


class MainApi(BaseSubMainClass):
    mode = "api"
    parser_kwargs = {"help": "启动api，不打开浏览器"}

    def init_parses(self, parser):
        # 添加 'api' 子命令解析器
        parser.add_argument("-p", '--port', metavar="", type=int, help="(可选)端口号", default=5000)
        parser.add_argument("--online", help="(可选)是否在线查看(局域网查看)", default=False, action='store_true')
        parser.add_argument("--debug", action='store_true', help="(可选)是否开启debug模式", default=False)
        parser.add_argument("--killPort", dest='kill_port', default=False, action='store_true',
                            help="(可选)端口被占用时，自动结束占用该端口的进程（默认不杀，自动换一个空闲端口）")
        # ---- 【4.x 改造 · 第三步】同 ui：启动即自动准备 ----
        parser.add_argument("--key_file", "--keys_file", dest="key_file", metavar="", default="",
                            help="(可选·4.x)本地密钥文件，默认自动找 ~/.wechat-cli/all_keys.json")
        parser.add_argument("--mode", dest="wx_mode", metavar="", choices=["auto", "3x", "4x"], default="auto",
                            help="(可选)auto/4x=启动时自动准备 4.x（读密钥→解密→加载会话）；3x=完全走 3.x 老逻辑")
        parser.add_argument("--decrypted_dir", dest="decrypted_dir", metavar="", default="",
                            help="(可选·4.x)解密产物目录，默认复用已有解密库或 <工作目录>/decrypted_wx4")
        parser.add_argument("--no_decrypt", dest="no_decrypt", default=False, action="store_true",
                            help="(可选·4.x)完全不解密，只用 --decrypted_dir 里现成的库")
        parser.add_argument("--force_decrypt", dest="force_decrypt", default=False, action="store_true",
                            help="(可选·4.x)把已存在但比原始库旧的库也重新解密一遍")
        return parser

    def run(self, args):
        print(f"[*] PyWxDump v{pywxdump.__version__}")
        # 从命令行参数获取值
        online = args.online
        port = args.port
        debug = args.debug

        start_server(port=port, online=online, debug=debug, isopenBrowser=False,
                     key_file=getattr(args, "key_file", "") or "",
                     mode=getattr(args, "wx_mode", "auto") or "auto",
                     decrypted_dir=getattr(args, "decrypted_dir", "") or "",
                     no_decrypt=bool(getattr(args, "no_decrypt", False)),
                     force_decrypt=bool(getattr(args, "force_decrypt", False)),
                     kill_port=getattr(args, "kill_port", False))


def console_run():
    # 检查是否需要显示帮助信息
    if len(sys.argv) == 1:
        sys.argv.append(MainUi.mode)
    elif len(sys.argv) == 2 and sys.argv[1] not in models.keys():
        sys.argv.append('-h')
        main_parser.print_help()
        return

    args = main_parser.parse_args()  # 解析命令行参数

    if not any(vars(args).values()):
        main_parser.print_help()
        return

    # 根据不同的 'mode' 参数，执行不同的操作
    models[args.mode].run(args)


if __name__ == '__main__':
    console_run()
