# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         getwxinfo.py
# Description:  
# Author:       xaoyaoo
# Date:         2023/08/21
# -------------------------------------------------------------------------------
import ctypes
import json
import os
import re
import sqlite3
import time
import winreg
from typing import List, Union
from .utils import verify_key, get_exe_bit, wx_core_error
from .utils import get_process_list, get_memory_maps, get_process_exe_path, get_file_version_info
from .utils import search_memory
from .utils import wx_core_loger, CORE_DB_TYPE
import ctypes.wintypes as wintypes

# 定义常量
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

ReadProcessMemory = kernel32.ReadProcessMemory
void_p = ctypes.c_void_p


# 读取内存中的字符串(key部分)
@wx_core_error
def get_key_by_offs(h_process, address, address_len=8):
    array = ctypes.create_string_buffer(address_len)
    if ReadProcessMemory(h_process, void_p(address), array, address_len, 0) == 0: return None
    address = int.from_bytes(array, byteorder='little')  # 逆序转换为int地址（key地址）
    key = ctypes.create_string_buffer(32)
    if ReadProcessMemory(h_process, void_p(address), key, 32, 0) == 0: return None
    key_string = bytes(key).hex()
    return key_string


# 读取内存中的字符串(非key部分)
@wx_core_error
def get_info_string(h_process, address, n_size=64):
    array = ctypes.create_string_buffer(n_size)
    if ReadProcessMemory(h_process, void_p(address), array, n_size, 0) == 0: return None
    array = bytes(array).split(b"\x00")[0] if b"\x00" in array else bytes(array)
    text = array.decode('utf-8', errors='ignore')
    return text.strip() if text.strip() != "" else None


# 读取内存中的字符串(昵称部分name)
@wx_core_error
def get_info_name(h_process, address, address_len=8, n_size=64):
    array = ctypes.create_string_buffer(n_size)
    if ReadProcessMemory(h_process, void_p(address), array, n_size, 0) == 0: return None
    address1 = int.from_bytes(array[:address_len], byteorder='little')  # 逆序转换为int地址（key地址）
    info_name = get_info_string(h_process, address1, n_size)
    if info_name != None:
        return info_name
    array = bytes(array).split(b"\x00")[0] if b"\x00" in array else bytes(array)
    text = array.decode('utf-8', errors='ignore')
    return text.strip() if text.strip() != "" else None


# 读取内存中的wxid
@wx_core_error
def get_info_wxid(h_process):
    find_num = 100
    addrs = search_memory(h_process, br'\\Msg\\FTSContact', max_num=find_num)
    wxids = []
    for addr in addrs:
        array = ctypes.create_string_buffer(80)
        if ReadProcessMemory(h_process, void_p(addr - 30), array, 80, 0) == 0: return None
        array = bytes(array)  # .split(b"\\")[0]
        array = array.split(b"\\Msg")[0]
        array = array.split(b"\\")[-1]
        wxids.append(array.decode('utf-8', errors='ignore'))
    wxid = max(wxids, key=wxids.count) if wxids else None
    return wxid


# 读取内存中的wx_path基于wxid（慢）
@wx_core_error
def get_wx_dir_by_wxid(h_process, wxid=""):
    find_num = 10
    addrs = search_memory(h_process, wxid.encode() + br'\\Msg\\FTSContact', max_num=find_num)
    wxid_dir = []
    for addr in addrs:
        win_addr_len = 260
        array = ctypes.create_string_buffer(win_addr_len)
        if ReadProcessMemory(h_process, void_p(addr - win_addr_len + 50), array, win_addr_len, 0) == 0: return None
        array = bytes(array).split(b"\\Msg")[0]
        array = array.split(b"\00")[-1]
        wxid_dir.append(array.decode('utf-8', errors='ignore'))
    wxid_dir = max(wxid_dir, key=wxid_dir.count) if wxid_dir else None
    return wxid_dir


@wx_core_error
def get_wx_dir_by_reg(wxid="all"):
    """
    # 读取 wx_dir (微信文件路径) （快）
    :param wxid: 微信id
    :return: 返回wx_dir,if wxid="all" return wx_dir else return wx_dir/wxid
    """
    if not wxid:
        return None
    w_dir = "MyDocument:"
    is_w_dir = False

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\WeChat", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "FileSavePath")
        winreg.CloseKey(key)
        w_dir = value
        is_w_dir = True
    except Exception as e:
        w_dir = "MyDocument:"

    if not is_w_dir:
        try:
            user_profile = os.environ.get("USERPROFILE")
            path_3ebffe94 = os.path.join(user_profile, "AppData", "Roaming", "Tencent", "WeChat", "All Users", "config",
                                         "3ebffe94.ini")
            with open(path_3ebffe94, "r", encoding="utf-8") as f:
                w_dir = f.read()
            is_w_dir = True
        except Exception as e:
            w_dir = "MyDocument:"

    if w_dir == "MyDocument:":
        try:
            # 打开注册表路径
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            documents_path = winreg.QueryValueEx(key, "Personal")[0]  # 读取文档实际目录路径
            winreg.CloseKey(key)  # 关闭注册表
            documents_paths = os.path.split(documents_path)
            if "%" in documents_paths[0]:
                w_dir = os.environ.get(documents_paths[0].replace("%", ""))
                w_dir = os.path.join(w_dir, os.path.join(*documents_paths[1:]))
                # print(1, w_dir)
            else:
                w_dir = documents_path
        except Exception as e:
            profile = os.environ.get("USERPROFILE")
            w_dir = os.path.join(profile, "Documents")

    wx_dir = os.path.join(w_dir, "WeChat Files")

    if wxid and wxid != "all":
        wxid_dir = os.path.join(wx_dir, wxid)
        return wxid_dir if os.path.exists(wxid_dir) else None
    return wx_dir if os.path.exists(wx_dir) else None


def get_wx_dir(wxid: str = "", Handle=None):
    """
    综合运用多种方法获取wx_path
    优先调用 get_wx_dir_by_reg (该方法速度快)
    次要调用 get_wx_dir_by_wxid （该方法通过搜索内存进行，速度较慢）
    """
    if wxid:
        wx_dir = get_wx_dir_by_reg(wxid) if wxid else None
        if wxid is not None and wx_dir is None and Handle:  # 通过wxid获取wx_path,如果wx_path为空则通过wxid获取wx_path
            wx_dir = get_wx_dir_by_wxid(Handle, wxid=wxid)
    else:
        wx_dir = get_wx_dir_by_reg()
    return wx_dir


@wx_core_error
def get_key_by_mem_search(pid, db_path, addr_len):
    """
    获取key （慢）
    :param pid: 进程id
    :param db_path: 微信数据库路径
    :param addr_len: 地址长度
    :return: 返回key
    """

    def read_key_bytes(h_process, address, address_len=8):
        array = ctypes.create_string_buffer(address_len)
        if ReadProcessMemory(h_process, void_p(address), array, address_len, 0) == 0: return None
        address = int.from_bytes(array, byteorder='little')  # 逆序转换为int地址（key地址）
        key = ctypes.create_string_buffer(32)
        if ReadProcessMemory(h_process, void_p(address), key, 32, 0) == 0: return None
        key_bytes = bytes(key)
        return key_bytes

    phone_type1 = "iphone\x00"
    phone_type2 = "android\x00"
    phone_type3 = "ipad\x00"

    MicroMsg_path = os.path.join(db_path, "MSG", "MicroMsg.db")

    start_adress = 0x7FFFFFFFFFFFFFFF
    end_adress = 0

    memory_maps = get_memory_maps(pid)
    for module in memory_maps:
        if module.FileName and 'WeChatWin.dll' in module.FileName:
            s = module.BaseAddress
            e = module.BaseAddress + module.RegionSize
            start_adress = s if s < start_adress else start_adress
            end_adress = e if e > end_adress else end_adress

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    type1_addrs = search_memory(hProcess, phone_type1.encode(), max_num=2, start_address=start_adress,
                                end_address=end_adress)
    type2_addrs = search_memory(hProcess, phone_type2.encode(), max_num=2, start_address=start_adress,
                                end_address=end_adress)
    type3_addrs = search_memory(hProcess, phone_type3.encode(), max_num=2, start_address=start_adress,
                                end_address=end_adress)

    type_addrs = []
    if len(type1_addrs) >= 2: type_addrs += type1_addrs
    if len(type2_addrs) >= 2: type_addrs += type2_addrs
    if len(type3_addrs) >= 2: type_addrs += type3_addrs
    if len(type_addrs) == 0: return None

    type_addrs.sort()  # 从小到大排序

    for i in type_addrs[::-1]:
        for j in range(i, i - 2000, -addr_len):
            key_bytes = read_key_bytes(hProcess, j, addr_len)
            if key_bytes == None:
                continue
            if verify_key(key_bytes, MicroMsg_path):
                return key_bytes.hex()
    CloseHandle(hProcess)
    return None


@wx_core_error
def get_wx_key(key: str = "", wx_dir: str = "", pid=0, addrLen=8):
    """
    获取key （慢）
    :param key: 微信key
    :param wx_dir: 微信文件路径
    :param pid: 进程id
    :param addrLen: 地址长度
    :return: 返回key
    """
    isKey = verify_key(
        bytes.fromhex(key),
        os.path.join(wx_dir, "MSG", "MicroMsg.db")) if key is not None and wx_dir is not None else False
    if wx_dir is not None and not isKey:
        key = get_key_by_mem_search(pid, wx_dir, addrLen)
    return key


@wx_core_error
def get_info_details(pid, WX_OFFS: dict = None):
    path = get_process_exe_path(pid)
    rd = {'pid': pid, 'version': get_file_version_info(path),
          "account": None, "mobile": None, "nickname": None, "mail": None,
          "wxid": None, "key": None, "wx_dir": None}
    try:
        bias_list = WX_OFFS.get(rd['version'], None)

        Handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

        addrLen = get_exe_bit(path) // 8
        if not isinstance(bias_list, list) or len(bias_list) <= 4:
            wx_core_loger.warning(f"[-] WeChat Current Version Is Not Supported(not get account,mobile,nickname,mail)")
        else:
            wechat_base_address = 0
            memory_maps = get_memory_maps(pid)
            for module in memory_maps:
                if module.FileName and 'WeChatWin.dll' in module.FileName:
                    wechat_base_address = module.BaseAddress
                    rd['version'] = get_file_version_info(module.FileName) if os.path.exists(module.FileName) else rd[
                        'version']
                    bias_list = WX_OFFS.get(rd['version'], None)
                    break
            if wechat_base_address != 0:
                name_baseaddr = wechat_base_address + bias_list[0]
                account_baseaddr = wechat_base_address + bias_list[1]
                mobile_baseaddr = wechat_base_address + bias_list[2]
                mail_baseaddr = wechat_base_address + bias_list[3]
                key_baseaddr = wechat_base_address + bias_list[4]

                rd['account'] = get_info_string(Handle, account_baseaddr, 32) if bias_list[1] != 0 else None
                rd['mobile'] = get_info_string(Handle, mobile_baseaddr, 64) if bias_list[2] != 0 else None
                rd['nickname'] = get_info_name(Handle, name_baseaddr, addrLen, 64) if bias_list[0] != 0 else None
                rd['mail'] = get_info_string(Handle, mail_baseaddr, 64) if bias_list[3] != 0 else None
                rd['key'] = get_key_by_offs(Handle, key_baseaddr, addrLen) if bias_list[4] != 0 else None
            else:
                wx_core_loger.warning(f"[-] WeChat WeChatWin.dll Not Found")

        rd['wxid'] = get_info_wxid(Handle)
        rd['wx_dir'] = get_wx_dir(rd['wxid'], Handle)
        rd['key'] = get_wx_key(rd['key'], rd['wx_dir'], rd['pid'], addrLen)

        CloseHandle(Handle)
    except Exception as e:
        wx_core_loger.error(f"[-] WeChat Get Info Error:{e}", exc_info=True)
    return rd


# ==================================================================================
# 微信 4.x：不读内存，直接根据【已解密的数据库 + 注册表】还原「微信信息」
#
# 4.x 的进程名是 Weixin.exe、模块是 Weixin.exe 自身（没有 WeChatWin.dll），
# 原来那套 WeChatWin.dll 内存偏移在 4.x 上完全对不上，强行扫内存风险也高。
# 既然数据库已经解密好了，wxid / 昵称 / 微信号 / 头像 / 版本号都能从库里和注册表拿到，
# 所以 4.x 一律走这条路，一个字节的进程内存都不读。
# ==================================================================================
def wx4_get_install_path():
    """4.x 安装目录：HKCU\\Software\\Tencent\\Weixin -> InstallPath"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\Weixin", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "InstallPath")
        winreg.CloseKey(key)
        return value if value and os.path.exists(value) else None
    except Exception:
        return None


def wx4_get_version():
    """4.x 版本号：读 Weixin.exe 的文件版本（只读文件属性，不碰内存）"""
    install = wx4_get_install_path()
    if not install:
        return None
    for exe in ("Weixin.exe", "WeChat.exe"):
        p = os.path.join(install, exe)
        if os.path.exists(p):
            v = get_file_version_info(p)
            if v:
                return v
    return None


def _find_decrypted_db(decrypted_dir, prefix, excludes=("fts", "resource", "merge", "wal", "shm", "journal")):
    """在解密目录里按文件名前缀找库（如 contact / session / message）"""
    if not decrypted_dir or not os.path.isdir(decrypted_dir):
        return None
    for fn in sorted(os.listdir(decrypted_dir)):
        low = fn.lower()
        if not low.endswith(".db") or any(x in low for x in excludes):
            continue
        if low.startswith(prefix):
            return os.path.join(decrypted_dir, fn)
    return None


def _read_keys_file(keys_file):
    """
    读取 all_keys.json（如果存在）。
    兼容几种常见形态：
      {"wxid_xxx": {"key": "...", "wxid": "..."}}   /   {"key": "...", "wxid": "..."}
      [{"key": "...", "wxid": "..."}, ...]
    返回 (key, wxid)，拿不到就 (None, None)。
    """
    if not keys_file or not os.path.exists(keys_file):
        return None, None
    try:
        with open(keys_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        wx_core_loger.warning(f"[-] 读取 key 文件失败 {keys_file}: {e}")
        return None, None

    items = []
    if isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        if "key" in data:
            items = [data]
        else:
            for k, v in data.items():
                if isinstance(v, dict):
                    d = dict(v)
                    d.setdefault("wxid", k)
                    items.append(d)
    for d in items:
        k = d.get("key") or (d.get("Key") if isinstance(d.get("Key"), str) else None)
        if isinstance(k, bytes):
            k = k.hex()
        if k:
            return k, d.get("wxid")
    return None, None


def read_wx4_keys_file(key_file):
    """
    【第二步·4.x · B 计划】读取 4.x 形态的本地密钥文件（完全不读进程内存）：
        {
          "message\\\\message_0.db": {"enc_key": "<64位hex>", "salt": "<32位hex>", "size_mb": 84.3},
          "contact\\\\contact.db":   {"enc_key": "<64位hex>", "salt": "<32位hex>"},
          ...
        }
    也兼容 [{"db": "...", "enc_key": "..."}, ...] 这种列表写法。

    :param key_file: 密钥文件路径（如 C:\\Users\\Administrator\\.wechat-cli\\all_keys.json）
    :return: {库路径: enc_key}；文件不存在 / 格式不认 / 没读到 key 时返回 {}
    """
    if not key_file or not os.path.exists(key_file):
        return {}
    try:
        with open(key_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        wx_core_loger.warning(f"[-] 读取 4.x 密钥文件失败 {key_file}: {e}")
        return {}

    items = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                d = dict(v)
                d.setdefault("db", k)          # 键名本身就是库路径，带上
                items.append(d)
            elif isinstance(v, str):           # 兼容 {"库路径": "64位hex"}
                items.append({"db": k, "enc_key": v})
    elif isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]

    out = {}
    for d in items:
        db = d.get("db") or d.get("path") or d.get("file") or d.get("db_path")
        k = d.get("enc_key") or d.get("key") or d.get("Key")
        if isinstance(k, bytes):
            k = k.hex()
        if not isinstance(k, str):
            continue
        k = k.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", k):   # 只要 32 字节(64位hex)的 enc_key
            continue
        out[str(db) if db else f"db_{len(out)}"] = k
    return out


def _wx4_pick_main_db(keymap):
    """从 {库路径: key} 里挑一个作为 rd['key'] 的代表（优先 message\\message_0.db，其次 contact.db）"""
    keys = sorted(keymap)
    prefs = (r"message\message_0.db", "message_0.db", "message_0", "contact.db", "contact")
    for p in prefs:
        low = p.lower()
        cands = [k for k in keys if k.replace("/", "\\").lower().endswith(low)]
        if not cands:
            cands = [k for k in keys if low in k.replace("/", "\\").lower()]
        if cands:
            return min(cands, key=len)   # 路径最短的那个，避免命中 biz_message_0 之类
    return keys[0]


def _wx4_guess_decrypted_dir(my_wxid=None):
    """【4.x】没传 -dd 时，按常见位置找一个像"已解密库目录"的目录（含 contact 库且不含 -wal）"""
    cands = [r"D:\decrypted_wx_db", r"E:\decrypted_wx_db", r"C:\decrypted_wx_db",
             os.path.join(os.path.expanduser("~"), "decrypted_wx_db"),
             os.path.join(os.getcwd(), "decrypted_wx_db")]
    # 【4.0.1 修复】D:\decrypted_wx_db 这类老路径被清理后，真正的解密库在
    #   wxdump_work\decrypted_wx4\<账号>\（wxdump ui / api 的输出）与 wxdump_work\wx4_autodecrypt
    #   原来完全不看这两处，导致 info 拿不到 contact 库、昵称/微信号全空。
    prio = []
    for base in (os.path.join(os.getcwd(), "wxdump_work"),
                 os.path.join(os.path.expanduser("~"), "wxdump_work")):
        root = os.path.join(base, "decrypted_wx4")
        if not os.path.isdir(root):
            continue
        try:
            subs = sorted(os.listdir(root))
        except Exception:
            continue
        if my_wxid:  # 当前账号优先
            subs = ([s for s in subs if str(s).startswith(my_wxid)]
                    + [s for s in subs if not str(s).startswith(my_wxid)])
        prio += [os.path.join(root, s) for s in subs]
    try:
        prio.append(_wx4_work_dir())
    except Exception:
        pass
    for d in prio + cands:
        try:
            if d and os.path.isdir(d) and _find_decrypted_db(d, "contact"):
                return d
        except Exception:
            continue
    return None


def _wx4_find_wx_dir(my_wxid, wx_path=None):
    """
    4.x 数据目录形如 D:\\xwechat_files\\wxid_xxx_fed4（带 4 位后缀）。
    优先用显式传入的 wx_path，其次在常见根目录里按 <my_wxid>_* 找。

    注意：同一个 wxid 可能同时存在「带后缀（真数据目录，里面有 db_storage）」和
    「不带后缀（空壳/残留）」两种目录，所以命中多个时优先选含 db_storage 的那个。
    """
    if wx_path and os.path.exists(wx_path):
        return wx_path
    if not my_wxid:
        return None
    roots = [r"D:\xwechat_files", r"E:\xwechat_files", r"C:\xwechat_files",
             os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files"),
             os.path.join(os.environ.get("USERPROFILE", ""), "xwechat_files")]
    hits = []
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if os.path.isdir(full) and (name == my_wxid or name.startswith(my_wxid + "_")):
                hits.append(full)
    if not hits:
        return None
    with_db = [p for p in hits if os.path.isdir(os.path.join(p, "db_storage"))]
    return (with_db or hits)[0]


def _wx4_guess_my_wxid(contact_db, wx_path=None):
    """
    猜当前登录账号 wxid（三级）：
      1. wx_path 目录名 wxid_xxx_fed4 -> 去掉结尾 _xxxx
      2. contact 表里 flag=2049 且形如 wxid_xxx 的私聊账号（@ 结尾的服务号/ChatBot 排除）
    """
    if wx_path:
        base = os.path.basename(str(wx_path).rstrip("\\/"))
        m = re.match(r"^(wxid_[A-Za-z0-9]+|[A-Za-z][A-Za-z0-9_\-]{5,})_[0-9a-f]{4}$", base)
        if m:
            return m.group(1)
    if contact_db and os.path.exists(contact_db):
        try:
            con = sqlite3.connect(contact_db)
            rows = con.execute(
                "SELECT username FROM contact "
                "WHERE flag=2049 AND username LIKE 'wxid=_%' ESCAPE '=' AND username NOT LIKE '%@%'"
            ).fetchall()
            con.close()
            if len(rows) == 1:
                return rows[0][0]
        except Exception as e:
            wx_core_loger.warning(f"[-] 从 contact 库推断本人 wxid 失败: {e}")
    return None


@wx_core_error
def _wx4_work_dir(sub="wx4_autodecrypt"):
    """4.x 默认工作目录（与 api 的 wxdump_work 保持一致）"""
    try:
        base = os.path.join(os.getcwd(), "wxdump_work")
    except Exception:
        base = os.path.join(os.path.expanduser("~"), "wxdump_work")
    return os.path.join(base, sub)


def _wx4_default_root():
    """
    【4.0.1 路径统一】4.x 数据根目录：先动态定位（注册表 → 各盘 xwechat_files → 我的文档），
    全都不在才回退 D:\\xwechat_files。避免换机器/换盘后仍死认某一个固定路径。
    """
    try:
        from .wx4_prepare import default_wx_root as _wx4prep_default_root
        r = _wx4prep_default_root()
        if r and os.path.isdir(r):
            return r
    except Exception:
        pass
    for p in (r"D:\xwechat_files", r"E:\xwechat_files", r"C:\xwechat_files",
              os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files")):
        try:
            if os.path.isdir(p):
                return p
        except Exception:
            continue
    return r"D:\xwechat_files"


# 【4.0】info 里"账号信息"只依赖这几张家用小库，缺解密库时按需自动解密它们即可
WX4_MINIMAL_DBS = ("contact.db", "session.db", "head_image.db")


def _wx4_autodecrypt_minimal(mem_keys, wx_root=None, out_dir=None, log=print, my_wxid=None):
    """
    【4.0】干净环境兜底：没有现成解密库（例如 D:\\decrypted_wx_db 已删除）时，
    只用内存里取到的密钥解密【最小集】库（contact / session / head_image），
    让 wxdump info 依然能打印昵称、微信号、wxid。

    只读原始库、只写这几张小库到工作目录，不删任何文件；失败返回 None（调用方照常输出密钥）。
    """
    if not mem_keys:
        return None
    try:
        from .wx4_prepare import decrypt_db_file, decode_out_name
    except Exception as e:
        if log:
            log(f"[-] 自动解密最小集不可用：{e}")
        return None
    out = out_dir or _wx4_work_dir()
    root = wx_root or _wx4_default_root()
    try:
        os.makedirs(out, exist_ok=True)
    except Exception as e:
        if log:
            log(f"[-] 自动解密最小集失败（建目录 {out}）：{e}")
        return None
    done = []
    skipped = []
    try:
        accounts = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
    except Exception:
        accounts = []
    items = list((mem_keys or {}).items())
    if my_wxid:
        # 【4.0.1】已知当前账号：它的条目排最前，避免多账号都有 contact 密钥时互相覆盖同名文件
        items.sort(key=lambda kv: 0 if str(kv[0]).replace("/", "\\").split("\\")[0].startswith(str(my_wxid)) else 1)
    produced = set()
    for acct_rel, kh in items:
        rel = str(acct_rel).replace("/", "\\").strip("\\")
        parts = rel.split("\\")
        if len(parts) < 2 or parts[-1].lower() not in WX4_MINIMAL_DBS:
            continue
        if parts[-1].lower() in produced:      # 本次已写过，不让其它账号覆盖
            continue
        # 【4.0.1】密钥条目的路径有两种形态，都要能定位到原始加密库：
        #   ① 带账号前缀：wxid_xxx_fed4\contact\contact.db
        #   ② 不带前缀  ：contact\contact.db
        sub_dir, file_name = parts[-2], parts[-1]
        tries = []
        if len(parts) >= 3:
            tries.append(os.path.join(root, parts[0], "db_storage", sub_dir, file_name))
        tries += [os.path.join(root, a, "db_storage", sub_dir, file_name) for a in accounts]
        src = next((t for t in tries if os.path.isfile(t)), None)
        if not src:
            skipped.append(f"{file_name}(原始库不存在)")
            continue
        dst = os.path.join(out, decode_out_name(file_name))
        try:
            if (os.path.isfile(dst) and os.path.getsize(dst) > 0
                    and os.path.getmtime(dst) >= os.path.getmtime(src)):
                done.append((file_name, "复用"))
                produced.add(file_name.lower())
                continue
            decrypt_db_file(src, dst, kh)
            done.append((file_name, "已解密"))
            produced.add(file_name.lower())
        except Exception as e:
            done.append((file_name, f"失败：{e}"))
    if log and done:
        log(f"[*] 没有可用的解密库目录，已用内存密钥自动解密最小集 → {out}："
            + "，".join(f"{n}({s})" for n, s in done))
    if log and skipped:
        log("[-] 最小集自动解密跳过：" + "，".join(sorted(set(skipped))))
    if not done and not skipped and log:
        log("[-] 内存密钥里没有 contact/session/head_image 的条目，无法自动解密最小集")
    if not [1 for n, s in done if n.lower().startswith("contact") and s in ("已解密", "复用")]:
        return None
    return out


def get_wx_info_from_db(decrypted_dir: str = None, my_wxid: str = None, wx_path: str = None,
                        keys_file: str = None, is_print: bool = False, save_path: str = None,
                        key_file: str = None, keys: dict = None, wx_root: str = None):
    """
    4.x 专用：不读内存，从已解密的数据库 + 本地密钥文件还原微信信息。
    :param decrypted_dir: 解密后的数据库目录（如 D:\\decrypted_wx_db），可缺省
    :param my_wxid:       当前登录账号，不传会自动推断
    :param wx_path:       4.x 数据目录（如 D:\\xwechat_files\\wxid_xxx_fed4），用于填 wx_dir
    :param keys_file:     （旧名，兼容保留）密钥文件路径
    :param key_file:      【第二步】本地密钥文件路径，形如 {"库路径": {"enc_key": "64位hex", "salt": "..."}}
    :param keys:          也可以直接传 {库路径: enc_key}
    :return: 与 get_wx_info 同样的结构 [{"pid","version","account",...,"source"}, ...]
    """
    key_file = key_file or keys_file

    if not decrypted_dir or not os.path.isdir(decrypted_dir):
        if key_file and os.path.exists(key_file):
            # 【第二步·B 计划】只给了密钥文件、没有解密库：不报错，照样输出密钥与库路径
            wx_core_loger.warning(f"[-] 解密目录不可用（{decrypted_dir}），本次只输出密钥文件里的密钥")
            decrypted_dir = None
        elif isinstance(keys, dict) and keys:
            # 【4.0】只拿到内存密钥、没有解密库：照样输出密钥与库路径（昵称/微信号留空，不报错）
            wx_core_loger.warning("[-] 没有可用的解密库目录，本次只输出内存里取到的密钥（昵称/微信号留空）")
            decrypted_dir = None
        else:
            wx_core_loger.warning(f"[-] get_wx_info_from_db: 解密目录不存在 {decrypted_dir}")
            return []

    contact_db = _find_decrypted_db(decrypted_dir, "contact") if decrypted_dir else None

    # 【4.0.1 需求3】有密钥但没有解密库（或库里缺 contact）时，现场按需解密最小集，
    #   把 contact / session / head_image 补出来，让昵称、微信号能正常显示。
    if not contact_db:
        _km = {str(k): v for k, v in keys.items()} if isinstance(keys, dict) and keys else (
            read_wx4_keys_file(key_file) if key_file else {})
        if _km:
            _auto = _wx4_autodecrypt_minimal(_km, wx_root=wx_root, my_wxid=my_wxid,
                                             out_dir=decrypted_dir if (decrypted_dir and os.path.isdir(decrypted_dir)) else None)
            if _auto:
                _c = _find_decrypted_db(_auto, "contact")
                if _c:
                    decrypted_dir, contact_db = _auto, _c

    if decrypted_dir and not contact_db:
        # 【4.0.1 修复】原来这里直接 return []，会让 info 连密钥都打不出来（整个命令像坏了一样）。
        #   改成降级：继续往下走输出密钥，只有昵称/微信号留空。
        wx_core_loger.warning(f"[-] {decrypted_dir} 里没找到 contact 库，"
                              f"本次只输出密钥（昵称/微信号留空）")

    # 【4.0】只给了内存密钥时，从库路径反推本人 wxid（形如 wxid_xxx_abcd\message\message_0.db）
    if not my_wxid and isinstance(keys, dict) and keys:
        for _k in keys:
            _head = str(_k).replace("/", "\\").split("\\")[0]
            _m = re.match(r"^(wxid_[A-Za-z0-9]{4,})_[0-9a-fA-F]{4}$", _head)
            if _m:
                my_wxid = _m.group(1)
                break

    if decrypted_dir and not my_wxid:
        my_wxid = _wx4_guess_my_wxid(contact_db, wx_path)
    if decrypted_dir and not my_wxid:
        wx_core_loger.warning("[-] 未能推断本人 wxid，请用 --my_wxid 指定")

    rd = {'pid': None, 'version': wx4_get_version(), "account": None, "mobile": None, "nickname": None,
          "mail": None, "wxid": my_wxid, "key": None,
          "wx_dir": _wx4_find_wx_dir(my_wxid, wx_path), "source": "db"}
    # 【4.0.1 修复】contact 库缺失时，原来会执行 con.text_factory 抛
    #   AttributeError: 'NoneType' object has no attribute 'text_factory'
    #   （还带一整页 exc_info 栈）。这里明确判空：读不到就只留空昵称/微信号，
    #   保证 version / wxid / key_source / 密钥列表照常输出，info 命令始终可用。
    con = None
    if contact_db:
        try:
            con = sqlite3.connect(contact_db)
            con.text_factory = lambda b: b.decode("utf-8", "replace") if isinstance(b, bytes) else b
            row = None
            if my_wxid:
                row = con.execute(
                    "SELECT username, nick_name, alias, remark FROM contact WHERE username=? LIMIT 1",
                    (my_wxid,)).fetchone()
            if not row:
                # 兜底：flag=2049 的私聊账号就是本人
                row = con.execute(
                    "SELECT username, nick_name, alias, remark FROM contact "
                    "WHERE flag=2049 AND username LIKE 'wxid=_%' ESCAPE '=' AND username NOT LIKE '%@%' LIMIT 1"
                ).fetchone()
            if row:
                rd["wxid"] = row[0] or my_wxid
                rd["nickname"] = row[1] or None
                rd["account"] = row[2] or None  # 微信号(alias)
        except Exception as e:
            wx_core_loger.warning(f"[-] 读取 contact 库失败（昵称/微信号留空，密钥照常输出）: {e}")
        finally:
            try:
                if con:
                    con.close()
            except Exception:
                pass
    else:
        wx_core_loger.warning("[-] 没有可用的 contact 解密库 → 昵称/微信号留空，"
                              "密钥列表照常输出（可先跑一次 wxdump ui 触发自动解密补全）")

    # 【第二步·B 计划】密钥：从本地密钥文件读，不读进程内存
    keymap = {}
    if isinstance(keys, dict) and keys:
        keymap = {str(k): v for k, v in keys.items()}
    elif key_file:
        keymap = read_wx4_keys_file(key_file)
    if keymap:
        main_db = _wx4_pick_main_db(keymap)
        rd["key"] = keymap[main_db]
        rd["key_db"] = main_db
        rd["keys"] = keymap
        rd["key_count"] = len(keymap)
    else:
        # 兼容 3.x 形态的密钥文件（{"key": "...", "wxid": "..."}）
        cands = ([key_file] if key_file else [])
        if decrypted_dir:
            cands += [os.path.join(decrypted_dir, n) for n in ("all_keys.json", "keys.json")]
        for cand in cands:
            k, kwxid = _read_keys_file(cand)
            if k:
                rd["key"] = k
                if not rd.get("wxid") and kwxid:
                    rd["wxid"] = kwxid
                break

    result = [rd]
    if is_print:
        print("=" * 32)
        print("[+] 数据来源: 已解密数据库 + 本地密钥文件（4.x，未读取微信进程内存）")
        for k, v in rd.items():
            if k == "keys" and isinstance(v, dict):
                print(f"[+] {k:>8}: {len(v)} 个库的密钥")
                continue
            print(f"[+] {k:>8}: {v if v else 'None'}")
        if isinstance(rd.get("keys"), dict) and rd["keys"]:
            print("    {数据库路径: 密钥}")
            for db, kk in rd["keys"].items():
                print(f"    {db} -> {kk}")
        print("=" * 32)

    if save_path:
        try:
            infos = json.load(open(save_path, "r", encoding="utf-8")) if os.path.exists(save_path) else []
        except Exception:
            infos = []
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(infos + result, f, ensure_ascii=False, indent=4)
    return result


def _wx4_mem_keys_report(wx_root=None, time_budget=300, pids=None, do_print=True,
                         sync_store=True, keys_file=None, extra_file=None):
    """
    【4.x·内存取密钥】只读内存扫描的正式入口：形状预筛 + 真库 salt 反推 32 字节 XOR 掩码 +
    第 1 页 HMAC 校验。返回结构化报告（keys = {相对库路径: key hex}）。
    sync_store=True（默认）时，顺手做两件落盘的事：
      ① 把内存取到、且通过 HMAC 校验的密钥回写 all_keys.json（写前自动备份）；
      ② 把未匹配串另存到 extra_mem_keys.json。
    失败/无命中都不抛异常，不影响 info / bias 主流程。
    """
    try:
        from .get_bias_addr import BiasAddr      # 局部导入，避免模块级循环依赖
    except Exception as e:
        print(f"[-] 4.x 内存取密钥不可用：{e}")
        return {"mask": None, "mask_at": None, "keys": {}, "unmatched": {},
                "processes": [], "error": str(e)}
    try:
        b = BiasAddr("", "", "", "", None)
        return b.run_wx4_xor_keys(wx_root=wx_root, pids=pids, time_budget=time_budget,
                                  do_print=do_print, sync_store=sync_store,
                                  keys_file=keys_file, extra_file=extra_file)
    except Exception as e:
        print(f"[-] 4.x 内存取密钥异常：{e}")
        return {"mask": None, "mask_at": None, "keys": {}, "unmatched": {},
                "processes": [], "error": str(e)}


def _wx4_scan_mem_report(key_file=None, keys=None):
    """
    【第二步·4.x】只读内存诊断：在 Weixin.exe 里搜 com.Tencent.WCDB.Config.Cipher 结构名，
    命中处做「单字节 XOR 解混淆」和「32 字节原始候选 -> 第 1 页 HMAC 校验」；
    结果打印出来并返回结构化报告。诊断失败/无命中都不影响 info / bias 的主流程。
    """
    try:
        from .get_bias_addr import BiasAddr      # 局部导入，避免模块级循环依赖
    except Exception as e:
        print(f"[-] 4.x 内存诊断不可用：{e}")
        return {"conclusion": "unavailable", "error": str(e), "verified_keys": {},
                "needle_totals": {}, "pids": []}
    try:
        b = BiasAddr("", "", "", "", None)
        key_list = list(keys.values()) if isinstance(keys, dict) else list(keys or [])
        return b.run_wx4_scan_mem(keys=key_list, key_file=(None if key_list else key_file))
    except Exception as e:
        print(f"[-] 4.x 内存诊断异常：{e}")
        return {"conclusion": "error", "error": str(e), "verified_keys": {},
                "needle_totals": {}, "pids": []}


# 读取微信信息(account,mobile,nickname,mail,wxid,key)
@wx_core_error
def get_wx_info(WX_OFFS: dict = None, is_print: bool = False, save_path: str = None,
                decrypted_dir: str = None, my_wxid: str = None, wx_path: str = None, keys_file: str = None,
                mode: str = None, key_file: str = None, scan_mem: bool = False,
                wx_root: str = None, mem_time_budget: float = 300,
                sync_store: bool = True, extra_keys_file: str = None):
    """
    读取微信信息(account,mobile,nickname,mail,wxid,key)
    :param WX_OFFS:  版本偏移量
    :param is_print:  是否打印结果
    :param save_path:  保存路径
    :param decrypted_dir: 【4.x】解密库目录；给了就走「读库」模式
    :param my_wxid:       【4.x】当前登录账号
    :param wx_path:       【4.x】微信数据目录
    :param keys_file:     【4.x】（旧名，兼容保留）密钥文件路径
    :param mode:          【第二步】auto / 3x / 4x
                          - auto：能附加 WeChat.exe 就走 3.x 老逻辑，否则走 4.x 读库
                          - 4x  ：【B 计划】完全不读进程内存，也不要求存在 WeChatWin.dll，
                                  密钥直接来自 --key_file 指定的本地密钥文件
                          - 3x  ：强制老逻辑
    :param key_file:      【第二步·4.x】本地密钥文件，形如 {"库路径": {"enc_key": "64位hex", "salt": "..."}}
    :param scan_mem:      【第三步·4.x】只读内存取密钥：形状预筛 + 真库 salt 反推 32 字节 XOR 掩码 +
                          第 1 页 HMAC 校验。给出 --scan_mem 时：
                            - 没给 --key_file：密钥直接用内存里拿到的（并打印掩码与逐库密钥）
                            - 给了 --key_file：以密钥文件为准，内存结果作为附加报告
    :param wx_root:       【4.x】微信数据根目录（默认 D:\\xwechat_files，用于收集真库 salt 与第 1 页）
    :param mem_time_budget: 【4.x】每个进程的内存扫描时间上限（秒）
    :param sync_store:    【收尾·4.x】内存取到密钥后是否自动落盘（默认 True）：
                            ① 与 all_keys.json 不同时回写（写前备份 .bak_时间戳）
                            ② 未匹配串另存到 extra_mem_keys.json
    :param extra_keys_file: 【收尾·4.x】未匹配串另存路径（默认 ...\\.wechat-cli\\extra_mem_keys.json）
    :return: 返回微信信息 [{"pid": pid, "version": version, "account": account,
                          "mobile": mobile, "nickname": nickname, "mail": mail, "wxid": wxid,
                          "key": key, "wx_dir": wx_dir}, ...]
    """
    if WX_OFFS is None:
        WX_OFFS = {}

    mode = (mode or "auto").lower()
    if mode not in ("auto", "3x", "4x"):
        wx_core_loger.warning(f"[-] mode 只支持 auto/3x/4x，收到 {mode}，按 auto 处理")
        mode = "auto"
    key_file = key_file or keys_file

    wechat_pids = []
    weixin_pids = []
    result = []

    # 【第一步·4.x】进程识别：原来只认 WeChat.exe，4.x 的 Weixin.exe 会被漏掉
    #   这里统一用 get_wx_processes()（名单 = WeChat.exe + Weixin.exe），再按代次分开用。
    #   3.x 分支只吃 wechat_pids，行为与改造前完全一致。
    try:
        from .get_bias_addr import get_wx_processes   # 局部导入，避免模块级循环依赖
        wx_procs = get_wx_processes()
    except Exception as e:
        wx_core_loger.warning(f"[-] get_wx_processes 不可用（{e}），回退到只认 WeChat.exe")
        wx_procs = [{"pid": pid, "name": name, "is_wx4": False}
                    for pid, name in get_process_list() if name == "WeChat.exe"]
    for d in wx_procs:
        if d.get("is_wx4"):
            weixin_pids.append(d["pid"])
        else:
            wechat_pids.append(d["pid"])
    if weixin_pids:
        wx_core_loger.warning(f"[*] 检测到 4.x 进程 Weixin.exe：{weixin_pids}"
                              f"（3.x 进程 WeChat.exe：{wechat_pids}）")

    if mode == "4x":
        # 【第三步·4.x】--scan_mem：只读内存取密钥（形状预筛 + 真库 salt 反推 XOR 掩码 + HMAC 校验）
        mem_report = None
        if scan_mem:
            mem_report = _wx4_mem_keys_report(wx_root=wx_root, time_budget=mem_time_budget,
                                              sync_store=sync_store,
                                              extra_file=extra_keys_file)
            if mem_report.get("keys") and not key_file:
                mem_keys = dict(mem_report["keys"])
                print(f"[+] 已从 Weixin.exe 内存直接取到 {len(mem_keys)} 把密钥，"
                      f"本次不需要 --key_file")
                if not decrypted_dir:
                    decrypted_dir = _wx4_guess_decrypted_dir(my_wxid)
                if not decrypted_dir:
                    # 【4.0】干净环境兜底：没现成解密库就只用内存密钥解密 contact/session/head_image
                    decrypted_dir = _wx4_autodecrypt_minimal(mem_keys, wx_root=wx_root)
                result = get_wx_info_from_db(decrypted_dir=decrypted_dir, my_wxid=my_wxid,
                                             wx_path=wx_path, keys=mem_keys, wx_root=wx_root)
                if result:
                    result[0]["key_source"] = "memory"
                    result[0]["mem_scan"] = {k: v for k, v in mem_report.items()
                                             if k != "processes"}
                    result[0]["mem_scan_conclusion"] = "ok"
                    if mem_report.get("key_store"):
                        result[0]["key_store"] = mem_report["key_store"]
        if not result:
            # 【第二步·B 计划】「解密库 + 本地密钥文件」路线：
            # 不扫内存、不要求 WeChatWin.dll，只读 contact 库 + 密钥文件。
            if not decrypted_dir:
                decrypted_dir = _wx4_guess_decrypted_dir(my_wxid)
                if decrypted_dir:
                    wx_core_loger.warning(f"[-] 未指定解密库目录(-dd)，自动使用 {decrypted_dir}")
            result = get_wx_info_from_db(decrypted_dir=decrypted_dir, my_wxid=my_wxid,
                                         wx_path=wx_path, key_file=key_file, wx_root=wx_root)
            if mem_report is not None and result:
                # 给了密钥文件时，内存结果作为附加报告；没命中也不改变密钥来源
                result[0]["mem_scan"] = {k: v for k, v in mem_report.items() if k != "processes"}
                result[0]["mem_scan_conclusion"] = ("ok" if mem_report.get("keys") else "no_hit")
                if mem_report.get("key_store"):
                    result[0]["key_store"] = mem_report["key_store"]
            elif scan_mem and result:
                report = _wx4_scan_mem_report(key_file=key_file,
                                             keys=(result[0].get("keys") if result else None))
                result[0]["mem_scan"] = {k: v for k, v in report.items() if k != "processes"}
                result[0]["mem_scan_conclusion"] = report.get("conclusion")
    elif mode == "3x" or (mode == "auto" and len(wechat_pids) > 0):
        for pid in wechat_pids:
            rd = get_info_details(pid, WX_OFFS)
            result.append(rd)
        if not result:
            wx_core_loger.error("[-] WeChat No Run")
            return result
    elif decrypted_dir or key_file:
        # 4.x：进程名是 Weixin.exe，而且没有 WeChatWin.dll 这套偏移可用，
        # 所以这里不报「WeChat No Run」直接退出，改成从已解密的库里读信息（完全不读进程内存）。
        wx_core_loger.warning("[-] 未发现微信 3.x 进程（WeChat.exe），改用已解密数据库读取微信信息")
        if not decrypted_dir:
            decrypted_dir = _wx4_guess_decrypted_dir(my_wxid)
        result = get_wx_info_from_db(decrypted_dir=decrypted_dir, my_wxid=my_wxid, wx_path=wx_path,
                                     key_file=key_file, wx_root=wx_root)
    else:
        wx_core_loger.error("[-] WeChat No Run")
        return result

    if is_print:
        print("=" * 32)
        if isinstance(result, str):  # 输出报错
            print(result)
        else:  # 输出结果
            if result and isinstance(result[0], dict) and result[0].get("source") == "db":
                if result[0].get("key_source") == "memory":
                    print("[+] 数据来源：已解密数据库 + Weixin.exe 只读内存扫描得到的密钥"
                          "（未注入、未 Hook、未修改微信文件）")
                else:
                    print("[+] 数据来源：已解密数据库 + 本地密钥文件（微信 4.x，未读取微信进程内存）")
            for i, rlt in enumerate(result):
                for k, v in rlt.items():
                    if k == "keys" and isinstance(v, dict):
                        print(f"[+] {k:>8}: {len(v)} 个库的密钥（见下方 库路径:密钥 列表）")
                        continue
                    print(f"[+] {k:>8}: {v if v else 'None'}")
                if isinstance(rlt.get("keys"), dict) and rlt["keys"]:
                    print("    {库路径: 密钥}")
                    for db, kk in rlt["keys"].items():
                        print(f"    {db} -> {kk}")
                print(end="-" * 32 + "\n" if i != len(result) - 1 else "")
        print("=" * 32)

    if save_path:
        try:
            infos = json.load(open(save_path, "r", encoding="utf-8")) if os.path.exists(save_path) else []
        except:
            infos = []
        with open(save_path, "w", encoding="utf-8") as f:
            infos += result
            json.dump(infos, f, ensure_ascii=False, indent=4)
    return result


def _wx4_guess_msg_dir():
    r"""
    【4.0】微信 4.x 数据目录兜底定位（3.x 的注册表路径在 4.x 上根本不存在，不能拿它当唯一来源）

    顺序：
      1) 密钥文件 + 账号目录 → 用 page1 HMAC 认出「当前登录账号」的目录（谁在写库选谁），
         这样 wx_path 直接列出该账号的库；
      2) 拿不到密钥/认不出账号 → 返回 4.x 数据根目录（如 D:\xwechat_files），
         由 get_wx_db 自己往下枚举各账号目录；
      3) 都没有 → None。
    返回：可用的目录（str）或 None
    """
    try:
        from .wx4_prepare import (default_wx_root, find_account_dirs, pick_account,
                                  read_keys, default_key_file, _account_recency)
    except Exception as e:  # 理论上不会发生；任何异常都不该让 wx_path 崩掉
        wx_core_loger.warning(f"[-] 4.x 目录定位模块不可用: {e}")
        return None

    root = None
    try:
        root = default_wx_root()
    except Exception:
        root = None

    accounts = []
    if root and os.path.isdir(root):
        try:
            accounts = find_account_dirs(root)
        except Exception:
            accounts = []

    # 1) 用密钥文件认「当前登录账号」
    keys = {}
    try:
        kf = default_key_file()
        if kf and os.path.exists(kf):
            keys = read_keys(kf)
    except Exception:
        keys = {}
    if keys and accounts:
        try:
            acct, _ds, detail = pick_account(accounts, keys)
        except Exception:
            acct, detail = None, ""
        if acct and os.path.isdir(acct):
            wx_core_loger.info(f"[*] 4.x 已定位当前登录账号目录：{acct}（{detail}）")
            return acct

    # 2) 没有密钥也要能用：多个账号时选"库文件最新被写入"的那个（正在登录的账号）
    if accounts:
        try:
            acct = max(accounts, key=lambda t: _account_recency(t[0]))[0]
            if acct and os.path.isdir(acct):
                ts = _account_recency(acct)
                wx_core_loger.info(
                    f"[*] 4.x 无可用密钥，按库最新写入时间选了账号目录：{acct}"
                    + (f"（{time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))}）" if ts else ""))
                return acct
        except Exception:
            pass

    # 3) 退回 4.x 数据根目录
    if root and os.path.isdir(root):
        wx_core_loger.info(f"[*] 4.x 使用数据根目录：{root}")
        return root
    return None


@wx_core_error
def get_wx_db(msg_dir: str = None,
              db_types: Union[List[str], str] = None,
              wxids: Union[List[str], str] = None) -> List[dict]:
    r"""
    获取微信数据库路径
    :param msg_dir:  微信数据库目录 eg: C:\Users\user\Documents\WeChat Files （非wxid目录）
                     4.x 可传：数据根目录 D:\xwechat_files / 账号目录 / 账号目录\db_storage，留空则自动定位
    :param db_types:  需要获取的数据库类型,如果为空,则获取所有数据库
    :param wxids:  微信id列表,如果为空,则获取所有wxid下的数据库
    :return: [{"wxid": wxid, "db_type": db_type, "db_path": db_path, "wxid_dir": wxid_dir}, ...]
    """
    result = []

    if msg_dir and not os.path.exists(msg_dir):
        # 4.x 常见写法：直接给 D:\xwechat_files\db_storage 或账号目录下的 db_storage
        alt = os.path.join(msg_dir, "db_storage")
        if os.path.isdir(alt):
            msg_dir = alt
        else:
            wx_core_loger.warning(f"[-] 传入的目录不存在: {msg_dir}")

    if not msg_dir or not os.path.exists(msg_dir):
        msg_dir = get_wx_dir_by_reg(wxid="all")

    # 【4.0】3.x 注册表路径拿不到（微信 4.x 没有 WeChat Files 注册表项）→ 自动定位 4.x 目录
    if not msg_dir or not os.path.exists(msg_dir):
        wx_core_loger.warning("[-] 未取到 3.x 微信文件目录（微信 4.x 无此注册表项），尝试自动定位 4.x 数据目录……")
        msg_dir = _wx4_guess_msg_dir()

    if not msg_dir or not os.path.exists(msg_dir):
        wx_core_loger.error(f"[-] 目录不存在: {msg_dir}；请用 -wf/--wx_path 指定微信数据目录", exc_info=True)
        return result

    wxids = wxids.split(";") if isinstance(wxids, str) else wxids
    if not isinstance(wxids, list) or len(wxids) <= 0:
        wxids = None
    db_types = db_types.split(";") if isinstance(db_types, str) and db_types else db_types
    if not isinstance(db_types, list) or len(db_types) <= 0:
        db_types = None

    wxid_dirs = {}  # wx用户目录
    if wxids or "All Users" in os.listdir(msg_dir) or "Applet" in os.listdir(msg_dir) or "WMPF" in os.listdir(msg_dir):
        for sub_dir in os.listdir(msg_dir):
            if os.path.isdir(os.path.join(msg_dir, sub_dir)) and sub_dir not in ["All Users", "Applet", "WMPF"]:
                wxid_dirs[os.path.basename(sub_dir)] = os.path.join(msg_dir, sub_dir)
    else:
        wxid_dirs[os.path.basename(msg_dir)] = msg_dir
    for wxid, wxid_dir in wxid_dirs.items():
        if wxids and wxid not in wxids:  # 如果指定wxid,则过滤掉其他wxid
            continue
        for root, dirs, files in os.walk(wxid_dir):
            for file_name in files:
                if not file_name.endswith(".db"):
                    continue
                db_type = re.sub(r"\d*\.db$", "", file_name)
                if db_types and db_type not in db_types:  # 如果指定db_type,则过滤掉其他db_type
                    continue
                db_path = os.path.join(root, file_name)
                result.append({"wxid": wxid, "db_type": db_type, "db_path": db_path, "wxid_dir": wxid_dir})
    return result


@wx_core_error
def get_core_db(wx_path: str, db_types: list = None) -> [dict]:
    r"""
    获取聊天消息核心数据库路径
    :param wx_path: 微信文件夹路径 eg：C:\*****\WeChat Files\wxid*******
    :param db_types: 数据库类型 eg: CORE_DB_TYPE，中选择一个或多个
    :return: 返回数据库路径 eg: [{"wxid": wxid, "db_type": db_type, "db_path": db_path, "wxid_dir": wxid_dir}, ...]
    """
    if not os.path.exists(wx_path):
        return False, f"[-] 目录不存在: {wx_path}"

    if not db_types:
        db_types = CORE_DB_TYPE
    db_types = [dt for dt in db_types if dt in CORE_DB_TYPE]
    msg_dir = os.path.dirname(wx_path)
    my_wxid = os.path.basename(wx_path)
    wxdbpaths = get_wx_db(msg_dir=msg_dir, db_types=db_types, wxids=my_wxid)

    if len(wxdbpaths) == 0:
        wx_core_loger.error(f"[-] get_core_db 未获取到数据库路径")
        return False, "未获取到数据库路径"
    return True, wxdbpaths


if __name__ == '__main__':
    from pywxdump import WX_OFFS

    get_wx_info(WX_OFFS, is_print=True)
