# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         get_base_addr.py
# Description:  
# Author:       xaoyaoo
# Date:         2023/08/22
# -------------------------------------------------------------------------------
import ctypes
import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct
import sys
import time as _time
from ctypes import wintypes

import psutil
import pymem

from .utils import get_exe_version, get_exe_bit, verify_key
from .utils import get_process_list, get_memory_maps, get_process_exe_path, get_file_version_info
from .utils import search_memory

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory if sys.platform == "win32" else None
void_p = ctypes.c_void_p

# 定义常量
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# 【第一步·4.x 新增】扫 4.x 的 key 要按区段属性过滤，这里补上需要的常量
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

# ==================================================================
# 【第一步·4.x 新增】进程识别：3.x 是 WeChat.exe，4.x 是 Weixin.exe，两家都要认
#   以前只认 WeChat.exe，所以 4.x 下永远报 "WeChat No Run"。
#   这里统一成一份名单 + 一个遍历函数，3.x/4.x 都从这里取进程。
# ==================================================================
WX_PROCESS_NAMES = ("WeChat.exe", "Weixin.exe")


def get_wx_processes(names=WX_PROCESS_NAMES):
    """
    遍历系统进程，返回所有微信进程（3.x 的 WeChat.exe 与 4.x 的 Weixin.exe 一起返回）。

    :param names: 进程名白名单（不区分大小写）
    :return: [{"pid": int, "name": "Weixin.exe", "is_wx4": bool, "private": int}, ...]
             按私有内存从大到小排序（4.x 是多进程架构，主进程一般私有内存最大）
    """
    out = []
    lowered = tuple(n.lower() for n in names)
    for pid, name in get_process_list():
        if not name or name.lower() not in lowered:
            continue
        try:
            private = psutil.Process(pid).memory_info().private or 0
        except Exception:
            private = 0
        out.append({"pid": pid, "name": name,
                    "is_wx4": name.lower() == "weixin.exe", "private": private})
    return sorted(out, key=lambda d: d["private"], reverse=True)


def find_wx_process_pids(wx4=None):
    """
    :param wx4: True 只要 4.x 的 Weixin.exe；False 只要 3.x 的 WeChat.exe；None 全要
    :return: [pid, ...]（按私有内存从大到小）
    """
    procs = get_wx_processes()
    if wx4 is not None:
        procs = [d for d in procs if d["is_wx4"] == bool(wx4)]
    return [d["pid"] for d in procs]


class BiasAddr:
    def __init__(self, account, mobile, name, key, db_path):
        # 【第一步·4.x】4.x 分支不需要昵称/手机号/微信号，允许传 None/空，避免 .encode 直接崩
        self.account = (account or "").encode("utf-8")
        self.mobile = (mobile or "").encode("utf-8")
        self.name = (name or "").encode("utf-8")
        self.key = bytes.fromhex(key) if key else b""
        self.raw_db_path = db_path  # 原样留存：4.x 报错时能告诉用户他到底传了什么
        self.db_path = db_path if db_path and os.path.exists(db_path) else ""

        self.process_name = "WeChat.exe"      # 3.x：保持原样
        self.module_name = "WeChatWin.dll"    # 3.x：保持原样

        # 【第一步·4.x】4.x：进程名是 Weixin.exe，没有 WeChatWin.dll 可用
        self.wx4_process_name = "Weixin.exe"
        self.is_wx4 = False

        self.pm = None  # Pymem 对象
        self.is_WoW64 = None  # True: 32位进程运行在64位系统上 False: 64位进程运行在64位系统上
        self.process_handle = None  # 进程句柄
        self.pid = None  # 进程ID
        self.version = None  # 微信版本号
        self.process = None  # 进程对象
        self.exe_path = None  # 微信路径
        self.address_len = None  # 4 if self.bits == 32 else 8  # 4字节或8字节
        self.bits = 64 if sys.maxsize > 2 ** 32 else 32  # 系统：32位或64位

    def get_process_handle(self, process_name=None):
        # 【第一步·4.x】多一个可选参数：不传就还是原来的 WeChat.exe，
        # 3.x 的调用方式与行为一字不变；4.x 由外部传 "Weixin.exe"。
        process_name = process_name or self.process_name
        try:
            self.pm = pymem.Pymem(process_name)
            self.pm.check_wow64()
            self.is_WoW64 = self.pm.is_WoW64
            self.process_handle = self.pm.process_handle
            self.pid = self.pm.process_id
            self.process = psutil.Process(self.pid)
            self.exe_path = self.process.exe()
            self.version = get_exe_version(self.exe_path)

            version_nums = list(map(int, self.version.split(".")))  # 将版本号拆分为数字列表
            if version_nums[0] <= 3 and version_nums[1] <= 9 and version_nums[2] <= 2:
                self.address_len = 4
            else:
                self.address_len = 8
            return True, ""
        except pymem.exception.ProcessNotFound:
            return False, "[-] WeChat No Run"

    def search_memory_value(self, value: bytes, module_name="WeChatWin.dll"):
        start_adress = 0x7FFFFFFFFFFFFFFF
        end_adress = 0

        memory_maps = get_memory_maps(self.pid)
        for module in memory_maps:
            if module.FileName and module_name in module.FileName:
                s = module.BaseAddress
                e = module.BaseAddress + module.RegionSize
                start_adress = s if s < start_adress else start_adress
                end_adress = e if e > end_adress else end_adress
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        ret = search_memory(hProcess, value, max_num=3, start_address=start_adress,
                                    end_address=end_adress)
        ret = ret[-1] - start_adress if len(ret) > 0 else 0

        # # 创建 Pymem 对象
        # module = pymem.process.module_from_name(self.pm.process_handle, module_name)
        # ret = self.pm.pattern_scan_module(value, module, return_multiple=True)
        # ret = ret[-1] - module.lpBaseOfDll if len(ret) > 0 else 0
        return ret

    def get_key_bias1(self):
        """
        2024.01.26 wx version：3.9.9.35 失效
        :return:
        """
        try:
            byteLen = self.address_len  # 4 if self.bits == 32 else 8  # 4字节或8字节

            keyLenOffset = 0x8c if self.bits == 32 else 0xd0
            keyWindllOffset = 0x90 if self.bits == 32 else 0xd8

            module = pymem.process.module_from_name(self.process_handle, self.module_name)
            keyBytes = b'-----BEGIN PUBLIC KEY-----\n...'
            publicKeyList = pymem.pattern.pattern_scan_all(self.process_handle, keyBytes, return_multiple=True)
            keyaddrs = []
            for addr in publicKeyList:
                keyBytes = addr.to_bytes(byteLen, byteorder="little", signed=True)  # 低位在前
                may_addrs = pymem.pattern.pattern_scan_module(self.process_handle, module, keyBytes,
                                                              return_multiple=True)
                if may_addrs != 0 and len(may_addrs) > 0:
                    for addr in may_addrs:
                        keyLen = self.pm.read_uchar(addr - keyLenOffset)
                        if keyLen != 32:
                            continue
                        keyaddrs.append(addr - keyWindllOffset)

            return keyaddrs[-1] - module.lpBaseOfDll if len(keyaddrs) > 0 else 0
        except:
            return 0

    def search_key(self, key: bytes):
        key = re.escape(key)  # 转义特殊字符
        key_addr = self.pm.pattern_scan_all(key, return_multiple=False)
        key = key_addr.to_bytes(self.address_len, byteorder='little', signed=True)
        result = self.search_memory_value(key, self.module_name)
        return result

    def get_key_bias2(self, wx_db_path):

        addr_len = get_exe_bit(self.exe_path) // 8
        db_path = wx_db_path

        def read_key_bytes(h_process, address, address_len=8):
            array = ctypes.create_string_buffer(address_len)
            if ReadProcessMemory(h_process, void_p(address), array, address_len, 0) == 0: return "None"
            address = int.from_bytes(array, byteorder='little')  # 逆序转换为int地址（key地址）
            key = ctypes.create_string_buffer(32)
            if ReadProcessMemory(h_process, void_p(address), key, 32, 0) == 0: return "None"
            key_bytes = bytes(key)
            return key_bytes

        phone_type1 = "iphone\x00"
        phone_type2 = "android\x00"
        phone_type3 = "ipad\x00"

        pm = pymem.Pymem(self.pid)
        module_name = "WeChatWin.dll"

        MicroMsg_path = os.path.join(db_path, "MSG", "MicroMsg.db")

        type1_addrs = pm.pattern_scan_module(phone_type1.encode(), module_name, return_multiple=True)
        type2_addrs = pm.pattern_scan_module(phone_type2.encode(), module_name, return_multiple=True)
        type3_addrs = pm.pattern_scan_module(phone_type3.encode(), module_name, return_multiple=True)

        type_addrs = []
        if len(type1_addrs) >= 2: type_addrs += type1_addrs
        if len(type2_addrs) >= 2: type_addrs += type2_addrs
        if len(type3_addrs) >= 2: type_addrs += type3_addrs
        if len(type_addrs) == 0: return "None"

        type_addrs.sort()  # 从小到大排序

        module = pymem.process.module_from_name(pm.process_handle, module_name)

        for i in type_addrs[::-1]:
            for j in range(i, i - 2000, -addr_len):
                key_bytes = read_key_bytes(pm.process_handle, j, addr_len)
                if key_bytes == "None":
                    continue
                if verify_key(key_bytes, MicroMsg_path):
                    return j - module.lpBaseOfDll
        return 0

    # ==================================================================
    # 【第一步·4.x 新增】微信 4.x 的密钥扫描
    #
    # 4.x 和 3.x 是两套东西，不能混：
    #   3.x：WeChatWin.dll + WX_OFFS.json 里的一组固定偏移 -> base+off 直接读内存
    #   4.x：没有 WeChatWin.dll、没有固定偏移（所以 WX_OFFS.json 在 4.x 上作废）。
    #        WCDB 把每个库派生好的 raw key 以【明文 ASCII】缓存在进程堆里，形态是
    #            x'<64位hex的enc_key><32位hex的salt>'
    #        拿到候选后必须用 SQLCipher4 的第 1 页 HMAC-SHA512 校验（见 verify_page1_hmac_4x）：
    #            mac_key = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3a, 2, 32)
    #            HMAC-SHA512(mac_key, page1[16 : 4096-80+16] + LE32(1)) == page1[4096-64:]
    #        3.x 的 verify_key 是 PBKDF2-SHA1/64000，在 4.x 上永远 False，不能拿它校验。
    #   * 每个库自带 salt、各有一把 key，所以 4.x 的产物是 {加密库路径: key}，没有"偏移"。
    #   * 扫不到时只报错并提示重启微信，不做 DLL 注入 / Hook。
    # ==================================================================
    WX4_PAGE_SIZE = 4096        # SQLCipher4 页大小
    WX4_KEY_SIZE = 32           # enc_key 32 字节（=64 位 hex）
    WX4_SALT_SIZE = 16          # salt 16 字节（=32 位 hex）
    WX4_IV_SIZE = 16
    WX4_HMAC_SIZE = 64
    WX4_RESERVE_SIZE = 80       # 每页尾部 reserve = IV(16) + HMAC(64)
    WX4_SQLITE_HDR = b"SQLite format 3\x00"
    # WCDB 缓存在内存里的密钥字符串
    WCDB_KEY_RE = re.compile(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})'")

    def _read_mem(self, hProcess, address, size):
        """
        读一段进程内存。地址必须用 void_p() 包一层：
        本模块的 ReadProcessMemory 没设 argtypes，直接传 Python int 会按 32 位截断。
        """
        if size <= 0:
            return b""
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        ret = ReadProcessMemory(hProcess, void_p(address), buf, ctypes.c_size_t(size),
                                ctypes.byref(bytes_read))
        if ret == 0:
            return b""
        n = bytes_read.value
        return buf.raw[:n] if n else buf.raw

    def _iter_wx4_scannable_regions(self, pid):
        """
        4.x 只在【已提交、可读、非映射文件】的区段里找 key。
        跳过 FileName 非空的是因为那都是 dll/映像，key 不在里面（在堆上），能省大量时间。
        """
        allowed = (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                   PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
        for m in get_memory_maps(pid):
            if m.State != MEM_COMMIT or not m.RegionSize or m.RegionSize <= 0:
                continue
            if m.Protect & PAGE_NOACCESS or m.Protect & PAGE_GUARD:
                continue
            if (m.Protect & 0xFF) not in allowed:   # 低 8 位才是基础保护属性
                continue
            if m.FileName:                          # 映射进来的文件/映像，跳过
                continue
            yield m

    @staticmethod
    def _read_page1(path):
        """读加密库的第 1 页（4096 字节），用来做 key 校验"""
        try:
            with open(path, "rb") as f:
                data = f.read(BiasAddr.WX4_PAGE_SIZE)
        except (OSError, IOError):
            return b""
        return data if len(data) == BiasAddr.WX4_PAGE_SIZE else b""

    def _wx4_candidate_pids(self):
        """
        4.x 是多进程架构，Weixin.exe 往往有好几个（主进程 + 渲染/插件等）。
        主进程一般占用私有内存最多，所以按私有内存从大到小排，逐个扫、命中即停。
        【第一步·4.x】进程名匹配统一走 get_wx_processes（同时认 WeChat.exe / Weixin.exe）。
        """
        pids = [d["pid"] for d in get_wx_processes((self.wx4_process_name,))]
        if self.pid and self.pid not in pids:
            pids.insert(0, self.pid)
        return pids

    def _wx4_default_roots(self):
        """4.x 数据目录候选：注册表 -> 常见位置（各盘的 xwechat_files 目录、我的文档下）"""
        roots = []
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\Weixin",
                                0, winreg.KEY_READ) as k:
                for name in ("FileSavePath", "SavePath"):
                    try:
                        v, _ = winreg.QueryValueEx(k, name)
                    except OSError:
                        continue
                    if isinstance(v, str) and v and os.path.isdir(v):
                        roots.append(v)
        except Exception:
            pass
        for drive in ("C:", "D:", "E:", "F:", "G:"):
            p = os.path.join(drive + os.sep, "xwechat_files")
            if os.path.isdir(p):
                roots.append(p)
        p = os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files")
        if os.path.isdir(p):
            roots.append(p)
        out = []
        for r in roots:          # 去重、保序
            if r not in out:
                out.append(r)
        return out

    def collect_wx4_databases(self, db_path=None):
        """
        收集 4.x 的加密库，返回 [(库路径, 第1页4096字节), ...]

        db_path 可以给账号目录（...\\wxid_xxx_abcd）也可以直接给 db_storage；
        不给就按注册表 / 常见位置自动找。
        """
        roots = []
        if db_path:
            if os.path.isdir(db_path):
                roots.append(db_path)
            else:
                print(f"[-] 指定的 db_path 不存在：{db_path}（改为自动查找）")
        if not roots:
            roots = self._wx4_default_roots()
        if not roots:
            return []

        # 注册表给的多半是账号目录，数据库在它下面的 db_storage 里
        out, seen = [], set()
        for root in roots:
            sub = os.path.join(root, "db_storage")
            walk_root = sub if os.path.isdir(sub) else root
            for dirpath, _dirs, files in os.walk(walk_root):
                for fn in files:
                    low = fn.lower()
                    if not low.endswith(".db") or low.endswith(("-wal", "-shm", "-journal")):
                        continue
                    p = os.path.join(dirpath, fn)
                    if p in seen:
                        continue
                    seen.add(p)
                    page1 = self._read_page1(p)
                    if page1:
                        out.append((p, page1))
        return out

    def verify_page1_hmac_4x(self, enc_key, page1):
        """
        4.x（SQLCipher4）的 key 校验：只用第 1 页的 HMAC-SHA512，不需要解密整页。
        逻辑与已跑通的 batch_decrypt.py 完全一致（同一套页格式参数）。
        """
        try:
            if len(enc_key) != self.WX4_KEY_SIZE or len(page1) < self.WX4_PAGE_SIZE:
                return False
            salt = page1[:self.WX4_SALT_SIZE]
            mac_salt = bytes(b ^ 0x3A for b in salt)
            mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=self.WX4_KEY_SIZE)
            data = page1[self.WX4_SALT_SIZE:
                         self.WX4_PAGE_SIZE - self.WX4_RESERVE_SIZE + self.WX4_IV_SIZE]
            stored = page1[self.WX4_PAGE_SIZE - self.WX4_HMAC_SIZE: self.WX4_PAGE_SIZE]
            hm = hmac_mod.new(mac_key, data, hashlib.sha512)
            hm.update(struct.pack("<I", 1))
            return hmac_mod.compare_digest(hm.digest(), stored)
        except Exception:
            return False

    def scan_wcdb_keys(self, pid=None, databases=None, chunk_size=8 << 20, overlap=128,
                       progress_every=64):
        """
        在 4.x 进程内存里扫 WCDB 缓存的 key，并用本地加密库的第 1 页 HMAC 校验。

        :param pid:        目标进程 pid（默认用 self.pid）
        :param databases:  [(库路径, 第1页), ...]，不传就按 self.db_path / 默认位置自动收集
        :param chunk_size: 单次读取的块大小（默认 8MB），块间留 overlap 避免 key 串被切断
        :return: {加密库路径: key_hex}，只有 HMAC 校验通过的才会出现
        """
        pid = pid or self.pid
        if not pid:
            return {}
        if databases is None:
            databases = self.collect_wx4_databases(self.db_path)
        if not databases:
            return {}

        # salt(hex) -> [(库路径, 第1页), ...]：同 salt 的库用同一把 key 校验
        by_salt = {}
        for path, page1 in databases:
            salt = page1[:self.WX4_SALT_SIZE].hex().lower()
            by_salt.setdefault(salt, []).append((path, page1))

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not hProcess:
            print("[-] OpenProcess 失败：读进程内存需要管理员权限，请用【管理员身份】重开 PowerShell")
            print(f"[-] 目标 pid = {pid}")
            return {}

        cands, regions, scanned, hits = {}, 0, 0, 0
        try:
            for m in self._iter_wx4_scannable_regions(pid):
                regions += 1
                addr, remain = m.BaseAddress, int(m.RegionSize)
                while remain > 0:
                    n = min(chunk_size, remain)
                    buf = self._read_mem(hProcess, addr, n)
                    scanned += n
                    if buf:
                        for mt in self.WCDB_KEY_RE.finditer(buf):
                            hits += 1
                            cands.setdefault(mt.group(2).decode().lower(), set()).add(
                                mt.group(1).decode().lower())
                    step = n - overlap if n > overlap else n     # 留重叠，防止 key 串被切断
                    addr += step
                    remain -= step
                if progress_every and regions % progress_every == 0:
                    print(f"    …已扫 {regions} 个区段 / {scanned / 1048576:.0f} MB，"
                          f"命中候选 {hits} 个")
        finally:
            CloseHandle(hProcess)

        print(f"[*] 内存扫描完成：{regions} 个区段 / {scanned / 1048576:.0f} MB，"
              f"命中 WCDB key 字符串 {hits} 个，覆盖 {len(cands)} 个 salt")
        if not cands:
            return {}

        keymap = {}
        for salt, dbs in by_salt.items():
            keys = cands.get(salt)
            if not keys:
                continue
            for path, page1 in dbs:
                for key_hex in keys:
                    if self.verify_page1_hmac_4x(bytes.fromhex(key_hex), page1):
                        keymap[path] = key_hex
                        break
        return keymap

    # ==================================================================
    # 【第二步·4.x 新增】按结构名定位 com.Tencent.WCDB.Config.Cipher，并尝试解混淆
    #
    #   和上面的 scan_wcdb_keys 是两条不同的路：
    #     scan_wcdb_keys  ：WCDB 把派生好的 key 以【明文 ASCII】缓存成 x'<64hex><32hex>'
    #     本段（用户方案）：先找 Config.Cipher 结构体，再读/解混淆结构里的 32 字节密钥
    #
    #   全程只读：不注入、不 Hook、不写对方进程内存、不改任何库文件。
    #
    #   步骤：
    #     1) 在 Weixin.exe 的私有可读区段里搜结构名字符串
    #        （ascii / utf16le 的 "com.Tencent.WCDB.Config.Cipher"，以及 "Config.Cipher"、"WCDB.Config"）
    #     2) 每个命中点输出：地址 + 原始字节 hex + ASCII 视图（先把原始字节交出来）
    #     3) 命中点 ±xor_ctx 窗口内做两类解混淆：
    #        (a) 单字节 XOR 反查：0x00~0xFF 逐一遍历，命中即得到 mask（用户提到的 XOR 混淆）
    #        (b) 不假定任何混淆：窗口内所有 32 字节切片原样提取，直接做第 1 页 HMAC 校验，
    #            能过校验的就是真密钥（不依赖"到底是不是 XOR"的猜测）
    #     4) 返回结构化报告，任何异常都不会往外抛。
    #
    #   本机实测（微信 4.1.15.13 / 5 个 Weixin.exe / 2040 区段 / 432 MB）：
    #     结构名 0 命中 → 没有可解混淆的对象，report["verified_keys"] 为空，
    #     调用方据此回退本地密钥文件（B 计划）。逻辑本身有 --selftest 合成缓冲区自测兜底。
    # ==================================================================
    WX4_CIPHER_NEEDLES = (
        ("ascii:com.Tencent.WCDB.Config.Cipher", b"com.Tencent.WCDB.Config.Cipher"),
        ("utf16:com.Tencent.WCDB.Config.Cipher",
         "com.Tencent.WCDB.Config.Cipher".encode("utf-16-le")),
        ("ascii:Config.Cipher", b"Config.Cipher"),
        ("ascii:WCDB.Config", b"WCDB.Config"),
        ("utf16:Cipher", "Cipher".encode("utf-16-le")),
    )

    @staticmethod
    def wx4_module_base(pid, module_name="Weixin.exe"):
        """Weixin.exe 映像基址：区段里 FileName 命中该模块的最小 BaseAddress（拿不到返回 None）"""
        base = None
        try:
            for m in get_memory_maps(pid):
                if (m.FileName or "").lower().endswith(module_name.lower()):
                    if base is None or m.BaseAddress < base:
                        base = m.BaseAddress
        except Exception:
            return None
        return base

    @staticmethod
    def _xor_sweep(window, keys):
        """
        单字节 XOR 解混淆：对每把已知真密钥，遍历 mask=0x00~0xFF 去找 key^mask。
        :return: {"raw": [明文直接命中的 key_hex], "xored": [(key_hex, mask), ...]}
        """
        raw, xored = [], []
        for key_hex in (keys or ()):
            try:
                k = bytes.fromhex(str(key_hex).strip())
            except ValueError:
                continue
            if len(k) != BiasAddr.WX4_KEY_SIZE:
                continue
            if window.find(k) >= 0:
                raw.append(key_hex)
                continue
            for mask in range(1, 256):
                if window.find(bytes(c ^ mask for c in k)) >= 0:
                    xored.append((key_hex, mask))
                    break
        return {"raw": raw, "xored": xored}

    @staticmethod
    def _extract_32b_candidates(window, step=1, cap=1024):
        """把窗口里所有 32 字节切片原样提取（去重 + 限量），用于直接做 HMAC 校验"""
        out, seen, n = [], set(), BiasAddr.WX4_KEY_SIZE
        for i in range(0, max(0, len(window) - n + 1), step):
            c = window[i:i + n]
            if c in seen:
                continue
            seen.add(c)
            out.append((i, c))
            if len(out) >= cap:
                break
        return out

    def _verify_key_into(self, key_hex, databases, info, mask=None, offset=None):
        """
        候选 32 字节密钥 -> 用第 1 页 HMAC 校验，通过的记进 info["raw_verified"]。
        :return: True 表示至少有一个库校验通过
        """
        if not databases or not key_hex:
            return False
        key_hex = str(key_hex).lower()
        tried = info.setdefault("_tried", set())
        if key_hex in tried:
            return False
        tried.add(key_hex)
        try:
            kb = bytes.fromhex(key_hex)
        except ValueError:
            return False
        ok = False
        for path, page1 in databases:
            try:
                if self.verify_page1_hmac_4x(kb, page1):
                    info["raw_verified"][path] = {"key": key_hex, "mask": mask, "offset": offset}
                    ok = True
            except Exception:
                continue
        return ok

    def _scan_one_buffer(self, buf, base_addr, keys, databases, info, ctx, max_hits, max_cands,
                         max_verify):
        """
        扫一个内存块：找结构名 -> dump 原始字节 -> XOR 反查 / 32 字节候选校验

        成本控制（命中很多时不能把时间烧光）：
          · XOR 反查窗口 = ±ctx（默认 8KB）
          · 32 字节候选按 step=4 抽，每个命中点最多 max_cands 个
          · 每个进程累计校验次数上限 max_verify（HMAC 校验是这里最贵的一步）
        """
        for name, needle in self.WX4_CIPHER_NEEDLES:
            start = 0
            while True:
                pos = buf.find(needle, start)
                if pos < 0:
                    break
                info["needle_hits"][name] += 1
                start = pos + 1
                if len(info["samples"]) >= max_hits:
                    continue
                win_lo = max(0, pos - ctx)
                win_hi = min(len(buf), pos + ctx + len(needle))
                win = buf[win_lo:win_hi]
                lo, hi = max(0, pos - 48), min(len(buf), pos + 96)
                sample = {"needle": name, "addr": base_addr + pos,
                          "hex": buf[lo:hi].hex(" "),
                          "ascii": re.sub(rb"[^\x20-\x7e]", b".", buf[lo:hi]).decode("ascii", "replace")}
                sw = self._xor_sweep(win, keys) if keys else {"raw": [], "xored": []}
                sample["xor_raw_hit"] = list(sw["raw"])
                sample["xor_mask_hit"] = [{"key": str(k)[:16] + "…", "mask": m} for k, m in sw["xored"]]
                for k, m in sw["xored"]:
                    if not any(d["key"] == k and d["mask"] == m for d in info["xor_found"]):
                        info["xor_found"].append({"key": k, "mask": m, "addr": base_addr + pos})
                    self._verify_key_into(k, databases, info, mask=m)
                # 不假定任何混淆：窗口内 32 字节切片原样提取后直接做 HMAC 校验
                for off, cand in self._extract_32b_candidates(win, step=4, cap=max_cands):
                    if info.get("_verified", 0) >= max_verify:
                        break
                    info["_verified"] = info.get("_verified", 0) + 1
                    self._verify_key_into(cand.hex(), databases, info, offset=win_lo + off)
                info["samples"].append(sample)

    def scan_cipher_struct(self, pid=None, keys=None, databases=None, chunk_size=8 << 20,
                           overlap=256, ctx=8192, max_hits=50, max_cands=256, max_verify=4000,
                           progress_every=64):
        """
        按结构名扫 Config.Cipher（只读）。返回报告：
          processes     : [{pid,name,base,regions,mb,elapsed,needle_hits,samples,xor_found,raw_verified}]
          needle_totals : {特征串: 总命中数}
          verified_keys : {库路径: {key, mask, offset}}   —— 真的从内存里验出密钥时才非空
          conclusion    : hit / no_hit / no_key / no_process / open_failed
        :param keys:      已知真密钥 [64位hex, ...]，用于单字节 XOR 反查（可空）
        :param databases: [(库路径, 第1页4096字节), ...]，用于校验 32 字节候选；不传就自动收集
        :param ctx:        命中点两侧窗口大小（默认 8KB）
        :param max_verify: 每个进程最多做多少次 HMAC 校验（默认 4000，防止命中一大堆时拖太久）
        """
        report = {"pids": [], "processes": [],
                  "needle_totals": {n: 0 for n, _ in self.WX4_CIPHER_NEEDLES},
                  "verified_keys": {}, "conclusion": "", "error": None}
        pids = [pid] if pid else self._wx4_candidate_pids()
        report["pids"] = list(pids)
        if not pids:
            report["conclusion"] = "no_process"
            return report

        if databases is None:
            try:
                databases = self.collect_wx4_databases(self.raw_db_path or self.db_path)
            except Exception as e:
                report["error"] = f"收集加密库失败：{e}"
                databases = []

        for one in pids:
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, one)
            if not hProcess:
                report["processes"].append({"pid": one,
                                            "error": "OpenProcess 失败（读进程内存需要管理员权限）"})
                report["conclusion"] = "open_failed"
                continue
            t0 = _time.time()
            try:
                try:
                    pname = psutil.Process(one).name()
                except Exception:
                    pname = ""
                info = {"pid": one, "name": pname, "base": self.wx4_module_base(one),
                        "regions": 0, "mb": 0.0, "elapsed": 0.0,
                        "needle_hits": {n: 0 for n, _ in self.WX4_CIPHER_NEEDLES},
                        "samples": [], "xor_found": [], "raw_verified": {},
                        "_verified": 0, "_tried": set()}
                for m in self._iter_wx4_scannable_regions(one):
                    info["regions"] += 1
                    addr, remain = m.BaseAddress, int(m.RegionSize)
                    while remain > 0:
                        n = min(chunk_size, remain)
                        buf = self._read_mem(hProcess, addr, n)
                        if buf:
                            info["mb"] += len(buf) / 1048576
                            self._scan_one_buffer(buf, addr, keys, databases, info, ctx,
                                                  max_hits, max_cands, max_verify)
                        step = n - overlap if n > overlap else n
                        addr += step
                        remain -= step
                info["elapsed"] = _time.time() - t0
                info.pop("_tried", None)
                info["verified_tried"] = info.pop("_verified", 0)
                for name, cnt in info["needle_hits"].items():
                    report["needle_totals"][name] += cnt
                for path, d in info["raw_verified"].items():
                    report["verified_keys"][path] = dict(d)
                report["processes"].append(info)
            except Exception as e:
                report["processes"].append({"pid": one, "error": f"扫描异常：{e}"})
                if not report["error"]:
                    report["error"] = str(e)
            finally:
                CloseHandle(hProcess)

        total_hits = sum(report["needle_totals"].values())
        if report["verified_keys"]:
            report["conclusion"] = "hit"
        elif report["conclusion"] != "open_failed":
            report["conclusion"] = "no_hit" if total_hits == 0 else "no_key"
        return report

    @staticmethod
    def print_cipher_report(report):
        """把人看的诊断报告打出来（info/bias/自测都用它）"""
        print("=" * 60)
        print("[*] 4.x 内存诊断：按结构名定位 com.Tencent.WCDB.Config.Cipher（只读，无注入）")
        print(f"[*] 目标进程：{report.get('pids')}")
        for p in report.get("processes", []):
            if p.get("error"):
                print(f"[-] pid={p['pid']} {p['error']}")
                continue
            base = p.get("base")
            print(f"[*] pid={p['pid']} ({p.get('name')})  映像基址={hex(base) if base else 'None'}"
                  f"  区段 {p['regions']} 个 / 读取 {p['mb']:.1f} MB / 耗时 {p['elapsed']:.1f}s"
                  f" / HMAC 校验 {p.get('verified_tried', 0)} 次")
            for n, c in p["needle_hits"].items():
                print(f"      特征串 {n}: {c} 命中")
            for s in p["samples"][:3]:
                print(f"      · [{s['needle']}] @ 0x{s['addr']:x}")
                print(f"        hex  : {s['hex']}")
                print(f"        ascii: {s['ascii']}")
                if s.get("xor_mask_hit") or s.get("xor_raw_hit"):
                    print(f"        XOR  : mask 命中 {s['xor_mask_hit']} / 明文命中 {s['xor_raw_hit']}")
            if p["xor_found"]:
                print(f"      [+] 单字节 XOR 解混淆命中 {len(p['xor_found'])} 处：{p['xor_found']}")
            if p["raw_verified"]:
                print(f"      [+] 32 字节原始候选通过第 1 页 HMAC 校验的库：{list(p['raw_verified'])}")
        print("[*] 各特征串总命中：" + "，".join(f"{k}={v}" for k, v in report["needle_totals"].items()))
        if report["verified_keys"]:
            print(f"[+] 从内存里取到 {len(report['verified_keys'])} 个库的密钥：")
            for db, d in report["verified_keys"].items():
                print(f"     {db} -> {d['key']}（mask={d.get('mask')}, offset={d.get('offset')}）")
        else:
            print(f"[-] 内存里没有取到能通过第 1 页 HMAC 校验的密钥（conclusion={report['conclusion']}）")
            print("[-] 说明：该版本不把库密钥以明文/单字节XOR形态驻留在可读内存里")
            print("[-] 对策：走本地密钥文件（--key_file），或重启微信登录后立刻重扫")
        if report.get("error"):
            print(f"[-] 错误信息：{report['error']}")
        print("=" * 60)

    def run_wx4_xor_keys(self, wx_root=None, pids=None, time_budget=300, do_print=True,
                         log=print, sync_store=True, keys_file=None, extra_file=None,
                         page1_map=None):
        """
        【4.x 内存取密钥·只读】把密钥"从内存里真正读出来"的入口（这是 4.1.15.13 上唯一可行的内存路线）：

        实测结论（本机 4.1.15.13）：
          - 内存里【没有】明文 x'<64hex><32hex>' 串，也【没有】com.Tencent.WCDB.Config.Cipher 结构名；
          - 但密钥明文确实在，只是被一份【32 字节固定 XOR 掩码】逐字节保护，
            掩码按【绝对地址 % 32】对齐、全进程共用同一份。
        因此做法是：
          1) 差分预筛（隔 32/64 字节 XOR 落在 hex^hex 集合内）+ 熵过滤，挑出"像密钥串"的窗口；
          2) 用真库文件开头 16 字节的 salt（明文，不是秘密）作假设，
             salt 的 32 个字符正好"每个残类各覆盖一次"，一步唯一确定整份 32 字节掩码；
          3) 用该掩码全局解码，收集所有密钥串，再逐把用真库第 1 页 HMAC-SHA512 校验 —— 通过的才算数。

        只申请 PROCESS_QUERY_INFORMATION | PROCESS_VM_READ，只读，不改微信文件、不注入、不 Hook。
        :param wx_root:     微信数据根目录（默认 D:\\xwechat_files），用于收集真库 salt 与第 1 页
        :param time_budget: 每个进程的扫描时间上限（秒）
        :param sync_store:  【收尾】True 时把内存取到的密钥回写 all_keys.json，并把未匹配串
                            另存到 extra_mem_keys.json（写前自动备份；没通过 HMAC 的一律不写）
        :param keys_file:   回写目标（默认 C:\\Users\\Administrator\\.wechat-cli\\all_keys.json）
        :param extra_file:  未匹配串另存目标（默认 ...\\.wechat-cli\\extra_mem_keys.json）
        :return: {"mask": hex|None, "mask_at": int|None, "keys": {相对库路径: key hex},
                  "unmatched": {...}, "processes": [...], "salts": n, "verifiable": n,
                  "key_store": {...}（sync_store=True 时）}
        """
        from .wx4_xor_scan import (extract_keys_from_memory, collect_salts_from_db_files,
                                   build_page1_map)
        root = wx_root or (self._wx4_default_roots() or [r"D:\xwechat_files"])[0]
        if page1_map is None:
            page1_map = build_page1_map(root)
        salts = collect_salts_from_db_files(root)
        if do_print:
            print(f"[*] 可校验的加密库（第 1 页可读）：{len(page1_map)} 个")
            print(f"[*] 磁盘真库 salt 参照集：{len(salts)} 个（用于反推掩码 + 校验密钥）")
        rep = extract_keys_from_memory(pids=pids, page1_map=page1_map, valid_salts=salts,
                                       time_budget=time_budget,
                                       log=log if do_print else (lambda *a: None))
        rep["salts"] = len(salts)
        rep["verifiable"] = len(page1_map)
        # 【第四步·收尾】落盘：①回写 all_keys.json ②另存未匹配串（失败不影响扫描结果）
        if sync_store:
            from .wx4_key_store import sync_from_memory_report
            rep["key_store"] = sync_from_memory_report(
                rep, keys_file=keys_file, extra_file=extra_file, wx_root=root,
                page1_map=page1_map, log=log if do_print else (lambda *a: None))
        if do_print:
            self.print_xor_key_report(rep)
        return rep

    @staticmethod
    def print_xor_key_report(rep):
        """打印 4.x 内存取密钥报告（掩码 + 逐库密钥 + 各进程统计）"""
        print("=" * 60)
        mask = rep.get("mask")
        if mask:
            at = rep.get("mask_at")
            print(f"[+] 自动反推出全局 32 字节 XOR 掩码：{mask}")
            print(f"[*] 掩码确认位置：{hex(at) if isinstance(at, int) else at}"
                  f"（索引方式：明文 = 内存字节 ^ 掩码[绝对地址 % 32]）")
        else:
            print("[-] 未能自动反推掩码：本次没在可读内存里找到密钥串")
            print("[-] 对策：保持微信登录状态后重试；或直接用 --key_file 走本地密钥文件路线")
        for p in rep.get("processes", []):
            extra = f"（{p.get('error')}）" if p.get("error") else ""
            bit = "（超时提前结束）" if p.get("timed_out") else ""
            print(f"    pid={p['pid']} 区段 {p.get('regions')} / {p.get('mb', 0):.1f} MB / "
                  f"{p.get('elapsed', 0):.1f}s / 校验通过 {len(p.get('keys') or {})} 把{bit}{extra}")
        keys = rep.get("keys") or {}
        print(f"[+] 从内存校验通过的密钥：{len(keys)} 把")
        for rel, kh in keys.items():
            print(f"    {rel} -> {kh}")
        unmatched = rep.get("unmatched") or {}
        if unmatched:
            print(f"[*] 另有 {len(unmatched)} 个串在 {rep.get('verifiable')} 个可校验库里找不到对应 salt"
                  f"（可能是其它账号/已轮换）：")
            for (kh, sh), cnt in list(unmatched.items())[:12]:
                print(f"    {kh[:16]}…/{sh[:8]}…  出现 {cnt} 次")
        ks = rep.get("key_store") or {}
        if ks:
            from .wx4_key_store import print_key_store_report
            print_key_store_report(ks)
        print("=" * 60)

    def run_wx4_scan_mem(self, keys=None, key_file=None, do_print=True, **kw):
        """
        info / bias 用的入口：扫结构名 + 尝试解混淆。
        keys 不给、但给了 key_file 时，自动从本地密钥文件读出真密钥用于 XOR 反查比对。
        """
        keys = list(keys or [])
        if not keys and key_file:
            try:
                from .wx_info import read_wx4_keys_file      # 局部导入，避免循环依赖
                keys = list(read_wx4_keys_file(key_file).values())
            except Exception:
                keys = []
        report = self.scan_cipher_struct(keys=keys, **kw)
        if do_print:
            self.print_cipher_report(report)
        return report

    @staticmethod
    def selftest_xor():
        """
        合成缓冲区自测：证明「单字节 XOR 反查 + 32 字节候选提取 + HMAC 校验」这套逻辑是对的，
        不依赖真机内存里有没有那个结构体（真机实测该结构名 0 命中）。
        """
        # 自测向量：合成长度 32B 的值（不写真实密钥）
        real = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        k = bytes.fromhex(real)
        # 1) 明文形态：必须命中 raw
        buf1 = b"\x00" * 100 + k + b"\x00" * 100
        sw1 = BiasAddr._xor_sweep(buf1, [real])
        assert real in sw1["raw"], f"明文形态未命中：{sw1}"
        # 2) 单字节 XOR 0x5A 形态：必须解出 mask=0x5A
        buf2 = b"\x11" * 77 + bytes(c ^ 0x5A for c in k) + b"\x22" * 77
        sw2 = BiasAddr._xor_sweep(buf2, [real])
        assert sw2["xored"] == [(real, 0x5A)], f"XOR 形态未解出：{sw2}"
        # 3) 32 字节候选提取：明文/变形后的 key 都要能被原样提取出来（交给 HMAC 校验）
        cands1 = [c.hex() for _, c in BiasAddr._extract_32b_candidates(buf1)]
        assert real in cands1, "明文形态的 32 字节候选未提取到密钥"
        cands2 = [c.hex() for _, c in BiasAddr._extract_32b_candidates(buf2)]
        assert bytes(c ^ 0x5A for c in k).hex() in cands2, "XOR 变形后的 32 字节候选未提取到"
        # 4) 真校验函数：拿真实库的第 1 页验证这把 key（能过就说明校验函数也是对的）
        #    【路径统一】不再写死某个账号目录：在动态定位到的 4.x 根目录下找任意 message_0.db
        page1 = b""
        for _root in (BiasAddr("", "", "", "", None)._wx4_default_roots() or [r"D:\xwechat_files"]):
            for _dp, _dn, _fns in os.walk(_root):
                if "message_0.db" in _fns:
                    page1 = BiasAddr._read_page1(os.path.join(_dp, "message_0.db"))
                    if page1:
                        break
            if page1:
                break
        ok = BiasAddr._verify_hmac_raw(real, page1) if page1 else None
        msg = "[+] 自测通过：明文命中 / 单字节 XOR(0x5A) 解混淆命中 / 32 字节候选提取命中"
        if ok is not None:
            msg += f" / 真库第1页 HMAC 校验={ok}"
        return msg

    @staticmethod
    def selftest_xor_scan():
        """新内存取密钥模块的自测：掩码还原 + 无锚点盲反推"""
        try:
            from .wx4_xor_scan import selftest, selftest_blind
            return selftest() + "\n" + selftest_blind()
        except Exception as e:
            return f"[-] wx4_xor_scan 自测不可用：{e}"

    @staticmethod
    def selftest_key_store():
        """【收尾】密钥落盘逻辑自测：回写 / 一致 / 拒写 / 另存 四个分支（在临时目录里跑，不动真文件）"""
        try:
            from .wx4_key_store import selftest as ks_selftest
            return ks_selftest()
        except Exception as e:
            return f"[-] wx4_key_store 自测不可用：{e}"

    @staticmethod
    def _verify_hmac_raw(key_hex, page1):
        """selftest 用的独立校验（不依赖实例）"""
        b = BiasAddr("", "", "", "", None)
        try:
            return b.verify_page1_hmac_4x(bytes.fromhex(key_hex), page1)
        except Exception:
            return False

    def run_wx4(self, logging_path=False, keys_out=None, db_path=None):
        """
        4.x 分支：扫内存拿密钥，产出 {加密库路径: key}
        注意：4.x 不写 WX_OFFS.json（那套固定偏移在 4.x 上不存在）
        """
        if not self.pid:
            if not self.get_process_handle(self.wx4_process_name)[0]:
                print(f"[-] 未找到微信 4.x 进程 {self.wx4_process_name}")
                return None

        self.is_wx4 = True
        print(f"[*] 微信 4.x：进程 {self.wx4_process_name}（pid={self.pid}），版本 {self.version}")
        print("[*] 4.x 没有 WeChatWin.dll / 固定偏移，改为动态扫描 WCDB 缓存的密钥并逐库校验")

        databases = self.collect_wx4_databases(db_path or self.raw_db_path or self.db_path)
        if not databases:
            print("[-] 没找到可用于校验的加密库（4.x 的库在 ...\\xwechat_files\\<wxid>_xxxx\\db_storage 下）")
            print("[-] 请用 --db_path 指定账号目录，例如：D:\\xwechat_files\\wxid_xxx_abcd")
            return None
        print(f"[*] 待校验的加密库 {len(databases)} 个（按第 1 页的 salt 与内存里的候选配对）")

        pids = self._wx4_candidate_pids()
        if not pids:
            print(f"[-] 没有找到 {self.wx4_process_name} 进程")
            return None
        if len(pids) > 1:
            print(f"[*] 发现 {len(pids)} 个 {self.wx4_process_name} 进程（4.x 是多进程架构），"
                  f"按私有内存从大到小逐个扫、命中即停：{pids}")

        keymap = {}
        for pid in pids:
            print(f"[*] 开始扫 pid={pid} 的内存 …")
            keymap = self.scan_wcdb_keys(pid, databases)
            if keymap:
                print(f"[+] 在该进程命中：pid={pid}")
                break

        if not keymap:
            print("[-] 所有 Weixin.exe 进程都没有扫到通过校验的密钥")
            print("[-] 最常见原因：微信已经运行很久。WCDB 只在真正用到数据库时才把 key 短暂放进内存，")
            print("[-] 之后可能就释放了，此时内存里已经没有它。请：")
            print("[-]   1) 完全退出微信；2) 重新登录；3) 立刻重跑本命令。")
            print("[-] 本工具不做 DLL 注入 / Hook，也不会去猜密钥。")
            return None

        rdata = {path: key for path, key in sorted(keymap.items())}
        print(f"[+] 校验通过，拿到 {len(rdata)} 个库的密钥：")
        for path, key in rdata.items():
            print(f"[+]   {path}  ->  {key}")

        if keys_out:
            try:
                with open(keys_out, "w", encoding="utf-8") as f:
                    json.dump(rdata, f, ensure_ascii=False, indent=4)
                print(f"[+] 密钥表已写入：{keys_out}")
            except (OSError, IOError) as e:
                print(f"[-] 写密钥表失败 {keys_out}: {e}")

        if isinstance(logging_path, str) and logging_path and os.path.exists(logging_path):
            with open(logging_path, "a", encoding="utf-8") as f:
                f.write("{数据库路径: 密钥}" + "\n")
                f.write(str(rdata) + "\n")
        elif logging_path:
            print("{数据库路径: 密钥}")
            print(rdata)
        return rdata

    def run(self, logging_path=False, WX_OFFS_PATH=None, mode=None, keys_out=None):
        """
        :param logging_path: 原来就有（3.x 行为不变）
        :param WX_OFFS_PATH: 3.x 的偏移文件；4.x 不使用、也不写入
        :param mode:         None/"auto" 自动判断；"3x" 强制老逻辑；"4x" 强制新扫描
        :param keys_out:     4.x 专用：把 {库路径: key} 写到这个 json
        """
        mode = "auto" if mode is None else mode
        if mode not in ("auto", "3x", "4x"):
            print(f"[-] mode 只支持 auto / 3x / 4x，收到：{mode}")
            return None

        # ---------- 分流：3.x 优先（保持老行为），没有 WeChat.exe 再看 4.x 的 Weixin.exe ----------
        if mode == "auto":
            if self.get_process_handle()[0]:
                mode = "3x"
            else:
                try:
                    attached_4x = self.get_process_handle(self.wx4_process_name)[0]
                except Exception as e:
                    print(f"[-] 附加进程 {self.wx4_process_name} 失败：{e}")
                    attached_4x = False
                mode = "4x" if attached_4x else None

        if mode is None:
            print("[-] WeChat No Run")
            print(f"[-] 没找到微信进程：3.x 是 {self.process_name}，4.x 是 {self.wx4_process_name}")
            print("[-] 微信确实在运行却仍报这个，请用【管理员身份】重开 PowerShell"
                  "（读进程内存需要管理员权限）")
            return None

        if mode == "4x":
            return self.run_wx4(logging_path=logging_path, keys_out=keys_out)

        # ---------- 3.x：原逻辑，一行不改 ----------
        if not self.pid and not self.get_process_handle()[0]:
            return None
        mobile_bias = self.search_memory_value(self.mobile, self.module_name)
        name_bias = self.search_memory_value(self.name, self.module_name)
        account_bias = self.search_memory_value(self.account, self.module_name)
        key_bias = 0
        key_bias = self.get_key_bias1() if key_bias <= 0 else key_bias
        key_bias = self.search_key(self.key) if key_bias <= 0 and self.key else key_bias
        key_bias = self.get_key_bias2(self.db_path) if key_bias <= 0 and self.db_path else key_bias

        rdata = {self.version: [name_bias, account_bias, mobile_bias, 0, key_bias]}

        if WX_OFFS_PATH and os.path.exists(WX_OFFS_PATH):
            with open(WX_OFFS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                data.update(rdata)
            with open(WX_OFFS_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
        if os.path.exists(logging_path) and isinstance(logging_path, str):
            with open(logging_path, "a", encoding="utf-8") as f:
                f.write("{版本号:昵称,账号,手机号,邮箱,KEY}" + "\n")
                f.write(str(rdata) + "\n")
        elif logging_path:
            print("{版本号:昵称,账号,手机号,邮箱,KEY}")
            print(rdata)
        return rdata


if __name__ == '__main__':
    # 【第一步·4.x】自测入口：改完就能直接跑，不用先动 cli.py。
    # 注意本文件用的是相对 import，必须以【模块】方式运行（在 D:\PyWxDump_Source 下执行）：
    #   4.x 扫内存：   python -m pywxdump.wx_core.get_bias_addr --mode 4x
    #   指定账号目录： python -m pywxdump.wx_core.get_bias_addr --mode 4x --db_path D:\xwechat_files\wxid_xxx_abcd
    #   存下密钥表：   python -m pywxdump.wx_core.get_bias_addr --mode 4x --keys_out D:\wx4_keys.json
    #   3.x 老逻辑：   python -m pywxdump.wx_core.get_bias_addr --mode 3x --mobile 138xxxx --name 昵称 --account 微信号
    import argparse

    ap = argparse.ArgumentParser(description="BiasAddr 自测（4.x：扫 WCDB 密钥 / 扫 Config.Cipher 结构名）")
    ap.add_argument("--mode", default="auto", choices=["auto", "3x", "4x"])
    ap.add_argument("--db_path", default=None, help=r"4.x 账号目录，如 D:\xwechat_files\wxid_xxx_abcd")
    ap.add_argument("--keys_out", default=None, help="4.x：把 {库路径: key} 写到这个 json")
    ap.add_argument("--key_file", default=None,
                    help="4.x：本地密钥文件（all_keys.json），用于 XOR 反查时比对真密钥")
    ap.add_argument("--scan_mem", action="store_true",
                    help="4.x：只读内存取密钥（形状预筛 + 真库 salt 反推 32 字节 XOR 掩码 + 第 1 页 HMAC 校验）")
    ap.add_argument("--scan_mem_struct", action="store_true",
                    help="4.x：旧诊断——搜 com.Tencent.WCDB.Config.Cipher 结构名（实测该结构名不在可读内存）")
    ap.add_argument("--wx_root", default=None, help=r"4.x：微信数据根目录（默认 D:\xwechat_files）")
    ap.add_argument("--mem_budget", type=float, default=300, help="4.x：每个进程内存扫描时间上限（秒）")
    ap.add_argument("--no_sync_keys", action="store_true",
                    help="4.x：本次【不】回写 all_keys.json、也不另存未匹配串（默认是回写+另存）")
    ap.add_argument("--keys_out_file", default=None,
                    help=r"4.x：回写目标密钥文件（默认 C:\Users\Administrator\.wechat-cli\all_keys.json）")
    ap.add_argument("--extra_keys", default=None,
                    help=r"4.x：未匹配串另存路径（默认 C:\Users\Administrator\.wechat-cli\extra_mem_keys.json）")
    ap.add_argument("--key_store_selftest", action="store_true",
                    help="只测【回写 / 另存】逻辑本身（在临时目录里造数据，不动真文件）")
    ap.add_argument("--selftest", action="store_true",
                    help="跑合成缓冲区自测：验证 XOR 反查 / 32 字节候选提取 / HMAC 校验逻辑")
    ap.add_argument("--mobile", default="", help="3.x：手机号")
    ap.add_argument("--name", default="", help="3.x：微信昵称")
    ap.add_argument("--account", default="", help="3.x：微信号")
    ap.add_argument("--key", default=None, help="3.x：可选密钥")
    a = ap.parse_args()

    bias_addr = BiasAddr(a.account, a.mobile, a.name, a.key, a.db_path)

    if a.key_store_selftest:
        from .wx4_key_store import selftest as ks_selftest
        print(ks_selftest())
        raise SystemExit(0)

    if a.selftest:
        print("[*] 合成缓冲区自测（不依赖真机内存）：")
        print(bias_addr.selftest_xor())
        print(bias_addr.selftest_xor_scan())
        print(bias_addr.selftest_key_store() if hasattr(bias_addr, "selftest_key_store") else "")
        raise SystemExit(0)

    if a.scan_mem:
        bias_addr.run_wx4_xor_keys(wx_root=a.wx_root, time_budget=a.mem_budget,
                                   sync_store=not a.no_sync_keys,
                                   keys_file=a.keys_out_file, extra_file=a.extra_keys)
        print("[*] 内存取密钥结束；下面继续走正常的 4.x 密钥获取流程")

    if a.scan_mem_struct:
        bias_addr.run_wx4_scan_mem(key_file=a.key_file)
        print("[*] 结构名诊断结束；下面继续走正常的 4.x 密钥获取流程")

    bias_addr.run(logging_path=True, mode=a.mode, keys_out=a.keys_out)
