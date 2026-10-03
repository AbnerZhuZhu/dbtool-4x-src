# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# 【微信 4.x 改造 · 无锚点内存扫描】wx4_xor_scan.py
#
# 目的：验证「4.x 把库密钥用固定/周期性 XOR 掩码保护后常驻内存」这一假设，
#       并且**不依赖任何锚点字符串**（不要求内存里有 com.Tencent.WCDB.Config.Cipher）。
#
# 原理（已知明文 + 周期性掩码反推）：
#   设明文 P（32 字节 key / 16 字节 salt / 它们的 ASCII hex 形态），
#   内存里存的是 P[j] ^ mask[(addr + j) % p]，即被一个周期为 p 的掩码逐字节 XOR。
#   令 d = mem ^ tile(P)（P 按自身长度平铺），则在命中处 i：
#       d[i + t] = mask[(i + t) % p]                      （明文被异或掉了）
#   而 mask 是周期 p 的，所以 d[i .. i+L-1] 必然满足 d[i+t] == d[i+t+p] (∀t)。
#   随机数据满足这个条件的概率是 2^(-8*(L-p))，几乎不可能误报
#   （例如 L=96, p=8 → 2^-704）。
#   命中即可直接得到掩码：mask = d[i .. i+p-1]。
#
# 拿到掩码之后（关键收益）：
#   用该掩码 + 已知相位把命中处附近整段解码，再在解码结果里直接找 unmasked 的
#   x'<64hex key><32hex salt>' / 32 字节 key / 16 字节 salt，
#   逐个做 SQLCipher4 第 1 页 HMAC-SHA512 校验 → 一次可能捞回多把真密钥。
#
# 只读：只用 PROCESS_QUERY_INFORMATION | PROCESS_VM_READ 打开进程读内存；
#       不注入、不 Hook、不改微信任何文件、不写对方进程内存。
#       （同用户进程读内存不需要管理员权限；本模块也兼容管理员运行）
# -------------------------------------------------------------------------------
import ctypes
import json
import os
import re
import sys
import time
from ctypes import wintypes

import numpy as np
import psutil

from .utils import get_memory_maps
from .get_bias_addr import (BiasAddr, get_wx_processes, OpenProcess, CloseHandle,
                            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
                            MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD,
                            PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                            PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

WCDB_KEY_RE = re.compile(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})'")
DEFAULT_PERIODS = (1, 2, 4, 8, 16, 32)
DEFAULT_KINDS = ("x96",)


# =====================================================================
# 一、明文清单（needle）：从本地密钥文件构造"我们知道会长什么样"的明文
# =====================================================================
def build_needles(key_file, kinds=DEFAULT_KINDS):
    """
    从 keys 文件构造明文清单。
    :return: [{"kind","db","data"(bytes),"key_hex","salt_hex"}, ...]（已去重）
    """
    if not key_file or not os.path.exists(key_file):
        return []
    with open(key_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
    items = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, dict):
                d = dict(v)
                d.setdefault("db", k)
                items.append(d)
    out, seen = [], set()
    for d in items:
        key_hex = str(d.get("enc_key") or d.get("key") or "").strip().lower()
        salt_hex = str(d.get("salt") or "").strip().lower()
        db = str(d.get("db") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", key_hex):
            continue
        if not re.fullmatch(r"[0-9a-f]{32}", salt_hex):
            salt_hex = ""
        cands = []
        if "x96" in kinds and salt_hex:
            cands.append(("x96", f"x'{key_hex}{salt_hex}'".encode("ascii")))
        if "hex64" in kinds:
            cands.append(("hex64", key_hex.encode("ascii")))
        if "key32" in kinds:
            cands.append(("key32", bytes.fromhex(key_hex)))
        if "salt16" in kinds and salt_hex:
            cands.append(("salt16", bytes.fromhex(salt_hex)))
        for kind, data in cands:
            sig = (kind, data)
            if sig in seen:
                continue
            seen.add(sig)
            out.append({"kind": kind, "db": db, "data": data,
                        "key_hex": key_hex, "salt_hex": salt_hex})
    return out


# =====================================================================
# 二、核心：在一个内存块里找「周期性掩码」命中的明文
#
#   为什么不用"平铺明文再异或"的写法：
#     那种写法要求明文副本的起点恰好是明文长度的整数倍，否则平铺相位对不上，会漏检。
#     真实内存里副本起点是任意的，所以这里改成【差分匹配】，与对齐无关：
#
#       设命中处 i，内存里 arr[i+j] = P[j] ^ mask[(i+j) % p]
#       两边同取"隔 p 个字节的差"：
#           arr[i+j] ^ arr[i+j+p] = P[j] ^ P[j+p]        （掩码被消掉！）
#       也就是：令 Q_p[x] = arr[x] ^ arr[x+p]（只跟内存有关），
#              令 R_p[j] = P[j] ^ P[j+p]（只跟明文有关），
#       则命中等价于 —— 在 Q_p 里出现 R_p。
#       Q_p 只依赖 p，可以对一个内存块只算一次，再给所有明文共用。
#
#       命中后再用 arr[i:i+p] ^ P[0:p] 直接得到该相位下的掩码周期，
#       并逐字节复核 arr[i+j] == P[j] ^ mask[(i+j)%p]（全长度），杜绝误报。
# =====================================================================
def _diff_pattern(P, p):
    """R_p[j] = P[j] ^ P[j+p]"""
    return bytes(P[j] ^ P[j + p] for j in range(len(P) - p))


def scan_buffer(buf, needles, periods=DEFAULT_PERIODS, base_addr=0, max_hits=32, min_len=12):
    """
    在 bytes 缓冲区里扫「被周期性 XOR 掩码保护的已知明文」。

    :param min_len: 差分模式最短长度（默认 12 字节 → 误报率 2^-96，实际不可能误报）
    :return: [{"kind","db","addr","period","mask_hex","plain_hex"}, ...]
    """
    if not buf or not needles:
        return []
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    n = arr.size
    hits = []
    for p in periods:
        if p >= n - min_len:
            continue
        # 一次算出该内存块的 Q_p = arr[x] ^ arr[x+p]，供本块所有明文共用
        Q = bytes(arr[:-p] ^ arr[p:])
        for nd in needles:
            P = nd["data"]
            L = len(P)
            W = L - p
            if W < min_len:
                continue
            R = _diff_pattern(P, p)
            start = 0
            while True:
                i = Q.find(R, start)
                if i < 0:
                    break
                start = i + 1
                # 还原该相位下的掩码周期，并做全长度复核
                mask_rot = bytes(arr[i:i + p] ^ np.frombuffer(P[:p], dtype=np.uint8))
                ok = True
                for j in range(L):
                    if int(arr[i + j]) != P[j] ^ mask_rot[j % p]:
                        ok = False
                        break
                if not ok:
                    continue
                hits.append({"kind": nd["kind"], "db": nd["db"],
                             "addr": base_addr + i, "period": int(p),
                             "mask_hex": mask_rot.hex(),
                             "plain_hex": bytes(arr[i:i + L]).hex()})
                if len(hits) >= max_hits:
                    return hits
    return hits


# =====================================================================
# 三、掩码解码 + 级联捞其它密钥
# =====================================================================
def decode_with_mask(arr, anchor_offset, mask_period):
    """用周期掩码解码：dec[x] = arr[x] ^ mask[(x - anchor) % p]"""
    p = len(mask_period)
    idx = (np.arange(arr.size, dtype=np.int64) - anchor_offset) % p
    return arr ^ np.resize(np.frombuffer(mask_period, dtype=np.uint8), p)[idx]


def verify_key_page1(key_hex, dbs):
    """做 SQLCipher4 第 1 页 HMAC-SHA512 校验；dbs = [(库路径, 第1页4096字节), ...]"""
    b = BiasAddr("", "", "", "", None)
    try:
        kb = bytes.fromhex(key_hex)
    except ValueError:
        return []
    out = []
    for path, page1 in dbs:
        try:
            if b.verify_page1_hmac_4x(kb, page1):
                out.append(path)
        except Exception:
            continue
    return out


def cascade_recover(reader, hit, dbs, window=2 << 20, max_find=200):
    """
    命中之后：用拿到的掩码把命中处附近解码，再找 unmasked 的
    x'<64hex><32hex>' / 明文 key，并做 HMAC 校验。
    :param reader: 可调用对象 reader(addr, size) -> bytes
    :return: {"decoded_addr_range": (lo,hi), "found_ascii": [...], "keys_verified": {库: key}}
    """
    res = {"decoded_addr_range": None, "found_ascii": [], "keys_verified": {}}
    mask_full = bytes.fromhex(hit["mask_hex"])
    p = hit["period"]
    mask_period = mask_full[:p]
    lo = max(0, hit["addr"] - window)
    raw = reader(lo, min(hit["addr"] + window, lo + window * 2) - lo)
    if not raw:
        return res
    arr = np.frombuffer(bytes(raw), dtype=np.uint8)
    dec = decode_with_mask(arr, hit["addr"] - lo, mask_period)   # 锚点相位对齐
    dec_b = bytes(dec)
    res["decoded_addr_range"] = (lo, lo + len(dec_b))
    for m in list(WCDB_KEY_RE.finditer(dec_b))[:max_find]:
        key_hex = m.group(1).decode().lower()
        salt_hex = m.group(2).decode().lower()
        item = {"addr": lo + m.start(), "key": key_hex, "salt": salt_hex}
        res["found_ascii"].append(item)
        for path in verify_key_page1(key_hex, dbs):
            res["keys_verified"][path] = key_hex
    return res


# =====================================================================
# 四、进程扫描
# =====================================================================
def _scannable_regions(pid):
    allowed = (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
               PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
    for m in get_memory_maps(pid):
        if m.State != MEM_COMMIT or not m.RegionSize or m.RegionSize <= 0:
            continue
        if m.Protect & PAGE_NOACCESS or m.Protect & PAGE_GUARD:
            continue
        if (m.Protect & 0xFF) not in allowed:
            continue
        if m.FileName:            # 映像/dll 跳过，密钥类数据在私有堆上
            continue
        yield m


def _read_mem(hProcess, address, size):
    if size <= 0:
        return b""
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not ctypes.windll.kernel32.ReadProcessMemory(
            hProcess, ctypes.c_void_p(address), buf, ctypes.c_size_t(size), ctypes.byref(got)):
        return b""
    return buf.raw[:got.value] if got.value else buf.raw


def scan_process(pid, needles, periods=DEFAULT_PERIODS, chunk_size=32 << 20, overlap=256,
                 time_budget=180.0, dbs=None, cascade=True, cascade_window=2 << 20,
                 log=print):
    """
    扫一个进程：按块读一次内存，块内对所有明文 × 所有周期做检测。
    :return: {"pid","regions","mb","elapsed","hits":[...],"cascade":[...],"timed_out"}
    """
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    info = {"pid": pid, "regions": 0, "mb": 0.0, "elapsed": 0.0,
            "hits": [], "cascade": [], "timed_out": False}
    if not hProcess:
        info["error"] = "OpenProcess 失败"
        return info
    t0 = time.time()
    try:
        for m in _scannable_regions(pid):
            if time.time() - t0 > time_budget:
                info["timed_out"] = True
                break
            info["regions"] += 1
            addr, remain = m.BaseAddress, int(m.RegionSize)
            while remain > 0:
                if time.time() - t0 > time_budget:
                    info["timed_out"] = True
                    break
                size = min(chunk_size, remain)
                buf = _read_mem(hProcess, addr, size)
                if buf:
                    info["mb"] += len(buf) / 1048576
                    got = scan_buffer(buf, needles, periods, base_addr=addr)
                    for h in got:
                        info["hits"].append(h)
                        log(f"    [!] 命中：{h['kind']} @ 0x{h['addr']:x} 周期={h['period']} "
                            f"掩码={h['mask_hex'][:32]}…")
                        if cascade and dbs:
                            r = cascade_recover(lambda a, s: _read_mem(hProcess, a, s),
                                                h, dbs, window=cascade_window)
                            info["cascade"].append(r)
                            for dbp, kk in r["keys_verified"].items():
                                log(f"        [+] 级联校验通过：{dbp} -> {kk}")
                step = size - overlap if size > overlap else size
                addr += step
                remain -= step
    finally:
        CloseHandle(hProcess)
    info["elapsed"] = time.time() - t0
    return info


def scan_all(key_file, kinds=DEFAULT_KINDS, periods=DEFAULT_PERIODS, chunk_size=32 << 20,
             time_budget_per_pid=180.0, db_path=None, cascade=True, pids=None, log=print):
    """扫所有 Weixin.exe 进程"""
    needles = build_needles(key_file, kinds)
    b = BiasAddr("", "", "", "", db_path)
    try:
        dbs = b.collect_wx4_databases(db_path)
    except Exception:
        dbs = []
    report = {"needles": len(needles), "kinds": list(kinds), "periods": list(periods),
              "pids": [], "processes": [], "verified_keys": {}, "dbs": len(dbs)}
    if pids is None:
        pids = [d["pid"] for d in get_wx_processes(("Weixin.exe",))]
    report["pids"] = list(pids)
    log(f"[*] 明文清单 {len(needles)} 条（种类 {','.join(kinds)}）；可校验的加密库 {len(dbs)} 个")
    log(f"[*] 周期集合 {list(periods)}；目标进程 {list(pids)}")
    for pid in pids:
        log(f"[*] 扫 pid={pid} …")
        info = scan_process(pid, needles, periods, chunk_size=chunk_size,
                            time_budget=time_budget_per_pid, dbs=dbs, cascade=cascade, log=log)
        for c in info.get("cascade", []):
            report["verified_keys"].update(c.get("keys_verified", {}))
        report["processes"].append(info)
        log(f"    完成：区段 {info['regions']} / {info['mb']:.1f} MB / {info['elapsed']:.1f}s / "
            f"命中 {len(info['hits'])}"
            + ("（超时提前结束）" if info.get("timed_out") else ""))
    return report


# =====================================================================
# 四之二、不需要密钥文件、不需要任何锚点：靠"密钥串的形状"自动反推全局掩码，捞出全部密钥
#
# 本机 4.1.15.13 实测事实：
#   微信把每个库的 SQLCipher 密钥串 x'<64hex key><32hex salt>'（ASCII）留在堆内存里，
#   整体 XOR 一个【32 字节固定掩码】，掩码按【绝对地址 % 32】对齐，全机共用同一份。
#   所以只要反推出这 32 字节，就能一次把整个进程堆里的密钥串全部解出来 —— 不需要
#   com.Tencent.WCDB.Config.Cipher 结构体，也不需要提前知道任何一把密钥。
#
# 反推掩码只依赖"形状"：
#   窗口 99 字节：j=0 是 'x'、j=1 与 j=98 是 "'"、j=2..97 是 hex 字符。
#   同一残类 (addr%32 相同) 的字节共享同一个掩码字节 m[r]，于是它们的"两两 XOR"必然落在
#   {hex ^ hex} = {0x00-0x0F, 0x51-0x5F} 内 —— 这是与掩码无关的强预筛，
#   随机数据通过率约 10^-65，所以候选窗口极少，之后再逐个枚举 m[r] 并用正则整段确认。
# =====================================================================
HEX_CHARS = b"0123456789abcdef"
HEX_SET = set(HEX_CHARS)
PLAIN_ALLOWED = HEX_SET | {0x78, 0x27}          # hex 字符 + 'x' + "'"
KEYSTR_LEN = 99
KEYSTR_RE = re.compile(rb"^x'[0-9a-fA-F]{64}[0-9a-fA-F]{32}'$")


def _allowed_diff_table():
    """hex 字符 ^ hex 字符 的合法取值表"""
    t = np.zeros(256, dtype=bool)
    for a in HEX_CHARS:
        for b in HEX_CHARS:
            t[a ^ b] = True
    return t


ALLOWED_DIFF = _allowed_diff_table()


def find_masked_candidates(buf, base_addr, max_cand=None, min_changes=40):
    """
    【与掩码无关】的差分预筛：找出所有可能是"掩码保护的 x'<64hex><32hex>' 串"的窗口起点。

    两条判据：
      1) 隔 32 / 隔 64 字节的 XOR 必须落在 {hex^hex} 内（掩码被消掉，与掩码无关）
      2) 窗口内相邻字节的"变化次数"要够多（≥ min_changes）
         —— 这一条专门用来踢掉内存里大量"常量/低熵垃圾区"，
            否则它们会因为 XOR 恒为 0 而全部通过判据 1，把候选表刷爆。

    :return: [buffer 内偏移 A, ...]
    """
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    n = arr.size
    if n < KEYSTR_LEN + 64:
        return []
    d32 = ALLOWED_DIFF[arr[:-32] ^ arr[32:]]
    d64 = ALLOWED_DIFF[arr[:-64] ^ arr[64:]]
    chg = (arr[:-1] != arr[1:]).astype(np.int64)
    cs32 = np.concatenate(([0], np.cumsum(d32, dtype=np.int64)))
    cs64 = np.concatenate(([0], np.cumsum(d64, dtype=np.int64)))
    csc = np.concatenate(([0], np.cumsum(chg, dtype=np.int64)))
    A = np.arange(0, n - KEYSTR_LEN, dtype=np.int64)
    # 需要 d32[A+2 .. A+65] 全 True（64 个）、d64[A+2 .. A+33] 全 True（32 个）、
    # 且窗口 [A, A+99) 内相邻变化次数 ≥ min_changes
    ok = (((cs32[A + 66] - cs32[A + 2]) == 64)
          & ((cs64[A + 34] - cs64[A + 2]) == 32)
          & ((csc[A + KEYSTR_LEN - 1] - csc[A]) >= min_changes))
    idx = np.flatnonzero(ok)
    return [int(x) for x in (idx if max_cand is None else idx[:max_cand])]


def _residue_candidates(buf, base_addr, offset):
    """
    单个候选窗口：按残类给出掩码字节的候选集合。
    - 三处已知明文字符（'x' 与两处 "'"）所在残类被唯一确定
    - 其它残类里的明文全是 hex 字符 → 只允许落在 hex 字符集内
    :return: {residue: [k, ...]} 或 None（该窗口不可能是密钥串）
    """
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    if offset + KEYSTR_LEN > arr.size:
        return None
    base = base_addr + offset
    by_res = {}
    for j in range(KEYSTR_LEN):
        by_res.setdefault((base + j) % 32, []).append(int(arr[offset + j]))
    pinned = {}
    for j, ch in ((0, 0x78), (1, 0x27), (KEYSTR_LEN - 1, 0x27)):
        pinned[(base + j) % 32] = int(arr[offset + j]) ^ ch
    out = {}
    for r, vals in by_res.items():
        if r in pinned:
            out[r] = [pinned[r]]
            continue
        ks = [k for k in range(256) if all((v ^ k) in HEX_SET for v in vals)]
        if not ks:
            return None
        out[r] = ks
    return out


def _window_stats(buf, base_addr, offset):
    """窗口的字节特征：不同值个数、最常见值占比（用来踢掉常量/低熵垃圾窗口）"""
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    seg = arr[offset:offset + KEYSTR_LEN]
    if seg.size < KEYSTR_LEN:
        return 0, 1.0
    vals, counts = np.unique(seg, return_counts=True)
    return int(vals.size), float(counts.max()) / float(seg.size)


def recover_mask_via_salts(buf, base_addr, salts, log=None, max_windows=200000,
                           min_distinct=32, max_mode_ratio=0.3):
    """
    【精确、快速】用磁盘真库的 salt 作假设，一步反推全局 32 字节掩码。

    原理：密钥串形如 x'<64hex key><32hex salt>'，其中 salt 就是真库文件开头 16 字节（明文，不是秘密）。
    对一个候选窗口 A：
      第 66..97 共 32 个字符正好"每个残类各覆盖一次"，
      因此只要假设 salt = 某个已知值 S，窗口里对应位置的密文字节 ^ S 就唯一确定了全部 32 个掩码字节；
      随后用形状（首字节 'x'、第 2 字节 "'"、末尾 "'"、其余 96 位必须是 hex）做校验，
      再对该缓冲区做一次全局解码确认 —— 掩码正确时能一次解出该缓冲区里所有密钥串。

    :return: (mask32 bytes, [(addr, plain), ...]) 或 (None, [])
    """
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    cand_offsets = find_masked_candidates(buf, base_addr)
    if not cand_offsets:
        return None, []
    good = []
    for off in cand_offsets:
        nd, ratio = _window_stats(buf, base_addr, off)
        if nd >= min_distinct and ratio <= max_mode_ratio:
            good.append(off)
    if not good:
        return None, []
    if len(good) > max_windows:
        pick = np.linspace(0, len(good) - 1, max_windows).astype(int)
        good = [good[int(i)] for i in pick]
    if log:
        log(f"    预筛 {len(cand_offsets)} 个 → 熵过滤后 {len(good)} 个候选窗口")
    salt_list = sorted({s.lower() for s in salts if len(s) == 32})
    if not salt_list:
        return None, []
    S = np.frombuffer("".join(salt_list).encode("ascii"), dtype=np.uint8).reshape(-1, 32)
    res_of_salt = np.arange(66, 98)                         # salt 各字符的窗口内偏移（残类另算）
    hexmap = np.zeros(256, dtype=bool)
    for c in HEX_SET:
        hexmap[c] = True
    for A in good:
        if A + KEYSTR_LEN > arr.size:
            continue
        # salt 的 32 个字符正好"每个残类各覆盖一次"，故每个 salt 假设唯一确定整份掩码
        masks = np.zeros((len(salt_list), 32), dtype=np.uint8)
        masks[:, (base_addr + A + res_of_salt) % 32] = arr[A + 66:A + 98][None, :] ^ S
        idx = (base_addr + A + np.arange(KEYSTR_LEN)) % 32
        dec = arr[A:A + KEYSTR_LEN][None, :] ^ masks[:, idx]  # (n_salt, 99)
        shape = ((dec[:, 0] == 0x78) & (dec[:, 1] == 0x27) & (dec[:, 98] == 0x27)
                 & hexmap[dec[:, 2:98]].all(axis=1))
        for si in np.flatnonzero(shape):
            mm = bytes(int(x) for x in masks[si])
            plist = _harvest_keys(buf, base_addr, mm)
            if plist and any(p[66:98].decode("ascii", "replace").lower() in salts
                             for _a, p in plist):
                if log:
                    log(f"[+] 由真库 salt 假设反推出全局掩码 @0x{base_addr + A:x}：{mm.hex()}"
                        f"（一次解出 {len(plist)} 个密钥串）")
                return mm, plist
    return None, []


def _harvest_keys(buf, base_addr, mask):
    """用给定掩码全局解码缓冲区，收集所有合法密钥串"""
    dec = decode_with_global_mask(bytes(buf), base_addr, mask)
    out = []
    for m in WCDB_KEY_RE.finditer(dec):
        out.append((base_addr + m.start(), m.group(0)))
    return out


def recover_mask_from_candidates(buf, base_addr, salts=None, log=None):
    """先走"真库 salt 假设"精确路线；不可用时退回"形状投票"路线"""
    if salts:
        mm, plist = recover_mask_via_salts(buf, base_addr, salts, log=log)
        if mm:
            return mm, plist
    return recover_global_mask(buf, base_addr, valid_salts=salts)


def recover_global_mask(buf, base_addr, valid_salts=None, max_windows=24,
                        min_distinct=40, max_mode_ratio=0.25):
    """
    【只靠形状】从一块内存里反推出全局 32 字节掩码：
      所有密钥串共用同一份掩码（按绝对地址%32 索引）。做法：
        1) 差分预筛 + 熵过滤挑出"像密钥串"的窗口（常量垃圾区会被熵过滤踢掉）
        2) 把这些窗口的"每残类候选集合"做支持度投票 —— 真掩码字节会被几乎所有窗口支持
        3) 枚举残余同分候选（受控上限），用"解出多少合法 x'<64hex><32hex>' 串"打分；
           若给出 valid_salts（磁盘真库文件开头 16 字节的 hex 集合），还要求解出的 salt 命中它 ——
           命中真库 salt 的掩码即为正解（等价于一次性通过真库校验）。

    :return: (mask32 bytes, [(addr, plain), ...]) 或 (None, [])
    """
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    cand_offsets = find_masked_candidates(buf, base_addr)
    if not cand_offsets:
        return None, []
    # 熵过滤：真密钥串的 99 字节里不同值很多；常量/低熵垃圾区会被踢掉
    good = []
    for off in cand_offsets:
        nd, mode_ratio = _window_stats(buf, base_addr, off)
        if nd >= min_distinct and mode_ratio <= max_mode_ratio:
            good.append(off)
    if not good:
        return None, []
    if len(good) > max_windows:                 # 均匀取样，避免只看开头一段
        pick = np.linspace(0, len(good) - 1, max_windows).astype(int)
        good = [good[int(i)] for i in pick]
    per_win = []
    for off in good:
        d = _residue_candidates(buf, base_addr, off)
        if d:
            per_win.append((off, d))
    if not per_win:
        return None, []
    # 逐残类投票
    mask = [None] * 32
    for r in range(32):
        score = {}
        for off, d in per_win:
            for k in d.get(r, []):
                score[k] = score.get(k, 0) + 1
        if not score:
            return None, []
        best = max(score.values())
        winners = [k for k, v in score.items() if v == best]
        mask[r] = winners[:4]                    # 同分时保留少量候选，交给验收环节筛
    from itertools import product
    combos = 1
    for r in range(32):
        combos *= len(mask[r])
        if combos > 4096:
            break
    iterator = product(*mask) if combos <= 4096 else [tuple(m[0] for m in mask)]
    probe = cand_offsets if len(cand_offsets) <= 4096 else \
        [cand_offsets[int(i)] for i in np.linspace(0, len(cand_offsets) - 1, 4096).astype(int)]
    best_combo, best_plist, best_salt_hits = None, [], -1
    for combo in iterator:
        mm = bytes(combo)
        plist = []
        salt_hits = 0
        for off in probe:
            if off + KEYSTR_LEN > arr.size:
                continue
            plain = decode_with_global_mask(bytes(arr[off:off + KEYSTR_LEN]),
                                            base_addr + off, mm)
            if KEYSTR_RE.match(plain):
                plist.append((base_addr + off, plain))
                if valid_salts and plain[66:98].decode().lower() in valid_salts:
                    salt_hits += 1
        key = (salt_hits, len(plist))
        if key > (best_salt_hits, len(best_plist)):
            best_combo, best_plist, best_salt_hits = mm, plist, salt_hits
    if best_combo is None:
        return None, []
    if valid_salts is not None and best_salt_hits >= 1:
        return best_combo, best_plist
    if len(best_plist) >= 2:                     # 无 salt 参照时，至少两个串才认账
        return best_combo, best_plist
    if len(best_plist) == 1:
        return best_combo, best_plist
    return None, []


def _default_wx_root():
    """
    【4.0.1 路径统一】4.x 数据根目录：先动态定位（注册表 → 各盘 xwechat_files → 我的文档），
    全都不在才回退 D:\\xwechat_files。可用环境变量 PYWXDUMP_WX4_ROOT 覆盖。
    """
    env = os.environ.get("PYWXDUMP_WX4_ROOT")
    if env and os.path.isdir(env):
        return env
    try:
        from .wx4_prepare import default_wx_root as _prep_default
        r = _prep_default()
        if r:
            return r
    except Exception:
        pass
    for p in (r"D:\xwechat_files", r"E:\xwechat_files", r"C:\xwechat_files",
              os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files")):
        if os.path.isdir(p):
            return p
    return r"D:\xwechat_files"


def collect_salts_from_db_files(root=None):
    """收集磁盘上所有真库文件开头的 16 字节 salt（hex，小写），用于消歧与校验
    （root 留空 → 动态定位 4.x 数据根目录，回退 D:\\xwechat_files）"""
    root = root or _default_wx_root()
    salts = set()
    if not os.path.isdir(root):
        return salts
    for acct in os.listdir(root):
        sub = os.path.join(root, acct, "db_storage")
        if not os.path.isdir(sub):
            continue
        for dirpath, _d, files in os.walk(sub):
            for fn in files:
                if fn.endswith(".db"):
                    p1 = BiasAddr._read_page1(os.path.join(dirpath, fn))
                    if p1 and len(p1) >= 16:
                        salts.add(p1[:16].hex().lower())
    return salts


def mask_from_window(buf, base_addr, offset):
    """
    单窗口版本的掩码枚举（只用该窗口自身的约束，命中时可能不唯一）。
    一般情况下应优先使用 recover_global_mask()：它用多个密钥串投票，结果唯一且可靠。
    :return: (mask32, 明文 99 字节) 或 (None, None)
    """
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    cand = _residue_candidates(buf, base_addr, offset)
    if not cand:
        return None, None
    residues = sorted(cand)
    total = 1
    for r in residues:
        total *= len(cand[r])
        if total > 4096:
            break
    import itertools
    combos = itertools.product(*[cand[r] for r in residues]) if total <= 4096 else None
    if combos is None:                                  # 组合过多时取首个候选
        combos = [tuple(cand[r][0] for r in residues)]
    base = base_addr + offset
    for combo in combos:
        m = [0] * 32
        for r, k in zip(residues, combo):
            m[r] = k
        plain = bytes(int(arr[offset + j]) ^ m[(base + j) % 32] for j in range(KEYSTR_LEN))
        if KEYSTR_RE.match(plain):
            return bytes(m), plain
    return None, None


def decode_with_global_mask(buf, base_addr, mask32):
    """按"掩码索引 = 绝对地址 % 32"解码整块内存"""
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    idx = (np.arange(arr.size, dtype=np.int64) + base_addr) % 32
    return bytes(arr ^ np.frombuffer(mask32, dtype=np.uint8)[idx])


def build_page1_map(root=None, log=None):
    """
    遍历 root 下所有账号目录的 .db，建立 salt(前16字节) -> (相对路径, 第 1 页) 映射。
    root 留空 → 动态定位 4.x 数据根目录（回退 D:\\xwechat_files）。
    :return: {"<账号目录>/<库相对路径>": page1_bytes}
    """
    root = root or _default_wx_root()
    page1_map = {}
    if not os.path.isdir(root):
        return page1_map
    for acct in os.listdir(root):
        sub = os.path.join(root, acct, "db_storage")
        if not os.path.isdir(sub):
            continue
        for dirpath, _d, files in os.walk(sub):
            for fn in files:
                if not fn.endswith(".db"):
                    continue
                full = os.path.join(dirpath, fn)
                p1 = BiasAddr._read_page1(full)
                if p1:
                    page1_map[acct + "\\" + os.path.relpath(full, sub)] = p1
    if log:
        log(f"[*] 可校验的加密库（第 1 页可读）：{len(page1_map)} 个")
    return page1_map


def extract_keys_from_memory(pids=None, page1_map=None, chunk_size=16 << 20,
                             time_budget=180.0, valid_salts=None, log=print):
    """
    【无密钥文件、无锚点】地从 Weixin.exe 内存里取出所有 SQLCipher 密钥。

    :return: {"mask": "<32字节hex>", "mask_at": 地址, "keys": {"库相对路径": key_hex},
              "unmatched": [(key,salt,出现次数)], "processes": [{pid,regions,mb,elapsed,keys}]}
    """
    report = {"mask": None, "mask_at": None, "keys": {}, "unmatched": {},
              "processes": [], "verified": {}}
    if pids is None:
        pids = [d["pid"] for d in get_wx_processes(("Weixin.exe",))]
    b = BiasAddr("", "", "", "", None)
    mask32 = None
    for pid in pids:
        info = {"pid": pid, "regions": 0, "mb": 0.0, "elapsed": 0.0, "keys": {}, "mask": None}
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not hProcess:
            info["error"] = "OpenProcess 失败"
            report["processes"].append(info)
            continue
        log(f"[*] 扫描 pid={pid} …")
        t0 = time.time()
        raw_found = {}
        try:
            mask = mask32
            for m in _scannable_regions(pid):
                if time.time() - t0 > time_budget:
                    info["timed_out"] = True
                    break
                info["regions"] += 1
                addr, remain = m.BaseAddress, int(m.RegionSize)
                while remain > 0:
                    n = min(chunk_size, remain)
                    buf = _read_mem(hProcess, addr, n)
                    if buf:
                        info["mb"] += len(buf) / 1048576
                        if mask is None:                  # 先自动反推掩码（真库 salt 假设 / 形状投票）
                            mm, plist = recover_mask_from_candidates(buf, addr, salts=valid_salts,
                                                                     log=log)
                            if mm:
                                mask = mask32 = mm
                                report["mask"] = mm.hex()
                                report["mask_at"] = plist[0][0] if plist else addr
                                log(f"[+] 自动反推出全局掩码 @0x{report['mask_at']:x}：{mm.hex()}")
                                log(f"    同缓冲区一次解出 {len(plist)} 个密钥串，例如："
                                    f"{plist[0][1].decode('ascii', 'replace')}")
                        if mask is not None:
                            dec = decode_with_global_mask(buf, addr, mask)
                            for mo in WCDB_KEY_RE.finditer(dec):
                                kh = mo.group(1).decode().lower()
                                sh = mo.group(2).decode().lower()
                                raw_found.setdefault((kh, sh), []).append(addr + mo.start())
                    addr += n
                    remain -= n
        finally:
            CloseHandle(hProcess)
        info["elapsed"] = time.time() - t0
        info["mask"] = report["mask"]
        # 校验：salt 必须能在真库文件里找到，且 key 要过第 1 页 HMAC
        for (kh, sh), addrs in raw_found.items():
            rel = None
            page1 = None
            if page1_map:
                for r, p1 in page1_map.items():
                    if p1[:16].hex().lower() == sh:
                        rel, page1 = r, p1
                        break
            if page1 is None:
                report["unmatched"][(kh, sh)] = report["unmatched"].get((kh, sh), 0) + len(addrs)
                continue
            try:
                if b.verify_page1_hmac_4x(bytes.fromhex(kh), page1):
                    info["keys"][rel] = kh
                    report["keys"][rel] = kh
            except Exception:
                continue
        report["processes"].append(info)
        log(f"    完成：区段 {info['regions']} / {info['mb']:.1f} MB / {info['elapsed']:.1f}s / "
            f"校验通过 {len(info['keys'])} 把"
            + ("（超时提前结束）" if info.get("timed_out") else ""))
    return report



# =====================================================================
# 五、自测
#   5.1 selftest()       —— 已知明文 + 任意周期掩码：能否找回掩码并还原明文
#   5.2 selftest_blind() —— 不给任何密钥、不给锚点：能否只靠"形状"反推出 32 字节掩码
# =====================================================================
def selftest_blind(bases=(0x10000000, 0x1cbcd91800, 0x7ff6abc12340), n_strings=6):
    """不给密钥文件、不给锚点，检验"只靠形状"能否精确恢复 32 字节掩码"""
    rng = np.random.default_rng(20261005)
    outs = []
    for base in bases:
        for shift in (0, 2, 7, 16, 23, 31):                    # 故意错开相位
            mask = bytes(int(x) for x in rng.integers(0, 256, size=32, dtype=np.uint8))
            strings = []
            for _ in range(n_strings):
                hex_part = bytes(int(HEX_CHARS[i]) for i in rng.integers(0, 16, size=96))
                strings.append(b"x'" + hex_part + b"'")        # 与真实密钥串同形状
            off0 = 1024 + shift
            parts = [bytes(int(x) for x in rng.integers(0, 256, size=off0, dtype=np.uint8))]
            for k, P in enumerate(strings):
                parts.append(bytes(P[j] ^ mask[(base + off0 + k * KEYSTR_LEN + j) % 32]
                                   for j in range(KEYSTR_LEN)))
            parts.append(bytes(int(x) for x in rng.integers(0, 256, size=512, dtype=np.uint8)))
            buf = b"".join(parts)
            # 扮演"磁盘上真库"的角色：把各串的 salt 作为参照集合喂进去（消歧用）
            salts = {s[66:98].decode() for s in strings}
            mm, plist = recover_global_mask(buf, base, valid_salts=salts)
            assert mm, f"base=0x{base:x} shift={shift}：未能反推掩码"
            assert mm == mask, (f"base=0x{base:x} shift={shift}：掩码不符 "
                                f"{mm.hex()} != {mask.hex()}")
            assert len(plist) == n_strings, f"解出 {len(plist)} 个串，应为 {n_strings}"
            # 再检验一遍"不给参照"时的行为（只要求能解出 ≥2 个串）
            mm2, plist2 = recover_global_mask(buf, base)
            assert mm2 and len(plist2) >= 2, f"base=0x{base:x} shift={shift}：无参照时退化"
            outs.append((hex(base), shift, len(plist)))
    return f"[+] 盲扫自测通过：{len(outs)} 组（不同基址/相位）全部精确恢复 32 字节掩码，明细 {outs}"


def _default_key_file():
    """默认密钥文件（可用环境变量 PYWXDUMP_WX4_KEY_FILE 覆盖）"""
    return (os.environ.get("PYWXDUMP_WX4_KEY_FILE")
            or r"C:\Users\Administrator\.wechat-cli\all_keys.json")


def selftest(key_file=None, kinds=("x96",)):
    """
    用真实密钥构造合成缓冲区（明文被周期掩码 XOR 保护），验证：
      1) 能在正确位置命中
      2) 解出的掩码与真实掩码一致
      3) 用掩码解码后能还原明文
      4) 还原出的密钥能通过真库第 1 页 HMAC 校验
    """
    needles = build_needles(key_file or _default_key_file(), kinds)
    if not needles:
        return "[!] 自测失败：密钥文件里没有可用的明文清单"
    nd = needles[0]
    P = nd["data"]
    rng = np.random.default_rng(20261004)
    ok_all = []
    for p in (1, 2, 4, 8, 16, 32):
        mask = bytes(rng.integers(0, 256, size=p, dtype=np.uint8))
        anchor = 4096                       # 故意不取明文长度的整数倍，检验与对齐无关
        head = bytes(rng.integers(0, 256, size=anchor, dtype=np.uint8))
        tail = bytes(rng.integers(0, 256, size=2048, dtype=np.uint8))
        body = bytes(P[j] ^ mask[(anchor + j) % p] for j in range(len(P)))
        buf = head + body + tail
        hits = scan_buffer(buf, [nd], periods=(p,))
        assert hits, f"周期 {p}：未命中"
        h = hits[0]
        assert h["addr"] == anchor, f"周期 {p}：位置不符 {h['addr']} != {anchor}"
        expect_rot = bytes(mask[(anchor + j) % p] for j in range(p))
        assert bytes.fromhex(h["mask_hex"]) == expect_rot, f"周期 {p}：掩码不符"
        arr = np.frombuffer(buf, dtype=np.uint8)
        dec = decode_with_mask(arr, h["addr"], bytes.fromhex(h["mask_hex"]))
        assert bytes(dec[anchor:anchor + len(P)]) == P, f"周期 {p}：解码后明文不符"
        ok_all.append(p)
    # 真库校验：拿还原出来的密钥去验【它自己那个库】的第 1 页
    # 【路径统一】不写死某个账号目录：在动态定位到的 4.x 根目录下按"库相对路径"找它自己那个库
    want = nd["db"].replace("/", "\\").lower()
    page1, used = b"", None
    roots = []
    for _r in (_default_wx_root(),):
        if os.path.isdir(_r):
            roots += [os.path.join(_r, _a, "db_storage") for _a in sorted(os.listdir(_r))]
    for raw_root in roots:
        if not os.path.isdir(raw_root):
            continue
        for dirpath, _dirs, files in os.walk(raw_root):
            for fn in files:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, raw_root).replace("/", "\\").lower()
                if rel == want or (not used and fn.lower() == os.path.basename(want)):
                    page1, used = BiasAddr._read_page1(full), rel
                    if os.path.basename(want) == fn.lower():
                        break
            if page1 and used == want:
                break
        if page1 and used == want:
            break
    hm = None
    if page1:
        b = BiasAddr("", "", "", "", None)
        hm = b.verify_page1_hmac_4x(bytes.fromhex(nd["key_hex"]), page1)
    return (f"[+] 自测通过：周期 {ok_all} 全部命中且掩码/明文均正确；"
            f"还原出的密钥对 {used} 第 1 页 HMAC 校验 = {hm}")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="4.x 无锚点内存扫描：已知明文 + 周期性 XOR 掩码反推")
    ap.add_argument("--key_file", default=r"C:\Users\Administrator\.wechat-cli\all_keys.json")
    ap.add_argument("--kinds", default=",".join(DEFAULT_KINDS),
                    help="明文种类：x96（x'<64hex key><32hex salt>'）/ hex64 / key32 / salt16")
    ap.add_argument("--periods", default=",".join(map(str, DEFAULT_PERIODS)))
    ap.add_argument("--chunk_mb", type=int, default=32)
    ap.add_argument("--time_budget", type=float, default=180.0, help="每个进程的扫描时间上限（秒）")
    ap.add_argument("--db_path", default=None)
    ap.add_argument("--no_cascade", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--selftest_blind", action="store_true")
    ap.add_argument("--blind", action="store_true",
                    help="【推荐】不要密钥文件、不要锚点：自动反推掩码并取出全部密钥")
    ap.add_argument("--wx_root", default=None,
                    help="用于校验密钥的微信数据根目录（留空自动定位，回退 D:\\xwechat_files）")
    ap.add_argument("--pid", type=int, action="append", default=None, help="只扫指定 pid（可多次）")
    a = ap.parse_args()

    kinds = tuple(x.strip() for x in a.kinds.split(",") if x.strip())
    # 【路径统一】不再写死数据根目录：留空就动态定位
    wx_root = a.wx_root or _default_wx_root()
    periods = tuple(int(x) for x in a.periods.split(",") if x.strip())
    if a.selftest_blind:
        print(selftest_blind())
        raise SystemExit(0)
    if a.selftest:
        print(selftest(a.key_file, kinds=kinds))
        print(selftest_blind())
        raise SystemExit(0)

    if a.blind:
        pm = build_page1_map(wx_root)
        salts = collect_salts_from_db_files(wx_root)
        print(f"[*] 磁盘真库 salt 参照集：{len(salts)} 个（用于消歧）")
        rep = extract_keys_from_memory(pids=a.pid, page1_map=pm, valid_salts=salts,
                                       chunk_size=a.chunk_mb << 20, time_budget=a.time_budget)
        print("=" * 70)
        print(f"自动反推的全局掩码：{rep['mask']}  （命中地址 "
              f"{hex(rep['mask_at']) if rep['mask_at'] else None}）")
        print(f"从内存校验通过的密钥：{len(rep['keys'])} 把")
        for dbp, kk in sorted(rep["keys"].items()):
            print(f"    {dbp} -> {kk}")
        if rep["unmatched"]:
            print(f"另有 {len(rep['unmatched'])} 个串在本机库里找不到对应 salt（可能是其它账号/已轮换）：")
            for (kh, sh), cnt in list(rep["unmatched"].items())[:10]:
                print(f"    {kh[:16]}…/{sh[:8]}…  出现 {cnt} 次")
        print("=" * 70)
        raise SystemExit(0)

    rep = scan_all(a.key_file, kinds=kinds, periods=periods,
                   chunk_size=a.chunk_mb << 20, time_budget_per_pid=a.time_budget,
                   db_path=a.db_path, cascade=not a.no_cascade)
    print("=" * 60)
    tot = sum(len(p.get("hits", [])) for p in rep["processes"])
    print(f"[*] 命中合计：{tot}")
    if rep["verified_keys"]:
        print(f"[+] 从内存里取到 {len(rep['verified_keys'])} 把密钥：")
        for dbp, kk in rep["verified_keys"].items():
            print(f"    {dbp} -> {kk}")
    else:
        print("[-] 未命中：内存里没有该明文（也不存在被周期掩码保护的版本）")
    print("=" * 60)
