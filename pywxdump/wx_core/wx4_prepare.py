# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# 【微信 4.x 改造 · 第三步】4.x 库自动准备（供 `wxdump ui` / `wxdump api` 启动时调用）
#
#   流程：定位账号目录 → 读本地密钥文件 → 增量解密 → 汇总（主库 / 解密目录 / 本人 wxid）
#
#   设计要点：
#     · 本模块只服务 4.x。3.x 路径完全不受影响（调用方在 mode=3x 时不要调用它）。
#     · 密钥全部来自本地 JSON 密钥文件，全程不读进程内存、不做 DLL 注入。
#     · 解密算法与 SQLCipher 4 一致（微信 4.x）：AES-256-CBC + HMAC-SHA512，
#       页大小 4096、reserve 80（IV 16 + HMAC 64）；与用户已在用的 batch_decrypt.py 同源。
#     · 增量：默认只补「缺失」的库；已存在但比原始库旧的库只在 --force_decrypt 时重解。
#     · 不删任何文件；写盘一律先写 .part 再原子替换，避免半个文件被当成可用库。
# -------------------------------------------------------------------------------
import glob
import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct
import time

from Crypto.Cipher import AES

# ---------------- SQLCipher 4（微信 4.x）参数 ----------------
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80  # IV(16) + HMAC(64)
SQLITE_HDR = b"SQLite format 3\x00"

# 选账号目录时用于 HMAC 校验的库（相对 db_storage）
PROBE_FILES = ("contact\\contact.db", "session\\session.db", "message\\message_0.db")

# 目录名形如 wxid_xxx_fed4（真实 wxid + 4 位十六进制后缀）
ACCOUNT_RE = re.compile(r"^(wxid_[A-Za-z0-9]{4,})_[0-9a-fA-F]{4}$")


# ============================= 一、密钥文件 =============================

def _default_key_file_candidates():
    """4.x 密钥文件的默认候选位置（先环境变量，再用户目录下的 .wechat-cli）"""
    cands = []
    env = os.getenv("PYWXDUMP_WX4_KEY_FILE")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.path.expanduser("~"), ".wechat-cli", "all_keys.json"))
    cands.append(r"C:\Users\Administrator\.wechat-cli\all_keys.json")
    return cands


def default_key_file():
    """返回第一个真实存在的默认密钥文件；都不存在时返回第一个候选（调用方据此报错）"""
    cands = _default_key_file_candidates()
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return cands[0] if cands else ""


def read_keys(key_file):
    """
    读密钥文件，返回 {相对库路径: enc_key}。

    认两种形态：
      {"message\\message_0.db": {"enc_key": "<64hex>", "salt": "<32hex>"}, ...}   ← all_keys.json
      {"message\\message_0.db": "<64hex>", ...}
    """
    with open(key_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    if not isinstance(data, dict):
        return out
    for rel, val in data.items():
        if isinstance(val, dict):
            k = val.get("enc_key") or val.get("key") or ""
        elif isinstance(val, str):
            k = val
        else:
            k = ""
        k = str(k).strip()
        if len(k) == 64:
            out[str(rel).replace("/", "\\")] = k
    return out


# ============================= 二、解密原语 =============================

def derive_mac_key(enc_key, salt):
    """HMAC 密钥 = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3a, 2, 32)"""
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def verify_page1_hmac(enc_key, page1):
    """校验第 1 页 HMAC：能过说明这把密钥就是这个库的（用于选账号目录/判断密钥有效性）"""
    if len(page1) < PAGE_SZ:
        return False
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    data = page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    stored = page1[PAGE_SZ - HMAC_SZ: PAGE_SZ]
    hm = hmac_mod.new(mac_key, data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == stored


def decrypt_page(enc_key, page_data, pgno):
    """解密单页，输出 4096 字节标准 SQLite 页（reserve 位置补零）"""
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    if pgno == 1:
        decrypted = cipher.decrypt(page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ])
        return bytes(SQLITE_HDR + decrypted + b"\x00" * RESERVE_SZ)
    decrypted = cipher.decrypt(page_data[: PAGE_SZ - RESERVE_SZ])
    return decrypted + b"\x00" * RESERVE_SZ


def decrypt_db_file(src, dst, enc_key_hex, log=None):
    """
    解密一个库文件：src(加密) -> dst(标准 sqlite)。返回页数。
    先写 dst + ".part" 再原子替换，失败不会留下半成品。
    """
    enc_key = bytes.fromhex(enc_key_hex)
    with open(src, "rb") as fin:
        page1 = fin.read(PAGE_SZ)
        if len(page1) < PAGE_SZ:
            raise ValueError("文件小于 1 页，不是有效的加密库")
        if not verify_page1_hmac(enc_key, page1):
            raise ValueError("Page1 HMAC 校验失败（密钥不匹配或库文件已变化）")

        total_pages = (os.path.getsize(src) + PAGE_SZ - 1) // PAGE_SZ
        tmp = dst + ".part"
        buf = bytearray()
        with open(tmp, "wb") as fout:
            for pgno in range(1, total_pages + 1):
                page = page1 if pgno == 1 else fin.read(PAGE_SZ)
                if len(page) < PAGE_SZ:
                    page = page + b"\x00" * (PAGE_SZ - len(page))
                buf += decrypt_page(enc_key, page, pgno)
                if len(buf) >= (1 << 20):
                    fout.write(buf)
                    del buf[:]
                if log and total_pages > 4096 and pgno % 4096 == 0:
                    log(f"       … {pgno}/{total_pages} 页")
            if buf:
                fout.write(buf)
    os.replace(tmp, dst)
    return total_pages


# ============================= 三、账号目录 =============================

def _wx4_roots():
    """4.x 数据根目录候选：注册表 → 各盘 xwechat_files → 我的文档"""
    roots = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\Weixin", 0, winreg.KEY_READ) as k:
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
    for r in roots:
        if r not in out:
            out.append(r)
    return out


def default_wx_root():
    """默认的 4.x 数据根目录（拿不到就回退 D:\\xwechat_files）"""
    try:
        roots = _wx4_roots()
        if roots:
            return roots[0]
    except Exception:
        pass
    return r"D:\xwechat_files"


def find_account_dirs(wx_path=None):
    """
    找出所有「含 db_storage 的账号目录」。返回 [(账号目录, db_storage 路径), ...]

    wx_path 三种给法都可以：账号目录本身 / db_storage / 上层根目录（如 D:\\xwechat_files）
    """
    cands = []

    def add_account(p):
        ds = os.path.join(p, "db_storage")
        if os.path.isdir(ds) and (p, ds) not in cands:
            cands.append((p, ds))

    if wx_path:
        wp = os.path.normpath(wx_path)
        if os.path.basename(wp).lower() == "db_storage" and os.path.isdir(wp):
            cands.append((os.path.dirname(wp), wp))
        elif os.path.isdir(wp):
            add_account(wp)                     # 账号目录
            for name in sorted(os.listdir(wp)):  # 上层根目录
                sub = os.path.join(wp, name)
                if os.path.isdir(sub):
                    add_account(sub)
    if not cands:
        for root in _wx4_roots():
            for name in sorted(os.listdir(root)):
                sub = os.path.join(root, name)
                if os.path.isdir(sub):
                    add_account(sub)
    return cands


def _looks_like_account(head):
    """首段是不是"账号目录名"（wiid_xxx_abcd / <账号目录名> 这类）——正则 + 真实目录双重判断"""
    if ACCOUNT_RE.match(head):
        return True
    try:
        for root in _wx4_roots():
            if os.path.isdir(os.path.join(root, head)):
                return True
    except Exception:
        pass
    return False


def _keymap_for_account(account_dir, keys):
    """
    把密钥文件的键对到【某个账号】下的真实库路径，返回 [(库相对路径, key, 真实文件)]。

    支持两种键写法：
      · 老式无账号前缀：'message\\message_0.db'
      · 【4.0】账号限定条目：'wxid_xxx_abcd\\message\\message_0.db'（多账号共用一份密钥文件时用）
    对不上的键直接丢掉，不参与打分。
    """
    ds = os.path.join(account_dir, "db_storage")
    acct = os.path.basename(account_dir).lower()
    out = []
    for rel, key in (keys or {}).items():
        rel_n = str(rel).replace("/", "\\").strip("\\")
        parts = rel_n.split("\\")
        if len(parts) >= 2 and _looks_like_account(parts[0]):
            if parts[0].lower() != acct:          # 别的账号的限定条目：本账号不用
                continue
            rel_n = "\\".join(parts[1:])
        src = os.path.join(ds, rel_n)
        if not os.path.isfile(src):
            src = os.path.join(ds, os.path.basename(rel_n))
            if not os.path.isfile(src):
                continue
        out.append((rel_n, key, src))
    return out


def keys_for_account(account_dir, keys):
    """【4.0】筛选出"该账号该用的密钥"：别账号的账号限定条目全部剔除（避免拿错账号的密钥去试）"""
    acct = os.path.basename(account_dir).lower()
    used, dropped = {}, 0
    for rel, key in (keys or {}).items():
        parts = str(rel).replace("/", "\\").strip("\\").split("\\")
        if len(parts) >= 2 and _looks_like_account(parts[0]):
            if parts[0].lower() != acct:
                dropped += 1
                continue
            used["\\".join(parts[1:])] = key
        else:
            used["\\".join(parts)] = key
    return used, dropped


def score_account(account_dir, keys, limit=60):
    """
    用「密钥能否通过 page1 HMAC」给账号目录打分（命中越多越是这个密钥文件对应的账号）

    page1 HMAC 只做 2 轮 PBKDF2，单次校验极快，所以对每个候选账号最多校验 limit 把密钥，
    先验 PROBE_FILES（最有代表性），再补其余（含账号限定条目）。
    """
    hits, checked = 0, 0
    pairs = _keymap_for_account(account_dir, keys)
    pairs.sort(key=lambda t: 0 if t[0] in PROBE_FILES else 1)
    for _rel, key, src in pairs[:limit]:
        checked += 1
        try:
            with open(src, "rb") as f:
                page1 = f.read(PAGE_SZ)
            if verify_page1_hmac(bytes.fromhex(key), page1):
                hits += 1
        except Exception:
            pass
    return hits, checked


def _account_recency(account_dir):
    """
    账号目录的"新鲜度"：db_storage 下几个探针库的最新修改时间。
    正在登录的账号微信一直在写库，所以时间最新的那个就是当前账号。
    """
    ds = os.path.join(account_dir, "db_storage")
    best = 0.0
    for rel in PROBE_FILES + ("message\\message_1.db", "message\\biz_message_0.db"):
        p = os.path.join(ds, rel)
        try:
            if os.path.isfile(p):
                best = max(best, os.path.getmtime(p))
        except Exception:
            continue
    if not best:
        try:
            best = os.path.getmtime(ds)
        except Exception:
            best = 0.0
    return best


def pick_account(accounts, keys, log=None):
    """
    选出密钥文件对应的账号目录。返回 (账号目录, db_storage, 详情字符串)

    判据是密码学校验（page1 HMAC），不是目录名，避免多账号误选；
    【4.0】当一份密钥文件同时装着多个账号的密钥（都能过 HMAC）时，
    再用"库文件最新写入时间"决胜 —— 正在登录的账号是唯一在持续写库的那个。
    """
    best, best_hits, best_detail = None, 0, ""
    cands = []
    for account_dir, _ds in accounts:
        hits, checked = score_account(account_dir, keys)
        recency = _account_recency(account_dir)
        cands.append((hits, recency, account_dir, checked))
        if log:
            ts = (time.strftime("%m-%d %H:%M", time.localtime(recency)) if recency else "无")
            log(f"    候选账号 {os.path.basename(account_dir)}：HMAC 校验 {hits}/{checked} 命中"
                f"，库最新写入 {ts}")
    for hits, recency, account_dir, checked in sorted(cands, key=lambda t: (t[1], t[0]), reverse=True):
        if hits <= 0:
            continue
        if best is None or (recency, hits) > (_account_recency(best), best_hits):
            best, best_hits = account_dir, hits
            best_detail = (f"HMAC 校验 {hits}/{checked} 命中"
                           f"，库最新写入 {time.strftime('%Y-%m-%d %H:%M', time.localtime(recency))}")
    if best and best_hits > 0:
        return best, os.path.join(best, "db_storage"), best_detail
    return None, "", ""


# ============================= 四、输出目录 / 本人 wxid =============================

def _dir_account(p):
    """读解密目录里的账号标记（自动创建的目录都会写这个标记，用来避免跨账号串库）"""
    try:
        with open(os.path.join(p, "_wx4_account.txt"), "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def choose_out_dir(decrypted_dir=None, work_path=None, account_dir=""):
    """
    解密产物目录：
      1. --decrypted_dir 指定 → 直接用（用户明确指定，不做账号校验）
      2. <work_path>/decrypted_wx4/<账号目录名> → 本账号专用目录，存在就直接复用
      3. D:\\decrypted_wx_db（本机历史解密库）→ 【仅当账号标记一致时】才复用

    【4.0】加账号校验的原因：本机同时存在多个 4.x 账号目录，若把 A 账号的解密库直接
    当成 B 账号的库用，会串库（会话列表是 B 的、消息却是 A 的）。所以只有确认同一个账号
    才复用旧目录，否则按账号另建。
    """
    def has_msg(p):
        return bool(p) and os.path.isdir(p) and glob.glob(os.path.join(p, "message_*_decrypted.db"))

    name = os.path.basename(os.path.normpath(account_dir)) if account_dir else "default"
    work_out = os.path.join(work_path, "decrypted_wx4", name) if work_path else ""
    if has_msg(work_out):
        return work_out, True
    if decrypted_dir:
        return decrypted_dir, has_msg(decrypted_dir)
    # 【4.0.1 路径统一】历史写法把解密库固定放在 D:\decrypted_wx_db，该目录可能已被清理或换盘。
    # 改成"候选列表 + 动态定位"，逐个试；只有账号标记一致才复用，全都不命中就按账号新建。
    for legacy in _legacy_decrypt_candidates(work_path, name):
        if has_msg(legacy) and _dir_account(legacy) == name:
            return legacy, True
    return work_out, False


def _legacy_decrypt_candidates(work_path=None, account_name=""):
    """
    历史 / 其它位置上的「已解密库目录」候选（按优先级去重返回）：
      1. <work_path>\\decrypted_wx4\\<账号>、<work_path>\\wx4_autodecrypt —— 本工具自己的输出位置
      2. 各盘根目录下的 decrypted_wx_db、用户目录下、当前工作目录下 —— 老脚本的历史写法
    只做"存在性 + 账号标记"判断，不创建、不删除任何目录。
    """
    out = []
    if work_path:
        if account_name:
            out.append(os.path.join(work_path, "decrypted_wx4", account_name))
        out.append(os.path.join(work_path, "wx4_autodecrypt"))
    for drive in ("C:", "D:", "E:", "F:", "G:"):
        out.append(os.path.join(drive + os.sep, "decrypted_wx_db"))
    try:
        out.append(os.path.join(os.path.expanduser("~"), "decrypted_wx_db"))
    except Exception:
        pass
    try:
        out.append(os.path.join(os.getcwd(), "decrypted_wx_db"))
    except Exception:
        pass
    seen, res = set(), []
    for p in out:
        k = os.path.normpath(p).lower()
        if k not in seen:
            seen.add(k)
            res.append(p)
    return res


def guess_my_wxid(account_dir, out_dir, log=None):
    """
    推本人 wxid：账号目录名 wxid_xxx_4hex → wxid_xxx，并用解密库里的旁证校验
    （contact 表里有这条联系人 / message_0 的 Name2Id 里有它）。
    推不出来就返回 ""，此时 UI 能看会话但「我发的」判定会不准。
    """
    import sqlite3
    name = os.path.basename(os.path.normpath(account_dir))
    m = ACCOUNT_RE.match(name)
    if not m:
        return "", f"账号目录名 {name!r} 不是 wxid_xxx_4hex 形式，无法推断"
    cand = m.group(1)

    proofs = []
    fp = os.path.join(out_dir, "contact_decrypted.db")
    if os.path.isfile(fp):
        try:
            con = sqlite3.connect(f"file:{fp}?mode=ro", uri=True)
            n = con.execute("SELECT count(*) FROM contact WHERE username=?", (cand,)).fetchone()[0]
            con.close()
            proofs.append(f"contact 命中 {n}")
        except Exception as e:
            proofs.append(f"contact 查询失败 {e}")
    fp = os.path.join(out_dir, "message_0_decrypted.db")
    if os.path.isfile(fp):
        try:
            con = sqlite3.connect(f"file:{fp}?mode=ro", uri=True)
            n = con.execute("SELECT count(*) FROM Name2Id WHERE user_name=?", (cand,)).fetchone()[0]
            con.close()
            proofs.append(f"Name2Id 命中 {n}")
        except Exception as e:
            proofs.append(f"Name2Id 查询失败 {e}")
    if log and proofs:
        log(f"    本人 wxid 推断：{cand}（{'; '.join(proofs)}）")
    return cand, "; ".join(proofs)


# ============================= 五、主流程 =============================

def _resolve_src(db_storage, rel):
    """把密钥文件里的相对路径对到真实文件（先按相对路径，再按文件名，最后浅层 glob）"""
    p = os.path.join(db_storage, rel)
    if os.path.isfile(p):
        return p
    base = os.path.basename(rel)
    p = os.path.join(db_storage, base)
    if os.path.isfile(p):
        return p
    hits = glob.glob(os.path.join(db_storage, "*", base))
    return hits[0] if hits else ""


def decode_out_name(rel):
    base = os.path.basename(rel)
    return base[:-3] + "_decrypted.db" if base.lower().endswith(".db") else base + "_decrypted.db"


def prepare_wx4(key_file=None, wx_path=None, decrypted_dir=None, my_wxid=None,
                no_decrypt=False, force_decrypt=False, work_path=None, log=print,
                allow_mem=True):
    """
    4.x UI 启动前的自动准备。返回 dict：

      ok             : 是否拿到了可用的主库
      my_wxid        : 本人 wxid（可能为空字符串）
      wx_path        : 账号目录（给 conf 的 wx_path 用）
      db_storage     : 原始（加密）库目录
      decrypted_dir  : 解密库目录
      primary_db     : 主库（message_0_decrypted.db 优先）
      key_file/key_count/key_source
      decrypted/reused/stale/not_found/failed: 各文件清单
      msg            : 人类可读的结论（失败原因或摘要）

    【4.0】allow_mem=True：密钥文件不存在/为空时，改为只读扫描 Weixin.exe 内存取密钥，
    并把取到的密钥回写密钥文件 —— 这样"删掉密钥文件"不会让 UI 启动失败。
    """
    ret = {"ok": False, "msg": "", "my_wxid": "", "wx_path": "", "db_storage": "",
           "decrypted_dir": "", "primary_db": "", "key_file": "", "key_count": 0,
           "decrypted": [], "reused": [], "stale": [], "not_found": [], "failed": [],
           "account_detail": "", "keys_other_account": 0, "key_source": "file"}

    # 1) 密钥：优先密钥文件；没有就从内存取（只读）
    kf = key_file or default_key_file()
    ret["key_file"] = kf
    keys = {}
    if kf and os.path.isfile(kf):
        try:
            keys = read_keys(kf)
        except Exception as e:
            log(f"[-] 密钥文件解析失败，尝试内存取密钥：{kf}：{e}")
            keys = {}
    if not keys and allow_mem:
        log(f"[-] 没读到可用密钥文件（{kf}）→ 改为只读扫描 Weixin.exe 内存取密钥……")
        try:
            from .get_bias_addr import BiasAddr
            bs = BiasAddr("", "", "", "", None)
            rep = bs.run_wx4_xor_keys(wx_root=default_wx_root(), sync_store=True,
                                      keys_file=kf, do_print=True, log=log)
            keys = dict(rep.get("keys") or {})
            ret["key_source"] = "memory"
            if keys:
                log(f"[+] 内存取到 {len(keys)} 把密钥（已回写 {kf}）")
        except Exception as e:
            log(f"[-] 内存取密钥失败：{e}")
            keys = {}
    if not keys:
        ret["msg"] = f"拿不到密钥：密钥文件 {kf} 不存在/为空，且内存取密钥也没成功"
        return ret
    ret["key_count"] = len(keys)
    log(f"[+] 密钥来源：{'Weixin.exe 只读内存' if ret['key_source'] == 'memory' else '密钥文件 ' + kf}"
        f"（{len(keys)} 把）")

    # 2) 账号目录（用密钥做 page1 HMAC 校验来定位）
    accounts = find_account_dirs(wx_path)
    if not accounts:
        ret["msg"] = "没找到任何含 db_storage 的 4.x 账号目录（可用 --wx_path 指定）"
        return ret
    log(f"[+] 候选账号目录 {len(accounts)} 个，正在用密钥校验……")
    account_dir, db_storage, detail = pick_account(accounts, keys, log=log)
    if not account_dir:
        ret["msg"] = (f"{len(accounts)} 个候选账号目录都没有通过 page1 HMAC 校验，"
                      f"密钥文件可能与当前数据不匹配")
        return ret
    ret["account_detail"] = detail
    ret["wx_path"] = account_dir
    ret["db_storage"] = db_storage
    log(f"[+] 账号目录：{account_dir}（{detail}）")

    # 【4.0】多账号共用一份密钥文件时：只留"本账号 + 无账号前缀"的密钥，剔掉别账号的账号限定条目
    keys, dropped = keys_for_account(account_dir, keys)
    ret["keys_other_account"] = dropped
    if dropped:
        log(f"[*] 密钥文件里另有 {dropped} 条属于其它账号的账号限定条目，本次已跳过")
    if not keys:
        ret["msg"] = f"密钥文件里没有可用于账号 {os.path.basename(account_dir)} 的密钥"
        return ret

    # 3) 解密产物目录
    out_dir, reused = choose_out_dir(decrypted_dir, work_path, account_dir)
    if not out_dir:
        ret["msg"] = "无法确定解密产物目录（可用 --decrypted_dir 指定）"
        return ret
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    ret["decrypted_dir"] = out_dir
    # 【4.0】自动选出来的目录写账号标记：下次同一个账号才能复用它（避免跨账号串库）
    if not decrypted_dir:
        try:
            with open(os.path.join(out_dir, "_wx4_account.txt"), "w", encoding="utf-8") as f:
                f.write(os.path.basename(os.path.normpath(account_dir)))
        except Exception:
            pass
    log(f"[+] 解密库目录：{out_dir}" + ("（已存在，直接复用）" if reused else "（新建）"))

    # 4) 本人 wxid
    if my_wxid:
        mid, why = my_wxid, "由 --my_wxid 指定"
    else:
        mid, why = guess_my_wxid(account_dir, out_dir, log=log)
    ret["my_wxid"] = mid
    if not mid:
        log(f"[!] 未能推断本人 wxid：{why}（会话能看，但「我发的/对方发的」可能不准）")

    # 5) 逐个库处理
    for rel in sorted(keys.keys()):
        src = _resolve_src(db_storage, rel)
        if not src:
            ret["not_found"].append(rel)
            continue
        dst = os.path.join(out_dir, decode_out_name(rel))
        try:
            if no_decrypt:
                if os.path.isfile(dst):
                    ret["reused"].append(rel)
                else:
                    ret["not_found"].append(rel)
                continue

            need = force_decrypt or (not os.path.isfile(dst)) or os.path.getsize(dst) == 0
            if not need:
                if os.path.getmtime(dst) >= os.path.getmtime(src):
                    ret["reused"].append(rel)
                else:
                    ret["stale"].append(rel)
                    ret["reused"].append(rel)
                continue

            size_mb = os.path.getsize(src) / 1024 / 1024
            log(f"    解密 {rel}（{size_mb:.1f} MB）……")
            t0 = os.path.getmtime(src)
            pages = decrypt_db_file(src, dst, keys[rel], log=log)
            # 与原始库时间对齐，便于下次判断新鲜度
            try:
                os.utime(dst, (t0, t0))
            except Exception:
                pass
            ret["decrypted"].append(rel)
            log(f"      完成（{pages} 页）")
        except Exception as e:
            ret["failed"].append(f"{rel}: {e}")

    # 6) 主库
    msg_dbs = sorted(glob.glob(os.path.join(out_dir, "message_[0-9]*_decrypted.db")))
    for cand in [os.path.join(out_dir, "message_0_decrypted.db")] + msg_dbs:
        if os.path.isfile(cand) and os.path.getsize(cand) > 0:
            ret["primary_db"] = cand
            break

    if ret["primary_db"]:
        ret["ok"] = True
        ret["msg"] = (f"已解密 {len(ret['decrypted'])} 个 / 复用 {len(ret['reused'])} 个"
                      + (f" / 过期未刷新 {len(ret['stale'])} 个（加 --force_decrypt 可刷新）" if ret["stale"] else "")
                      + (f" / 失败 {len(ret['failed'])} 个" if ret["failed"] else ""))
        # 【4.0】失败项把原因打出来（最常见是"该库密钥已轮换"或"库文件被微信占用"）
        for f in ret["failed"]:
            log(f"    [!] 跳过 {f}")
    else:
        ret["msg"] = (f"解密目录 {out_dir} 里没有可用的 message_*_decrypted.db"
                      + (f"；失败 {len(ret['failed'])} 个：{ret['failed'][:3]}" if ret["failed"] else ""))
    return ret


if __name__ == "__main__":  # 自测：python -m pywxdump.wx_core.wx4_prepare
    import sys
    args = dict(a.split("=", 1) for a in sys.argv[1:] if "=" in a)
    r = prepare_wx4(key_file=args.get("key_file"), wx_path=args.get("wx_path"),
                    decrypted_dir=args.get("decrypted_dir"), my_wxid=args.get("my_wxid"),
                    force_decrypt=args.get("force_decrypt") == "1",
                    no_decrypt=args.get("no_decrypt") == "1")
    print("-" * 80)
    for k in ("ok", "msg", "my_wxid", "wx_path", "db_storage", "decrypted_dir", "primary_db",
              "key_file", "key_count", "account_detail"):
        print(f"  {k}: {r[k]}")
    for k in ("decrypted", "reused", "stale", "not_found", "failed"):
        print(f"  {k}({len(r[k])}): {r[k][:8]}")
