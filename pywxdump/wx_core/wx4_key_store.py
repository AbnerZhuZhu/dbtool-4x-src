# -*- coding: utf-8 -*-
"""
【第四步·收尾】4.x 内存取密钥的「落盘」逻辑（只做这一件事，不参与扫描本身）

提供两个动作：
  1) 回写 all_keys.json
     内存里取到、且【再次通过真库第 1 页 HMAC 校验】的密钥，与本地密钥文件逐条比对：
       - 密钥不同  -> 更新 enc_key，并把被替换的旧值记录到 prev_enc_key，来源标记 source=memory_scan
       - 文件里没有 -> 新增一条（salt 取自真库文件开头 16 字节，size_mb 取自真实文件大小）
       - 密钥相同  -> 不动
     写文件前自动备份为 <文件名>.bak_YYYYmmdd_HHMMSS，并用「临时文件 + 原子替换」落盘，
     避免写一半把用户的密钥文件写坏。
     任何一条没通过 HMAC 校验的密钥，一律【拒绝写入】（不信任上游标记，自己重算一遍）。

  2) 另存未匹配串 extra_mem_keys.json
     内存里扫到、但在当前可校验库里找不到对应 salt 的密钥串，另存到独立文件，
     与已有内容【合并去重】（按 enc_key），保留 first_seen、刷新 last_seen / occurrences。

设计约束：
  - 不改动扫描模块（wx4_xor_scan.py）的任何判据；
  - 任何异常都只打印一行提示，绝不影响 info / bias 主流程；
  - 不写密钥明文到日志之外的地方，不改微信文件、不碰进程。
"""
import json
import os
import re
import shutil
import time

DEFAULT_EXTRA_FILE = r"C:\Users\Administrator\.wechat-cli\extra_mem_keys.json"


def _wx_root_default():
    """
    【4.0.1 路径统一】4.x 数据根目录：动态定位优先（注册表 → 各盘 xwechat_files → 我的文档），
    全都不在才回退 D:\\xwechat_files。可用环境变量 PYWXDUMP_WX4_ROOT 覆盖
    （与 wx4_xor_scan._default_wx_root 保持一致）。
    """
    env = os.environ.get("PYWXDUMP_WX4_ROOT")
    if env and os.path.isdir(env):
        return env
    try:
        from .wx4_prepare import default_wx_root as _prep_default
        r = _prep_default()
        if r and os.path.isdir(r):
            return r
    except Exception:
        pass
    for p in (r"D:\xwechat_files", r"E:\xwechat_files", r"C:\xwechat_files",
              os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files")):
        if os.path.isdir(p):
            return p
    return r"D:\xwechat_files"


# 保持"常量"用法不变（本模块多处直接引用该名字），值改为动态解析结果
DEFAULT_WX_ROOT = _wx_root_default()

# 账号目录形如 <账号目录名> / 其它账号目录名_4位hex
_ACCT_RE = re.compile(r"^[A-Za-z0-9_.\-]{4,}_[0-9a-fA-F]{4}$")


# =====================================================================
# 一、路径与文件工具
# =====================================================================
def _keys_file_default():
    """all_keys.json 的默认路径（沿用扫描模块的约定：可用 PYWXDUMP_WX4_KEY_FILE 覆盖）"""
    try:
        from .wx4_xor_scan import _default_key_file
        return _default_key_file()
    except Exception:
        return (os.environ.get("PYWXDUMP_WX4_KEY_FILE")
                or r"C:\Users\Administrator\.wechat-cli\all_keys.json")


def _extra_file_default():
    """extra_mem_keys.json 的默认路径（可用 PYWXDUMP_WX4_EXTRA_KEYS 覆盖）"""
    return os.environ.get("PYWXDUMP_WX4_EXTRA_KEYS") or DEFAULT_EXTRA_FILE


def normalize_db_relpath(rel):
    """把 'wxid_xxx_fed4\\message\\message_0.db' 归一成密钥文件里使用的 'message\\message_0.db'"""
    s = str(rel).replace("/", "\\").strip("\\")
    parts = [p for p in s.split("\\") if p]
    if len(parts) >= 2 and _ACCT_RE.match(parts[0]):
        parts = parts[1:]
    return "\\".join(parts)


def _find_existing_key(raw, norm):
    """在已有密钥文件里找与 norm 对应的键（先精确、再忽略大小写、最后按路径后缀）"""
    if norm in raw:
        return norm
    low = norm.lower()
    for k in raw:
        if str(k).replace("/", "\\").strip("\\").lower() == low:
            return k
    tail = "\\" + low
    cands = [k for k in raw
             if str(k).replace("/", "\\").strip("\\").lower().endswith(tail)]
    return min(cands, key=len) if cands else None


def _entry_key_salt(cur):
    """取出一个条目里的 (enc_key, salt)，兼容 str / dict 两种写法"""
    if isinstance(cur, dict):
        k = cur.get("enc_key") or cur.get("key") or ""
        s = cur.get("salt") or ""
    elif isinstance(cur, str):
        k, s = cur, ""
    else:
        k, s = "", ""
    return str(k).strip().lower(), str(s).strip().lower()


def _salt_owners(rel, entry_salt, page1_map):
    """
    判断密钥文件里这条 ['message\\message_0.db' + salt] 属于哪个账号目录。

    做法：在"第 1 页可读"的真库集合里找同相对路径、且【文件 salt == 条目 salt】的账号。
    salt 是每个库文件随机生成的 16 字节，撞车概率可忽略，而且不用做昂贵的 PBKDF2，
    所以这是判断归属最便宜的可靠依据。

    :return: 账号目录名列表（可能为空 = 已无对应文件，属于可安全刷新的陈旧条目）
    """
    if not entry_salt:
        return []
    tail = "\\" + str(rel).replace("/", "\\").strip("\\").lower()
    owners = []
    for k, p1 in (page1_map or {}).items():
        kn = str(k).replace("/", "\\").strip("\\")
        if not kn.lower().endswith(tail):
            continue
        try:
            if p1[:16].hex() == entry_salt and kn.split("\\")[0] not in owners:
                owners.append(kn.split("\\")[0])
        except Exception:
            continue
    return owners


def resolve_db_path(acct_rel, wx_root=None):
    """把 'wxid_xxx_fed4\\message\\message_0.db' 还原成磁盘上的真实 .db 路径"""
    parts = str(acct_rel).replace("/", "\\").strip("\\").split("\\")
    if len(parts) < 3:
        return None
    root = wx_root or DEFAULT_WX_ROOT
    p = os.path.join(root, parts[0], "db_storage", *parts[1:])
    return p if os.path.isfile(p) else None


def _size_mb(path):
    try:
        return round(os.path.getsize(path) / 1048576, 3)
    except Exception:
        return None


def _atomic_write_json(path, obj):
    """临时文件 + 原子替换，避免写一半损坏用户的 json"""
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp_%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# =====================================================================
# 二、回写 all_keys.json
# =====================================================================
def update_keys_file(mem_keys, keys_file=None, page1_map=None, wx_root=None,
                     dry_run=False, log=print):
    """
    把内存里取到、且【再次通过真库第 1 页 HMAC 校验】的密钥回写进 all_keys.json。

    :param mem_keys:  {“账号目录\\库相对路径”: key_hex} —— 即内存扫描报告的 rep["keys"]
    :param keys_file: 目标密钥文件（默认 C:\\Users\\Administrator\\.wechat-cli\\all_keys.json）
    :param page1_map: {“账号目录\\库相对路径”: 第1页4096字节}；不给就自己扫 D:\\xwechat_files
    :param dry_run:   True 时只算差异、不落盘（便于先看会改什么）
    :return: {"path","backup","changed","updated":[{db,old,new}],"added":[...],
              "unchanged":[...],"skipped":[{db,reason}]}
    """
    path = keys_file or _keys_file_default()
    rep = {"path": path, "backup": None, "changed": False, "updated": [], "added": [],
           "unchanged": [], "skipped": [], "salt_fixed": [], "protected": []}
    if not mem_keys:
        return rep

    raw = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            rep["skipped"].append({"db": "<文件>", "reason": f"读取密钥文件失败，已跳过回写：{e}"})
            if log:
                log(f"[-] 回写跳过：读取 {path} 失败：{e}")
            return rep
        if not isinstance(raw, dict):
            rep["skipped"].append({"db": "<文件>", "reason": "密钥文件不是 {库路径: {...}} 结构，已跳过"})
            if log:
                log("[-] 回写跳过：密钥文件不是 dict 结构")
            return rep

    if page1_map is None:
        from .wx4_xor_scan import build_page1_map
        page1_map = build_page1_map(wx_root or DEFAULT_WX_ROOT)

    from .get_bias_addr import BiasAddr          # 局部导入，避免模块级循环依赖
    b = BiasAddr("", "", "", "", None)

    for acct_rel, kh in mem_keys.items():
        acct_rel = str(acct_rel).replace("/", "\\").strip("\\")
        rel = normalize_db_relpath(acct_rel)
        kh = str(kh).strip().lower()

        page1 = page1_map.get(acct_rel)
        if page1 is None:                        # 只认精确匹配，避免把别的账号的同名库错认成它
            rep["skipped"].append({"db": rel, "reason": "找不到该库第 1 页，无法校验"})
            continue
        try:                                     # 自己再校验一遍，不信任上游标记
            ok = b.verify_page1_hmac_4x(bytes.fromhex(kh), page1)
        except Exception:
            ok = False
        if not ok:
            rep["skipped"].append({"db": rel, "reason": "第 1 页 HMAC 未通过，拒绝写入"})
            continue

        salt = page1[:16].hex()
        size_mb = _size_mb(resolve_db_path(acct_rel, wx_root))
        acct = acct_rel.split("\\")[0] if "\\" in acct_rel else ""
        existed = _find_existing_key(raw, rel)
        qualified = _find_existing_key(raw, acct_rel) if acct else None  # 账号限定条目（如 wxid_x_abcd\message\message_0.db）

        if existed is None and qualified is None:   # 文件里完全没有这个库 -> 新增
            entry = {"enc_key": kh, "salt": salt}
            if size_mb is not None:
                entry["size_mb"] = size_mb
            entry["source"] = "memory_scan"
            raw[rel] = entry
            rep["added"].append({"db": rel, "new": kh})
            continue

        # 选要比对的目标条目：优先账号限定条目，其次普通相对路径条目
        target = qualified or existed
        cur = raw[target]
        old, old_salt = _entry_key_salt(cur)

        if old == kh:                            # 密钥一致
            if isinstance(cur, dict) and old_salt != salt:
                # 【4.0】修掉"key 与 salt 不同源"的历史脏数据（换过账号的回写会留下这种记录）
                cur["salt"] = salt
                rep["salt_fixed"].append({"db": target, "old_salt": old_salt[:16], "new_salt": salt[:16]})
            else:
                rep["unchanged"].append({"db": target})
            continue

        # 【4.0】跨账号保护：文件里这条如果属于别的账号（salt 指向别的账号的同名库），就绝不覆盖，
        #        改为写入"账号限定条目"，两个账号的密钥都留着。
        if qualified is None and acct:
            owners = _salt_owners(rel, old_salt, page1_map)
            if owners and acct not in owners:
                entry = {"enc_key": kh, "salt": salt, "account": acct, "source": "memory_scan"}
                if size_mb is not None:
                    entry["size_mb"] = size_mb
                raw[acct_rel] = entry
                rep["added"].append({"db": acct_rel, "new": kh,
                                     "reason": f"原 {rel} 属于 {','.join(sorted(owners))}，未覆盖"})
                rep["protected"].append({"db": rel, "kept_salt": old_salt[:16], "owner": sorted(owners)})
                continue

        if isinstance(cur, dict):                # 同账号轮换 -> 原地更新（salt 一并更新，保持 key/salt 同源）
            cur["enc_key"] = kh
            cur["salt"] = salt
            if size_mb is not None:
                cur["size_mb"] = size_mb
            if old:
                cur["prev_enc_key"] = old
            cur["source"] = "memory_scan"
        else:
            raw[target] = {"enc_key": kh, "salt": salt}
        rep["updated"].append({"db": target, "old": old or None, "new": kh})

    changed = bool(rep["updated"] or rep["added"] or rep["salt_fixed"])
    rep["changed"] = changed
    if not changed:
        if log:
            log(f"[*] 密钥文件无需更新：{path}（内存密钥与文件一致，{len(rep['unchanged'])} 条）")
        return rep

    if dry_run:
        if log:
            log(f"[*] 试运行：将更新 {len(rep['updated'])} 条、新增 {len(rep['added'])} 条（未落盘）")
        return rep

    if os.path.exists(path):
        bk = f"{path}.bak_{time.strftime('%Y%m%d_%H%M%S')}"
        try:
            shutil.copy2(path, bk)
            rep["backup"] = bk
        except Exception as e:
            rep["backup"] = None
            if log:
                log(f"[-] 备份失败（已中止回写，保护原文件）：{e}")
            rep["changed"] = False
            rep["skipped"].append({"db": "<文件>", "reason": f"备份失败，已中止回写：{e}"})
            return rep
    try:
        _atomic_write_json(path, raw)
    except Exception as e:
        rep["changed"] = False
        rep["skipped"].append({"db": "<文件>", "reason": f"写入失败：{e}"})
        if rep.get("backup"):
            try:
                shutil.copy2(rep["backup"], path)
                if log:
                    log(f"[-] 写入失败，已从备份回滚：{rep['backup']}")
            except Exception:
                pass
        if log:
            log(f"[-] 回写失败：{e}")
        return rep

    if log:
        log(f"[+] 已回写密钥文件：{path}"
            + (f"（备份 {os.path.basename(rep['backup'])}）" if rep.get("backup") else ""))
        for u in rep["updated"]:
            log(f"    更新 {u['db']}：{str(u['old'])[:16]}… -> {u['new'][:16]}…")
        for a in rep["added"]:
            extra = f"（{a['reason']}）" if a.get("reason") else ""
            log(f"    新增 {a['db']}：{a['new'][:16]}…{extra}")
        for s in rep["salt_fixed"]:
            log(f"    修正 salt {s['db']}：{s['old_salt']}… -> {s['new_salt']}…（原来 key 与 salt 不同源）")
    return rep


# =====================================================================
# 三、另存未匹配串 extra_mem_keys.json
# =====================================================================
def save_unmatched_keys(unmatched, extra_file=None, mask=None, wx_root=None, log=print):
    """
    把「内存扫到、但当前可校验库里没有匹配 salt」的密钥串另存到独立文件，与已有内容合并去重。

    :param unmatched: 内存扫描报告的 rep["unmatched"]，形如 {(key_hex, salt_hex): 出现次数}
    :return: {"path","total","added"}
    """
    path = extra_file or _extra_file_default()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    doc = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f) or {}
        except Exception as e:
            if log:
                log(f"[-] 读取 {path} 失败（将以新内容覆盖同名字段）：{e}")
            doc = {}
    if not isinstance(doc, dict):
        doc = {}

    items = {}
    for e in (doc.get("unmatched_keys") or []):
        if isinstance(e, dict) and e.get("enc_key"):
            items[str(e["enc_key"]).lower()] = e

    added = 0
    for (kh, sh), cnt in (unmatched or {}).items():
        kh, sh = str(kh).lower(), str(sh).lower()
        e = items.get(kh)
        if e is None:
            items[kh] = {
                "enc_key": kh,
                "salt": sh,
                "occurrences": int(cnt),
                "page1_hmac_verified": False,
                "reason": "内存扫描命中，但当前可校验库里没有匹配该 salt 的库（可能是其它账号 / 已轮换）",
                "first_seen": now,
                "last_seen": now,
            }
            added += 1
        else:
            e["last_seen"] = now
            e["occurrences"] = max(int(e.get("occurrences") or 0), int(cnt))
            e.setdefault("salt", sh)

    doc["_note"] = ("本文件是内存扫描发现的密钥，未匹配到当前可校验库（未通过第 1 页 HMAC 或本机无对应库）。"
                    "仅供排查与后续比对，请勿直接用于解密。")
    doc["_source"] = "Weixin.exe 只读内存扫描（pywxdump.wx_core.wx4_xor_scan.extract_keys_from_memory）"
    doc["_generated_at"] = now
    if mask:
        doc["_mask"] = mask
    doc["_count"] = len(items)
    doc["unmatched_keys"] = sorted(items.values(), key=lambda x: str(x.get("enc_key", "")))

    try:
        _atomic_write_json(path, doc)
    except Exception as e:
        if log:
            log(f"[-] 另存未匹配串失败：{e}")
        return {"path": path, "total": len(items), "added": 0, "error": str(e)}
    if log:
        log(f"[+] 未匹配串已另存：{path}（文件累计 {len(items)} 条，本次新增 {added} 条）")
    return {"path": path, "total": len(items), "added": added}


# =====================================================================
# 四、把两个动作串起来（给 info / bias 调用）
# =====================================================================
def sync_from_memory_report(rep, keys_file=None, extra_file=None, wx_root=None,
                            page1_map=None, write_back=True, save_extra=True, log=print):
    """内存扫描结束后调用：①回写密钥文件 ②另存未匹配串。异常只提示，不影响主流程。"""
    out = {"keys_file": None, "extra_file": None}
    if not isinstance(rep, dict):
        return out
    try:
        mem_keys = rep.get("keys") or {}
        if write_back and mem_keys:
            out["keys_file"] = update_keys_file(mem_keys, keys_file=keys_file,
                                                page1_map=page1_map, wx_root=wx_root, log=log)
        unmatched = rep.get("unmatched") or {}
        if save_extra and unmatched:
            out["extra_file"] = save_unmatched_keys(unmatched, extra_file=extra_file,
                                                   mask=rep.get("mask"), log=log)
    except Exception as e:
        if log:
            log(f"[-] 密钥落盘步骤异常（不影响本次输出）：{e}")
    return out


def print_key_store_report(ks, log=print):
    """把 sync_from_memory_report 的结果打印成两三行摘要"""
    if not ks or not log:
        return
    kr = ks.get("keys_file")
    if kr:
        if kr.get("changed"):
            extra = ""
            if kr.get("salt_fixed"):
                extra += f"，修正 salt {len(kr['salt_fixed'])}"
            if kr.get("protected"):
                extra += f"，保护其它账号条目 {len(kr['protected'])}"
            log(f"[+] 密钥文件已更新：{kr['path']}"
                f"（更新 {len(kr.get('updated') or [])} / 新增 {len(kr.get('added') or [])}{extra}）")
        elif kr.get("skipped"):
            log(f"[*] 密钥文件未改动：{kr['path']}（跳过 {len(kr['skipped'])} 条）")
    er = ks.get("extra_file")
    if er and not er.get("error"):
        log(f"[*] 未匹配串文件：{er['path']}（累计 {er.get('total')} 条）")


# =====================================================================
# 五、自测：不碰内存，只用合成数据验证"回写/另存"逻辑本身
# =====================================================================
def selftest():
    """在临时目录里造一份假密钥文件 + 假第 1 页，验证：更新 / 新增 / 不变 / 拒绝写入 四种分支"""
    import tempfile
    ok = []
    tmpdir = tempfile.mkdtemp(prefix="wx4keystore_")
    kf = os.path.join(tmpdir, "all_keys.json")
    ef = os.path.join(tmpdir, "extra_mem_keys.json")

    from .get_bias_addr import BiasAddr
    b = BiasAddr("", "", "", "", None)

    # 造一个"真"密钥和它的第 1 页：必须是【本机真实账号目录里的库】+ 密钥文件里对应的那条，
    # 并且先验一遍 HMAC，确保这组样本本身是有效的（否则后面四个分支都会"看起来失败"）
    keys_file = _keys_file_default()
    real = {}
    try:
        with open(keys_file, "r", encoding="utf-8") as f:
            real = json.load(f)
    except Exception:
        real = {}
    pick = None
    if os.path.isdir(DEFAULT_WX_ROOT):
        for acct in sorted(os.listdir(DEFAULT_WX_ROOT)):
            for db, v in (real.items() if isinstance(real, dict) else []):
                if not (isinstance(v, dict) and v.get("enc_key")):
                    continue
                p = os.path.join(DEFAULT_WX_ROOT, acct, "db_storage", str(db))
                if not os.path.isfile(p):
                    continue
                p1 = BiasAddr._read_page1(p)
                if not p1:
                    continue
                try:
                    if b.verify_page1_hmac_4x(bytes.fromhex(v["enc_key"]), p1):
                        pick = (acct + "\\" + str(db), str(db), v["enc_key"], p1)
                        break
                except Exception:
                    continue
            if pick:
                break
    if not pick:
        return "[!] 自测跳过：本机找不到可用的真库 + 密钥样本"

    acct_rel, db_rel, key_real, page1 = pick
    page1_map = {acct_rel: page1}
    fake_old = "0" * 64

    def _write(obj):
        with open(kf, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    # 分支 1：密钥不同 -> 更新
    _write({db_rel: {"enc_key": fake_old, "salt": page1[:16].hex(), "size_mb": 1.0}})
    r1 = update_keys_file({acct_rel: key_real}, keys_file=kf, page1_map=page1_map, log=None)
    with open(kf, "r", encoding="utf-8") as f:
        after1 = json.load(f)
    ok.append(("更新分支", r1["changed"] and after1[db_rel]["enc_key"] == key_real
               and after1[db_rel].get("prev_enc_key") == fake_old and bool(r1.get("backup"))))

    # 分支 2：密钥一致 -> 不动、不备份
    r2 = update_keys_file({acct_rel: key_real}, keys_file=kf, page1_map=page1_map, log=None)
    ok.append(("一致分支", (not r2["changed"]) and len(r2["unchanged"]) == 1 and not r2.get("backup")))

    # 分支 3：HMAC 不通过的密钥 -> 拒绝写入
    _write({db_rel: {"enc_key": fake_old, "salt": page1[:16].hex()}})
    r3 = update_keys_file({acct_rel: "1" * 64}, keys_file=kf, page1_map=page1_map, log=None)
    with open(kf, "r", encoding="utf-8") as f:
        after3 = json.load(f)
    ok.append(("拒写分支", (not r3["changed"]) and after3[db_rel]["enc_key"] == fake_old
               and r3["skipped"]))

    # 分支 4：未匹配串另存 + 合并去重（第 1 条是 aaaa…，occurrences 被第二次调用刷成 5）
    r4a = save_unmatched_keys({("a" * 64, "b" * 32): 2}, extra_file=ef, mask="c" * 64, log=None)
    r4b = save_unmatched_keys({("a" * 64, "b" * 32): 5, ("d" * 64, "e" * 32): 1},
                              extra_file=ef, mask="c" * 64, log=None)
    with open(ef, "r", encoding="utf-8") as f:
        doc4 = json.load(f)
    first = doc4["unmatched_keys"][0]
    ok.append(("另存分支", r4a["total"] == 1 and r4b["total"] == 2 and r4b["added"] == 1
               and doc4["_count"] == 2 and doc4["_mask"] == "c" * 64
               and first["enc_key"] == "a" * 64 and first["occurrences"] == 5))

    # 分支 5：密钥一致但 salt 是别的账号的 -> 只修 salt，不动 key
    _write({db_rel: {"enc_key": key_real, "salt": "f" * 32}})
    r5 = update_keys_file({acct_rel: key_real}, keys_file=kf, page1_map=page1_map, log=None)
    with open(kf, "r", encoding="utf-8") as f:
        after5 = json.load(f)
    ok.append(("salt 修正分支", r5["changed"] and len(r5["salt_fixed"]) == 1
               and after5[db_rel]["enc_key"] == key_real
               and after5[db_rel]["salt"] == page1[:16].hex()))

    # 分支 6：文件里那条属于【别的账号】-> 不覆盖，改为新增账号限定条目
    other = None
    for acct in sorted(os.listdir(DEFAULT_WX_ROOT)):
        if acct == acct_rel.split("\\")[0]:
            continue
        p = os.path.join(DEFAULT_WX_ROOT, acct, "db_storage", db_rel)
        if os.path.isfile(p):
            p1o = BiasAddr._read_page1(p)
            if p1o and p1o[:16].hex() != page1[:16].hex():
                other = (acct, p1o)
                break
    if other:
        _write({db_rel: {"enc_key": fake_old, "salt": other[1][:16].hex()}})
        r6 = update_keys_file({acct_rel: key_real}, keys_file=kf,
                              page1_map={acct_rel: page1, other[0] + "\\" + db_rel: other[1]}, log=None)
        with open(kf, "r", encoding="utf-8") as f:
            after6 = json.load(f)
        ok.append(("跨账号保护分支", (not r6["protected"]) is False
                   and after6[db_rel]["enc_key"] == fake_old               # 别的账号那条没被覆盖
                   and after6[acct_rel]["enc_key"] == key_real))           # 本账号写成限定条目
    else:
        ok.append(("跨账号保护分支（本机无第二个同路径样本，跳过）", True))

    shutil.rmtree(tmpdir, ignore_errors=True)
    lines = [f"    {name}：{'通过' if v else '失败'}" for name, v in ok]
    allok = all(v for _n, v in ok)
    return ("[+] 密钥落盘自测通过（%d/%d）\n" % (sum(1 for _n, v in ok if v), len(ok))
            if allok else "[!] 密钥落盘自测存在失败项\n") + "\n".join(lines)


if __name__ == "__main__":
    print(selftest())
