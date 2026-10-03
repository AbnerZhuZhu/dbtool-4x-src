# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         local_server.py
# Description:  
# Author:       xaoyaoo
# Date:         2024/08/01
# -------------------------------------------------------------------------------
import os
import time
import shutil
import pythoncom

from pydantic import BaseModel
from fastapi import APIRouter, Body

from pywxdump import all_merge_real_time_db, get_wx_db
from pywxdump import get_wx_info, batch_decrypt, BiasAddr, merge_db, decrypt_merge

from .rjson import ReJson, RqJson
from .utils import error9999, ls_loger, random_str, gc

ls_api = APIRouter()


# ---------------- 【4.0】微信 4.x 环境判定 + 界面初始化自动兜底 ----------------
#   背景：4.x 没有 WeChatWin.dll，密钥/账号定位/解密库全归 wx_core.wx4_prepare.prepare_wx4 管。
#   而界面（DbInitComponent）点「确定」时调的是 /api/ls/init_key，那条路是 3.x 的
#   decrypt_merge（SQLCipher3 + 合并成 MSG 表），在 4.x 上必然失败，前端就会弹
#   {"code":2001,"body":"未获取到数据库路径"}。
#   所以这里：先判是不是 4.x 环境，是就走 4.x 自动流程；不是就原样走 3.x 老逻辑。


def _wx4_env():
    """
    是否处于微信 4.x 环境：
      1) 有 Weixin.exe 进程；或
      2) 磁盘上存在「含 db_storage 的 4.x 账号目录」（微信没开也能用已解密库）
    """
    try:
        import psutil
        for p in psutil.process_iter(["name"]):
            if str(p.info.get("name") or "").lower() == "weixin.exe":
                return True
    except Exception:
        pass
    try:
        from pywxdump.wx_core.wx4_prepare import find_account_dirs
        if find_account_dirs(None):
            return True
    except Exception:
        pass
    return False


def _s(v):
    """把请求参数里可能带引号/空白的字符串统一清洗一下（4.x 下前端可能传空串）"""
    return v.strip().strip("'").strip('"') if isinstance(v, str) else ""


def _wx4_apply_conf(wx4):
    """
    把 prepare_wx4 的结果写进 conf。
    与 api/__init__.py 里 start_server 的 4.x 分支保持完全一致，
    这样 /api/rs/*（会话列表、联系人、聊天记录）能直接按 conf 里的 last + db_config 取到库。
    """
    mid = wx4["my_wxid"] or "wxid_wx4"
    gc.set_conf(mid, "wxid", wx4["my_wxid"] or mid)
    gc.set_conf(mid, "my_wxid", wx4["my_wxid"] or mid)
    gc.set_conf(mid, "wx_path", wx4["wx_path"])
    gc.set_conf(mid, "key_file", wx4["key_file"])
    gc.set_conf(mid, "key", "")
    gc.set_conf(mid, "merge_path", wx4["primary_db"])
    gc.set_conf(mid, "db_config", {
        "key": mid,                 # 只作连接池缓存键，用 wxid 保证稳定
        "type": "sqlite",
        "path": wx4["primary_db"],
        "my_wxid": wx4["my_wxid"] or mid,
        "decrypted_dir": wx4["decrypted_dir"],   # side 库（contact/session/头像）在这
    })
    gc.set_conf(gc.at, "last", mid)
    return mid


def _wx4_auto_init(hint_wx_path="", hint_my_wxid=""):
    """
    【4.0】4.x 自动初始化：定位账号目录 → 复用/增量解密 → 写 conf。
    返回 (ok, rdata, msg)；rdata 结构跟 3.x init_key 成功时一致，前端不用改任何东西。
    界面传进来的 wx_path/my_wxid 只当"线索"，无效或为空时 prepare_wx4 会自动回落到
    默认 4.x 根目录（D:\\xwechat_files）并按密钥 HMAC 自己认账号。
    """
    try:
        from pywxdump.wx_core.wx4_prepare import prepare_wx4
    except Exception as e:
        return False, None, f"4.x 自动准备模块不可用：{e}"
    try:
        wx4 = prepare_wx4(wx_path=(hint_wx_path or None), my_wxid=(hint_my_wxid or None),
                          work_path=gc.work_path, log=print)
    except Exception as e:
        ls_loger.error(f"[-] 4.x 自动初始化异常：{e}", exc_info=True)
        return False, None, f"4.x 自动初始化异常：{e}"
    if not wx4.get("ok"):
        msg = wx4.get("msg") or "4.x 自动初始化失败"
        print(f"[-] 4.x 自动初始化未完成：{msg}")
        return False, None, msg
    mid = _wx4_apply_conf(wx4)
    print(f"[+] 4.x 自动初始化完成：wxid={mid}")
    print(f"    原始库目录：{wx4['db_storage']}")
    print(f"    解密库目录：{wx4['decrypted_dir']}")
    print(f"    主库      ：{wx4['primary_db']}")
    print(f"    {wx4['msg']}")
    rdata = {
        "merge_path": wx4["primary_db"],
        "wx_path": wx4["wx_path"],
        "key": "",
        "my_wxid": mid,
        "is_init": True,
    }
    return True, rdata, wx4.get("msg") or ""


# 以下为初始化相关 *******************************************************************************************************

@ls_api.post('/init_last_local_wxid')
@error9999
def init_last_local_wxid():
    """
    初始化，包括key
    :return:
    """
    local_wxid = gc.get_local_wxids()
    local_wxid.remove(gc.at)
    if local_wxid:
        return ReJson(0, {"local_wxids": local_wxid})
    return ReJson(0, {"local_wxids": []})


@ls_api.post('/init_last')
@error9999
def init_last(my_wxid: str = Body(..., embed=True)):
    """
    是否初始化
    :return:
    """
    my_wxid = my_wxid.strip().strip("'").strip('"') if isinstance(my_wxid, str) else ""
    ls_loger.info(f"[+] init_last: {my_wxid}")
    if not my_wxid:
        my_wxid = gc.get_conf(gc.at, "last")
        if not my_wxid: return ReJson(1001, body="my_wxid is required")
    if my_wxid:
        gc.set_conf(gc.at, "last", my_wxid)
        merge_path = gc.get_conf(my_wxid, "merge_path")
        wx_path = gc.get_conf(my_wxid, "wx_path")
        key = gc.get_conf(my_wxid, "key")
        rdata = {
            "merge_path": merge_path,
            "wx_path": wx_path,
            "key": key,
            "my_wxid": my_wxid,
            "is_init": True,
        }
        if merge_path and wx_path:
            return ReJson(0, rdata)
    return ReJson(0, {"is_init": False, "my_wxid": ""})


class InitKeyRequest(BaseModel):
    # 【4.0】字段给默认值：4.x 下界面上根本没东西可填，允许前端只发空串甚至空对象
    wx_path: str = ""
    key: str = ""
    my_wxid: str = ""


@ls_api.post('/init_key')
@error9999
def init_key(request: InitKeyRequest):
    """
    初始化key
    :param request:
    :return:
    """
    wx_path = _s(request.wx_path)
    key = _s(request.key)
    my_wxid = _s(request.my_wxid)

    # ---------------- 【4.0】4.x 分支：不需要任何手填项 ----------------
    #   微信 4.x：不跑 3.x 的 decrypt_merge（会返回 2001 未获取到数据库路径），
    #   改为「密钥文件/只读内存取密钥 → HMAC 认账号 → 复用或增量解密 → 写 conf」。
    if _wx4_env():
        ls_loger.info(f"[*] init_key：检测到微信 4.x（wx_path={wx_path!r}, my_wxid={my_wxid!r}）"
                      f"→ 走 4.x 自动初始化")
        print("[*] init_key：检测到微信 4.x，自动定位账号并复用/增量解密（无需手填路径与密钥）……")
        ok, rdata, msg = _wx4_auto_init(hint_wx_path=wx_path, hint_my_wxid=my_wxid)
        if ok:
            return ReJson(0, rdata)
        print(f"[-] init_key：4.x 自动初始化未成功（{msg}），回退 3.x 老流程")

    # ↓↓↓ 以下为 3.x 老逻辑，保持原样（4.x 自动初始化失败时也会落到这里，行为与改造前一致） ↓↓↓
    if not wx_path:
        return ReJson(1002, body=f"wx_path is required: {wx_path}")
    if not os.path.exists(wx_path):
        return ReJson(1001, body=f"wx_path not exists: {wx_path}")
    if not key:
        return ReJson(1002, body=f"key is required: {key}")
    if not my_wxid:
        return ReJson(1002, body=f"my_wxid is required: {my_wxid}")

    # db_config = get_conf(g.caf, my_wxid, "db_config")
    # if isinstance(db_config, dict) and db_config and os.path.exists(db_config.get("path")):
    #     pmsg = DBHandler(db_config)
    #     # pmsg.close_all_connection()

    out_path = os.path.join(gc.work_path, "decrypted", my_wxid) if my_wxid else os.path.join(gc.work_path, "decrypted")
    # 检查文件夹中文件是否被占用
    if os.path.exists(out_path):
        try:
            shutil.rmtree(out_path)
        except PermissionError as e:
            # 显示堆栈信息
            ls_loger.error(f"{e}", exc_info=True)
            return ReJson(2001, body=str(e))

    code, merge_save_path = decrypt_merge(wx_path=wx_path, key=key, outpath=str(out_path))
    time.sleep(1)
    if code:
        # 移动merge_save_path到g.work_path/my_wxid
        if not os.path.exists(os.path.join(gc.work_path, my_wxid)):
            os.makedirs(os.path.join(gc.work_path, my_wxid))
        merge_save_path_new = os.path.join(gc.work_path, my_wxid, "merge_all.db")
        shutil.move(merge_save_path, str(merge_save_path_new))

        # 删除out_path
        if os.path.exists(out_path):
            try:
                shutil.rmtree(out_path)
            except PermissionError as e:
                # 显示堆栈信息
                ls_loger.error(f"{e}", exc_info=True)
        db_config = {
            "key": random_str(16),
            "type": "sqlite",
            "path": merge_save_path_new
        }
        gc.set_conf(my_wxid, "db_config", db_config)
        gc.set_conf(my_wxid, "db_config", db_config)
        gc.set_conf(my_wxid, "merge_path", merge_save_path_new)
        gc.set_conf(my_wxid, "wx_path", wx_path)
        gc.set_conf(my_wxid, "key", key)
        gc.set_conf(my_wxid, "my_wxid", my_wxid)
        gc.set_conf(gc.at, "last", my_wxid)
        rdata = {
            "merge_path": merge_save_path_new,
            "wx_path": wx_path,
            "key": key,
            "my_wxid": my_wxid,
            "is_init": True,
        }
        return ReJson(0, rdata)
    else:
        return ReJson(2001, body=merge_save_path)


class InitNoKeyRequest(BaseModel):
    # 【4.0】同 init_key：4.x 下允许留空
    merge_path: str = ""
    wx_path: str = ""
    my_wxid: str = ""


@ls_api.post('/init_nokey')
@error9999
def init_nokey(request: InitNoKeyRequest):
    """
    初始化，包括key
    :return:
    """
    merge_path = _s(request.merge_path)
    wx_path = _s(request.wx_path)
    my_wxid = _s(request.my_wxid)

    # ---------------- 【4.0】4.x 分支：没给现成 merge_all.db 就自动准备 ----------------
    #   「不使用 KEY」这一页在 4.x 下同样没有 merge_all.db 可填，
    #   只要没给存在的合并库文件，就自动走 4.x 解密库；给了合并库则维持 3.x 老行为。
    if _wx4_env() and not (merge_path and os.path.exists(merge_path)):
        ls_loger.info("[*] init_nokey：检测到微信 4.x 且未提供现成 merge_all.db → 走 4.x 自动初始化")
        print("[*] init_nokey：检测到微信 4.x，自动定位账号并复用/增量解密（无需手填路径与密钥）……")
        ok, rdata, msg = _wx4_auto_init(hint_wx_path=wx_path, hint_my_wxid=my_wxid)
        if ok:
            return ReJson(0, rdata)
        print(f"[-] init_nokey：4.x 自动初始化未成功（{msg}），回退 3.x 老流程")

    # ↓↓↓ 以下为 3.x 老逻辑，保持原样 ↓↓↓
    if not wx_path:
        return ReJson(1002, body=f"wx_path is required: {wx_path}")
    if not os.path.exists(wx_path):
        return ReJson(1001, body=f"wx_path not exists: {wx_path}")
    if not merge_path:
        return ReJson(1002, body=f"merge_path is required: {merge_path}")
    if not my_wxid:
        return ReJson(1002, body=f"my_wxid is required: {my_wxid}")

    key = gc.get_conf(my_wxid, "key")
    db_config = {
        "key": random_str(16),
        "type": "sqlite",
        "path": merge_path
    }
    gc.set_conf(my_wxid, "db_config", db_config)
    gc.set_conf(my_wxid, "merge_path", merge_path)
    gc.set_conf(my_wxid, "wx_path", wx_path)
    gc.set_conf(my_wxid, "key", key)
    gc.set_conf(my_wxid, "my_wxid", my_wxid)
    gc.set_conf(gc.at, "last", my_wxid)
    rdata = {
        "merge_path": merge_path,
        "wx_path": wx_path,
        "key": "",
        "my_wxid": my_wxid,
        "is_init": True,
    }
    return ReJson(0, rdata)


# END 以上为初始化相关 ***************************************************************************************************


@ls_api.api_route('/realtimemsg', methods=["GET", "POST"])
@error9999
def get_real_time_msg():
    """
    获取实时消息 使用 merge_real_time_db()函数
    :return:
    """
    my_wxid = gc.get_conf(gc.at, "last")
    if not my_wxid: return ReJson(1001, body="my_wxid is required")
    merge_path = gc.get_conf(my_wxid, "merge_path")
    key = gc.get_conf(my_wxid, "key")
    wx_path = gc.get_conf(my_wxid, "wx_path")
    if not merge_path or not key or not wx_path:
        return ReJson(1002, body="msg_path or media_path or wx_path or key is required")

    real_time_exe_path = gc.get_conf(gc.at, "real_time_exe_path")

    code, ret = all_merge_real_time_db(key=key, wx_path=wx_path, merge_path=merge_path,
                                       real_time_exe_path=real_time_exe_path)
    if code:
        return ReJson(0, ret)
    else:
        return ReJson(2001, body=ret)


# start 这部分为专业工具的api *********************************************************************************************

@ls_api.api_route('/wxinfo', methods=["GET", 'POST'])
@error9999
def get_wxinfo():
    """
    获取微信信息
    :return:
    """
    import pythoncom
    from pywxdump import WX_OFFS
    pythoncom.CoInitialize()  # 初始化COM库

    # 4.x 兼容：进程名是 Weixin.exe，没有 WeChatWin.dll，内存偏移那套用不了。
    # 如果当前初始化时用的是「已解密数据库」，就把目录一起传下去，
    # 让 get_wx_info 在内存里找不到 3.x 微信时，自动改成从解密库里读（完全不读内存）。
    my_wxid = gc.get_conf(gc.at, "last") or ""
    decrypted_dir = None
    wx_path = None
    key_file = None
    if my_wxid:
        db_config = gc.get_conf(my_wxid, "db_config")
        wx_path = gc.get_conf(my_wxid, "wx_path")
        # 【4.x 改造 · 第三步】启动时自动准备写下的密钥文件，一并传给 get_wx_info，
        # 让 4.x 下的「微信信息」也能带出账号/密钥列表（3.x 时这里是 None，行为不变）。
        key_file = gc.get_conf(my_wxid, "key_file") or None
        if isinstance(db_config, dict):
            p = db_config.get("path") or ""
            if p and os.path.exists(p):
                decrypted_dir = os.path.dirname(p)

    wxinfos = get_wx_info(WX_OFFS, decrypted_dir=decrypted_dir,
                          my_wxid=my_wxid or None, wx_path=wx_path, key_file=key_file)
    pythoncom.CoUninitialize()  # 释放COM库
    return ReJson(0, wxinfos)


class BiasAddrRequest(BaseModel):
    mobile: str
    name: str
    account: str
    key: str = ""
    wxdbPath: str = ""


@ls_api.post('/biasaddr')
@error9999
def get_biasaddr(request: BiasAddrRequest):
    """
    BiasAddr
    :return:
    """
    mobile = request.mobile
    name = request.name
    account = request.account
    key = request.key
    wxdbPath = request.wxdbPath
    if not mobile or not name or not account:
        return ReJson(1002)
    pythoncom.CoInitialize()
    rdata = BiasAddr(account, mobile, name, key, wxdbPath).run()
    return ReJson(0, str(rdata))


@ls_api.api_route('/decrypt', methods=["GET", 'POST'])
@error9999
def get_decrypt(key: str, wxdbPath: str, outPath: str = ""):
    """
    解密
    :return:
    """
    if not outPath:
        outPath = gc.work_path
    wxinfos = batch_decrypt(key, wxdbPath, out_path=outPath)
    return ReJson(0, str(wxinfos))


class MergeRequest(BaseModel):
    dbPath: str
    outPath: str


@ls_api.post('/merge')
@error9999
def get_merge(request: MergeRequest):
    """
    合并
    :return:
    """
    wxdb_path = request.dbPath
    out_path = request.outPath
    db_path = get_wx_db(wxdb_path)
    # for i in db_path:print(i)
    rdata = merge_db(db_path, out_path)
    return ReJson(0, str(rdata))

# END 这部分为专业工具的api ***********************************************************************************************
