# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         __init__.py.py
# Description:  
# Author:       xaoyaoo
# Date:         2023/10/14
# -------------------------------------------------------------------------------
# 【4.0】本地适配版：在原版 3.1.46 基础上改造，新增对微信 4.x（实测 4.1.15.13）的支持：
#   · info / bias 默认自动识别微信代次；4.x 直接走只读内存取密钥（不注入 / 不 Hook / 不改微信文件）
#   · 数据库连接层动态表名（Msg_<hash>）、zstd 解压、4.x XML 解析、Name2Id 反查 IsSender
#   · ui / api 启动即自动完成「读密钥 → 解密 → 加载会话」
__version__ = "4.0.0"
__version_note__ = "wx4-adapted"      # 与上游 PyWxDump 3.x 不是同一条版本线

import os, json

try:
    WX_OFFS_PATH = os.path.join(os.path.dirname(__file__), "WX_OFFS.json")
    with open(WX_OFFS_PATH, "r", encoding="utf-8") as f:
        WX_OFFS = json.load(f)
except:
    WX_OFFS = {}
    WX_OFFS_PATH = None

from .wx_core import BiasAddr, get_wx_info, get_wx_db, batch_decrypt, decrypt, get_core_db
from .wx_core import get_wx_info_from_db
from .wx_core import merge_db, decrypt_merge, merge_real_time_db, all_merge_real_time_db
from .db import DBHandler, MsgHandler, MicroHandler, MediaHandler, OpenIMContactHandler, FavoriteHandler, \
    PublicMsgHandler
from .api import start_server, gen_fastapi_app
from .api.export import export_html, export_csv, export_json

# PYWXDUMP_ROOT_PATH = os.path.dirname(__file__)
# db_init = DBPool("DBPOOL_INIT")


__all__ = ["BiasAddr", "get_wx_info", "get_wx_db", "batch_decrypt", "decrypt", "get_core_db",
           "get_wx_info_from_db",
           "merge_db", "decrypt_merge", "merge_real_time_db", "all_merge_real_time_db",
           "DBHandler", "MsgHandler", "MicroHandler", "MediaHandler", "OpenIMContactHandler", "FavoriteHandler",
           "PublicMsgHandler", "start_server", "WX_OFFS", "WX_OFFS_PATH", "__version__"]
