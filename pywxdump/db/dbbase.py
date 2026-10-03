# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         dbbase.py
# Description:
# Author:       xaoyaoo
# Date:         2024/04/15
# -------------------------------------------------------------------------------
# 【4.x 改造 · 第一步】新增微信 4.x 连接与表识别支持
#   · 4.x 消息库没有 MSG 表，而是 Msg_<md5(会话wxid)> 分表 + Name2Id 映射表
#   · 本文件负责：识别 4.x、索引所有 Msg_ 表、把逻辑表名 MSG 映射到物理分表、
#     并提供「把 4.x 行投影成 3.x MSG 列名」的 SQL 片段
#   · 一切新逻辑都以 self.is_wx4 为开关，3.x 路径完全不变
# -------------------------------------------------------------------------------
import hashlib
import importlib
import os
import sqlite3
import time

from .utils import db_loger
from dbutils.pooled_db import PooledDB


# import logging
#
# db_loger = logging.getLogger("db_prepare")


class DatabaseSingletonBase:
    # _singleton_instances = {}  # 使用字典存储不同db_path对应的单例实例
    _class_name = "DatabaseSingletonBase"
    _db_pool = {}  # 使用字典存储不同db_path对应的连接池

    # def __new__(cls, *args, **kwargs):
    #     if cls._class_name not in cls._singleton_instances:
    #         cls._singleton_instances[cls._class_name] = super().__new__(cls)
    #     return cls._singleton_instances[cls._class_name]

    @classmethod
    def connect(cls, db_config):
        """
        连接数据库，如果增加其他数据库连接，则重写该方法
        :param db_config: 数据库配置
        :return: 连接池
        """
        if not db_config:
            raise ValueError("db_config 不能为空")
        db_key = db_config.get("key", "xaoyaoo_741852963")
        db_type = db_config.get("type", "sqlite")
        if db_key in cls._db_pool and cls._db_pool[db_key] is not None:
            return cls._db_pool[db_key]

        if db_type == "sqlite":
            db_path = db_config.get("path", "")
            if not os.path.exists(db_path):
                raise FileNotFoundError(f"文件不存在: {db_path}")
            pool = PooledDB(
                creator=sqlite3,  # 使用 sqlite3 作为连接创建者
                maxconnections=0,  # 连接池最大连接数
                mincached=4,  # 初始化时，链接池中至少创建的空闲的链接，0表示不创建
                maxusage=1,  # 一个链接最多被重复使用的次数，None表示无限制
                blocking=True,  # 连接池中如果没有可用连接后，是否阻塞等待。True，等待；False，不等待然后报错
                ping=0,  # ping 数据库判断是否服务正常
                database=db_path
            )
        elif db_type == "mysql":
            mysql_config = {
                'user': db_config['user'],
                'host': db_config['host'],
                'password': db_config['password'],
                'database': db_config['database'],
                'port': db_config['port']
            }
            pool = PooledDB(
                creator=importlib.import_module('pymysql'),  # 使用 mysql 作为连接创建者
                ping=1,  # ping 数据库判断是否服务正常
                **mysql_config
            )
        else:
            raise ValueError(f"不支持的数据库类型: {db_type}")

        db_loger.info(f"{pool} 连接句柄创建 {db_config}")
        cls._db_pool[db_key] = pool
        return pool


class DatabaseBase(DatabaseSingletonBase):
    _class_name = "DatabaseBase"
    existed_tables = []

    # ==================================================================
    # 微信 4.x 相关常量
    # ==================================================================
    MSG_TABLE_PREFIX = "msg_"  # Msg_<md5(会话wxid)>；注意 existed_tables 已全部小写
    MSG_FILE_PREFIX = "message"  # 4.x 消息库文件名前缀：message_0..8_decrypted.db
    MSG_UNION_CHUNK = 200      # 单条 SQL 里 UNION ALL 的最大分支数（SQLite 默认上限 500，留余量）

    # 4.x 的【联系人 / 会话 / 头像】不在消息库里，而是各自独立的库文件；
    # 这里按文件名前缀自动识别（排除 *_fts / *_resource / merge_all 等辅助库）。
    WX4_CONTACT_FILE_PREFIX = "contact"
    WX4_SESSION_FILE_PREFIX = "session"
    WX4_HEADIMG_FILE_PREFIX = "head_image"
    WX4_MIN_PREFIX_LEN = 4  # 文件名前缀至少匹配这么长，避免把别的库误认成 side 库
    WX4_ATTACH_ALIAS = "wx4c"  # 跨库 JOIN 时 contact 库的 ATTACH 别名

    # 4.x 下这些「3.x 逻辑表名」是由 side 库（contact/session）承载的，
    # 让 tables_exist() 照常返回 True，上层 dbMicro.py 的守卫判断就不用改。
    WX4_CONTACT_TABLES = ("contact", "contactheadimgurl", "contactlabel")
    WX4_SESSION_TABLES = ("session", "chatinfo")
    WX4_CONTACT_SIDE_TABLES = ("chatroom", "chatroominfo")

    def __init__(self, db_config):
        r"""
        db_config = {
            "key": "test1",
            "type": "sqlite",
            "path": r"C:\***\wxdump_work\merge_all.db"
        }

        —— 微信 4.x 追加字段（都可选，不填则完全保持原来的 3.x 行为）——
        db_config = {
            "key": "test1",
            "type": "sqlite",
            # 4.x：这里指向「已解密的库目录」。当前默认位置是
            #       <启动目录>\wxdump_work\decrypted_wx4\<账号>\ （wxdump ui / api / info 自动解密后的输出）
            #       老脚本的历史位置 D:\decrypted_wx_db 仍兼容，但已不再写死——由代码自动定位。
            "path": r"<解密库目录>\message_0_decrypted.db",   # 主库（连接池用的那个）
            "msg_db_paths": [                                 # 4.x 其余消息库 message_1..8
                r"<解密库目录>\message_1_decrypted.db",
            ],
            "my_wxid": "wxid_xxxxxxxxxxxx"                 # 当前登录账号（DBHandler 会自动带上）
        }
        """
        self.config = db_config
        self.pool = self.connect(self.config)
        self.__get_existed_tables()
        self._init_wx4()

    # ------------------------------------------------------------------
    # 表探测
    # ------------------------------------------------------------------
    def __get_existed_tables(self):
        sql = "SELECT tbl_name FROM sqlite_master WHERE type = 'table' and tbl_name!='sqlite_sequence';"
        existing_tables = self.execute(sql)
        if existing_tables:
            self.raw_tables = [row[0] for row in existing_tables]  # 保留原始大小写
            self.existed_tables = [row[0].lower() for row in existing_tables]
            return self.existed_tables
        else:
            self.raw_tables = []
            return None

    def tables_exist(self, required_tables: str or list):
        """
        判断该类所需要的表是否存在
        Check if all required tables exist in the database.
        Args:
            required_tables (list or str): A list of table names or a single table name string.
        Returns:
            bool: True if all required tables exist, False otherwise.

        4.x 说明：4.x 消息库里没有 MSG 表，只有 Msg_<hash> 分表。
        这里把逻辑表名 "MSG" 视作「存在」，于是上层所有 tables_exist("MSG")
        的保护判断都不用改，真正的物理表名交给 msg_sources_for() 动态给出。
        """
        if isinstance(required_tables, str):
            required_tables = [required_tables]
        rbool = all(self._table_exists(table) for table in (required_tables or []))
        if not rbool:
            # 4.x 单个消息库有几百张 Msg_ 分表，把 existed_tables 整个打出来会让日志爆掉
            # （实测一个库 431 张表 × 每次缺表检查 = 每次几百 KB），这里只记数量和缺哪张表。
            if getattr(self, "is_wx4", False):
                db_loger.info(f"{required_tables=} 不存在（4.x，主库共 {len(self.existed_tables or [])} 张表）")
            else:
                db_loger.warning(f"{required_tables=}\n{self.existed_tables=}\n{rbool=}")
        return rbool

    def _table_exists(self, table):
        tl = str(table).lower()
        if tl in (self.existed_tables or []):
            return True
        # 4.x：MSG 由 Msg_<hash> 分表承载
        if not getattr(self, "is_wx4", False):
            return False
        if tl == "msg":
            return True
        # 4.x：Contact / Session / ChatRoom 这些逻辑表由 side 库承载
        if tl in self.WX4_CONTACT_TABLES or tl in self.WX4_CONTACT_SIDE_TABLES:
            return bool(getattr(self, "wx4_contact", ""))
        if tl in self.WX4_SESSION_TABLES:
            return bool(getattr(self, "wx4_session", ""))
        return False

    # ------------------------------------------------------------------
    # 微信 4.x：结构探测与消息库索引
    # ------------------------------------------------------------------
    @staticmethod
    def md5hex(s):
        """4.x 里 Msg_<hash> 的 hash = md5(会话 wxid)"""
        return hashlib.md5(str(s).encode("utf-8")).hexdigest()

    def get_my_wxid(self):
        """
        当前登录账号 wxid。
        DBHandler.__init__ 在 super().__init__() 之前就设好了 self.my_wxid，
        所以这里优先取实例属性，其次取 db_config["my_wxid"]。
        """
        my = getattr(self, "my_wxid", None)
        if not my and isinstance(self.config, dict):
            my = self.config.get("my_wxid")
        return my or ""

    def _init_wx4(self):
        """
        探测并索引微信 4.x 消息库。

        4.x 结构：
          · 没有 MSG 表，而是 Msg_<md5(会话wxid)> 分表（一个库几百上千张）
          · 一张 Name2Id 表：rowid -> wxid；消息里的 real_sender_id 就是它的 rowid
          · 【坑】同一个人在【不同库】里的 rowid 不一样，rowid=1 不一定是本人
                实测：message_0 里本人在 rowid=1，message_1..8 里本人在 rowid=2
                所以「本人 rowid」必须逐库用 Name2Id 反查，绝不能写死 1

        结果写入：
          self.is_wx4          : bool
          self.msg_files_info  : {库文件: {"name2id":{rowid:wxid}, "my_rowid":int|None, "tables":{小写:原名}}}
          self.msg_wxid_index  : {会话wxid: (库文件, 物理表名)}
          self.msg_all_tables  : [(库文件, 物理表名, 会话wxid)]
        """
        self.is_wx4 = False
        self.msg_files_info = {}
        self.msg_wxid_index = {}
        self.msg_all_tables = []
        # 4.x side 库（联系人 / 会话 / 头像），_init_wx4_side() 里填充
        self.wx4_contact = ""
        self.wx4_session = ""
        self.wx4_headimg = ""

        # 3.x：有 MSG 表就不走 4.x 分支
        if "msg" in (self.existed_tables or []):
            return

        cfg = self.config if isinstance(self.config, dict) else {}
        paths = []
        for p in [cfg.get("path")] + list(cfg.get("msg_db_paths") or []):
            if p and os.path.exists(p) and p not in paths:
                paths.append(p)
        if not paths:
            return

        # 只给了一个消息库（UI 里就是选单个文件）时，把同目录下其余 message_* 也一起带上。
        # 4.x 同一个会话的消息会被拆到多个库（实测 Katie 一个人就散在 8 个库里，共 20101 条），
        # 只读一个库会整段丢消息。
        if not cfg.get("msg_db_paths"):
            d = paths[0] if os.path.isdir(paths[0]) else os.path.dirname(paths[0])
            if d and os.path.isdir(d):
                for fn in sorted(os.listdir(d)):
                    low = fn.lower()
                    if not low.startswith(self.MSG_FILE_PREFIX):
                        continue
                    if any(x in low for x in ("fts", "resource", "merge", "wal", "shm", "journal")):
                        continue
                    fp = os.path.join(d, fn)
                    if os.path.isfile(fp) and fp not in paths:
                        paths.append(fp)
                if len(paths) > 1:
                    db_loger.info(f"4.x: 自动带上同目录消息库 {len(paths)} 个")

        found_any = False

        # 第一遍：把每个库的 Msg_ 分表和 Name2Id 都收上来
        for p in paths:
            try:
                con = self._extra_conn(p)
                tabs = [r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'")]
            except Exception as e:
                db_loger.warning(f"4.x: 打开消息库失败 {p}: {e}")
                continue
            tab_lower = {t.lower(): t for t in tabs}
            msg_raw = {k: v for k, v in tab_lower.items() if k.startswith(self.MSG_TABLE_PREFIX)}
            if not msg_raw:
                continue
            found_any = True

            # 本库的 Name2Id
            n2i = {}
            if "name2id" in tab_lower:
                try:
                    n2i = {r[0]: (r[1] or "") for r in con.execute(
                        "SELECT rowid, user_name FROM Name2Id")}
                except Exception as e:
                    db_loger.warning(f"4.x: 读取 {p} 的 Name2Id 失败: {e}")

            # 本库的「本人 rowid」——必须反查，不能假设 1
            my = self.get_my_wxid()
            my_rowid = None
            if my:
                for rid, uname in n2i.items():
                    if uname == my:
                        my_rowid = rid
                        break
                if my_rowid is None:
                    db_loger.warning(f"4.x: 本人 wxid {my!r} 不在 {os.path.basename(p)} 的 Name2Id 中，"
                                     f"该库 IsSender 会全判为 0")

            self.msg_files_info[p] = {"name2id": n2i, "my_rowid": my_rowid,
                                      "tables": msg_raw, "msg_tables": msg_raw}

        if not found_any:
            return

        # 第二遍：建「全局 wxid -> md5(表名后缀)」表
        # 注意：某个会话的 Msg_ 分表落在哪个库，和它的 wxid 记录在哪个库的 Name2Id 里，
        #      并不一定相同。只在单库内反查会漏掉大量会话（实测会漏 893 张表），
        #      所以必须用所有库 Name2Id 的并集来反查。
        global_md5 = {}
        for info in self.msg_files_info.values():
            for uname in info["name2id"].values():
                if uname:
                    global_md5[self.MSG_TABLE_PREFIX + self.md5hex(uname)] = uname

        # 第三遍：把每张 Msg_ 分表对应到会话 wxid
        # 【重要】同一个会话的表会同时存在于【多个消息库】里，而且每个库只存一部分消息：
        #   实测 Katie 一个会话被拆在 8 个库里，分别是
        #   19 + 297 + 1000 + 2388 + 808 + 2746 + 8584 + 4259 = 20101 条，
        #   正好等于微信客户端显示的该会话消息总数。
        #   所以必须把同一会话在所有库里的分片【全部】收集起来做 UNION，
        #   只取第一份会严重丢消息。
        for p in self.msg_files_info:
            tbls = self.msg_files_info[p]["msg_tables"]
            for tl in sorted(tbls):
                uname = global_md5.get(tl)
                if not uname:
                    continue
                self.msg_all_tables.append((p, tbls[tl], uname))
                self.msg_wxid_index.setdefault(uname, []).append((p, tbls[tl]))

        self.is_wx4 = True
        self._init_wx4_side()
        if not self.get_my_wxid():
            db_loger.warning("4.x: 未提供 my_wxid，无法判定 IsSender（请在 db_config 里加 my_wxid）")
        total_tables = sum(len(v["msg_tables"]) for v in self.msg_files_info.values())
        if len(self.msg_all_tables) < total_tables:
            db_loger.warning(f"4.x: {total_tables} 张 Msg_ 表里有 "
                             f"{total_tables - len(self.msg_all_tables)} 张无法反查到会话 wxid，已跳过")
        db_loger.info(
            f"4.x 消息库索引完成：{len(self.msg_files_info)} 个库 / "
            f"{total_tables} 张 Msg_ 分表 / 归并成 {len(self.msg_wxid_index)} 个会话")

    @staticmethod
    def _lenient_text(b):
        """
        宽松的 text_factory：把 TEXT 的原始字节按 utf-8 解，解不出的用 U+FFFD 替换。
        4.x 里 message_content 经常混着非 utf-8 的字节，
        如果沿用原来的「先 str 失败再整体切 bytes」做法，StrTalker/StrContent 会全变 bytes，
        后面 xml2dict 拿到 bytes 直接返回 None，整条链路就崩了。
        """
        if isinstance(b, (bytes, bytearray, memoryview)):
            return bytes(b).decode("utf-8", "replace")
        return b

    def _extra_conn(self, path):
        """4.x 的额外数据库文件连接（按路径缓存，不走连接池）"""
        if getattr(self, "_extra_conns", None) is None:
            self._extra_conns = {}
        con = self._extra_conns.get(path)
        if con is None:
            con = sqlite3.connect(path)
            con.text_factory = self._lenient_text
            self._extra_conns[path] = con
        return con

    def _exec_on(self, path, sql, params=None):
        """
        在指定库文件上执行 SQL。
        path=None 表示走主库连接池，否则用 _extra_conn 的独立连接。
        """
        if path is None:
            return self.execute(sql, params)
        con = self._extra_conn(path)
        try:
            cur = con.cursor()
            cur.execute(sql, params or ())
            return cur.fetchall()
        except Exception as e:
            db_loger.error(f"{path=}\n{sql=}\n{params=}\n{e=}\n", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # 微信 4.x：联系人 / 会话 / 头像 side 库的连接
    # ------------------------------------------------------------------
    def _init_wx4_side(self):
        """
        找出 4.x 的联系人库、会话库、头像库。

        3.x 里 Contact / Session / ChatRoom 全都在同一个 MicroMsg.db；
        4.x 把它们拆成了独立文件，所以要先定位这几个文件。

        查找顺序：
          1. db_config 显式指定：contact_db_path / session_db_path / head_img_db_path
          2. 在「主库 & 各消息库所在的目录」里按文件名前缀自动识别
             （也可用 db_config["decrypted_dir"] 指定要扫描的目录）
        """
        cfg = self.config if isinstance(self.config, dict) else {}
        self.wx4_contact = cfg.get("contact_db_path") or ""
        self.wx4_session = cfg.get("session_db_path") or ""
        self.wx4_headimg = cfg.get("head_img_db_path") or ""

        # 收集候选目录
        dirs = []
        for p in [cfg.get("path")] + list(cfg.get("msg_db_paths") or []):
            if not p:
                continue
            d = p if os.path.isdir(p) else os.path.dirname(p)
            if d and d not in dirs:
                dirs.append(d)
        dec_dir = cfg.get("decrypted_dir")
        if dec_dir and os.path.isdir(dec_dir) and dec_dir not in dirs:
            dirs.insert(0, dec_dir)
        if not dirs:
            return

        # 这些词出现在文件名里就排除，免得把 fts / 资源库 / 合并库误当成 side 库
        excludes = ("fts", "resource", "merge", "wal", "shm", "journal")

        def pick(prefix):
            for d in dirs:
                try:
                    names = sorted(os.listdir(d))
                except Exception:
                    continue
                for fn in names:
                    low = fn.lower()
                    if not low.endswith(".db") or any(x in low for x in excludes):
                        continue
                    if low.startswith(prefix) and len(prefix) >= self.WX4_MIN_PREFIX_LEN:
                        fp = os.path.join(d, fn)
                        if os.path.exists(fp):
                            return fp
            return ""

        if not self.wx4_contact or not os.path.exists(self.wx4_contact):
            self.wx4_contact = pick(self.WX4_CONTACT_FILE_PREFIX)
        if not self.wx4_session or not os.path.exists(self.wx4_session):
            self.wx4_session = pick(self.WX4_SESSION_FILE_PREFIX)
        if not self.wx4_headimg or not os.path.exists(self.wx4_headimg):
            self.wx4_headimg = pick(self.WX4_HEADIMG_FILE_PREFIX)

        db_loger.info(f"4.x side 库：contact={self.wx4_contact} session={self.wx4_session} "
                      f"head_image={self.wx4_headimg}")

    def wx4_side_path(self, role):
        """取 4.x side 库路径。role: contact / session / head_image"""
        return {"contact": self.wx4_contact, "session": self.wx4_session,
                "head_image": self.wx4_headimg}.get(role, "") or ""

    def _exec_contact(self, sql, params=None):
        """在 4.x 联系人库（contact_decrypted.db）上执行 SQL"""
        p = self.wx4_contact
        if not p or not os.path.exists(p):
            db_loger.warning(f"4.x: 联系人库不存在，无法执行 {sql}")
            return None
        return self._exec_on(p, sql, params)

    def _exec_session(self, sql, params=None):
        """在 4.x 会话库（session_decrypted.db）上执行 SQL"""
        p = self.wx4_session
        if not p or not os.path.exists(p):
            db_loger.warning(f"4.x: 会话库不存在，无法执行 {sql}")
            return None
        return self._exec_on(p, sql, params)

    def _exec_session_join_contact(self, sql, params=None):
        """
        3.x 的会话列表 SQL 是 Session JOIN Contact 一条语句；4.x 里这两张表在
        【两个不同的库文件】里。SQLite 用 ATTACH 就能让同一条 SQL 照跑，
        于是 dbMicro.get_session_list() 的字段顺序和 Python 侧解析完全不用改。
        """
        sess, cont = self.wx4_session, self.wx4_contact
        if not sess or not cont or not os.path.exists(sess) or not os.path.exists(cont):
            db_loger.warning("4.x: 会话库或联系人库缺失，无法执行跨库 JOIN")
            return None
        try:
            con = self._extra_conn(sess)
            attached = {row[1] for row in con.execute("PRAGMA database_list")}
            if self.WX4_ATTACH_ALIAS not in attached:
                con.execute(f"ATTACH DATABASE ? AS {self.WX4_ATTACH_ALIAS}", (cont,))
            cur = con.cursor()
            cur.execute(sql, params or ())
            return cur.fetchall()
        except Exception as e:
            db_loger.error(f"{sql=}\n{params=}\n{e=}\n", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # 微信 4.x：把 Msg_<hash> 投影成 3.x 的 MSG 列名
    # ------------------------------------------------------------------
    def wx4_projection(self, path, table, talker):
        """
        生成一段把 4.x 的 Msg_<hash> 投影成 3.x MSG 列名的 SELECT。

        IsSender 的判定（第一步的重点）：
          不能再用 real_sender_id == 1。
          正确做法是拿 real_sender_id 去本库 Name2Id 查出 wxid 再和本人比对；
          这里把它等价地写成 real_sender_id == 本人在【本库】Name2Id 里的 rowid。
        """
        info = self.msg_files_info.get(path) or {}
        my_rowid = info.get("my_rowid")
        if my_rowid is None:
            is_sender_sql = "0"
        else:
            is_sender_sql = f"CASE WHEN real_sender_id = {int(my_rowid)} THEN 1 ELSE 0 END"

        # 会话 wxid 是常量：这张表本身就等于 md5(该会话)
        talker_lit = str(talker).replace("'", "''")

        return (
            "SELECT "
            "local_id AS localId, "
            "real_sender_id AS TalkerId, "
            "server_id AS MsgSvrID, "
            "(local_type % 4294967296) AS Type, "
            "(local_type / 4294967296) AS SubType, "
            "create_time AS CreateTime, "
            f"{is_sender_sql} AS IsSender, "
            "sort_seq AS Sequence, "
            "0 AS StatusEx, 0 AS FlagEx, status AS Status, "
            "0 AS MsgSequence, "
            # 【第三步】4.x 的 message_content 有两种形态，由 WCDB_CT_message_content 决定：
            #   CT=0 -> 明文 TEXT（本机 364148 条）
            #   CT=4 -> zstd 压缩的 BLOB（本机 230616 条，magic 28 b5 2f fd）
            # 原来这里写的是 CAST(message_content AS TEXT)，会把 zstd 的二进制字节直接当成
            # 文本吐出来，解压前数据就已经被破坏了。所以这里必须原样取出，
            # 解压交给 Python 侧（dbMSG.wx4_decode_message_content）按 magic 处理。
            "message_content AS StrContent, "
            "server_seq AS MsgServerSeq, "
            f"'{talker_lit}' AS StrTalker, "
            "'' AS DisplayContent, "
            "0 AS Reserved0, 0 AS Reserved1, 0 AS Reserved3, "
            "0 AS Reserved4, 0 AS Reserved5, 0 AS Reserved6, "
            "compress_content AS CompressContent, "
            "packed_info_data AS BytesExtra, "
            "NULL AS BytesTrans, "
            "0 AS Reserved2, "
            # 【第三步】把 CT 一起投影出来（0=明文 / 4=zstd），
            # 上层 dbMSG.get_msg_list 才能把它一并 SELECT 出来决定要不要解压。
            # 注意必须放在这里（子查询内部），外层只能引用子查询已输出的列名。
            "WCDB_CT_message_content AS WCDB_CT "
            f"FROM '{table}'"
        )

    def msg_sources_for(self, wxids=None):
        """
        返回 [(库文件路径, 可直接 FROM 的数据源), ...]，用来替换原来死板的 FROM MSG。

        3.x -> [(None, "MSG")]
        4.x -> 按库文件分组，每组一个 "(SELECT ... UNION ALL SELECT ...)" 子查询；
               wxids 为空表示全部会话（会遍历所有 Msg_ 表）。
               注意 SQLite 的复合 SELECT 分支上限默认 500，所以每 200 张表
               先合并成一段，再把这几段 UNION ALL 起来（两层，不超限）。
        """
        if not getattr(self, "is_wx4", False):
            return [(None, "MSG")]

        if wxids:
            items = []
            for w in wxids:
                for path, table in (self.msg_wxid_index.get(w) or []):
                    items.append((path, table, w))
        else:
            items = list(self.msg_all_tables)

        by_file = {}
        for path, table, talker in items:
            by_file.setdefault(path, []).append((table, talker))

        # 每 MSG_UNION_CHUNK 张分表拼成一个独立的子查询源。
        # 【坑】千万不要把多个分块再 UNION ALL 成一条语句：
        #   SQLite 会把括号内的复合 SELECT 拍平，总项数超过 SQLITE_MAX_COMPOUND_SELECT(默认 500)
        #   就报 "too many terms in compound SELECT"，整个库的数据全丢。
        #   所以这里拆成「多个小数据源」，由调用方在 Python 侧合并。
        sources = []
        for path, lst in by_file.items():
            for i in range(0, len(lst), self.MSG_UNION_CHUNK):
                chunk = lst[i:i + self.MSG_UNION_CHUNK]
                src = "(" + " UNION ALL ".join(
                    self.wx4_projection(path, t, w) for t, w in chunk) + ")"
                sources.append((path, src))
        return sources

    def msg_table_for(self, wxid):
        """
        给定会话 wxid，返回它在 4.x 下的第一个 (库文件路径, 物理表名)；
        3.x 恒为 (None, "MSG")；(None, None) 表示该会话没有消息表。

        注意：一个会话的消息可能分散在多个库的多张分表里，
        完整列表用 msg_tables_for()，查询请用 msg_sources_for()。
        """
        if not getattr(self, "is_wx4", False):
            return None, "MSG"
        lst = self.msg_wxid_index.get(wxid) or []
        if lst:
            return lst[0]
        return None, None

    def msg_tables_for(self, wxid):
        """给定会话 wxid，返回它在 4.x 下的全部分片 [(库文件, 物理表名), ...]"""
        if not getattr(self, "is_wx4", False):
            return [(None, "MSG")]
        return list(self.msg_wxid_index.get(wxid) or [])

    def wx4_sender_wxid(self, talker, real_sender_id):
        """
        4.x：把某条消息的 real_sender_id 解析成发送者 wxid。
        各库的 Name2Id 是独立的（同一个人在不同库里 rowid 不同），
        所以按该会话分片所在库逐个尝试解析。
        """
        if not getattr(self, "is_wx4", False) or real_sender_id is None:
            return None
        for path, _tbl in (self.msg_wxid_index.get(talker) or []):
            info = self.msg_files_info.get(path) or {}
            sw = (info.get("name2id") or {}).get(real_sender_id)
            if sw:
                return sw
        return None

    def wx4_known_ids(self):
        """
        本套解密库里出现过的所有账号 id（各消息库 Name2Id 的并集）。

        【第三步】用来判断消息正文最前面那一段「xxx:\n」到底是不是发送者账号：
        4.x 的群聊正文会把发送者（有时是群 id 本身，例如系统消息）拼在正文前面，
        剥掉它才能让后面的 XML 正常解析。只看「像不像 wxid_」不够严谨，
        用全库账号集合来判断更可靠。结果缓存，避免每条消息都重算。
        """
        if not getattr(self, "is_wx4", False):
            return set()
        cached = getattr(self, "_wx4_known_ids_cache", None)
        if cached is None:
            cached = set()
            for info in (self.msg_files_info or {}).values():
                cached.update(v for v in (info.get("name2id") or {}).values() if v)
            self._wx4_known_ids_cache = cached
        return cached

    # ------------------------------------------------------------------
    # 通用执行
    # ------------------------------------------------------------------
    def execute(self, sql, params=None):
        """
        执行SQL语句
        :param sql: SQL语句 (str)
        :param params: 参数 (tuple)
        :return: 查询结果 (list)
        """
        connection = self.pool.connection()
        try:
            # connection.text_factory = bytes
            cursor = connection.cursor()
            if params:
                cursor.execute(sql, params)
            else:
                cursor.execute(sql)
            return cursor.fetchall()
        except Exception as e1:
            try:
                connection.text_factory = bytes
                cursor = connection.cursor()
                if params:
                    cursor.execute(sql, params)
                else:
                    cursor.execute(sql)
                rdata = cursor.fetchall()
                connection.text_factory = str
                return rdata
            except Exception as e2:
                db_loger.error(f"{sql=}\n{params=}\n{e1=}\n{e2=}\n", exc_info=True)
                return None
        finally:
            connection.close()

    def close(self):
        for con in (getattr(self, "_extra_conns", None) or {}).values():
            try:
                con.close()
            except Exception:
                pass
        self._extra_conns = {}
        self.pool.close()
        db_loger.info(f"关闭数据库 - {self.config}")

    def __del__(self):
        self.close()
