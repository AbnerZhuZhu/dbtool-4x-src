# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         MSG.py
# Description:  负责处理消息数据库数据
# Author:       xaoyaoo
# Date:         2024/04/15
# -------------------------------------------------------------------------------
import json
import os
import re
import lz4.block
import blackboxprotobuf

try:
    # 【第三步】微信 4.x 的消息正文用 zstd 压缩（WCDB_CT_message_content == 4），
    # 3.x 用不到这个库，所以做成可选依赖，装不上也不能影响老版本使用。
    import zstandard
except Exception:  # pragma: no cover
    zstandard = None

from .dbbase import DatabaseBase
from .utils import db_error, timestamp2str, xml2dict, match_BytesExtra, type_converter, db_loger


class MsgHandler(DatabaseBase):
    _class_name = "MSG"
    MSG_required_tables = ["MSG"]

    def Msg_add_index(self):
        """
        添加索引,加快查询速度
        """
        # 检查是否存在索引
        if not self.tables_exist("MSG"):
            return
        if getattr(self, "is_wx4", False):
            # 4.x 是 Msg_<hash> 分表（本机 9 个库共 2417 张），逐表建索引代价太高，
            # 而且每次启动都会跑一遍，这里直接跳过。单会话查询只扫一张小表，速度可接受。
            db_loger.info("4.x：跳过 MSG 索引创建（Msg_<hash> 分表不做全量建索引）")
            return
        self.execute("CREATE INDEX IF NOT EXISTS idx_MSG_StrTalker ON MSG(StrTalker);")
        self.execute("CREATE INDEX IF NOT EXISTS idx_MSG_CreateTime ON MSG(CreateTime);")
        self.execute("CREATE INDEX IF NOT EXISTS idx_MSG_StrTalker_CreateTime ON MSG(StrTalker, CreateTime);")

    @db_error
    def get_m_msg_count(self, wxids: list = ""):
        """
        获取聊天记录数量,根据wxid获取单个联系人的聊天记录数量，不传wxid则获取所有联系人的聊天记录数量
        :param wxids: wxid list
        :return: 聊天记录数量列表 {wxid: chat_count, total: total_count}
        """
        if not self.tables_exist("MSG"):
            return {}
        if isinstance(wxids, str) and wxids:
            wxids = [wxids]
        wxids = list(wxids or [])

        # 【4.x 改造】原来是死板的 "FROM MSG"，现在换成动态数据源：
        #   3.x -> "MSG"
        #   4.x -> "(SELECT ... FROM 'Msg_xxx' UNION ALL ...)"，按库文件分组
        counts = {}
        for path, src in self.msg_sources_for(wxids):
            if wxids:
                sql = (f"SELECT StrTalker, COUNT(*) FROM {src} "
                       f"WHERE StrTalker IN ({', '.join('?' for _ in wxids)}) "
                       f"GROUP BY StrTalker ORDER BY COUNT(*) DESC;")
                rows = self._exec_on(path, sql, tuple(wxids))
            else:
                sql = f"SELECT StrTalker, COUNT(*) FROM {src} GROUP BY StrTalker ORDER BY COUNT(*) DESC;"
                rows = self._exec_on(path, sql)
            for k, v in (rows or []):
                counts[k] = counts.get(k, 0) + v

        if not counts:
            return {}

        # total 语义与原来保持一致：全库消息总数（不受 wxids 过滤影响）
        if wxids:
            total = 0
            for path, src in self.msg_sources_for([]):
                r = self._exec_on(path, f"SELECT COUNT(*) FROM {src};")
                if r:
                    total += r[0][0] or 0
        else:
            total = sum(counts.values())

        msg_count = {"total": total}
        msg_count.update(counts)
        return msg_count

    @db_error
    def get_msg_list(self, wxids: list or str = "", start_index=0, page_size=500, msg_type: str = "",
                     msg_sub_type: str = "", start_createtime=None, end_createtime=None, my_talker="我"):
        """
        获取聊天记录列表
        :param wxids: [wxid]
        :param start_index: 起始索引
        :param page_size: 页大小
        :param msg_type: 消息类型
        :param msg_sub_type: 消息子类型
        :param start_createtime: 开始时间
        :param end_createtime: 结束时间
        :param my_talker: 我
        :return: 聊天记录列表 {"id": _id, "MsgSvrID": str(MsgSvrID), "type_name": type_name, "is_sender": IsSender,
                    "talker": talker, "room_name": StrTalker, "msg": msg, "src": src, "extra": {},
                    "CreateTime": CreateTime, }
        """
        if not self.tables_exist("MSG"):
            return [], []

        if isinstance(wxids, str) and wxids:
            wxids = [wxids]
        wxids = list(wxids or [])
        param = ()
        sql_wxid, param = (f"AND StrTalker in ({', '.join('?' for _ in wxids)}) ",
                           param + tuple(wxids)) if wxids else ("", param)
        # 【4.x】Type / SubType 在 4.x 里是由 local_type 算出来的表达式列，不携带列亲和性，
        # 传进来的字符串参数不会被 SQLite 自动转成整数，会把过滤结果全部滤空。
        # 3.x 的 Type 是真实 INTEGER 列，本来就能吃字符串，所以这里统一转成数字对两边都安全。
        def _to_num(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return v

        sql_type, param = ("AND Type=? ", param + (_to_num(msg_type),)) if msg_type else ("", param)
        sql_sub_type, param = ("AND SubType=? ", param + (_to_num(msg_sub_type),)) if msg_type and msg_sub_type else (
            "", param)
        sql_start_createtime, param = ("AND CreateTime>=? ", param + (start_createtime,)) if start_createtime else (
            "", param)
        sql_end_createtime, param = ("AND CreateTime<=? ", param + (end_createtime,)) if end_createtime else ("", param)

        # 【第三步】4.x 的正文有两种形态，靠 WCDB_CT_message_content 区分：
        #   CT=0 -> 明文 TEXT；CT=4 -> zstd 压缩的 BLOB
        # 所以 4.x 要多取一列 CT（由 dbbase.wx4_projection 投影成 WCDB_CT），
        # 才能决定要不要解压；3.x 没有这一列，列数与顺序保持原样。
        extra_col = "WCDB_CT, " if getattr(self, "is_wx4", False) else ""
        sel_cols = (
            "SELECT localId,TalkerId,MsgSvrID,Type,SubType,CreateTime,IsSender,Sequence,StatusEx,FlagEx,Status,"
            "MsgSequence,StrContent,MsgServerSeq,StrTalker,DisplayContent,Reserved0,Reserved1,Reserved3,"
            "Reserved4,Reserved5,Reserved6,CompressContent,BytesExtra,BytesTrans,Reserved2,"
            + extra_col
        )
        n_biz = 27 if extra_col else 26  # 业务列数量（不含结尾的 id 列）
        sql_where = (f"WHERE 1=1 "
                     f"{sql_wxid}"
                     f"{sql_type}"
                     f"{sql_sub_type}"
                     f"{sql_start_createtime}"
                     f"{sql_end_createtime}")

        # 【4.x 改造】数据源由 msg_sources_for() 动态给出，不再写死 MSG
        sources = self.msg_sources_for(wxids)
        if len(sources) == 1:
            # 单数据源（3.x，或 4.x 已指定会话）：分页仍交给 SQL 做，行为与原来完全一致
            path, src = sources[0]
            sql = (sel_cols + "ROW_NUMBER() OVER (ORDER BY CreateTime ASC) AS id "
                   f"FROM {src} {sql_where}"
                   "ORDER BY CreateTime ASC LIMIT ?,?")
            result = self._exec_on(path, sql, param + (start_index, page_size))
        else:
            # 多数据源（4.x 未指定会话，或会话分布在多个库）：
            # 各源分别取回后在 Python 里合并排序再分页。
            # 每个源只需要取「前 start_index + page_size 条」：
            # 按同一排序键，能进入全局窗口的行一定排在自己那一段的这个范围内。
            per_source_limit = start_index + page_size
            rows = []
            for path, src in sources:
                sql = (sel_cols + "0 AS id "
                       f"FROM {src} {sql_where}"
                       "ORDER BY CreateTime ASC, localId ASC LIMIT ?")
                r = self._exec_on(path, sql, param + (per_source_limit,))
                if r:
                    rows.extend(r)
            # 先按时间、再按 localId 排序，保证翻页稳定
            rows.sort(key=lambda x: ((x[5] or 0), (x[0] or 0)))
            rows = rows[start_index:start_index + page_size]
            # 重新编号 id，保持与单源一致的全局序号语义（首条 = start_index + 1）
            result = [tuple(list(r[:n_biz]) + [start_index + i + 1]) for i, r in enumerate(rows)]

        if not result:
            return [], []

        result_data = (self.get_msg_detail(row, my_talker=my_talker) for row in result)
        rdata = [d for d in result_data if d]  # 转为列表（个别解析失败的脏数据跳过，不拖垮整页）
        wxid_list = {d['talker'] for d in rdata}  # 创建一个无重复的 wxid 列表
        return rdata, list(wxid_list)

    @db_error
    def get_date_count(self, wxid='', start_time: int = 0, end_time: int = 0, time_format='%Y-%m-%d'):
        """
        获取每日聊天记录数量，包括发送者数量、接收者数量和总数。
        """
        if not self.tables_exist("MSG"):
            return {}
        if isinstance(start_time, str) and start_time.isdigit():
            start_time = int(start_time)
        if isinstance(end_time, str) and end_time.isdigit():
            end_time = int(end_time)

        # if start_time or end_time is not an integer and not a float, set both to 0
        if not (isinstance(start_time, (int, float)) and isinstance(end_time, (int, float))):
            start_time = 0
            end_time = 0
        params = ()

        sql_wxid = "AND StrTalker = ? " if wxid else ""
        params = params + (wxid,) if wxid else params

        sql_time = "AND CreateTime BETWEEN ? AND ? " if start_time and end_time else ""
        params = params + (start_time, end_time) if start_time and end_time else params

        sql = (f"SELECT strftime('{time_format}', CreateTime, 'unixepoch', 'localtime') AS date, "
               "       COUNT(*) AS total_count ,"
               "       SUM(CASE WHEN IsSender = 1 THEN 1 ELSE 0 END) AS sender_count, "
               "       SUM(CASE WHEN IsSender = 0 THEN 1 ELSE 0 END) AS receiver_count "
               "FROM {src_} "
               "WHERE StrTalker NOT LIKE '%chatroom%' "
               f"{sql_wxid} {sql_time} "
               f"GROUP BY date ORDER BY date ASC;")

        # 【4.x 改造】数据源按库拆分，各自 GROUP BY 后再在 Python 侧合并
        result_dict = {}
        for path, src in self.msg_sources_for([wxid] if wxid else []):
            rows = self._exec_on(path, sql.format(src_=src), params)
            for row in (rows or []):
                date, total_count, sender_count, receiver_count = row
                item = result_dict.setdefault(date, {"sender_count": 0, "receiver_count": 0, "total_count": 0})
                item["sender_count"] += sender_count or 0
                item["receiver_count"] += receiver_count or 0
                item["total_count"] += total_count or 0
        return dict(sorted(result_dict.items()))

    @db_error
    def get_date_range(self, wxid=''):
        """
        【4.0 热力图自适应】返回消息的时间跨度与逐年条数。

        与 get_date_count 共用同一套数据源（msg_sources_for，3.x/4.x 自动分流），
        但只做 MIN/MAX/COUNT 聚合，返回：
            {min_ts, max_ts, min_date, max_date, min_year, max_year, span_years, total, per_year}
        其中 min_ts/max_ts 是原始时间戳（MIN/MAX(CreateTime)），min_date/max_date 是 'YYYY-MM-DD'。
        前端据此决定日历要渲染哪些年份，避免跨度大时被截断。
        """
        if not self.tables_exist("MSG"):
            return {}
        sql_wxid = "AND StrTalker = ? " if wxid else ""
        params = (wxid,) if wxid else ()
        span_sql = ("SELECT MIN(CreateTime), MAX(CreateTime), COUNT(*) FROM {src_} "
                    "WHERE StrTalker NOT LIKE '%chatroom%' " + sql_wxid)
        year_sql = ("SELECT strftime('%Y', CreateTime, 'unixepoch', 'localtime') AS y, COUNT(*) "
                    "FROM {src_} WHERE StrTalker NOT LIKE '%chatroom%' " + sql_wxid + " GROUP BY y")
        min_ts = max_ts = None
        total = 0
        per_year = {}
        for path, src in self.msg_sources_for([wxid] if wxid else []):
            for row in (self._exec_on(path, span_sql.format(src_=src), params) or []):
                if row and row[0] is not None:
                    min_ts = row[0] if min_ts is None else min(min_ts, row[0])
                    max_ts = row[1] if max_ts is None else max(max_ts, row[1])
                    total += row[2] or 0
            for row in (self._exec_on(path, year_sql.format(src_=src), params) or []):
                if row and row[0]:
                    per_year[row[0]] = per_year.get(row[0], 0) + (row[1] or 0)
        if min_ts is None:
            return {}
        min_date = timestamp2str(min_ts)[:10]
        max_date = timestamp2str(max_ts)[:10]
        return {
            "min_ts": int(min_ts),
            "max_ts": int(max_ts),
            "min_date": min_date,
            "max_date": max_date,
            "min_year": int(min_date[:4]),
            "max_year": int(max_date[:4]),
            "span_years": int(max_date[:4]) - int(min_date[:4]) + 1,
            "total": total,
            "per_year": dict(sorted(per_year.items())),
        }

    @db_error
    def get_top_talker_count(self, top: int = 10, start_time: int = 0, end_time: int = 0):
        """
        获取聊天记录数量最多的联系人,他们聊天记录数量
        """
        if not self.tables_exist("MSG"):
            return {}
        if isinstance(start_time, str) and start_time.isdigit():
            start_time = int(start_time)
        if isinstance(end_time, str) and end_time.isdigit():
            end_time = int(end_time)

        # if start_time or end_time is not an integer and not a float, set both to 0
        if not (isinstance(start_time, (int, float)) and isinstance(end_time, (int, float))):
            start_time = 0
            end_time = 0

        sql_time = f"AND CreateTime BETWEEN {start_time} AND {end_time} " if start_time and end_time else ""
        sql = (
            "SELECT StrTalker, COUNT(*) AS count,"
            "SUM(CASE WHEN IsSender = 1 THEN 1 ELSE 0 END) AS sender_count, "
            "SUM(CASE WHEN IsSender = 0 THEN 1 ELSE 0 END) AS receiver_count "
            "FROM {src_} "
            "WHERE StrTalker NOT LIKE '%chatroom%' "
            f"{sql_time} "
            "GROUP BY StrTalker ORDER BY count DESC;"
        )

        # 【4.x 改造】跨库合并：各库分别统计后在 Python 里汇总，再取前 top 个
        merged = {}
        for path, src in self.msg_sources_for([]):
            rows = self._exec_on(path, sql.format(src_=src))
            for row in (rows or []):
                talker, count, sender_count, receiver_count = row
                item = merged.setdefault(talker, {"total_count": 0, "sender_count": 0, "receiver_count": 0})
                item["total_count"] += count or 0
                item["sender_count"] += sender_count or 0
                item["receiver_count"] += receiver_count or 0
        if not merged:
            return {}
        # 原来是 SQL 里的 LIMIT top；因为改成跨库合并了，这里在 Python 里截断
        top_items = sorted(merged.items(), key=lambda kv: kv[1]["total_count"], reverse=True)[:top]
        return dict(top_items)

    # 单条消息处理
    @db_error
    def _msg_body(self, StrContent, CompressContent):
        """
        取「用来解析 XML 的那份正文」，给需要解析 appmsg / 引用 / 转账 / 合并转发的类型分支使用。

        3.x：正文通常压在 CompressContent 里（lz4），保持原逻辑一字不动。
        4.x：正文已经在 StrContent 里（get_msg_detail 开头已按 CT 解压过），
             而 4.x 的 compress_content 列实测【全库都是空的】，再去读它只会拿到空字符串，
             于是链接/引用/转账这些消息在界面上就只剩一个空标题 —— 这也是第三步要修的现象之一。
        """
        if getattr(self, "is_wx4", False):
            return StrContent
        return decompress_CompressContent(CompressContent)

    def get_msg_detail(self, row, my_talker="我"):
        """
        获取单条消息详情,格式化输出
        """
        # 【第三步】4.x 的行尾多一列 WCDB_CT_message_content（见 get_msg_list），
        # 先把它摘出来，让后面的解包逻辑与 3.x 共用一个 27 列的写法。
        WCDB_CT = None
        if len(row) == 28:
            WCDB_CT = row[26]
            row = tuple(row[:26]) + (row[27],)

        (localId, TalkerId, MsgSvrID, Type, SubType, CreateTime, IsSender, Sequence, StatusEx, FlagEx, Status,
         MsgSequence, StrContent, MsgServerSeq, StrTalker, DisplayContent, Reserved0, Reserved1, Reserved3,
         Reserved4, Reserved5, Reserved6, CompressContent, BytesExtra, BytesTrans, Reserved2, _id) = row

        is_wx4 = bool(getattr(self, "is_wx4", False))

        # 【4.x】正文解码：CT=4 是 zstd（先解压，再剥掉群聊正文前面的「发送者wxid:\n」）；
        # CT=0 本来就是明文。3.x 的 is_wx4 为 False，下面这段完全不执行，
        # StrContent / CompressContent 的处理与原来一字不差。
        if is_wx4:
            StrContent = wx4_decode_message_content(StrContent, WCDB_CT, CompressContent)
            if isinstance(StrContent, (bytes, bytearray)):
                StrContent = bytes(StrContent).decode("utf-8", "replace")
            StrContent = wx4_strip_sender_prefix(StrContent,
                                                 sender_wxid=self.wx4_sender_wxid(StrTalker, TalkerId),
                                                 talker=StrTalker,
                                                 known_ids=self.wx4_known_ids())

        # 【4.x】字段兜底：个别列还可能以 bytes 返回，统一规整成 str，避免下面各种 .get() / endswith 崩掉。
        if isinstance(StrContent, (bytes, bytearray)):
            StrContent = StrContent.decode("utf-8", "replace")
        if StrContent is None:
            StrContent = ""
        if isinstance(StrTalker, (bytes, bytearray)):
            StrTalker = StrTalker.decode("utf-8", "replace")
        if not isinstance(StrTalker, str):
            StrTalker = ""

        CreateTime = timestamp2str(CreateTime)

        type_id = (Type, SubType)
        type_name = type_converter(type_id)

        msg = StrContent
        src = ""
        extra = {}

        if type_id == (1, 0):  # 文本
            msg = StrContent

        elif type_id == (3, 0):  # 图片
            DictExtra = get_BytesExtra(BytesExtra)
            DictExtra_str = str(DictExtra)
            img_paths = [i for i in re.findall(r"(FileStorage.*?)'", DictExtra_str)]
            img_paths = sorted(img_paths, key=lambda p: "Image" in p, reverse=True)
            if img_paths:
                img_path = img_paths[0].replace("'", "")
                img_path = [i for i in img_path.split("\\") if i]
                img_path = os.path.join(*img_path)
                src = img_path
            else:
                src = ""
            msg = "图片"
        elif type_id == (34, 0):  # 语音
            tmp_c = xml2dict(StrContent)
            voicelength = tmp_c.get("voicemsg", {}).get("voicelength", "")
            transtext = tmp_c.get("voicetrans", {}).get("transtext", "")
            if voicelength.isdigit():
                voicelength = int(voicelength) / 1000
                voicelength = f"{voicelength:.2f}"
            msg = f"语音时长：{voicelength}秒\n翻译结果：{transtext}" if transtext else f"语音时长：{voicelength}秒"
            if is_wx4 and not str(voicelength).strip():
                # 【4.x】个别语音的 XML 取不到 voicelength，别出现「语音时长：秒」这种半截文案
                msg = "[语音]"
            src = os.path.join(f"{StrTalker}",
                               f"{CreateTime.replace(':', '-').replace(' ', '_')}_{IsSender}_{MsgSvrID}.wav")
        elif type_id == (43, 0):  # 视频
            DictExtra = get_BytesExtra(BytesExtra)
            DictExtra = str(DictExtra)

            DictExtra_str = str(DictExtra)
            video_paths = [i for i in re.findall(r"(FileStorage.*?)'", DictExtra_str)]
            video_paths = sorted(video_paths, key=lambda p: "mp4" in p, reverse=True)
            if video_paths:
                video_path = video_paths[0].replace("'", "")
                video_path = [i for i in video_path.split("\\") if i]
                video_path = os.path.join(*video_path)
                src = video_path
            else:
                src = ""
            msg = "视频"

        elif type_id == (47, 0):  # 动画表情
            content_tmp = xml2dict(StrContent)
            cdnurl = content_tmp.get("emoji", {}).get("cdnurl", "")
            if not cdnurl:
                DictExtra = get_BytesExtra(BytesExtra)
                cdnurl = match_BytesExtra(DictExtra)
            if cdnurl:
                msg, src = "表情", cdnurl
            elif is_wx4:
                # 【4.x】表情的 cdnurl 取不到时（表情本体在 media 库里），
                # 至少保证类型标签正确，不要漏出整段 emoji XML。
                msg = "动画表情"

        elif type_id == (48, 0):  # 地图信息
            content_tmp = xml2dict(StrContent)
            location = content_tmp.get("location", {})
            if not isinstance(location, dict):
                location = {}
            if "x" not in location and "x" in content_tmp:
                # 【4.x】位置消息的根节点有时直接就是 <location ...>，属性在最外层，
                # 原来直接 location.pop('x') 会 KeyError 并把整页消息带崩。这里改成安全取值，
                # 且要把 label / poiname 一起带过来（否则界面上只剩一个空壳）。
                location = {k: v for k, v in content_tmp.items() if not isinstance(v, (dict, list))}
            else:
                location = dict(location)
            msg = (f"纬度:【{location.get('x', '')}】 经度:【{location.get('y', '')}】\n"
                   f"位置：{location.get('label', '')} {location.get('poiname', '')}\n"
                   f"其他信息：{json.dumps({k: v for k, v in location.items() if k not in ('x', 'y', 'label', 'poiname')}, ensure_ascii=False, indent=4)}"
                   )
            src = ""
        elif type_id == (49, 0):  # 文件
            DictExtra = get_BytesExtra(BytesExtra)
            url = match_BytesExtra(DictExtra)
            src = url
            file_name = os.path.basename(url)
            msg = file_name

        elif type_id == (49, 5):  # (分享)卡片式链接
            CompressContent_tmp = xml2dict(self._msg_body(StrContent, CompressContent))
            appmsg = CompressContent_tmp.get("appmsg", {})
            title = appmsg.get("title", "")
            des = appmsg.get("des", "")
            url = appmsg.get("url", "")
            msg = f'{title}\n{des}\n\n<a href="{url}" target="_blank">点击查看详情</a>'
            src = url
            extra = appmsg

        elif type_id == (49, 19):  # 合并转发的聊天记录
            content_tmp = xml2dict(self._msg_body(StrContent, CompressContent))
            title = content_tmp.get("appmsg", {}).get("title", "")
            des = content_tmp.get("appmsg", {}).get("des", "")
            recorditem = content_tmp.get("appmsg", {}).get("recorditem", "")
            recorditem = xml2dict(recorditem)
            if is_wx4:
                # 【4.x】<des>/<title> 里偶尔嵌着别的标签，xml2dict 会给出 dict，
                # 直接拼进消息正文就会在界面上显示成「{}」
                if not isinstance(title, str):
                    title = ""
                if not isinstance(des, str):
                    des = ""
            msg = f"{title}\n{des}"
            src = recorditem

        elif type_id == (49, 57):  # 带有引用的文本消息
            content_tmp = xml2dict(self._msg_body(StrContent, CompressContent))
            appmsg = content_tmp.get("appmsg", {})

            title = appmsg.get("title", "")
            refermsg = appmsg.get("refermsg", {})

            type_id = appmsg.get("type", "1")

            displayname = refermsg.get("displayname", "")
            display_content = refermsg.get("content", "")
            display_createtime = refermsg.get("createtime", "")

            display_createtime = timestamp2str(
                int(display_createtime)) if display_createtime.isdigit() else display_createtime

            # 【4.x】被引用的原文自己也可能是一条媒体/链接消息：群聊里它还会自带
            # 「发送者:\n」前缀，而且 4.x 的 XML 不带 <?xml 声明，上面那段（3.x 的写法）
            # 认不出来，会把整段 <msg><img …/> 甚至 <![CDATA[…]]> 原样显示在引用行里。
            # 所以先剥前缀，再统一抽成「图片 / 语音时长：x秒 / 标题」。
            if is_wx4 and isinstance(display_content, str):
                display_content = wx4_strip_sender_prefix(display_content, talker=StrTalker,
                                                          known_ids=self.wx4_known_ids())
            if display_content and display_content.startswith("<?xml"):
                display_content = xml2dict(display_content)
                if "img" in display_content:
                    display_content = "图片"
                else:
                    appmsg1 = display_content.get("appmsg", {})
                    title1 = appmsg1.get("title", "")
                    display_content = title1 if title1 else display_content

            if is_wx4 and (isinstance(display_content, dict)
                           or (isinstance(display_content, str) and display_content.lstrip().startswith("<"))):
                display_content = wx4_content_label(display_content)
            msg = f"{title}\n\n[引用]({display_createtime}){displayname}:{display_content}"
            src = ""

        elif type_id == (49, 2000):  # 转账消息
            content_tmp = xml2dict(self._msg_body(StrContent, CompressContent))
            wcpayinfo = content_tmp.get("appmsg", {}).get("wcpayinfo", {})
            paysubtype = wcpayinfo.get("paysubtype", "")  # 转账类型
            feedesc = wcpayinfo.get("feedesc", "")  # 转账金额
            pay_memo = wcpayinfo.get("pay_memo", "")  # 转账备注
            begintransfertime = wcpayinfo.get("begintransfertime", "")  # 转账开始时间
            msg = (f"{'已收款' if paysubtype == '3' else '转账'}：{feedesc}\n"
                   f"转账说明：{pay_memo if pay_memo else ''}\n"
                   f"转账时间：{timestamp2str(begintransfertime)}\n"
                   )
            src = ""

        elif type_id[0] == 49 and type_id[1] != 0:
            # 【4.x】49 是一大类（链接/文件/小程序/音乐/拍一拍/红包…），4.x 用到的子类型
            # 比 3.x 多，type_converter 认不出来的会返回「未知」。这里先按 appmsg 里的
            # title/des 抽出真实文案，抽不到再退回类型名。
            if is_wx4:
                msg = wx4_content_label(StrContent, type_name, type_id)
                src = ""
            else:
                DictExtra = get_BytesExtra(BytesExtra)
                url = match_BytesExtra(DictExtra)
                src = url
                msg = type_name

        elif type_id == (50, 0):  # 语音通话
            # 【4.x】通话消息的正文是 <voipmsg type="VoIPBubbleMsg"><VoIPBubbleMsg><msg>已取消</msg>…
            # 而 3.x 用的 DisplayContent 在 4.x 里恒为空，会显示成「语音/视频通话[]」。
            if is_wx4:
                tip = wx4_voip_text(StrContent)
                msg = f"语音/视频通话[{tip}]" if tip else "语音/视频通话"
            else:
                msg = "语音/视频通话[%s]" % DisplayContent

        # elif type_id == (10000, 0):
        #     msg = StrContent
        # elif type_id == (10000, 4):
        #     msg = StrContent
        # elif type_id == (10000, 8000):
        #     msg = StrContent

        # 【4.x】最后一道兜底：3.x 的分支里有些类型在 4.x 下拿不到内容
        # （系统消息 10000、名片 42、企业微信 66/67、视频号 49/51、新子类型…），
        # 结果会把整段 XML 或者「未知」直接丢到界面上。这里统一再抽一次可读标签，
        # 保证「图片 / 语音时长：x秒 / 视频 / 链接 / 文件 / 位置」这类标签一定能显示。
        if is_wx4 and wx4_need_label(msg):
            msg = wx4_content_label(StrContent, type_name, type_id)

        # 【4.x】「图片 / 视频 / 动画表情 / 文件」这四类在前端是【只渲染媒体、不显示文字】的组件，
        # 而 4.x 的图片视频本体在 media_*.db 里（消息库只留了 md5）、表情给的是需要登录态的
        # CDN 直链、文件给的是空路径 —— 这些 src 交上去只会渲染成一个空白框，反而把
        # 「图片 / 视频 / 文件：xxx」这种类型标签盖掉。所以只保留确实存在的本地文件，
        # 其余一律置空，让界面退回文字分支，保证类型标签一定看得见。
        if is_wx4 and src and type_name in ("图片", "视频", "动画表情", "文件"):
            _s = str(src)
            if _s.lower().startswith(("http://", "https://")) or not os.path.isfile(_s):
                src = ""

        talker = "未知"
        if IsSender == 1:
            talker = my_talker
        else:
            if StrTalker.endswith("@chatroom"):
                # 【4.x 改造】群聊发送者：直接拿 real_sender_id 去本库 Name2Id 解析成 wxid。
                # 3.x 没有 is_wx4，走不到这里，下面原来的 BytesExtra 逻辑保持不动。
                if getattr(self, "is_wx4", False):
                    sender_wxid = self.wx4_sender_wxid(StrTalker, TalkerId)
                    if sender_wxid:
                        talker = sender_wxid
                if talker == "未知":
                    bytes_extra = get_BytesExtra(BytesExtra)
                    if bytes_extra:
                        try:
                            talker = bytes_extra['3'][0]['2']
                            if "publisher-id" in talker:
                                talker = "系统"
                        except:
                            pass
            else:
                talker = StrTalker

        row_data = {"id": _id, "MsgSvrID": str(MsgSvrID), "type_name": type_name, "is_sender": IsSender,
                    "talker": talker, "room_name": StrTalker, "msg": msg, "src": src, "extra": extra,
                    "CreateTime": CreateTime, }
        return row_data


@db_error
def decompress_CompressContent(data):
    """
    解压缩Msg：CompressContent内容
    :param data: CompressContent内容 bytes
    :return:
    """
    if data is None or not isinstance(data, bytes):
        return None
    try:
        dst = lz4.block.decompress(data, uncompressed_size=len(data) << 8)
        dst = dst.replace(b'\x00', b'')  # 已经解码完成后，还含有0x00的部分，要删掉，要不后面ET识别的时候会报错
        uncompressed_data = dst.decode('utf-8', errors='ignore')
        return uncompressed_data
    except Exception as e:
        return data.decode('utf-8', errors='ignore')


# ---------------------------------------------------------------------------
# 【第三步】微信 4.x 的消息正文处理
#   4.x 的正文有两种形态，由 Msg_<hash>.WCDB_CT_message_content 决定：
#     CT=0 -> 明文 TEXT                   （本机 364148 条）
#     CT=4 -> zstd 压缩的 BLOB            （本机 230616 条，magic = 28 b5 2f fd）
#   注意：4.x 被压缩的是 message_content【这一列本身】，
#         compress_content 列在本机 594764 条里【全部为空】，所以不能去解 compress_content。
#   另外 4.x 的正文结构就是 3.x 那套 XML（<msg><img/>、<msg><appmsg>、<msgsource>…），
#   真正的差异只有三点：① 整段被 zstd 压过；② 群聊正文前面拼了「发送者wxid:\n」；
#   ③ 少数类型（如 42 名片）属性挂在 <msg> 根节点上。
# ---------------------------------------------------------------------------

# zstd 帧头（28 B5 2F FD），用来判断「这份正文是不是压缩过的」
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# 4.x 群聊正文的「发送者前缀」，实测形如  <他人wxid>:\n@李剑飞 看到信息来个电话
WX4_SENDER_PREFIX_RE = re.compile(r"^([A-Za-z0-9_\-\.@]{3,64}):\r?\n")

# 【第三步】4.x 媒体/功能消息的数字类型 -> 兜底标签。
# 正文 XML 万一遇到没见过的写法，也保证界面上至少是个正确的类型标签，
# 不会出现「空白一片」。键 = local_type 的低 32 位（即 3.x 的 Type）。
WX4_MEDIA_TAGS = {
    3: "图片",
    34: "语音",
    42: "名片",
    43: "视频",
    47: "动画表情",
    48: "位置",
    49: "链接",
    50: "语音/视频通话",
    66: "企业微信名片",
    67: "企业微信名片",
}


def wx4_decode_message_content(data, ct=None, fallback=None):
    """
    解码微信 4.x 的单条消息正文，返回 str。

    :param data:     Msg_<hash>.message_content 的原始值（CT=0 是 str，CT=4 是 bytes）
    :param ct:       WCDB_CT_message_content 的值，仅用于日志；真正的判据是 zstd magic，
                     因为「CT=4 才是压缩」只是当前版本的实测规律，按 magic 判断更稳。
    :param fallback: 兜底数据（4.x 的 compress_content，本机实测恒为空，留作保险）
    """
    if isinstance(data, memoryview):
        data = bytes(data)

    # CT=0：明文，直接返回
    if isinstance(data, str):
        return data

    if not isinstance(data, (bytes, bytearray)) or not data:
        # 自己是空的，再看一眼兜底列（正常情况这里也是空）
        if isinstance(fallback, (bytes, bytearray)) and fallback:
            data = bytes(fallback)
        elif isinstance(fallback, str):
            return fallback
        else:
            return ""

    data = bytes(data)

    # ① zstd（4.x）：magic 28 b5 2f fd
    if data[:4] == ZSTD_MAGIC:
        if zstandard is None:
            db_loger.warning("4.x 正文是 zstd 压缩，但当前环境没有安装 zstandard，"
                             "请执行： pip install zstandard")
            return ""
        try:
            out = zstandard.ZstdDecompressor().decompressobj().decompress(data)
            return out.decode("utf-8", "replace").rstrip("\x00")
        except Exception as e:
            db_loger.warning(f"4.x zstd 解压失败(CT={ct}, {len(data)} bytes): {e}")
            return ""

    # ② 不是 zstd：可能是明文被存成了 bytes，按 utf-8 宽松解
    return data.decode("utf-8", "replace")


def wx4_strip_sender_prefix(text, sender_wxid=None, talker=None, known_ids=None):
    """
    剥掉 4.x 群聊正文最前面的「发送者:\n」。

    这个前缀不属于消息内容，而且挡在 XML 前面会让 xml2dict 直接返回 {}（实测 lxml 的
    recover 也救不回来），于是【图片 / 位置 / 群系统消息】在界面上就解析成了空 —— 这是
    第三步的关键一环。实测本机 4.8 万条群消息带这种前缀，前缀有三种形态：
      · 发送者本人        <他人wxid>:\\n@李剑飞 看到信息来个电话
      · 企业微信成员      <企业微信id>:\\n今天可能有事没看到
      · 群自己(系统消息)  <群ID>:\\n<sysmsg type="sysmsgtemplate">…
      # 示例已脱敏

    为了不误伤正常文本（例如「12:30」这种），只在下面任一条件成立时才剥：
      · 前缀字符集是账号 id 会用的字符（ASCII 字母数字 _ - . @），中文/斜杠/空格都不算；
      · 前缀后面紧跟换行；
      · 且前缀【是已知账号】：等于该消息发送者 / 等于该会话 / 在 Name2Id 账号集合里 /
        形如 wxid_… 或 …@openim / …@chatroom。
    """
    if not text or not isinstance(text, str):
        return text
    m = WX4_SENDER_PREFIX_RE.match(text)
    if not m:
        return text
    who = m.group(1)
    if sender_wxid and who == sender_wxid:
        return text[m.end():]
    if talker and who == talker:
        return text[m.end():]
    if known_ids and who in known_ids:
        return text[m.end():]
    if who.startswith("wxid_") or who.endswith(("@openim", "@chatroom")):
        return text[m.end():]
    return text


def wx4_need_label(msg):
    """判断 4.x 的一条消息是否还需要从正文里再抽一次可读标签"""
    if msg is None:
        return True
    s = str(msg).strip()
    if not s:
        return True
    if s.startswith("<"):
        # 还是整段原始 XML，说明上面没有任何分支认得它
        return True
    if s == "未知" or s.startswith("未知-"):
        return True
    if s.endswith("[]"):
        # 「语音/视频通话[]」这种半截文案
        return True
    return False


def _wx4_link_text(link_node):
    """从 <link> 节点里取出可读文本：优先 nickname 列表（用「、」连接），其次 <plain> 文本"""
    nicks, plains = [], []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "nickname" and isinstance(v, str) and v.strip():
                    nicks.append(v.strip())
                elif k == "plain" and isinstance(v, str) and v.strip():
                    plains.append(v.strip())
                elif k in ("separator", "username", "type", "name", "antispam_ticket"):
                    continue
                else:
                    walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(link_node)
    if nicks:
        return "、".join(dict.fromkeys(nicks))  # 去重且保持顺序
    return " ".join(plains)


def wx4_sysmsg_template(content, d=None):
    """
    4.x 群系统消息（入群/被邀请/改群名/企业微信接替等）的真实结构：

      <sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template>
        <template><![CDATA["$username$"邀请"$names$"加入了群聊]]></template>
        <link_list>
          <link name="username"><memberlist><member><nickname>铁血狼魂-吴军长</nickname>…
          <link name="names">…两个成员，用 <separator>、</separator> 分隔

    模板里的 $变量$ 就是 link 的 name，把对应 link 里的昵称填回去，就得到和微信里
    一模一样的文案（例：「"铁血狼魂-吴军长"邀请"贺帥"加入了群聊」）。
    """
    if not isinstance(content, str) or "sysmsgtemplate" not in content:
        return ""
    d = d if isinstance(d, dict) else xml2dict(content)
    st = d.get("sysmsgtemplate")
    if isinstance(st, list):
        st = st[0] if st else None
    if not isinstance(st, dict):
        return ""
    ct = st.get("content_template")
    if isinstance(ct, list):
        ct = ct[0] if ct else None
    if not isinstance(ct, dict):
        return ""
    tmpl = ct.get("template")
    if not isinstance(tmpl, str) or not tmpl.strip():
        return ""

    vals = {}
    ll = ct.get("link_list")
    links = ll.get("link") if isinstance(ll, dict) else None
    if isinstance(links, dict):
        links = [links]
    for lk in (links or []):
        if isinstance(lk, dict) and isinstance(lk.get("name"), str):
            txt = _wx4_link_text(lk.get("memberlist"))
            if txt:
                vals[lk["name"]] = txt
    out = tmpl
    for k, v in vals.items():
        out = out.replace(f"${k}$", v)
    out = re.sub(r"\$[A-Za-z_]\w*\$", "", out)  # 没填上的占位符去掉
    return re.sub(r"[ \t]{2,}", " ", out).strip()


def wx4_voip_text(content):
    """4.x 通话消息：<voipmsg type="VoIPBubbleMsg"><VoIPBubbleMsg><msg><![CDATA[已取消]]></msg>…"""
    if isinstance(content, (bytes, bytearray)):
        content = bytes(content).decode("utf-8", "replace")
    if not isinstance(content, str) or "voipmsg" not in content:
        return ""
    d = xml2dict(content)
    if not isinstance(d, dict):
        return ""
    bubble = d.get("VoIPBubbleMsg")
    if isinstance(bubble, dict):
        tip = bubble.get("msg", "")
        if isinstance(tip, str) and tip.strip():
            return tip.strip()
    # 兜底：直接从 CDATA 里抠
    m = re.search(r"<msg>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</msg>", content, re.S)
    return (m.group(1).strip() if m else "")


def wx4_content_label(content, type_name="", type_id=None):
    """
    4.x 正文兜底解析：把（已解压的）XML 抽成界面上能直接看的一句话。

    覆盖 4.x 实际出现的各种类型，保证「媒体消息就算不能预览，类型标签也一定正确」：
      图片 -> 图片          视频 -> 视频          语音 -> 语音时长：x.xx秒
      动画表情 -> 动画表情   位置 -> 位置：xxx     链接/文件/音乐/引用/转账/合并转发 -> 标题+描述
      通话 -> 语音/视频通话[已取消]                 系统消息 -> 你撤回了一条消息
      名片 -> 名片：xxx      视频号 -> 视频号：xxx

    type_id 用于判断「这根 XML 到底是哪一类」（例如位置消息），
    因为界面上拿到的是中文类型名（"位置"），里面没有数字，光靠 type_name 认不出来。
    """
    if isinstance(content, (bytes, bytearray)):
        content = bytes(content).decode("utf-8", "replace")
    if content is None:
        content = ""
    text = str(content).strip()

    if not text:
        return f"[{type_name}]" if type_name and not str(type_name).startswith("未知") else "[无内容消息]"

    # 纯文本（大多数 CT=0 的文本消息、以及拍一拍等系统提示就是这种）
    if not text.startswith("<"):
        return text

    d = xml2dict(text)
    if not isinstance(d, dict):
        d = {}

    # ① 媒体类：给类型标签（4.x 的媒体本体在 media_*.db 里，不做预览，但标签必须对）
    if isinstance(d.get("img"), dict):
        img = d["img"]
        w, h = img.get("cdnthumbwidth", ""), img.get("cdnthumbheight", "")
        return f"图片（{w}x{h}）" if w and h else "图片"
    if isinstance(d.get("videomsg"), dict):
        vm = d["videomsg"]
        play = vm.get("playlength", "")
        return f"视频（{play}秒）" if str(play).isdigit() and int(play) > 0 else "视频"
    if isinstance(d.get("voicemsg"), dict):
        vl = d["voicemsg"].get("voicelength", "")
        if str(vl).isdigit() and int(vl) > 0:
            return f"语音时长：{int(vl) / 1000:.2f}秒"
        return "语音"
    if isinstance(d.get("emoji"), dict):
        return "动画表情"

    # ② 位置：4.x 有两种写法，<msg><location .../></msg> 或根节点就是 <location .../>
    loc = d.get("location")
    if not isinstance(loc, dict) and "x" in d and "y" in d:
        loc = {k: v for k, v in d.items() if not isinstance(v, (dict, list))}
    if isinstance(loc, dict):
        label = str(loc.get("label") or "").strip()
        poiname = str(loc.get("poiname") or "").strip()
        tip = f"{label} {poiname}".strip()
        return f"位置：{tip}" if tip else "位置"

    # ③ 视频号 / 直播：<appmsg> 里的 finderFeed 才是真信息，
    #    title 常常是「当前微信版本不支持展示该内容」这种占位文案
    appmsg = d.get("appmsg")
    if isinstance(appmsg, dict):
        ff = appmsg.get("finderFeed")
        if isinstance(ff, dict):
            nick = str(ff.get("nickname") or "").strip()
            desc = str(ff.get("desc") or "").strip()
            head = f"视频号：{nick}" if nick else "视频号"
            return f"{head} {desc}".strip()
        title = str(appmsg.get("title") or "").strip()
        des = str(appmsg.get("des") or "").strip()
        # 文件消息：4.x 的 <appmsg><title> 就是文件名，<totallen> 是字节数
        attach = appmsg.get("appattach")
        if str(appmsg.get("type", "")) == "6" or (not title and isinstance(attach, dict)
                                                 and attach.get("filename")):
            fname = title or str((attach or {}).get("filename") or "").strip()
            total = (attach or {}).get("totallen", "")
            size = wx4_human_size(total)
            return f"文件：{fname}{f'（{size}）' if size else ''}".strip()
        if title or des:
            return "\n".join(x for x in (title, des) if x)

    # ④ 通话
    if "voipmsg" in text or "voipmsg" in d:
        tip = wx4_voip_text(text)
        return f"语音/视频通话[{tip}]" if tip else "语音/视频通话"

    # ⑤ 系统消息：分两种
    #    · <sysmsg type="sysmsgtemplate"> 群系统消息 → 用模板 + 成员昵称还原成自然语言
    #    · <sysmsg type="revokemsg"><revokemsg><content>你撤回了一条消息</content>
    tip = wx4_sysmsg_template(text, d)
    if tip:
        return tip
    for key, val in d.items():
        if isinstance(val, dict) and isinstance(val.get("content"), str) and val["content"].strip():
            return val["content"].strip()
    if isinstance(d.get("content"), str) and d["content"].strip():
        return d["content"].strip()

    # ⑥ 名片（42）：属性挂在 <msg> 根节点上
    nick = d.get("nickname")
    if isinstance(nick, str) and nick.strip():
        alias = d.get("alias") or d.get("username") or ""
        return f"名片：{nick.strip()}{f'（{alias}）' if alias else ''}"

    # ⑦ 企业微信（66/67）：openimdesc / nickname
    desc = d.get("openimdesc") or d.get("openimnickname")
    if isinstance(desc, str) and desc.strip():
        return f"企业微信：{desc.strip()}"

    # ⑧ 都不认识：先按数字类型 id 兜一层媒体标签（保证类型标签不会丢），再退回去标签留正文
    tid = None
    if type_id is not None:
        try:
            tid = int(type_id[0]) if isinstance(type_id, (tuple, list)) and type_id else int(type_id)
        except (TypeError, ValueError, IndexError):
            tid = None
    if tid in WX4_MEDIA_TAGS:
        return f"[{WX4_MEDIA_TAGS[tid]}]"
    plain = re.sub(r"<[^>]+>", " ", text)
    plain = re.sub(r"\s+", " ", plain).strip()
    if plain:
        return plain[:200]
    return f"[{type_name}]" if type_name and not str(type_name).startswith("未知") else "[无内容消息]"


def wx4_human_size(num):
    """把字节数转成 1.2 MB 这样的可读文本"""
    try:
        n = int(num)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return ""


@db_error
def get_BytesExtra(BytesExtra):
    BytesExtra_message_type = {
        "1": {
            "type": "message",
            "message_typedef": {
                "1": {
                    "type": "int",
                    "name": ""
                },
                "2": {
                    "type": "int",
                    "name": ""
                }
            },
            "name": "1"
        },
        "3": {
            "type": "message",
            "message_typedef": {
                "1": {
                    "type": "int",
                    "name": ""
                },
                "2": {
                    "type": "str",
                    "name": ""
                }
            },
            "name": "3",
            "alt_typedefs": {
                "1": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {},
                        "name": ""
                    }
                },
                "2": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "13": {
                                "type": "fixed32",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "3": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "15": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "4": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "15": {
                                "type": "int",
                                "name": ""
                            },
                            "14": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "5": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "12": {
                                "type": "fixed32",
                                "name": ""
                            },
                            "7": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "6": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "6": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "7": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "6": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "7": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "12": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "8": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "6": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "9": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "15": {
                                "type": "int",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "6": {
                                "type": "int",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "10": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "6": {
                                "type": "fixed32",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
            }
        }
    }
    if BytesExtra is None or not isinstance(BytesExtra, bytes):
        return None
    try:
        deserialize_data, message_type = blackboxprotobuf.decode_message(BytesExtra, BytesExtra_message_type)
        return deserialize_data
    except Exception as e:
        return None
