# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         MicroMsg.py
# Description:  负责处理联系人数据库
# Author:       xaoyaoo
# Date:         2024/04/15
# -------------------------------------------------------------------------------
import hashlib
import logging

from .dbbase import DatabaseBase
from .utils import timestamp2str, bytes2str, bytes2str_deep, db_loger, db_error

import blackboxprotobuf

# 群 RoomData 解码缓存：同一个群的 ext_buffer 在一次请求里会被反复解码，按内容 md5 缓存
_ROOMDATA_CACHE = {}


class MicroHandler(DatabaseBase):
    _class_name = "MicroMsg"
    Micro_required_tables = ["ContactLabel", "Contact", "ContactHeadImgUrl", "Session", "ChatInfo", "ChatRoom",
                             "ChatRoomInfo"]

    def Micro_add_index(self):
        """
        添加索引, 加快查询速度

        4.x 说明：4.x 的 Contact / Session / ChatRoom 是【只读的独立库文件】，
        而且 tables_exist() 会把它们当成「存在于主库」，如果在主库上
        CREATE INDEX ON Contact(...) 会直接报 no such table。
        这些库本来就是微信自己维护好的、规模也小（联系人 9 千行 / 会话 5 百行），
        不需要我们建索引，所以 4.x 直接跳过。
        """
        if getattr(self, "is_wx4", False):
            db_loger.info("4.x: 跳过多库索引创建（side 库为只读，本次不写任何库）")
            return
        # 为 Session 表添加索引
        if self.tables_exist("Session"):
            self.execute("CREATE INDEX IF NOT EXISTS idx_Session_strUsrName_nTime ON Session(strUsrName, nTime);")
            self.execute("CREATE INDEX IF NOT EXISTS idx_Session_nOrder ON Session(nOrder);")
            self.execute("CREATE INDEX IF NOT EXISTS idx_Session_nTime ON Session(nTime);")

        # 为 Contact 表添加索引

        if self.tables_exist("Contact"):
            self.execute("CREATE INDEX IF NOT EXISTS idx_Contact_UserName ON Contact(UserName);")

        # 为 ContactHeadImgUrl 表添加索引
        if self.tables_exist('ContactHeadImgUrl'):
            self.execute("CREATE INDEX IF NOT EXISTS idx_ContactHeadImgUrl_usrName ON ContactHeadImgUrl(usrName);")

        # 为 ChatInfo 表添加索引
        if self.tables_exist('ChatInfo'):
            self.execute("CREATE INDEX IF NOT EXISTS idx_ChatInfo_Username_LastReadedCreateTime "
                         "ON ChatInfo(Username, LastReadedCreateTime);")
            self.execute(
                "CREATE INDEX IF NOT EXISTS idx_ChatInfo_LastReadedCreateTime ON ChatInfo(LastReadedCreateTime);")

        # 为 Contact 表添加复合索引
        if self.tables_exist('Contact'):
            self.execute("CREATE INDEX IF NOT EXISTS idx_Contact_search "
                         "ON Contact(UserName, NickName, Remark, Alias, QuanPin, PYInitial, RemarkQuanPin, RemarkPYInitial);")

        # 为 ChatRoom 和 ChatRoomInfo 表添加索引
        if self.tables_exist(['ChatRoomInfo', "ChatRoom"]):
            self.execute("CREATE INDEX IF NOT EXISTS idx_ChatRoom_ChatRoomName ON ChatRoom(ChatRoomName);")
            self.execute("CREATE INDEX IF NOT EXISTS idx_ChatRoomInfo_ChatRoomName ON ChatRoomInfo(ChatRoomName);")

    @db_error
    def get_labels(self, id_is_key=True):
        """
        读取标签列表
        :param id_is_key: id_is_key: True: id作为key，False: name作为key
        :return:
        """
        labels = {}
        if not self.tables_exist("ContactLabel"):
            return labels
        if getattr(self, "is_wx4", False):
            # 4.x: contact_label(label_id_, label_name_, sort_order_)
            sql = "SELECT label_id_, label_name_ FROM contact_label ORDER BY label_name_ ASC;"
            result = self._exec_contact(sql)
        else:
            sql = "SELECT LabelId, LabelName FROM ContactLabel ORDER BY LabelName ASC;"
            result = self.execute(sql)
        if not result:
            return labels
        if id_is_key:
            labels = {row[0]: row[1] for row in result}
        else:
            labels = {row[1]: row[0] for row in result}
        return labels

    @db_error
    def get_session_list(self):
        """
        获取会话列表
        :return: 会话列表
        """
        sessions = {}
        if not self.tables_exist(["Session", "Contact", "ContactHeadImgUrl"]):
            return sessions
        if getattr(self, "is_wx4", False):
            # 4.x：会话在 session_decrypted.db 的 SessionTable，联系人在 contact_decrypted.db 的 contact。
            # 两张表在两个库里，靠 ATTACH 让这条 3.x 形状的 JOIN 照跑；
            # 输出列的顺序、含义跟 3.x 完全一致，下面的解析代码一行都不用改。
            sql = (
                "SELECT S.username,S.sort_timestamp,S.unread_count, "
                "COALESCE(NULLIF(C.remark,''), NULLIF(C.nick_name,''), '') AS strNickName, "
                "S.status, 0, S.summary, "
                "S.last_msg_locald_id, 0, S.last_timestamp, S.last_msg_type, S.last_msg_sub_type, "
                "C.username, C.alias, "
                "C.delete_flag, C.local_type, C.verify_flag, 0, 0, C.remark, C.nick_name, '', "
                "C.chat_room_type, C.chat_room_notify, 0, C.description, C.extra_buffer, C.big_head_url "
                "FROM (SELECT username, MAX(last_timestamp) AS MaxnTime FROM SessionTable GROUP BY username) "
                "AS SubQuery "
                "JOIN SessionTable S ON S.username = SubQuery.username AND S.last_timestamp = SubQuery.MaxnTime "
                f"left join {self.WX4_ATTACH_ALIAS}.contact C ON C.username = S.username "
                "WHERE S.username!='@publicUser' "
                "ORDER BY S.last_timestamp DESC;"
            )
            db_loger.info(f"get_session_list(4.x) sql: {sql}")
            ret = self._exec_session_join_contact(sql)
        else:
            sql = (
                "SELECT S.strUsrName,S.nOrder,S.nUnReadCount, S.strNickName, S.nStatus, S.nIsSend, S.strContent, "
                "S.nMsgLocalID, S.nMsgStatus, S.nTime, S.nMsgType, S.Reserved2 AS nMsgSubType, C.UserName, C.Alias, "
                "C.DelFlag, C.Type, C.VerifyFlag, C.Reserved1, C.Reserved2, C.Remark, C.NickName, C.LabelIDList, "
                "C.ChatRoomType, C.ChatRoomNotify, C.Reserved5, C.Reserved6 as describe, C.ExtraBuf, H.bigHeadImgUrl "
                "FROM (SELECT strUsrName, MAX(nTime) AS MaxnTime FROM Session GROUP BY strUsrName) AS SubQuery "
                "JOIN Session S ON S.strUsrName = SubQuery.strUsrName AND S.nTime = SubQuery.MaxnTime "
                "left join Contact C ON C.UserName = S.strUsrName "
                "LEFT JOIN ContactHeadImgUrl H ON C.UserName = H.usrName "
                "WHERE S.strUsrName!='@publicUser' "
                "ORDER BY S.nTime DESC;"
            )

            db_loger.info(f"get_session_list sql: {sql}")
            ret = self.execute(sql)
        if not ret:
            return sessions

        id2label = self.get_labels()
        for row in ret:
            (strUsrName, nOrder, nUnReadCount, strNickName, nStatus, nIsSend, strContent,
             nMsgLocalID, nMsgStatus, nTime, nMsgType, nMsgSubType,
             UserName, Alias, DelFlag, Type, VerifyFlag, Reserved1, Reserved2, Remark, NickName, LabelIDList,
             ChatRoomType, ChatRoomNotify, Reserved5, describe, ExtraBuf, bigHeadImgUrl) = row

            ExtraBuf = get_ExtraBuf(ExtraBuf)
            LabelIDList = LabelIDList.split(",") if LabelIDList else []
            LabelIDList = [id2label.get(int(label_id), label_id) for label_id in LabelIDList if label_id]
            nTime = timestamp2str(nTime) if nTime else None

            sessions[strUsrName] = {
                "wxid": strUsrName, "nOrder": nOrder, "nUnReadCount": nUnReadCount, "strNickName": strNickName,
                "nStatus": nStatus, "nIsSend": nIsSend, "strContent": strContent, "nMsgLocalID": nMsgLocalID,
                "nMsgStatus": nMsgStatus, "nTime": nTime, "nMsgType": nMsgType, "nMsgSubType": nMsgSubType,
                "LastReadedCreateTime": nTime,
                "nickname": NickName, "remark": Remark, "account": Alias,
                "describe": describe, "headImgUrl": bigHeadImgUrl if bigHeadImgUrl else "",
                "ExtraBuf": ExtraBuf, "LabelIDList": tuple(LabelIDList)
            }
        return sessions

    @db_error
    def get_recent_chat_wxid(self):
        """
        获取最近聊天的联系人
        :return: 最近聊天的联系人
        """
        users = []
        if not self.tables_exist(["ChatInfo"]):
            return users
        if getattr(self, "is_wx4", False):
            # 4.x：没有 ChatInfo 表，用 SessionTable 的 last_timestamp 顶上。
            # 3.x 那边存的是毫秒且按 > 1007911408000 过滤，所以这里 *1000 对齐口径。
            sql = (
                "SELECT username, last_timestamp*1000, 0 FROM SessionTable "
                "WHERE last_timestamp IS NOT NULL AND last_timestamp*1000 > 1007911408000 "
                "ORDER BY last_timestamp DESC;"
            )
            db_loger.info(f"get_recent_chat_wxid(4.x) sql: {sql}")
            result = self._exec_session(sql)
        else:
            sql = (
                "SELECT A.Username, LastReadedCreateTime, LastReadedSvrId "
                "FROM (   SELECT Username, MAX(LastReadedCreateTime) AS MaxLastReadedCreateTime  FROM ChatInfo "
                "WHERE LastReadedCreateTime IS NOT NULL AND LastReadedCreateTime > 1007911408000   GROUP BY Username "
                ") AS SubQuery JOIN ChatInfo A "
                "ON A.Username = SubQuery.Username AND LastReadedCreateTime = SubQuery.MaxLastReadedCreateTime "
                "ORDER BY A.LastReadedCreateTime DESC;"
            )

            db_loger.info(f"get_recent_chat_wxid sql: {sql}")
            result = self.execute(sql)
        if not result:
            return []
        for row in result:
            # 获取用户名、昵称、备注和聊天记录数量
            username, LastReadedCreateTime, LastReadedSvrId = row
            LastReadedCreateTime = timestamp2str(LastReadedCreateTime) if LastReadedCreateTime else None
            users.append(
                {"wxid": username, "LastReadedCreateTime": LastReadedCreateTime, "LastReadedSvrId": LastReadedSvrId})
        return users

    @db_error
    def get_user_list(self, word: str = None, wxids: list = None, label_ids: list = None):
        """
        获取联系人列表
        [ 注意：如果修改这个函数，要同时修改dbOpenIMContact.py中的get_im_user_list函数 ]
        :param word: 查询关键字，可以是wxid,用户名、昵称、备注、描述，允许拼音
        :param wxids: wxid列表
        :param label_ids: 标签id
        :return: 联系人字典
        """
        if isinstance(wxids, str):
            wxids = [wxids]
        if isinstance(label_ids, str):
            label_ids = [label_ids]

        users = {}
        if not self.tables_exist(["Contact", "ContactHeadImgUrl"]):
            return users
        is4 = getattr(self, "is_wx4", False)
        if is4:
            # 4.x：contact 库的 contact 表，字段名全不一样，且没有单列 LabelIDList（打标签信息不在此表）。
            # 输出列的顺序和 3.x 一一对应，下面解析代码不用改。
            sql = (
                "SELECT A.username, A.alias, A.delete_flag, A.local_type, A.verify_flag, 0, 0,"
                "A.remark, A.nick_name, '', A.chat_room_type, A.chat_room_notify, 0,"
                "A.description as describe, A.extra_buffer, A.big_head_url "
                "FROM contact A WHERE 1==1 ;"
            )
        else:
            sql = (
                "SELECT A.UserName, A.Alias, A.DelFlag, A.Type, A.VerifyFlag, A.Reserved1, A.Reserved2,"
                "A.Remark, A.NickName, A.LabelIDList, A.ChatRoomType, A.ChatRoomNotify, A.Reserved5,"
                "A.Reserved6 as describe, A.ExtraBuf, B.bigHeadImgUrl "
                "FROM Contact A LEFT JOIN ContactHeadImgUrl B ON A.UserName = B.usrName WHERE 1==1 ;"
            )
        if word:
            if is4:
                sql = sql.replace(";",
                                  f"AND ( A.username LIKE '%{word}%' "
                                  f"OR A.nick_name LIKE '%{word}%' "
                                  f"OR A.remark LIKE '%{word}%' "
                                  f"OR A.alias LIKE '%{word}%' "
                                  f"OR LOWER(A.quan_pin) LIKE LOWER('%{word}%') "
                                  f"OR LOWER(A.pin_yin_initial) LIKE LOWER('%{word}%') "
                                  f"OR LOWER(A.remark_quan_pin) LIKE LOWER('%{word}%') "
                                  f"OR LOWER(A.remark_pin_yin_initial) LIKE LOWER('%{word}%') "
                                  f") "
                                  ";")
            else:
                sql = sql.replace(";",
                                  f"AND ( A.UserName LIKE '%{word}%' "
                                  f"OR A.NickName LIKE '%{word}%' "
                                  f"OR A.Remark LIKE '%{word}%' "
                                  f"OR A.Alias LIKE '%{word}%' "
                                  f"OR LOWER(A.QuanPin) LIKE LOWER('%{word}%') "
                                  f"OR LOWER(A.PYInitial) LIKE LOWER('%{word}%') "
                                  f"OR LOWER(A.RemarkQuanPin) LIKE LOWER('%{word}%') "
                                  f"OR LOWER(A.RemarkPYInitial) LIKE LOWER('%{word}%') "
                                  f") "
                                  ";")
        if wxids:
            if is4:
                sql = sql.replace(";", f"AND A.username IN ('" + "','".join(wxids) + "') ;")
            else:
                sql = sql.replace(";", f"AND A.UserName IN ('" + "','".join(wxids) + "') ;")

        if label_ids:
            if is4:
                # 4.x 的 contact 表没有任何「标签列表」字段（contact_label 只存标签定义，
                # 不存「谁打了哪个标签」），所以按标签筛选在这里拿不到数据。
                # 不静默返回全部，直接返回空并记日志，避免给出错误结果。
                db_loger.warning(f"4.x: contact 表无 LabelIDList 字段，按标签筛选 {label_ids} 暂不支持，返回空")
                return users
            sql_label = [f"A.LabelIDList LIKE '%{i}%' " for i in label_ids]
            sql_label = " OR ".join(sql_label)
            sql = sql.replace(";", f"AND ({sql_label}) ;")

        db_loger.info(f"get_user_list sql: {sql}")
        result = self._exec_contact(sql) if is4 else self.execute(sql)
        if not result:
            return users
        id2label = self.get_labels()
        for row in result:
            # 获取wxid,昵称，备注，描述，头像,标签
            (UserName, Alias, DelFlag, Type, VerifyFlag, Reserved1, Reserved2, Remark, NickName, LabelIDList,
             ChatRoomType, ChatRoomNotify, Reserved5, describe, ExtraBuf, bigHeadImgUrl) = row

            ExtraBuf = get_ExtraBuf(ExtraBuf)
            LabelIDList = LabelIDList.split(",") if LabelIDList else []
            LabelIDList = [id2label.get(int(label_id), label_id) for label_id in LabelIDList if label_id]

            # print(f"{UserName=}\n{Alias=}\n{DelFlag=}\n{Type=}\n{VerifyFlag=}\n{Reserved1=}\n{Reserved2=}\n"
            #       f"{Remark=}\n{NickName=}\n{LabelIDList=}\n{ChatRoomType=}\n{ChatRoomNotify=}\n{Reserved5=}\n"
            #       f"{describe=}\n{ExtraBuf=}\n{bigHeadImgUrl=}")
            users[UserName] = {
                "wxid": UserName, "nickname": NickName, "remark": Remark, "account": Alias,
                "describe": describe, "headImgUrl": bigHeadImgUrl if bigHeadImgUrl else "",
                "ExtraBuf": ExtraBuf, "LabelIDList": tuple(LabelIDList),
                "extra": None}
        # 4.x 里 chatroom_member 会出现「群成员就是群自己 / 群 A 含群 B、群 B 又含群 A」的情况，
        # 而 get_room_list() 内部又会回调 get_user_list()，两边互相展开就会无限递归
        # （第一步真机跑出来的 max recursion depth exceeded 就是这么来的）。
        # 这里用一层深度标记：只有在最外层（非群成员展开）才去取群信息，内层直接跳过。
        if getattr(self, "_room_expand_depth", 0) > 0:
            extras = {}
        else:
            # 注意：这里必须先挑出真正含 @ 的 key 再判断是否为空。
            # get_room_list() 里 `if roomwxids:` 把「空列表」当成「不过滤」，
            # 传空列表进去会返回全部群，然后在调用方被逐个丢掉——纯浪费。
            # 联系人里一个 @ 都没有时直接不查，extras 取空的效果完全一样。
            room_wxids = [x for x in users.keys() if "@" in x]
            if not room_wxids:
                extras = {}
            else:
                self._room_expand_depth = 1
                try:
                    extras = self.get_room_list(roomwxids=room_wxids) or {}
                finally:
                    self._room_expand_depth = 0
        for UserName in users:
            users[UserName]["extra"] = extras.get(UserName, None)
        return users

    @db_error
    def get_room_list(self, word=None, roomwxids: list = None):
        """
        获取群聊列表
        :param word: 群聊搜索词
        :param roomwxids: 群聊wxid列表
        :return: 群聊字典
        """
        # 连接 MicroMsg.db 数据库，并执行查询
        if isinstance(roomwxids, str):
            roomwxids = [roomwxids]
        if roomwxids is not None and not isinstance(roomwxids, (list, tuple, set)):
            roomwxids = list(roomwxids)  # 上层可能传 filter 对象进来

        rooms = {}
        if not self.tables_exist(["ChatRoom", "ChatRoomInfo"]):
            return rooms
        is4 = getattr(self, "is_wx4", False)
        if is4:
            # 4.x：群在 chat_room(username/owner/ext_buffer)，群公告在 chat_room_info_detail，
            # 群成员在 chatroom_member(room_id/member_id 都是 contact.id)。
            # RoomData 直接用 chat_room.ext_buffer —— 它解码出来的结构跟 3.x 的 RoomData 一致。
            # 输出 11 列，顺序和 3.x 完全对应（第 7 列 Reserved2 就是群主）。
            sql = (
                "SELECT R.username,"
                "(SELECT GROUP_CONCAT(C2.username,'^G') FROM chatroom_member M "
                "   JOIN contact C2 ON C2.id = M.member_id WHERE M.room_id = R.id) AS UserNameList,"
                "'',0,0,'',R.owner,R.ext_buffer,"
                "D.announcement_,D.announcement_editor_,D.announcement_publish_time_ "
                "FROM chat_room R LEFT JOIN chat_room_info_detail D ON D.room_id_ = R.id "
                "WHERE 1==1 ;"
            )
        else:
            sql = (
                "SELECT A.ChatRoomName,A.UserNameList,A.DisplayNameList,A.ChatRoomFlag,A.IsShowName,"
                "A.SelfDisplayName,A.Reserved2,A.RoomData, "
                "B.Announcement,B.AnnouncementEditor,B.AnnouncementPublishTime "
                "FROM ChatRoom A LEFT JOIN ChatRoomInfo B ON A.ChatRoomName==B.ChatRoomName "
                "WHERE 1==1 ;")
        if word:
            sql = sql.replace(";",
                              f"AND {'R.username' if is4 else 'A.ChatRoomName'} LIKE '%{word}%' ;")
        if roomwxids:
            wk = "','".join(roomwxids)
            if is4:
                sql = sql.replace(";", f"AND R.username IN ('{wk}') ;")
            else:
                sql = sql.replace(";", f"AND A.ChatRoomName IN ('{wk}') ;")

        db_loger.info(f"get_room_list sql: {sql}")
        result = self._exec_contact(sql) if is4 else self.execute(sql)
        if not result:
            return rooms

        for row in result:
            # 获取用户名、昵称、备注和聊天记录数量
            (ChatRoomName, UserNameList, DisplayNameList, ChatRoomFlag, IsShowName, SelfDisplayName,
             Reserved2, RoomData,
             Announcement, AnnouncementEditor, AnnouncementPublishTime) = row

            UserNameList = UserNameList.split("^G") if UserNameList else []
            DisplayNameList = DisplayNameList.split("^G") if DisplayNameList else []

            RoomData = ChatRoom_RoomData(RoomData, fast=is4)
            wxid2roomNickname = {}
            if RoomData:
                rd = []
                for k, v in RoomData.items():
                    if isinstance(v, list):
                        rd += v
                for i in rd:
                    try:
                        if isinstance(i, dict) and isinstance(i.get('1'), str) and i.get('2'):
                            wxid2roomNickname[i['1']] = i["2"]
                    except Exception as e:
                        db_loger.error(f"wxid2remark: ChatRoomName:{ChatRoomName}, {i} error:{e}", exc_info=True)

            wxid2userinfo = self.get_user_list(wxids=UserNameList) or {}
            for i in wxid2userinfo:
                wxid2userinfo[i]["roomNickname"] = wxid2roomNickname.get(i, "")

            owner = wxid2userinfo.get(Reserved2, Reserved2)

            rooms[ChatRoomName] = {
                "wxid": ChatRoomName, "roomWxids": UserNameList, "IsShowName": IsShowName,
                "ChatRoomFlag": ChatRoomFlag, "SelfDisplayName": SelfDisplayName,
                "owner": owner, "wxid2userinfo": wxid2userinfo,
                "Announcement": Announcement, "AnnouncementEditor": AnnouncementEditor,
                "AnnouncementPublishTime": AnnouncementPublishTime}
        return rooms


@db_error
def ChatRoom_RoomData(RoomData, fast=False):
    """
    读取群聊数据，主要为 wxid 以及对应昵称。

    fast=True（微信 4.x）时先用内置解析器：4.x 的 chat_room.ext_buffer 结构固定，
    而 blackboxprotobuf 解这类 buffer 会先磨很久再抛它自己的 NameError
    （length_delim.py 里 field_tyepdef 拼写 bug），197 个群累计要几分钟。
    """
    # 读取群聊数据,主要为 wxid，以及对应昵称
    if RoomData is None or not isinstance(RoomData, bytes):
        return None

    # 同一个群的 buffer 在一次请求里会被反复解码（get_user_list / get_room_list 互相调用），
    # 按内容 md5 缓存，避免重复解码。
    cache_key = hashlib.md5(RoomData).hexdigest()
    if cache_key in _ROOMDATA_CACHE:
        return _ROOMDATA_CACHE[cache_key]

    data = _mini_parse_roomdata(RoomData) if fast else None
    if not data:
        data = get_BytesExtra(RoomData)
    # 4.x 的 ext_buffer 是嵌套结构（外层 dict -> list -> 内层 dict），
    # 原来的 bytes2str() 解不了这种嵌套，群昵称会全部丢掉，所以改用递归版。
    data = bytes2str_deep(data) if data else None
    if len(_ROOMDATA_CACHE) < 5000:
        _ROOMDATA_CACHE[cache_key] = data
    return data


def _read_varint(buf, i):
    """读一个 protobuf varint：返回 (值, 新下标)"""
    shift = 0
    val = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7
        if shift > 63:
            raise ValueError("varint 过长")
    raise ValueError("varint 读到结尾")


def _mini_parse_roomdata(buf):
    """
    极简 protobuf 解析，只服务群信息 RoomData，结构固定为：
      {"1": [{"1": wxid, "2": 群昵称, "3": int, "4": 邀请人}, ...], "3": int, "4": int}

    为什么需要它：本机装的 blackboxprotobuf 在解某些群 buffer 时会抛
      NameError: name 'field_tyepdef' is not defined   ← 是它库自身第 232 行的拼写 bug，
    于是 get_BytesExtra 返回 None，ChatRoom_RoomData 也就返回 None，整群群昵称全丢。

    注意：key 一律用【字符串】，和 blackboxprotobuf 的输出形状保持一致，
    否则上层 `i.get('1')` / `isinstance(v, list)` 取不到值，群昵称会被静默丢掉。
    """
    if not isinstance(buf, (bytes, bytearray)):
        return None
    out = {}
    i, n = 0, len(buf)
    while i < n:
        try:
            key, i = _read_varint(buf, i)
        except Exception:
            break
        tag, wire = str(key >> 3), key & 7
        if wire == 0:
            out[tag], i = _read_varint(buf, i)
        elif wire == 2:
            ln, i = _read_varint(buf, i)
            chunk = bytes(buf[i:i + ln])
            i += ln
            if tag == "1":  # 重复的成员条目
                item, j = {}, 0
                while j < len(chunk):
                    k2, j = _read_varint(chunk, j)
                    t2, w2 = str(k2 >> 3), k2 & 7
                    if w2 == 2:
                        l2, j = _read_varint(chunk, j)
                        item[t2] = bytes(chunk[j:j + l2]).decode("utf-8", "ignore")
                        j += l2
                    elif w2 == 0:
                        item[t2], j = _read_varint(chunk, j)
                    else:
                        break
                if item:
                    cur = out.get(tag)
                    if cur is None:
                        out[tag] = [item]
                    elif isinstance(cur, list):
                        cur.append(item)
                    else:
                        out[tag] = [cur, item]
            else:
                out[tag] = chunk.decode("utf-8", "ignore")
        elif wire == 5:
            i += 4
        elif wire == 1:
            i += 8
        else:
            break
    return out or None


@db_error
def get_BytesExtra(BytesExtra):
    if BytesExtra is None or not isinstance(BytesExtra, bytes):
        return None
    try:
        deserialize_data, message_type = blackboxprotobuf.decode_message(BytesExtra)
        return deserialize_data
    except Exception as e:
        # 只记一行，别把整段栈和几 KB 的 buffer 打出来刷屏
        db_loger.warning(f"get_BytesExtra 解码失败({type(e).__name__}: {e})，改用内置 RoomData 解析器兜底")
        return _mini_parse_roomdata(BytesExtra)


@db_error
def get_ExtraBuf(ExtraBuf: bytes):
    """
    读取ExtraBuf（联系人表）
    :param ExtraBuf:
    :return:
    """
    if not ExtraBuf:
        return None
    buf_dict = {
        '74752C06': '性别[1男2女]', '46CF10C4': '个性签名', 'A4D9024A': '国', 'E2EAA8D1': '省', '1D025BBF': '市',
        'F917BCC0': '公司名称', '759378AD': '手机号', '4EB96D85': '企微属性', '81AE19B4': '朋友圈背景',
        '0E719F13': '备注图片', '945f3190': '备注图片2',
        'DDF32683': '0', '88E28FCE': '1', '761A1D2D': '2', '0263A0CB': '3', '0451FF12': '4', '228C66A8': '5',
        '4D6C4570': '6', '4335DFDD': '7', 'DE4CDAEB': '8', 'A72BC20A': '9', '069FED52': '10', '9B0F4299': '11',
        '3D641E22': '12', '1249822C': '13', 'B4F73ACB': '14', '0959EB92': '15', '3CF4A315': '16',
        'C9477AC60201E44CD0E8': '17', 'B7ACF0F5': '18', '57A7B5A8': '19', '695F3170': '20', 'FB083DD9': '21',
        '0240E37F': '22', '315D02A3': '23', '7DEC0BC3': '24', '16791C90': '25'
    }

    rdata = {}
    for buf_name in buf_dict:
        rdata_name = buf_dict[buf_name]
        buf_name = bytes.fromhex(buf_name)
        offset = ExtraBuf.find(buf_name)
        if offset == -1:
            rdata[rdata_name] = ""
            continue
        offset += len(buf_name)
        type_id = ExtraBuf[offset: offset + 1]
        offset += 1

        if type_id == b"\x04":
            rdata[rdata_name] = int.from_bytes(ExtraBuf[offset: offset + 4], "little")

        elif type_id == b"\x18":
            length = int.from_bytes(ExtraBuf[offset: offset + 4], "little")
            rdata[rdata_name] = ExtraBuf[offset + 4: offset + 4 + length].decode("utf-16").rstrip("\x00")

        elif type_id == b"\x17":
            length = int.from_bytes(ExtraBuf[offset: offset + 4], "little")
            rdata[rdata_name] = ExtraBuf[offset + 4: offset + 4 + length].decode("utf-8", errors="ignore").rstrip(
                "\x00")
        elif type_id == b"\x05":
            rdata[rdata_name] = f"0x{ExtraBuf[offset: offset + 8].hex()}"
    return rdata
