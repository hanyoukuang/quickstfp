# database/user_model.py
import sqlite3
from typing import List, Tuple, Optional


class UserInfoDB:
    """
    用户信息数据库模型类。
    纯数据访问层 (DAO)，负责与 SQLite 数据库交互，没有任何 UI 逻辑。
    """

    def __init__(self, db_path: str = 'userinfo.db'):
        """
        初始化数据库连接
        :param db_path: 数据库文件路径，默认为 'userinfo.db'
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self) -> None:
        """初始化数据表结构"""
        create_table_password = '''
            CREATE TABLE IF NOT EXISTS Password (
                id INTEGER PRIMARY KEY,
                host TEXT,
                port INTEGER,
                username TEXT,
                password TEXT
            )
        '''
        create_table_key = '''
            CREATE TABLE IF NOT EXISTS Key (
                id INTEGER PRIMARY KEY,
                host TEXT,
                port INTEGER,
                username TEXT,
                key_path TEXT,
                passphrase TEXT
            )
        '''
        self.cursor.execute(create_table_password)
        self.cursor.execute(create_table_key)
        self.conn.commit()

    # ==========================================
    # 密码登录相关的数据操作
    # ==========================================

    def query_password(self, host: str, port: int, username: str, password: str) -> List[Tuple]:
        """精确查询指定的密码登录记录"""
        sql = "SELECT * FROM Password WHERE host = ? AND port = ? AND username = ? AND password = ?"
        self.cursor.execute(sql, (host, port, username, password))
        return self.cursor.fetchall()

    def insert_password(self, host: str, port: int, username: str, password: str) -> None:
        """
        新增一条密码登录记录
        注意：如果记录已存在，则不会重复插入
        """
        if len(self.query_password(host, port, username, password)) > 0:
            return
        sql = "INSERT INTO Password(host, port, username, password) VALUES (?, ?, ?, ?)"
        self.cursor.execute(sql, (host, port, username, password))
        self.conn.commit()

    def query_all_password(self) -> List[Tuple]:
        """获取所有保存的密码登录记录"""
        sql = "SELECT * FROM Password"
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def query_idx_password(self, idx: int) -> Optional[Tuple]:
        """根据 ID 获取单条密码登录记录"""
        sql = "SELECT * FROM Password WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        return self.cursor.fetchone()

    def del_idx_password(self, idx: int) -> None:
        """根据 ID 删除指定的密码登录记录"""
        sql = "DELETE FROM Password WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        self.conn.commit()

    # ==========================================
    # 秘钥登录相关的数据操作
    # ==========================================

    def query_key(self, host: str, port: int, username: str, key_path: str, passphrase: str = "") -> List[Tuple]:
        """精确查询指定的秘钥登录记录"""
        sql = "SELECT * FROM Key WHERE host = ? AND port = ? AND username = ? AND key_path = ? AND passphrase = ?"
        self.cursor.execute(sql, (host, port, username, key_path, passphrase))
        return self.cursor.fetchall()

    def insert_key(self, host: str, port: int, username: str, key_path: str, passphrase: str = "") -> None:
        """
        新增一条秘钥登录记录
        注意：如果记录已存在，则不会重复插入
        """
        if len(self.query_key(host, port, username, key_path, passphrase)) > 0:
            return
        sql = "INSERT INTO Key(host, port, username, key_path, passphrase) VALUES (?, ?, ?, ?, ?)"
        self.cursor.execute(sql, (host, port, username, key_path, passphrase))
        self.conn.commit()

    def query_all_key(self) -> List[Tuple]:
        """获取所有保存的秘钥登录记录"""
        sql = "SELECT * FROM Key"
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def query_idx_key(self, idx: int) -> Optional[Tuple]:
        """根据 ID 获取单条秘钥登录记录"""
        sql = "SELECT * FROM Key WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        return self.cursor.fetchone()

    def del_idx_key(self, idx: int) -> None:
        """根据 ID 删除指定的秘钥登录记录"""
        sql = "DELETE FROM Key WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        self.conn.commit()

    def close(self) -> None:
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()

    def __del__(self):
        """确保对象销毁时关闭游标和连接"""
        try:
            self.close()
        except Exception:
            pass
