# database/user_model.py
import os
import sqlite3
from typing import List, Tuple, Optional

from cryptography.fernet import Fernet

from core.config import get_data_path


class CryptoManager:
    """
    轻量级加密管理器。
    负责在本地生成并维护唯一的对称加密秘钥文件，提供字符串的透明加解密。
    """

    def __init__(self, key_file: str = None):
        self.key_file = key_file or get_data_path('.secret.key')
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

    def _load_or_generate_key(self) -> bytes:
        # 如果当前目录下存在秘钥文件则直接读取，否则生成一个新的并保存
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key

    def encrypt(self, plain_text: str) -> str:
        if not plain_text:
            return plain_text
        return self.cipher.encrypt(plain_text.encode('utf-8')).decode('utf-8')

    def decrypt(self, cipher_text: str) -> str:
        if not cipher_text:
            return cipher_text
        # 假设所有存储的数据都是加密过的，直接解密
        return self.cipher.decrypt(cipher_text.encode('utf-8')).decode('utf-8')


class UserInfoDB:
    """
    用户信息数据库模型类。
    纯数据访问层 (DAO)，负责与 SQLite 数据库交互，没有任何 UI 逻辑。
    并在底层对敏感信息(密码、passphrase)进行透明加解密拦截。
    """

    def __init__(self, db_path: str = None):
        """
        初始化数据库连接和加密管理器
        :param db_path: 数据库文件路径，默认使用 ~/.config/quickstfp/userinfo.db
        """
        self.db_path = db_path or get_data_path('userinfo.db')
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.crypto = CryptoManager()  # 初始化加密器
        self._migrate_schema()
        self.create_table()

    def _migrate_schema(self) -> None:
        """基于版本号的数据库迁移机制"""
        self.cursor.execute("CREATE TABLE IF NOT EXISTS SchemaVersion (version INTEGER)")
        self.cursor.execute("SELECT version FROM SchemaVersion")
        row = self.cursor.fetchone()
        current_version = row[0] if row else 0
        self.conn.commit()

        if current_version < 1:
            self.cursor.execute("INSERT OR REPLACE INTO SchemaVersion (version) VALUES (1)")
            self.conn.commit()

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
        idx_password = '''
            CREATE INDEX IF NOT EXISTS idx_password_host ON Password(host, port, username)
        '''
        idx_key = '''
            CREATE INDEX IF NOT EXISTS idx_key_host ON Key(host, port, username)
        '''
        self.cursor.execute(create_table_password)
        self.cursor.execute(create_table_key)
        self.cursor.execute(idx_password)
        self.cursor.execute(idx_key)
        self.conn.commit()

    # ==========================================
    # 密码登录相关的数据操作
    # ==========================================

    def query_password(self, host: str, port: int, username: str, password: str) -> List[Tuple]:
        """查询时，优先使用 SQL 过滤 host/port/username，仅对匹配行解密后比较密码"""
        sql = "SELECT * FROM Password WHERE host = ? AND port = ? AND username = ?"
        self.cursor.execute(sql, (host, port, username))
        rows = self.cursor.fetchall()
        return [(r[0], r[1], r[2], r[3], self.crypto.decrypt(r[4]))
                for r in rows if self.crypto.decrypt(r[4]) == password]

    def insert_password(self, host: str, port: int, username: str, password: str) -> None:
        """
        新增一条密码登录记录，在写入数据库前将 password 加密
        """
        # 防止重复插入
        if len(self.query_password(host, port, username, password)) > 0:
            return

        # 加密密码
        encrypted_password = self.crypto.encrypt(password)

        sql = "INSERT INTO Password(host, port, username, password) VALUES (?, ?, ?, ?)"
        self.cursor.execute(sql, (host, port, username, encrypted_password))
        self.conn.commit()

    def query_all_password(self) -> List[Tuple]:
        """获取所有保存的记录，并在返回前解密密码"""
        sql = "SELECT * FROM Password"
        self.cursor.execute(sql)
        rows = self.cursor.fetchall()

        # 将密文解密后重新组装为 Tuple 返回给前端
        return [(r[0], r[1], r[2], r[3], self.crypto.decrypt(r[4])) for r in rows]

    def query_idx_password(self, idx: int) -> Optional[Tuple]:
        """根据 ID 获取单条记录并解密"""
        sql = "SELECT * FROM Password WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        r = self.cursor.fetchone()
        if r:
            return (r[0], r[1], r[2], r[3], self.crypto.decrypt(r[4]))
        return None

    def del_idx_password(self, idx: int) -> None:
        """根据 ID 删除指定的密码登录记录"""
        sql = "DELETE FROM Password WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        self.conn.commit()

    # ==========================================
    # 秘钥登录相关的数据操作
    # ==========================================

    def query_key(self, host: str, port: int, username: str, key_path: str, passphrase: Optional[str] = None) -> List[Tuple]:
        """查询秘钥数据，使用 SQL 过滤 host/port/username/key_path 后仅解密匹配行"""
        sql = "SELECT * FROM Key WHERE host = ? AND port = ? AND username = ? AND key_path = ?"
        self.cursor.execute(sql, (host, port, username, key_path))
        rows = self.cursor.fetchall()
        return [(r[0], r[1], r[2], r[3], r[4], self.crypto.decrypt(r[5]))
                for r in rows if self.crypto.decrypt(r[5]) == passphrase]

    def insert_key(self, host: str, port: int, username: str, key_path: str, passphrase: Optional[str] = None) -> None:
        """
        新增一条秘钥登录记录，在写入数据库前将 passphrase 加密
        """
        if len(self.query_key(host, port, username, key_path, passphrase)) > 0:
            return

        # 加密 passphrase
        encrypted_passphrase = self.crypto.encrypt(passphrase or "")

        sql = "INSERT INTO Key(host, port, username, key_path, passphrase) VALUES (?, ?, ?, ?, ?)"
        self.cursor.execute(sql, (host, port, username, key_path, encrypted_passphrase))
        self.conn.commit()

    def query_all_key(self) -> List[Tuple]:
        """获取所有保存的秘钥记录，并在返回前解密 passphrase"""
        sql = "SELECT * FROM Key"
        self.cursor.execute(sql)
        rows = self.cursor.fetchall()

        return [(r[0], r[1], r[2], r[3], r[4], self.crypto.decrypt(r[5])) for r in rows]

    def query_idx_key(self, idx: int) -> Optional[Tuple]:
        """根据 ID 获取单条记录并解密"""
        sql = "SELECT * FROM Key WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        r = self.cursor.fetchone()
        if r:
            return (r[0], r[1], r[2], r[3], r[4], self.crypto.decrypt(r[5]))
        return None

    def del_idx_key(self, idx: int) -> None:
        """根据 ID 删除指定的秘钥登录记录"""
        sql = "DELETE FROM Key WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        self.conn.commit()

    def close(self) -> None:
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def update_password(self, idx: int, host: str, port: int, username: str, password: str) -> None:
        """更新密码登录记录"""
        encrypted_password = self.crypto.encrypt(password)
        sql = "UPDATE Password SET host=?, port=?, username=?, password=? WHERE id=?"
        self.cursor.execute(sql, (host, port, username, encrypted_password, idx))
        self.conn.commit()

    def update_key(self, idx: int, host: str, port: int, username: str, key_path: str,
                   passphrase: Optional[str] = None) -> None:
        """更新秘钥登录记录"""
        encrypted_passphrase = self.crypto.encrypt(passphrase or "")
        sql = "UPDATE Key SET host=?, port=?, username=?, key_path=?, passphrase=? WHERE id=?"
        self.cursor.execute(sql, (host, port, username, key_path, encrypted_passphrase, idx))
        self.conn.commit()
