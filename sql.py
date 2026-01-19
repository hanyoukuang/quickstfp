import sqlite3

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QPushButton, QWidget, QLabel, \
    QHBoxLayout, QMessageBox


class UserInfo:
    def __init__(self):
        self.conn = sqlite3.connect('userinfo.db')
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self) -> None:
        create_table_password = '''CREATE TABLE IF NOT EXISTS Password (
                                       id INTEGER PRIMARY KEY,
                                       host TEXT,
                                       port INTEGER,
                                       username TEXT,
                                       password TEXT
                                   )'''
        create_table_key = '''CREATE TABLE IF NOT EXISTS Key (
                                       id INTEGER PRIMARY KEY,
                                       host TEXT,
                                       port INTEGER,
                                       username TEXT,
                                       key_path TEXT,
                                       passphrase TEXT
                                   )'''
        self.cursor.execute(create_table_password)
        self.cursor.execute(create_table_key)
        self.conn.commit()

    def query_password(self, host: str, port: int, username: str, password: str) -> list[tuple]:
        sql = "Select * from Password where host = ? and port = ? and username = ? and password = ?"
        self.cursor.execute(sql, (host, port, username, password))
        return self.cursor.fetchall()

    def query_key(self, host: str, port: int, username: str, key_path: str, passphrase: str = "") -> list[tuple]:
        sql = "Select * from Key where host = ? and port = ? and username = ? and key_path = ? and passphrase = ?"
        self.cursor.execute(sql, (host, port, username, key_path, passphrase))
        return self.cursor.fetchall()

    def insert_password(self, host: str, port: int, username: str, password: str) -> None:
        if len(self.query_password(host, port, username, password)):
            return
        sql = "INSERT INTO Password(host, port, username, password) VALUES (?, ?, ?, ?)"
        self.cursor.execute(sql, (host, port, username, password))
        self.conn.commit()

    def insert_key(self, host: str, port: int, username: str, key_path: str, passphrase: str = "") -> None:
        if len(self.query_key(host, port, username, key_path, passphrase)):
            return
        sql = "INSERT INTO Key(host, port, username, key_path, passphrase) VALUES (?, ?, ?, ?, ?)"
        self.cursor.execute(sql, (host, port, username, key_path, passphrase))
        self.conn.commit()

    def query_all_password(self) -> list[tuple]:
        sql = "SELECT * FROM Password"
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def query_all_key(self) -> list[tuple]:
        sql = "SELECT * FROM Key"
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def query_idx_password(self, idx: int):
        sql = "SELECT * FROM Password WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        return self.cursor.fetchone()

    def query_idx_key(self, idx: int):
        sql = "SELECT * FROM Key WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        return self.cursor.fetchone()

    def del_idx_password(self, idx: int):
        sql = "DELETE FROM Password WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        self.conn.commit()

    def del_idx_key(self, idx: int):
        sql = "DELETE FROM Key WHERE id = ?"
        self.cursor.execute(sql, (idx,))
        self.conn.commit()


class UserItem(QListWidgetItem):
    sql_idx: int

    def __init__(self, idx: int):
        super().__init__()
        self.sql_idx = idx


class UserControl(QListWidget):
    def __init__(self, sftp_main_window):
        super().__init__(parent=sftp_main_window)
        self.setWindowFlags(Qt.WindowType.Tool)
        self.userinfo = UserInfo()
        self.add_all_user()

    def create_widget(self, idx: int, text: str) -> tuple[UserItem, QPushButton]:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        label = QLabel(text)
        button = QPushButton("删除")
        layout.addWidget(label)
        layout.addWidget(button)
        item = UserItem(idx)
        self.addItem(item)
        item.setSizeHint(widget.sizeHint())
        self.setItemWidget(item, widget)
        return item, button

    def create_user_item_password(self, idx: int, text: str):
        item, button = self.create_widget(idx, text)

        def delete():
            self.removeItemWidget(item)
            query = QMessageBox.question(
                self, "询问", "是否删除用户信息",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if query == QMessageBox.StandardButton.Ok:
                self.userinfo.del_idx_password(item.sql_idx)

        button.clicked.connect(delete)

    def create_user_item_key(self, idx: int, text: str):
        item, button = self.create_widget(idx, text)

        def delete():
            self.removeItemWidget(item)
            self.userinfo.del_idx_key(item.sql_idx)
            query = QMessageBox.question(
                self, "询问", "是否删除用户信息",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if query == QMessageBox.StandardButton.Ok:
                self.userinfo.del_idx_key(item.sql_idx)

        button.clicked.connect(delete)

    def add_all_user(self):
        for value in self.userinfo.query_all_password():
            self.create_user_item_password(value[0], f"{value[1]} {value[2]} {value[3]}")
        for value in self.userinfo.query_all_key():
            self.create_user_item_key(value[0], f"{value[1]} {value[2]} {value[3]} {value[4]}")
