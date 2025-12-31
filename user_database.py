import sqlite3


class UserInfoData:
    def __init__(self):
        self.conn = sqlite3.connect('host.db')
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self) -> None:
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS Host
                               (
                                   id
                                   INTEGER
                                   PRIMARY
                                   KEY,
                                   host
                                   TEXT,
                                   port
                                   INTEGER,
                                   username
                                   TEXT,
                                   password
                                   TEXT
                               )''')

    def query(self, host, port, username, password) -> list:
        self.cursor.execute(f'SELECT * FROM Host where host = ? AND port = ? AND username = ? AND password = ?', (host,
                                                                                                                  port,
                                                                                                                  username,
                                                                                                                  password))
        return self.cursor.fetchall()

    def insert(self, host, port, username, password) -> None:
        if len(self.query(host, port, username, password)):
            return
        self.cursor.execute(f'INSERT INTO Host (host, port, username, password) VALUES (?, ?, ?, ?)',
                            (host, port, username, password))
        self.conn.commit()

    def query_all(self):
        self.cursor.execute('SELECT * FROM Host')
        return self.cursor.fetchall()

    def query_idx(self, idx: int):
        self.cursor.execute('SELECT * FROM Host WHERE id = ?', (idx,))
        return self.cursor.fetchone()

    def del_idx(self, idx: int):
        self.cursor.execute('DELETE FROM Host WHERE id = ?', (idx,))
        self.conn.commit()
