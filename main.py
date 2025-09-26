import os
import sys
import asyncio
from typing import Sequence
import asyncssh
import asyncio_pool
from PyQt6.QtGui import QAction, QDropEvent, QDragEnterEvent, QCloseEvent
from PyQt6.QtCore import QThread, pyqtSignal, pyqtSlot, Qt, QPoint, QModelIndex
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QProgressBar, QLineEdit, QFormLayout,
    QLabel, QPushButton, QHBoxLayout, QStyle, QListWidget, QListWidgetItem,
    QTextEdit, QStackedWidget, QFileDialog, QGridLayout, QMenu, QInputDialog,
    QMainWindow, QTabWidget, QComboBox, QCheckBox, QAbstractItemView, QSplitter,
    QMessageBox, QToolBar
)
from qdarktheme import setup_theme
from user_database import UserInfoData

# 尝试导入 uvloop 提高异步性能，兼容 Windows 和其他平台
try:
    import uvloop
except ImportError:
    import winuvloop as uvloop
finally:
    uvloop.install()


def path_stand(src: str, loc: str) -> tuple[str, str]:
    """
    标准化文件路径格式，并将源文件/文件夹名添加到目标路径末尾
    示例:
        src = "c:\\path\\to\\src\\" -> "c:/path/to/src"
        loc = "c:\\path\\to\\loc\\" -> "c:/path/to/loc/src"
    :param src: 源文件或文件夹路径
    :param loc: 目标路径
    :return: 标准化后的 (src, loc) 元组
    """
    src = src.replace('\\', '/').rstrip('/')
    loc = loc.replace('\\', '/').rstrip('/')
    loc = '/'.join((loc, src.split('/')[-1]))
    return src, loc


class PasswordController(QWidget):
    """
    管理用户密码的界面，基于 host.db 数据库存储用户信息
    提供用户列表显示、添加和删除功能
    """

    def __init__(self) -> None:
        super().__init__()
        self.userinfo = UserInfoData()  # 用户信息数据库实例
        self.vbox = QVBoxLayout()  # 垂直布局
        self.user_list_widget = QListWidget()  # 用户信息列表控件
        self.vbox.addWidget(self.user_list_widget)
        self.setLayout(self.vbox)
        self.idxs = []  # 存储用户记录的索引
        self.add_user_dict = {}  # 记录已添加的用户，防止重复
        self.user_list_widget.clicked.connect(self.item_clicked)

    def add_all_user(self) -> None:
        """从数据库加载所有用户信息并显示在列表中"""
        for value in self.userinfo.query_all():
            if self.add_user_dict.get(value):
                continue
            self.add_user_dict[value] = True
            self.add_item(*value)

    def add_item(self, idx, host, port, username, _password) -> None:
        """
        添加用户条目到列表
        :param idx: 用户记录的数据库索引
        :param host: 主机地址
        :param port: 端口号
        :param username: 用户名
        :param _password: 密码（不显示）
        """
        self.idxs.append(idx)
        item = QListWidgetItem(f"IP地址: {host} 端口号:{port} 用户名:{username}")
        item.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
        self.user_list_widget.addItem(item)

    def item_clicked(self, idx: QModelIndex) -> None:
        """
        处理用户点击列表项，询问是否删除用户信息
        :param idx: 点击的列表项索引
        """
        query = QMessageBox.question(
            self, "询问", "是否删除用户信息",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if query == QMessageBox.StandardButton.Ok:
            self.user_list_widget.takeItem(idx.row())
            self.userinfo.del_idx(self.idxs[idx.row()])


class Edit(QWidget):
    """
    文件编辑窗口，用于编辑远程文件内容
    """

    def __init__(self, src: str, text: str) -> None:
        super().__init__()
        self.setGeometry(0, 0, 500, 500)  # 设置窗口大小
        self.src = src  # 文件路径
        self.button = QPushButton("保存")  # 保存按钮
        self.vbox = QVBoxLayout()  # 垂直布局
        self.textEdit = QTextEdit(text)  # 文本编辑区域
        self.vbox.addWidget(self.button)
        self.vbox.addWidget(self.textEdit)
        self.setLayout(self.vbox)
        self.show()


class Transport(QThread):
    """
    文件传输基类，支持上传和下载，管理进度条和错误信息
    TODO: 增加断点续传
    """

    def __init__(self, src: str, loc: str, co_num: int, session, pbar: int) -> None:
        super().__init__()
        self.src = src  # 源路径
        self.loc = loc  # 目标路径
        self.co_num = co_num  # 并发协程数量
        self.session = session  # SFTP 会话
        self.sftp = session.sftp  # SFTP 客户端
        self.loop = session.loop  # 异步事件循环
        self.task_core = []  # 存储传输任务
        self.transport_fail_file = []  # 记录传输失败的文件
        self.now_progress_bar = 0  # 当前进度条值
        self.pbar = pbar  # 进度条索引
        self.msg = session.msg  # 进度条更新信号
        self.pbar_msg = session.pbar_msg  # 进度条初始化信号
        self.err_msg = session.err_msg  # 错误信息信号

    async def start_core(self):
        """
        启动并发传输任务，优化大小文件传输效率
        大文件优先，同时处理小文件
        """
        self.task_core.sort(key=lambda item: item[0], reverse=True)
        self.task_core = [core for _, core in self.task_core]
        r = len(self.task_core) - 1
        async with asyncio_pool.AioPool(self.co_num, loop=self.loop) as pool:
            for l in range(0, r + 1):
                if r <= l + 1:
                    break
                self.task_core[l] = await pool.spawn(self.task_core[l])
                for idx in reversed(range(l + 1, r + 1)):
                    if self.task_core[l].done():
                        break
                    self.task_core[idx] = await pool.spawn(self.task_core[idx])
                    r = idx

    async def transport(self):
        """抽象方法，具体传输逻辑由子类实现"""

    def run(self):
        """运行传输任务并处理错误信息"""
        asyncio.run_coroutine_threadsafe(self.transport(), self.loop).result()
        err_src_str = "\n".join(self.transport_fail_file)
        self.err_msg.emit(err_src_str)


class DownloadTransport(Transport):
    """文件下载类，继承自 Transport"""

    def __init__(self, src: str, loc: str, co_num: int, session, pbar: int) -> None:
        super().__init__(src, loc, co_num, session, pbar)

    async def _transport_file(self, src: str, loc: str) -> None:
        """
        下载单个文件并更新进度条
        :param src: 远程文件路径
        :param loc: 本地目标路径
        """
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.msg.emit(self.pbar, self.now_progress_bar + now_size - last_size)
            self.now_progress_bar += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.get(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError):
            all_size = await self.sftp.getsize(src)
            self.msg.emit(self.pbar, self.now_progress_bar + all_size - last_size)
            self.now_progress_bar += all_size - last_size
            self.transport_fail_file.append(src)

    async def _transport_dir_init(self, src: str, loc: str) -> int:
        """
        初始化下载目录，递归处理子目录和文件
        :param src: 远程目录路径
        :param loc: 本地目标路径
        :return: 目录中文件总大小
        """
        if not os.path.exists(loc):
            os.mkdir(loc)
        task_list = []
        total = 0
        async for entry in self.sftp.scandir(src):
            if entry.filename in ('.', '..'):
                continue
            next_src = "/".join((src, entry.filename))
            next_loc = "/".join((loc, entry.filename))
            if entry.attrs.type == 2:  # 目录
                task_list.append(asyncio.create_task(self._transport_dir_init(next_src, next_loc)))
            else:  # 文件
                total += entry.attrs.size
                self.task_core.append((entry.attrs.size, self._transport_file(next_src, next_loc)))
        for future in asyncio.as_completed(task_list):
            total += await future
        return total

    async def transport(self) -> None:
        """执行下载任务，支持文件和目录"""
        src, loc = path_stand(self.src, self.loc)
        if await self.sftp.isdir(src):
            all_size = await self._transport_dir_init(src, loc)
            self.pbar_msg.emit(self.pbar, all_size)
            await self.start_core()
        else:
            all_size = await self.sftp.getsize(src)
            self.pbar_msg.emit(self.pbar, all_size)
            await self._transport_file(src, loc)
        self.msg.emit(self.pbar, all_size)


class UploadTransport(Transport):
    """文件上传类，继承自 Transport"""

    def __init__(self, src: str, loc: str, co_num: int, session, pbar: int) -> None:
        super().__init__(src, loc, co_num, session, pbar)
        self.task_list_mkdir = []

    async def _transport_file(self, src: str, loc: str) -> None:
        """
        上传单个文件并更新进度条
        :param src: 本地文件路径
        :param loc: 远程目标路径
        """
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.msg.emit(self.pbar, self.now_progress_bar + now_size - last_size)
            self.now_progress_bar += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.put(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError):
            all_size = os.path.getsize(src)
            self.msg.emit(self.pbar, self.now_progress_bar + all_size - last_size)
            self.now_progress_bar += all_size - last_size
            self.transport_fail_file.append(src)

    def _transport_dir_init(self, src: str, loc: str) -> int:
        """
        初始化上传目录，递归处理子目录和文件
        :param src: 本地目录路径
        :param loc: 远程目标路径
        :return: 目录中文件总大小
        """
        total_size = 0
        self.task_list_mkdir.append(self.sftp.makedirs(loc, exist_ok=True))
        for entry in os.scandir(src):
            next_src = "/".join((src, entry.name))
            next_loc = "/".join((loc, entry.name))
            if entry.is_dir():
                total_size += self._transport_dir_init(next_src, next_loc)
            else:
                self.task_core.append((entry.stat().st_size, self._transport_file(next_src, next_loc)))
                total_size += entry.stat().st_size
        return total_size

    async def transport(self) -> None:
        """执行上传任务，支持文件和目录"""
        src, loc = path_stand(self.src, self.loc)
        if os.path.isdir(src):
            all_size = self._transport_dir_init(src, loc)
            self.pbar_msg.emit(self.pbar, all_size)
            for future in asyncio.as_completed(self.task_list_mkdir):
                await future
            await self.start_core()
        else:
            all_size = os.path.getsize(src)
            self.pbar_msg.emit(self.pbar, all_size)
            await self._transport_file(src, loc)
        self.msg.emit(self.pbar, all_size)


class SFTPSession(QThread):
    """
    SFTP 会话管理类，负责与远程服务器的连接和文件操作
    """
    msg = pyqtSignal(int, int)  # 进度条更新信号
    pbar_msg = pyqtSignal(int, int)  # 进度条初始化信号
    err_msg = pyqtSignal(str)  # 错误信息信号

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.transport = []  # 存储传输任务
        self.loop = asyncio.new_event_loop()  # 创建异步事件循环
        self.ssh = self.loop.run_until_complete(
            asyncssh.connect(host=host, port=port, username=username, password=password, known_hosts=None))
        self.sftp = self.loop.run_until_complete(self.ssh.start_sftp_client())

    def run(self) -> None:
        """运行异步事件循环"""
        self.loop.run_forever()

    def getcwd(self) -> str:
        """获取当前工作目录"""
        return asyncio.run_coroutine_threadsafe(self.sftp.getcwd(), self.loop).result()

    def read_dir(self, src: str) -> Sequence[asyncssh.SFTPName]:
        """读取指定目录内容"""
        return asyncio.run_coroutine_threadsafe(self.sftp.readdir(src), self.loop).result()

    def change_dir(self, src: str) -> None:
        """切换工作目录"""
        asyncio.run_coroutine_threadsafe(self.sftp.chdir(src), self.loop).result()

    def is_file(self, src: str) -> bool:
        """判断路径是否为文件"""
        return asyncio.run_coroutine_threadsafe(self.sftp.isfile(src), self.loop).result()

    async def _read_file(self, src: str) -> str:
        """异步读取文件内容"""
        async with self.sftp.open(src, 'rb') as f:
            return (await f.read(1024)).decode()

    def read_file(self, src: str) -> str:
        """同步读取文件内容"""
        return asyncio.run_coroutine_threadsafe(self._read_file(src), self.loop).result()

    async def _save_file(self, src: str, text: str) -> None:
        """异步保存文件内容"""
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text.encode())

    def save_file(self, src: str, text: str) -> None:
        """同步保存文件内容"""
        asyncio.run_coroutine_threadsafe(self._save_file(src, text), self.loop).result()

    def del_file(self, src: str) -> None:
        """删除文件"""
        asyncio.run_coroutine_threadsafe(self.sftp.remove(src), self.loop).result()

    def del_dir(self, src: str) -> None:
        """删除目录"""
        asyncio.run_coroutine_threadsafe(self.remove_dir(src), self.loop).result()

    def make_dir(self, src: str) -> None:
        """创建目录"""
        asyncio.run_coroutine_threadsafe(self.sftp.makedirs(src, exist_ok=True), self.loop).result()

    def rename(self, src: str, new: str) -> None:
        """重命名文件或目录"""
        asyncio.run_coroutine_threadsafe(self.sftp.rename(src, new), self.loop).result()

    def download(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        """启动下载任务"""
        dt = DownloadTransport(src, loc, co_num, self, pbar)
        dt.start()
        self.transport.append(dt)

    def upload(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        """启动上传任务"""
        ut = UploadTransport(src, loc, co_num, self, pbar)
        ut.start()
        self.transport.append(ut)

    async def remove_dir(self, src: str) -> None:
        """异步删除目录"""
        await self.ssh.run(f"rm -rf {src}")

    async def _run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        """异步执行 SSH 命令"""
        return await self.ssh.run(com)

    def run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        """同步执行 SSH 命令"""
        return asyncio.run_coroutine_threadsafe(self._run_command(com), self.loop).result()

    def realpath(self, src: str) -> str:
        """获取文件的真实路径"""
        return asyncio.run_coroutine_threadsafe(self.sftp.realpath(src.encode()), self.loop).result().decode()

    def move_file(self, old_path: str, new_path: str) -> None:
        """移动文件或目录"""
        self.run_command(f"mv {old_path} {new_path}")

    def copy_file(self, src: str, dst: str) -> None:
        """复制文件或目录"""
        self.run_command(f"cp -r {src} {dst}")


class RemoteFileDisplay(QWidget):
    """
    远程文件显示界面，支持文件浏览、编辑、删除、移动、复制等操作
    TODO: 将文件拖出
    """

    def __init__(self, sftp_main_window) -> None:
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.session = sftp_main_window.session
        self.main_window_path = self.session.getcwd()
        self.dir_item = []  # 目录项列表
        self.file_item = []  # 文件项列表
        self.move_paths = []  # 待移动的文件路径
        self.copy_paths = []  # 待复制的文件路径
        self.back_button = QPushButton("返回上层目录")
        self.select_button = QPushButton("选择")
        self.no_button = QPushButton("取消")
        self.path_edit = QLineEdit()
        self.search_edit = QLineEdit()
        self.search_label = QLabel("搜索文件:")
        self.vbox = QVBoxLayout()
        self.display_file_list = QListWidget()
        self.select_item = None
        self.setLayout(self.vbox)
        self.init_ui()

    def init_ui(self) -> None:
        """初始化界面布局和事件绑定"""
        self.display_file_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.setAcceptDrops(True)  # 启用拖放支持
        self.search_edit.textChanged.connect(self.search_edit_value)
        self.back_button.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowBack))
        self.back_button.setStyleSheet("text-align: left;")
        hbox = QHBoxLayout()
        hbox_search = QHBoxLayout()
        hbox_search.addWidget(self.search_label)
        hbox_search.addWidget(self.search_edit)
        hbox.addWidget(self.back_button)
        hbox.addWidget(self.path_edit)
        hbox.addLayout(hbox_search)
        self.path_edit.setReadOnly(True)
        self.path_edit.setText(self.session.getcwd())
        self.vbox.addLayout(hbox)
        self.vbox.addWidget(self.display_file_list)
        self.back_button.clicked.connect(lambda: self.double_item_clicked(QListWidgetItem("..")))
        self.display_file_list.itemDoubleClicked.connect(self.double_item_clicked)
        self.display_file_list.itemClicked.connect(self.item_clicked)
        self.display_file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.display_file_list.customContextMenuRequested.connect(self.show_context_menu)
        self.display_dir(".")

    def search_edit_value(self, text) -> None:
        """根据输入过滤显示文件和目录"""
        if not text:
            for item in self.dir_item + self.file_item:
                item.setHidden(False)
            return
        for item in self.dir_item + self.file_item:
            item.setHidden(text not in item.text())

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        """处理拖放进入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        """处理拖放释放事件，上传拖放的文件"""
        for url in event.mimeData().urls():
            self.sftp_main_window.upload(url.toLocalFile(), self.session.getcwd(), 2)
        event.acceptProposedAction()

    def closeEvent(self, event: QCloseEvent) -> None:
        """窗口关闭时恢复初始目录"""
        self.session.change_dir(self.main_window_path)

    def show_context_menu(self, pos: QPoint) -> None:
        """显示右键上下文菜单"""
        item = self.display_file_list.itemAt(pos)
        context_menu = QMenu(self)
        reload_action = context_menu.addAction("刷新")
        makedir_action = context_menu.addAction("新建文件夹")
        new_file_action = context_menu.addAction("新文件")
        reload_action.triggered.connect(self.reload_dir)
        makedir_action.triggered.connect(self.makedir)
        new_file_action.triggered.connect(self.new_file)
        if item:
            edit_action = context_menu.addAction("打开")
            del_action = context_menu.addAction("删除")
            rename_action = context_menu.addAction("重命名")
            move_action = context_menu.addAction("移动")
            copy_action = context_menu.addAction("复制")
            download_action = context_menu.addAction("下载")
            rename_action.triggered.connect(lambda: self.rename(item))
            edit_action.triggered.connect(lambda: self.double_item_clicked(item))
            del_action.triggered.connect(self.del_items)
            move_action.triggered.connect(self.move_items)
            copy_action.triggered.connect(self.copy_items)
            download_action.triggered.connect(self.download_items)
        if self.move_paths:
            context_menu.addAction("放置").triggered.connect(self.put_items)
        if self.copy_paths:
            context_menu.addAction("粘贴").triggered.connect(self.paste_items)
        context_menu.exec(self.display_file_list.mapToGlobal(pos))

    def download_items(self) -> None:
        """下载选中的文件或目录"""
        for item in self.display_file_list.selectedItems():
            self.download_item(item)

    def download_item(self, item: QListWidgetItem) -> None:
        """下载单个文件或目录"""
        self.sftp_main_window.download(self.realpath(item.text()), "./tmp", 2)

    def paste_items(self) -> None:
        """粘贴复制的文件或目录"""
        for old_path in self.copy_paths:
            self.session.copy_file(old_path, self.session.getcwd())
        self.copy_paths.clear()
        self.reload_dir()

    def put_items(self) -> None:
        """放置移动的文件或目录"""
        for old_path in self.move_paths:
            self.session.move_file(old_path, self.session.getcwd())
        self.move_paths.clear()
        self.reload_dir()

    def reload_dir(self) -> None:
        """刷新当前目录显示"""
        self.display_file_list.clear()
        self.display_dir()

    def item_clicked(self, item: QListWidgetItem) -> None:
        """记录点击的列表项"""
        self.select_item = item

    def double_item_clicked(self, item: QListWidgetItem) -> None:
        """处理双击事件，打开文件或切换目录"""
        if not self.session.is_file(item.text()):
            self.session.change_dir(item.text())
            self.display_file_list.clear()
            self.display_dir()
            self.path_edit.setText(self.session.getcwd())
            return
        src = item.text()
        edit = Edit(src, self.session.read_file(src))
        edit.button.clicked.connect(lambda: self.session.save_file(src, edit.textEdit.toPlainText()))

    def del_items(self) -> None:
        """删除选中的文件或目录"""
        for item in self.display_file_list.selectedItems():
            self.del_item(item)
        self.reload_dir()

    def del_item(self, item: QListWidgetItem) -> None:
        """删除单个文件或目录"""
        src = self.realpath(item.text())
        if not self.session.is_file(src):
            self.session.del_dir(src)
        else:
            self.session.del_file(src)

    def makedir(self) -> None:
        """创建新文件夹"""
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok:
            self.session.make_dir(str(text))
            self.reload_dir()

    def new_file(self) -> None:
        """创建新文件"""
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok:
            self.session.save_file(str(text), "")
            self.reload_dir()

    def rename(self, item: QListWidgetItem) -> None:
        """重命名文件或目录"""
        text, ok = QInputDialog.getText(self, "重命名", "输入新的文件名")
        if ok:
            self.session.rename(item.text(), str(text))
            self.reload_dir()

    def display_dir(self, src: str = ".") -> None:
        """显示指定目录的内容"""
        self.dir_item.clear()
        self.file_item.clear()
        for entry in self.session.read_dir(src):
            if entry.filename in ('.', '..'):
                continue
            icon = QStyle.StandardPixmap.SP_FileIcon if entry.attrs.type != 2 else QStyle.StandardPixmap.SP_DirIcon
            item = QListWidgetItem(entry.filename)
            item.setIcon(QApplication.style().standardIcon(icon))
            (self.file_item if entry.attrs.type != 2 else self.dir_item).append(item)
        for item in self.dir_item + self.file_item:
            self.display_file_list.addItem(item)

    def move_items(self) -> None:
        """将选中的文件或目录加入移动列表"""
        for item in self.display_file_list.selectedItems():
            self.move_item(item)

    def move_item(self, item: QListWidgetItem) -> None:
        """将单个文件或目录加入移动列表"""
        item.setHidden(True)
        self.move_paths.append(self.realpath(item.text()))

    def copy_items(self) -> None:
        """将选中的文件或目录加入复制列表"""
        for item in self.display_file_list.selectedItems():
            self.copy_item(item)

    def copy_item(self, item: QListWidgetItem) -> None:
        """将单个文件或目录加入复制列表"""
        self.copy_paths.append(self.realpath(item.text()))

    def realpath(self, path: str) -> str:
        """获取真实路径"""
        return self.session.realpath(path)


class GetTransportPathWidget(QWidget):
    """传输路径选择基类，用于上传和下载路径设置"""

    def __init__(self, sftp_main_window) -> None:
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.ok_button = QPushButton("开始")
        self.src_edit = QLineEdit()
        self.src_button = QPushButton("源文件")
        self.src_button_dir = QPushButton("源文件夹")
        self.dst_edit = QLineEdit()
        self.dst_button = QPushButton("目标地址")
        self.co_num_edit = QLineEdit()
        self.grid = QGridLayout()
        self.setLayout(self.grid)
        self.remote_file = RemoteFileDisplay(self.sftp_main_window)
        self.init_ui()

    def init_ui(self) -> None:
        """初始化界面布局"""
        self.grid.addWidget(self.src_edit, 0, 0)
        self.grid.addWidget(self.src_button, 0, 1)
        self.grid.addWidget(self.src_button_dir, 0, 2)
        self.grid.addWidget(self.dst_edit, 1, 0)
        self.grid.addWidget(self.dst_button, 1, 1)
        self.grid.addWidget(self.co_num_edit, 2, 0)
        self.grid.addWidget(QLabel("协程数量"), 2, 1)
        self.grid.addWidget(self.ok_button, 3, 0)


class GetDownloadPathWidget(GetTransportPathWidget):
    """下载路径选择窗口"""

    def __init__(self, sftp_main_window) -> None:
        super().__init__(sftp_main_window)
        self.main_window = sftp_main_window
        self.src_button_dir.setVisible(False)
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(self.selected_file)
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.ok_button.clicked.connect(self.start_download)

    def selected_file(self) -> None:
        """选择远程文件路径"""
        self.src_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text()))
        self.remote_file.close()

    def start_download(self) -> None:
        """开始下载任务"""
        if self.src_edit.text() and self.dst_edit.text() and self.co_num_edit.text():
            self.main_window.download(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
            self.close()
        else:
            QMessageBox.warning(self, "参数警告", "请参数不能为空", QMessageBox.StandardButton.Ok)

    def get_src_file(self) -> None:
        """显示远程文件选择窗口"""
        self.remote_file.show()

    def get_local_file(self) -> None:
        """选择本地目标目录"""
        file_path = QFileDialog.getExistingDirectory(self, "Open file")
        self.dst_edit.setText(file_path)


class GetUploadPathWidget(GetTransportPathWidget):
    """上传路径选择窗口"""

    def __init__(self, sftp_main_window) -> None:
        super().__init__(sftp_main_window)
        self.main_window = sftp_main_window
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(self.selected_file)
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.ok_button.clicked.connect(self.start_upload)
        self.src_button_dir.clicked.connect(self.get_src_dir)

    def start_upload(self) -> None:
        """开始上传任务"""
        if self.src_edit.text() and self.dst_edit.text() and self.co_num_edit.text():
            self.main_window.upload(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
            self.close()
        else:
            QMessageBox.warning(self, "参数警告", "请把所有参数填写完整", QMessageBox.StandardButton.Ok)

    def selected_file(self) -> None:
        """选择远程目标路径"""
        self.dst_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text()))
        self.remote_file.close()

    def get_local_file(self) -> None:
        """显示远程文件选择窗口"""
        self.remote_file.show()

    def get_src_dir(self):
        """选择本地源目录"""
        dir_path = QFileDialog.getExistingDirectory(self, "Open dir")
        self.src_edit.setText(dir_path)

    def get_src_file(self):
        """选择本地源文件"""
        file_path = QFileDialog.getOpenFileName(self, "Open file")
        if file_path[0]:
            self.src_edit.setText(file_path[0])


class ControlListWidget(QWidget):
    """控制面板，切换 SFTP 文件列表、密码管理和传输管理"""

    def __init__(self, sftp_main_window) -> None:
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.layout = QVBoxLayout()
        self.control_list = QListWidget()
        self.items = ["SFTP文件", "密码管理", "传输管理"]
        self.control_list.addItems(self.items)
        self.control_list.clicked.connect(self.clicked_item)
        self.layout.addWidget(self.control_list)
        self.setLayout(self.layout)
        self.function = {
            "SFTP文件": self.sftp_file_list,
            "密码管理": self.password_changed,
            "传输管理": self.transport
        }

    def clicked_item(self, index: QModelIndex) -> None:
        """处理控制面板选项点击"""
        text = self.control_list.item(index.row()).text()
        self.function[text]()

    def password_changed(self) -> None:
        """切换到密码管理界面"""
        self.sftp_main_window.password_control.add_all_user()
        self.sftp_main_window.stacked_widget.setCurrentIndex(2)

    def sftp_file_list(self) -> None:
        """切换到 SFTP 文件列表界面"""
        self.sftp_main_window.stacked_widget.setCurrentIndex(0)

    def transport(self) -> None:
        """切换到传输管理界面"""
        self.sftp_main_window.stacked_widget.setCurrentIndex(1)


class SFTPMainWindow(QWidget):
    """SFTP 主窗口，整合文件显示、上传下载、密码管理和进度条"""

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.session = SFTPSession(host, port, username, password)
        self.session.msg.connect(self.update_progress)
        self.session.pbar_msg.connect(self.set_progress)
        self.session.err_msg.connect(self.display_error)
        self.session.start()
        self.stacked_widget = QStackedWidget()
        self.display_pbar_list = QListWidget()
        self.remote_file_widget = RemoteFileDisplay(self)
        self.download_widget = GetDownloadPathWidget(self)
        self.upload_widget = GetUploadPathWidget(self)
        self.password_control = PasswordController()
        self.control_windows = ControlListWidget(self)
        self.hbox = QHBoxLayout()
        self.setLayout(self.hbox)
        self.splitter_control_transport = QSplitter(Qt.Orientation.Horizontal)
        self.pbars = []
        self.init_ui()

    def init_ui(self) -> None:
        """初始化主窗口布局"""
        self.setWindowTitle("SFTP Session")
        self.splitter_control_transport.addWidget(self.control_windows)
        self.splitter_control_transport.addWidget(self.stacked_widget)
        self.splitter_control_transport.setStretchFactor(0, 0)
        self.splitter_control_transport.setStretchFactor(1, 3)
        self.hbox.addWidget(self.splitter_control_transport)
        self.stacked_widget.addWidget(self.remote_file_widget)  # 0: 文件列表
        self.stacked_widget.addWidget(self.display_pbar_list)  # 1: 传输管理
        self.stacked_widget.addWidget(self.password_control)  # 2: 密码管理

    def add_pbar(self, src) -> int:
        """添加进度条到传输管理界面"""
        icon = QStyle.StandardPixmap.SP_FileIcon if self.session.is_file(src) else QStyle.StandardPixmap.SP_DirIcon
        pbar = QProgressBar()
        item = QListWidgetItem(self.display_pbar_list)
        item_widget = QWidget()
        layout = QHBoxLayout(item_widget)
        text_label = QLabel(src)
        picture_label = QLabel()
        picture_label.setPixmap(QApplication.style().standardIcon(icon).pixmap(16, 16))
        layout.addWidget(picture_label)
        layout.addWidget(text_label)
        layout.addWidget(pbar)
        layout.setContentsMargins(0, 0, 0, 0)
        self.display_pbar_list.setItemWidget(item, item_widget)
        self.display_pbar_list.addItem(item)
        self.pbars.append(pbar)
        return len(self.pbars) - 1

    def download(self, src: str, loc: str, co_num: int) -> None:
        """启动下载任务并添加进度条"""
        pbar = self.add_pbar(src)
        self.session.download(src, loc, co_num, pbar)

    def upload(self, src: str, loc: str, co_num: int) -> None:
        """启动上传任务并添加进度条"""
        pbar = self.add_pbar(src)
        self.session.upload(src, loc, co_num, pbar)

    @pyqtSlot(int, int)
    def update_progress(self, pbar, value) -> None:
        """更新进度条值"""
        self.pbars[pbar].setValue(value)

    @pyqtSlot(int, int)
    def set_progress(self, pbar, value) -> None:
        """设置进度条范围"""
        self.pbars[pbar].setRange(0, value)

    @pyqtSlot(str)
    def display_error(self, value) -> None:
        """显示传输错误信息"""
        if value:
            QMessageBox.warning(self, "传输警告", f"{value}传输失败，注意检查权限和SFTP配置文件",
                                QMessageBox.StandardButton.Ok)


class LoginWindow(QWidget):
    """登录窗口，用于输入 SFTP 连接信息"""

    def __init__(self, tab: QTabWidget, sftp_widget_list: list) -> None:
        super().__init__()
        self.sftp_widget_list = sftp_widget_list
        self.tab = tab
        self.setWindowTitle("Login")
        self.form = QFormLayout()
        self.combox = QComboBox()
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.login_button = QPushButton("登录")
        self.cancel_button = QPushButton("取消")
        self.checkbox = QCheckBox()
        self.userinfo = UserInfoData()
        self.sftp_main_window = SFTPMainWindow
        self.setLayout(self.form)
        self.idxs = []
        self.password_display = False
        self.init_ui()

    def init_ui(self) -> None:
        """初始化登录窗口布局"""
        self.combox.currentIndexChanged.connect(self.selected_item)
        self.checkbox.clicked.connect(self.set_password_mode)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        users = [f"{query_value[1]}:{query_value[3]}" for query_value in self.userinfo.query_all()]
        self.idxs = [query_value[0] for query_value in self.userinfo.query_all()]
        self.combox.addItems(users)
        self.form.addRow(QLabel("存储IP"), self.combox)
        self.form.addRow(QLabel("服务器IP:"), self.host_edit)
        self.form.addRow(QLabel("端口号:"), self.port_edit)
        self.form.addRow(QLabel("用户名:"), self.username_edit)
        self.form.addRow(QLabel("密码:"), self.password_edit)
        self.form.addRow(QLabel("显示密码"), self.checkbox)
        self.form.addRow(self.login_button, self.cancel_button)
        self.login_button.clicked.connect(self.login)
        self.cancel_button.clicked.connect(self.close)

    def selected_item(self, idx: int) -> None:
        """填充选中的用户信息"""
        value = self.userinfo.query_idx(self.idxs[idx])
        self.host_edit.setText(value[1])
        self.port_edit.setText(str(value[2]))
        self.username_edit.setText(value[3])
        self.password_edit.setText(value[4])

    def login(self) -> None:
        """处理登录逻辑"""
        host = self.host_edit.text()
        port = self.port_edit.text()
        username = self.username_edit.text()
        password = self.password_edit.text()
        try:
            if host and port and username and password:
                self.sftp_main_window = self.sftp_main_window(host, int(port), username, password)
                self.userinfo.insert(host, int(port), username, password)
                self.close()
                self.tab.addTab(self.sftp_main_window, host)
                self.sftp_widget_list.append(self.sftp_main_window)
            else:
                QMessageBox.warning(self, "参数警告", "请参数不能为空", QMessageBox.StandardButton.Ok)
        except Exception as e:
            print(e)

    def set_password_mode(self) -> None:
        """切换密码显示模式"""
        self.password_display = not self.password_display
        self.password_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if self.password_display else QLineEdit.EchoMode.Password)


class UserMainWindow(QMainWindow):
    """主窗口，管理多个 SFTP 会话"""

    def __init__(self) -> None:
        super().__init__()
        self.tab = QTabWidget()
        self.setCentralWidget(self.tab)
        self.login_windows = []
        self.sftp_widget = []
        self.get_transport_path_widget = []
        self.init_ui()
        self.show()
        self.login()

    def init_ui(self) -> None:
        """初始化主窗口布局"""
        self.tab.setTabsClosable(True)
        self.tab.tabCloseRequested.connect(self.close_tab)
        tool_bar = QToolBar()
        self.addToolBar(tool_bar)
        new_action = QAction("新建会话", self)
        download_action = QAction("下载", self)
        upload_action = QAction("上传", self)
        new_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder))
        download_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown))
        upload_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp))
        download_action.triggered.connect(self.download)
        upload_action.triggered.connect(self.upload)
        new_action.triggered.connect(self.login)
        tool_bar.addAction(new_action)
        tool_bar.addAction(download_action)
        tool_bar.addAction(upload_action)

    def upload(self) -> None:
        """打开上传路径选择窗口"""
        idx = self.tab.currentIndex()
        if idx >= 0:
            sftp_main_window = self.sftp_widget[idx]
            gp = GetUploadPathWidget(sftp_main_window)
            gp.show()
            self.get_transport_path_widget.append(gp)

    def download(self) -> None:
        """打开下载路径选择窗口"""
        idx = self.tab.currentIndex()
        if idx >= 0:
            sftp_main_window = self.sftp_widget[idx]
            gd = GetDownloadPathWidget(sftp_main_window)
            gd.show()
            self.get_transport_path_widget.append(gd)

    def login(self) -> None:
        """打开登录窗口"""
        login_window = LoginWindow(self.tab, self.sftp_widget)
        login_window.show()
        self.login_windows.append(login_window)

    def close_tab(self, index) -> None:
        """关闭指定标签页"""
        self.tab.removeTab(index)
        self.sftp_widget[index].close()


if __name__ == '__main__':
    os.makedirs("tmp", exist_ok=True)
    app = QApplication(sys.argv)
    setup_theme("auto")
    us = UserMainWindow()
    sys.exit(app.exec())
