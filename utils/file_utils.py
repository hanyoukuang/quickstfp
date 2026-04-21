# utils/file_utils.py
import os
from typing import Tuple

# 常见二进制文件扩展名集合
# 将其定义为常量，方便统一维护和修改
BINARY_EXTENSIONS = (
    # 图像
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.ico',
    '.psd', '.ai', '.svgz',

    # 视频 & 音频
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.mid', '.midi',

    # 文档（带格式的，不建议直接用文本编辑器打开）
    '.pdf',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp',

    # 压缩 & 归档
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.cab',
    '.iso', '.img', '.dmg',

    # 可执行 & 库
    '.exe', '.dll', '.sys', '.so', '.o', '.obj', '.lib', '.a',
    '.app',  # macOS 应用包（实际是目录，但通常视为二进制）

    # 数据库
    '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.dbf',

    # 字体
    '.ttf', '.otf', '.woff', '.woff2', '.eot',

    # 其他常见二进制
    '.bin', '.dat', '.class', '.pyc', '.pyo',
    '.jar', '.apk', '.ipa',
    '.swf', '.elf', '.rom',
)


def is_binary(filename: str) -> bool:
    """
    根据文件扩展名快速判断是否为常见二进制文件。
    在双击打开远端文件时，通过此函数拦截二进制文件，防止乱码或程序卡死。

    :param filename: 文件名或包含文件名的路径
    :return: 如果是二进制文件返回 True，否则返回 False
    """
    _, ext = os.path.splitext(filename.lower())
    return ext in BINARY_EXTENSIONS


def path_stand(src: str, loc: str) -> Tuple[str, str]:
    """
    统一路径格式，并拼接目标路径。
    将 Windows 风格的反斜杠转换为斜杠，并去除末尾的斜杠，
    最后根据源文件/目录名生成在目标位置的完整路径。

    :param src: 源文件/目录路径
    :param loc: 目标存放位置的父目录路径
    :return: 格式化后的 (源路径, 拼接后的目标完整路径)
    """
    # 统一转换路径分隔符并去掉末尾的斜杠
    src_standard = src.replace('\\', '/').rstrip('/')
    loc_standard = loc.replace('\\', '/').rstrip('/')

    # 获取源路径的最后一部分（文件名或最底层目录名）
    target_name = src_standard.split('/')[-1]

    # 拼接出完整的目标路径
    loc_full = '/'.join((loc_standard, target_name))

    return src_standard, loc_full
