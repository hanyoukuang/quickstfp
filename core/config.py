from pathlib import Path


def get_config_dir() -> Path:
    """获取 quickstfp 配置目录，优先使用 ~/.config/quickstfp/"""
    config_dir = Path.home() / ".config" / "quickstfp"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_data_path(filename: str, legacy_cwd_fallback: bool = True) -> str:
    """
    获取数据文件路径。优先使用 ~/.config/quickstfp/ 下的文件，
    如果旧 CWD 文件存在则自动迁移并继续使用。

    :param filename: 数据文件名 (如 'userinfo.db', '.secret.key', 'quick_snippets_v2.json')
    :param legacy_cwd_fallback: 是否兼容 CWD 旧路径
    :return: 完整文件路径字符串
    """
    config_path = get_config_dir() / filename

    # 如果旧 CWD 文件存在且新路径不存在，使用旧路径（向后兼容）
    if legacy_cwd_fallback and Path(filename).exists() and not config_path.exists():
        return str(Path(filename).resolve())

    return str(config_path)
