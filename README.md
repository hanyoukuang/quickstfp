# quickstfp

跨平台 SFTP/SSH 客户端工具。支持多标签页终端、并发文件传输与站点管理。

终端渲染基于 [kai-term](https://github.com/hanyoukuang/kai-term)，使用原生 QPainter + Rust VT520 解析器（[par-term-emu-core-rust](https://github.com/paulrobello/par-term-emu-core-rust)），无 Web 依赖。

## 安装

需要 Python **3.12+** 和 [uv](https://docs.astral.sh/uv/)。

```bash
git clone https://github.com/hanyoukuang/quicksftp.git
cd quicksftp
uv sync
```

## 运行

```bash
uv run python main.py
# 或安装后直接使用命令
uv run quickstfp
```

## 安全注意事项

**发布到 GitHub 前请确保：**

1. **`.secret.key` 文件不会被提交**
   - 该文件是用于加密 SSH 密码的 Fernet 对称密钥
   - 已加入 `.gitignore`，如果密钥文件已存在，请手动使用 `git rm --cached .secret.key` 从跟踪中移除

2. **`userinfo.db` 和 `quick_snippets_v2.json` 不会被提交**
   - 这些文件分别存储加密后的 SSH 凭证和快捷命令配置
   - 同样已加入 `.gitignore`

3. **首次运行** 时程序会自动生成新的 `.secret.key`，但之前保存的所有站点凭证将因密钥变更而失效，需要重新添加站点。
