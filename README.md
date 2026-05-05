# quickstfp

此工具配备 SSH 伪终端、SFTP 界面。它封装了 asyncssh 的部分函数，可以并发地传输文件（夹）。GUI 部分使用 PySide6 显示。小巧、跨平台性能好，支持 Windows, Mac, Linux 主流操作系统。

## 使用指南

1. 首先需要安装一个 Python 解释器
2. 打开终端输入

```bash
pip install asyncssh pyside6
python3 main.py
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
