# QuickSFTP 项目综合分析报告

> 生成时间: 2026-06-01 | 项目: quickstfp v0.1.0 | 代码量: ~3780 行 Python (18 文件)

---

## 项目概览

QuickSFTP 是一个基于 PySide6 + asyncssh 的跨平台 SFTP/SSH 客户端工具，支持：

- SSH 伪终端 (xterm.js)
- SFTP 文件浏览与管理
- 并发文件传输 (多协程 + 断点续传)
- 站点凭证管理 (加密存储)
- 快捷命令面板

架构分层：

```
main.py          → 主窗口入口
core/            → 业务逻辑层 (session, transport)
database/        → 数据访问层 (DAO)
ui/views/        → 视图层 (QWidget 子类)
ui/components/   → 可复用组件 (进度条, 终端)
utils/           → 工具函数
```

---

## 检查清单

在每个改进项前标记 `- [ ]` 作为检查点，完成改进后可勾选。

---

## 🔴 严重问题 (Critical)

### - [x] CRIT-1: 命令注入漏洞 (Shell Injection) — `core/session.py:132-142`

**文件**: `core/session.py`
**行号**: 132, 138, 142

```python
# 行132 - 删除文件
def del_file(self, path: str) -> None:
    return self._run_sync(self.connection.run(f"rm -rf {path}\n"))

# 行138 - 复制文件
def copy_file(self, old_path: str, new_path: str) -> None:
    return self._run_sync(self.connection.run(f"cp -rf {old_path} {new_path}\n"))

# 行142 - 移动文件
def move_file(self, old_path: str, new_path: str) -> None:
    return self._run_sync(self.connection.run(f"mv {old_path} {new_path}\n"))
```

**风险**: 如果路径中包含空格、分号、反引号等特殊字符，可能导致任意命令执行。例如文件名 `foo; rm -rf /` 会导致灾难性后果。

**建议**: 优先使用 `SFTPClient` 的原生方法 (`sftp.remove()`, `sftp.posix_rename()`)，如果没有原生方法，使用 `shlex.quote()` 对路径进行转义。

---

### - [x] CRIT-2: MITM 中间人攻击风险 — `core/session.py:92`

**文件**: `core/session.py`
**行号**: 92

```python
known_hosts=None,  # TODO: 在生产环境中应使用 known_hosts 验证主机密钥以防范 MITM 攻击
```

**风险**: 已有 TODO 注释但未修复。任何首次连接的主机都会无条件接受，攻击者可以伪装成目标服务器窃取凭证和数据。

**建议**: 
1. 默认使用 `asyncssh.known_hosts.KnownHosts()` 
2. 对未知主机弹出确认对话框让用户选择是否信任
3. 参考 OpenSSH 的 known_hosts 文件路径 `~/.ssh/known_hosts`

---

### - [x] CRIT-3: 明文密码导出 — `ui/views/site_manager.py:140-174`

**文件**: `ui/views/site_manager.py`
**行号**: 140-174

```python
def export_sites(self):
    # 将密码以明文写入 JSON 文件
    export_data["passwords"].append({
        "password": r[4]  # 明文密码!
    })
    json.dump(export_data, f, ...)
    QMessageBox.information(self, "成功", "站点配置已成功导出！\n(注：导出的 JSON 文件中包含明文密码，请妥善保管)")
```

**风险**: 虽然数据库中的密码已加密存储，但导出功能在解密后以明文写入 JSON，存在严重泄露风险。

**建议**:
1. 导出的 JSON 中保留加密后的密码（不解密），导入时直接存入加密数据库
2. 或对导出文件进行加密（如使用密码保护的 zip）
3. 至少加一个二次确认对话框，对用户明确提示风险

---

## 🟠 高优先级问题 (High)

### - [ ] HIGH-1: 零测试覆盖率

**问题**: 项目中不存在任何测试文件 (`test_*.py`, `conftest.py`, `pytest.ini` 等均不存在)。

**影响**: 无回归测试保障，任何修改都可能引入未知 bug。特别是核心的传输层和加密层缺乏验证。

**建议**: 
- 为核心模块添加单元测试：`test_session.py`, `test_transport.py`, `test_user_model.py`
- 使用 `pytest` + `pytest-asyncio` + `pytest-qt`
- 优先覆盖：加密解密、路径拼接、ProgressTracker、SpeedLimiter

---

### - [x] HIGH-2: 缺少 `cryptography` 依赖声明 — `pyproject.toml`

**文件**: `pyproject.toml`

```toml
dependencies = [
    "asyncssh>=2.21.1",
    "pyside6>=6.10.3",
]
```

**问题**: `database/user_model.py` 使用了 `from cryptography.fernet import Fernet`，但 `cryptography` 未在 `pyproject.toml` 中声明为依赖。README 中也未提及需要安装 `cryptography`。

**影响**: 新环境 `pip install` 后运行会直接 ImportError。

**建议**: 将 `"cryptography>=41.0.0"` 加入 `dependencies`。

---

### - [x] HIGH-3: 大量重复代码 — `base_remote_tree.py` vs `remote_file_widget.py`

**文件**: `ui/views/base_remote_tree.py` 和 `ui/views/remote_file_widget.py`

以下方法在两个文件中**完全重复**:

| 方法 | 行数 | base_remote_tree.py | remote_file_widget.py |
|------|------|---------------------|----------------------|
| `fetch_current_dir()` | ~10 | ✓ | ✓ (完全相同) |
| `fetch_search_results()` | ~45 | ✓ | ✓ (完全相同) |
| `fetch_sub_dir()` | ~10 | ✓ | ✓ (完全相同) |
| `on_sub_folder_loaded()` | ~30 | ✓ | ✓ (完全相同) |
| `add_new_file()` | ~35 | ✓ | ✓ (完全相同) |
| `format_size()` | ~7 | ✓ | ✓ (完全相同) |

**原因**: `RemoteFileWidget` 继承 `BaseRemoteTreeWidget`，但子类**重写(override)** 了这些方法且内容完全一致，导致维护两份相同代码。可能是重构遗留问题。

**建议**: 从 `RemoteFileWidget` 中删除这些与基类完全相同的重写方法，直接使用继承。若子类有轻微差异，应抽取差异部分为可覆盖的钩子方法。

---

### - [x] HIGH-4: 无日志系统，只用 `print()` 

**问题**: 项目中所有调试/错误输出都使用 `print()`，包括：

```python
# transport.py:92
print(f"Task error: {e}")

# terminal_widget.py:39
print(f"Terminal read error: {e}")

# base_remote_tree.py:159
print(f"拉取目录失败: {e}")

# remote_file_widget.py:186
print(f"搜索远端文件失败: {e}")
```

**影响**: 无日志级别控制、无时间戳、无文件/行号、无法输出到文件。排查问题极其困难。

**建议**:
```python
import logging
logger = logging.getLogger(__name__)
# 在 main.py 中配置 logging.basicConfig(level=logging.INFO)
```

---

## 🟡 中优先级问题 (Medium)

### - [x] MED-1: 数据库连接依赖 `__del__` 清理 — `database/user_model.py:203-208`

**文件**: `database/user_model.py`

```python
def __del__(self):
    try:
        self.close()
    except Exception:
        pass
```

**问题**: 
1. `__del__` 不保证执行时机（可能永不调用）
2. 裸 `except Exception: pass` 吞掉所有异常
3. 没有使用上下文管理器 `with` 语句
4. 没有 `__enter__` / `__exit__` 方法

**建议**: 
- 实现上下文管理器协议
- 在 `SiteManagerWidget.closeEvent()` 中显式调用 `self.userinfo_db.close()`
- 移除 `__del__`，改用显式资源管理

---

### - [ ] MED-2: `pyproject.toml` 占位符描述

**文件**: `pyproject.toml`

```toml
description = "Add your description here"
```

**建议**: 更新为有意义的项目描述。

---

### - [x] MED-3: `uv.lock` 被加入 `.gitignore` — `.gitignore:40`

**文件**: `.gitignore`
**行号**: 40

```
uv.lock
```

**问题**: 对于使用 `uv` 作为包管理器的项目，`uv.lock` 应**被提交到 Git**（类似 `poetry.lock`），以确保所有开发者/部署环境使用完全相同的依赖版本。将其加入 `.gitignore` 会导致依赖版本漂移。

**建议**: 从 `.gitignore` 中移除 `uv.lock`。

---

### - [ ] MED-4: 可变默认参数 — `database/user_model.py`

**文件**: `database/user_model.py`
**行号**: 138, 144, 195-196

```python
def query_key(self, ..., passphrase: str = "") -> ...:  # 行138
def insert_key(self, ..., passphrase: str = "") -> ...:  # 行144
def update_key(self, ..., passphrase: str = "") -> ...:  # 行195-196
```

**问题**: 虽然 `str = ""` 是不可变对象，技术上可接受，但多处使用空字符串默认值暗示 `passphrase` 字段可能为 `""`，而代码没有专门处理空字符串与 `None` 的语义区别（`CryptoManager.decrypt` 对空字符串直接返回，不尝试解密）。

**建议**: 统一使用 `Optional[str] = None`，在 `CryptoManager` 层面同时处理 `None` 和 `""`。

---

### - [ ] MED-5: 大函数 — 超过 60 行

| 文件 | 方法 | 行数 |
|------|------|------|
| `site_manager.py` | `init_ui()` | ~100 |
| `remote_drag_drop.py` | `dropEvent()` | ~70 |
| `remote_file_widget.py` | `show_context_menu()` | ~45 |
| `transport.py` | `_transport_file()` (GET) | ~45 |
| `transport.py` | `_transport_file()` (PUT) | ~45 |

**建议**: 
- `init_ui()` 可拆分为 `_init_left_panel()`, `_init_right_panel()`, `_init_form_layout()` 等
- `dropEvent()` 可拆分为 `_handle_url_drop()`, `_handle_remote_drop()`

---

### - [ ] MED-6: 部分函数缺少类型注解

**示例**:
```python
# site_manager.py:313
def insert_new_record(self, host, port, username, auth_type):  # 无类型注解

# base_remote_tree.py:163
def on_item_expanded(self, index: QModelIndex):  # item 未注解
    item = self.model.itemFromIndex(name_index)
```

**建议**: 为所有公开方法添加完整类型注解以利用静态类型检查和 IDE 智能提示。

---

### - [ ] MED-7: 硬编码临时目录路径 — `remote_file_widget.py:318`

**文件**: `ui/views/remote_file_widget.py`
**行号**: 318

```python
os.makedirs("tmp", exist_ok=True)
self.sftp_tab_widget.transport_control_widget.get(self.get_item_path(item), "./tmp", 20)
```

**问题**: `"tmp"` 和 `"./tmp"` 硬编码，应使用 `tempfile.gettempdir()` 或项目统一的临时目录。

---

### - [ ] MED-8: 未使用的导入

```python
# remote_file_widget.py:14
from ui.components.terminal_widget import SSHPtyWidget  # 未使用
```

---

### - [x] MED-9: N+1 查询模式 — `database/user_model.py:90-93`

**文件**: `database/user_model.py`

```python
def query_password(self, host, port, username, password):
    return [row for row in self.query_all_password()
            if row[1] == host and row[2] == port and row[3] == username and row[4] == password]
```

**问题**: `query_all_password()` 先拉取全部记录并在 Python 层逐一解密，然后在内存中过滤。对于大量站点记录时性能很差，且浪费解密运算。

**建议**: 使用参数化 SQL 查询，对加密字段添加哈希索引辅助查找，或改为在数据库层面先过滤再解密。

---

### - [x] MED-10: 缺少 `[build-system]` — `pyproject.toml`

**文件**: `pyproject.toml`

`pyproject.toml` 中缺少 `[build-system]` 节。虽然当前不需要构建分发包，但这是 PEP 517/518 的标准要求。

**建议**:
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

---

### - [x] MED-11: 数据库表缺少索引 — `database/user_model.py`

**文件**: `database/user_model.py`

`Password` 和 `Key` 表的 `host`, `port`, `username` 列没有索引。每次按这些字段查询都是全表扫描。

**建议**: 在 `create_table()` 中添加:
```sql
CREATE INDEX IF NOT EXISTS idx_password_host ON Password(host, port, username);
CREATE INDEX IF NOT EXISTS idx_key_host ON Key(host, port, username);
```

---

### - [x] MED-12: SSH 连接缺少超时参数 — `core/session.py:86-91`

**文件**: `core/session.py`

```python
self.connection = await asyncssh.connect(
    host=self.host, port=self.port, ...,
    known_hosts=None,
    # ❌ 缺少 connect_timeout 参数
)
```

**问题**: `asyncssh.connect()` 未传入 `connect_timeout` 或 `login_timeout`，如果目标主机不可达，连接会挂起很长时间才报错，期间 UI 完全阻塞（因为 `wait_for_connection()` 中的 `QEventLoop` 在等待）。

**建议**: 添加 `connect_timeout=10` 或可配置的超时时间。

---

## 🟢 低优先级问题 (Low)

### - [ ] LOW-1: 无效注释语句 — `remote_drag_drop.py:152`

**文件**: `ui/views/remote_drag_drop.py`
**行号**: 152

```python
# 导入 PySide6.QtCore.Qt 用于类内部 (已在方法中局部导入)
```

这是无意义的注释，应删除。

---

### - [ ] LOW-2: 中英文混用

字符串和注释中存在中英文混用：
- `"QuickSFTP - 多会话终端"`
- `"连接失败"`, `"无法连接到"`
- `"👁️ 显示隐藏"`

**建议**: 统一使用中文（面向国内用户）或引入 i18n（面向国际化）。

---

### - [ ] LOW-3: 数据库缺少迁移机制

`user_model.py:create_table()` 使用 `CREATE TABLE IF NOT EXISTS`，只能创建初始表结构。如果未来需要添加字段/修改表结构，无法自动迁移。

**建议**: 引入 Alembic 或简单的版本号迁移机制。

---

### - [ ] LOW-4: 宽度硬编码 — `main.py:21`

```python
self.resize(1100, 700)
```

应考虑使用 `QScreen.availableGeometry()` 按屏幕比例缩放（如 70%），或记住用户的窗口大小。

---

### - [ ] LOW-5: `progress_bar.py` 存在重复导入

**文件**: `ui/views/transport_widgets.py`
**行号**: 5-7

```python
from PySide6.QtWidgets import QWidget, ..., QSlider, QSpinBox, ...,  QSlider
#                                                                         ^^^^^^ 重复
```

---

### - [ ] LOW-6: 图标缓存使用临时文件 hack — `base_remote_tree.py:77-93`

**文件**: `base_remote_tree.py:77-93`

`get_file_icon()` 方法为每种扩展名创建一个 0 字节的临时文件来获取系统图标。这是一种 hack，更优雅的方式是使用 `QFileInfo` 的 `suffix` 方法或预定义图标映射。

---

## 📊 统计摘要

| 类别 | 数量 |
|------|------|
| 🔴 严重问题 | 3 |
| 🟠 高优先级 | 4 |
| 🟡 中优先级 | 12 |
| 🟢 低优先级 | 6 |
| **总计** | **25** |

| 指标 | 数值 |
|------|------|
| 总 Python 文件 | 18 |
| 总代码行数 | ~3780 |
| 测试文件 | 0 |
| 测试覆盖率 | 0% |
| 重复代码行 | ~145 (base vs remote file) |
| 裸 except / except-pass | 4 处 |
| print() 调试语句 | ~10 处 |
| 数据库表索引 | 0 |
| 安全漏洞 | 3 (Shell注入, MITM, 明文导出) |

---

## 🗺️ 改进路线图建议

### 第一阶段: 安全加固 (立即)
1. CRIT-1: 修复 Shell 注入漏洞
2. CRIT-2: 启用 known_hosts 验证
3. CRIT-3: 修复明文密码导出
4. MED-12: 添加 SSH 连接超时

### 第二阶段: 质量基础 (近期)
5. HIGH-2: 补全依赖声明
6. HIGH-3: 消除重复代码
7. HIGH-4: 引入日志系统
8. MED-1: 修复数据库连接管理
9. MED-9: 优化 N+1 查询
10. MED-10: 补充 build-system 声明
11. MED-11: 添加数据库索引

### 第三阶段: 工程化 (中期)
12. HIGH-1: 添加核心测试
13. MED-5/6: 拆分大函数 + 补全类型注解
14. MED-3: 修复 uv.lock 版本控制

### 第四阶段: 优化 (长期)
15. LOW-1 ~ LOW-6: 细节优化
16. LOW-3: 数据库迁移
17. 引入 CI/CD pipeline
18. 添加 ruff / mypy / pytest 配置到 pyproject.toml

---

## 🏆 商业竞品分析 — 可追加功能评估

> 原则：在不改变轻巧易用定位的前提下，借鉴优秀商业产品的高价值功能。

### 现有功能清单 (Baseline)

quickstfp 在 ~3780 行 Python 中已实现的功能已相当丰富：

| 功能 | 状态 | 对标产品 |
|------|------|---------|
| 多标签页会话管理 | ✅ 已完备 | SecureCRT, MobaXterm |
| 站点凭证加密存储 | ✅ 已完备 (Fernet) | Termius, WinSCP |
| SFTP 文件浏览器 | ✅ 已完备 | FileZilla, WinSCP |
| 本地文件浏览器 | ✅ 已完备 | FileZilla |
| SSH 伪终端 (xterm.js) | ✅ 已完备 | Termius, Tabby |
| 并发文件传输 | ✅ 已完备 | FileZilla |
| 传输限速 | ✅ 已完备 | FileZilla |
| 暂停/续传 | ✅ 已完备 | WinSCP |
| 断点续传 | ✅ 已完备 | FileZilla, WinSCP |
| 拖拽下载/上传 | ✅ 已完备 | WinSCP, Transmit |
| 右键菜单操作 | ✅ 已完备 | 所有竞品 |
| 外部编辑器集成 | ✅ 已完备 | WinSCP |
| 文件权限编辑器 | ✅ 已完备 | WinSCP |
| 快捷命令面板 | ✅ 已完备 | Termius (Snippets) |
| 站点导入/导出 | ✅ 已完备 | FileZilla |
| 路径历史记录 | ✅ 已完备 | 所有竞品 |
| 隐藏文件切换 | ✅ 已完备 | FileZilla |
| 远端文件搜索 | ✅ 已完备 | WinSCP |
| 语法高亮编辑器 | ✅ 已完备 | SecureCRT |

---

### 竞品核心差异化功能矩阵

| 功能 | Termius | WinSCP | FileZilla | MobaXterm | SecureCRT | Tabby | quickstfp |
|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **站点管理器层级分组** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **目录比较 (Diff)** | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **同步浏览 (Synchronized Browsing)** | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **传输队列增强 (重试/调度)** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ⚠️ 基础 |
| **Keepalive / 心跳保活** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **SSH 端口转发 / 隧道** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **跳板机 / 代理连接** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **多会话同步执行** | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **暗色模式 / 主题** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **终端字体自定义** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ xterm.js 可行 |
| **终端日志记录** | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **宏录制** | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **自定义命令/按钮栏** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ⚠️ 有 Snippets |
| **文件传输过滤 (Masks)** | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **云同步 (跨设备)** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **团队共享** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **X11 转发** | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **脚本/自动化接口** | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **云存储集成 (S3/GCS)** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

---

### 🥇 Level 1 — 强烈建议追加 (高价值, 低实现成本)

每个改进项前标记 `- [ ]` 作为检查点。

#### - [ ] FEAT-1: 站点管理器层级分组 (Site Folder Hierarchy)

**灵感**: WinSCP, FileZilla, SecureCRT

**现状**: 站点列表是平铺的 `QListWidget`，所有站点线性排列。

**建议**: 引入树形分组（文件夹 → 站点），允许用户拖拽分组。数据结构只需在数据库加一张 `Folder` 表或给站点加 `parent_folder` 字段。

**实现估算**: ~150 行，无新依赖。将 `QListWidget` 改为 `QTreeWidget`。

---

#### - [ ] FEAT-2: 暗色模式 / 主题切换 (Dark Mode)

**灵感**: Termius, Tabby, 所有现代工具

**现状**: `main.py:122` 只设置了 `setStyle("Fusion")`，无暗色主题。

**建议**: 通过 `qt-material` 或自定义 QSS 样式表实现一键暗色切换。PySide6 原生支持 `QStyleFactory`，或编写一份轻量 QSS。

**实现估算**: ~80 行 QSS + ~50 行切换逻辑。可选 `qt-material` 依赖 (~200KB)。

---

#### - [ ] FEAT-3: SSH 保活 (Keepalive)

**灵感**: 所有商业 SSH 客户端

**现状**: 无任何心跳机制。长时间空闲后 SSH 连接被服务器断开，用户操作时才发现。

**建议**: 在 `core/session.py` 的 `get_session()` 中添加 `keepalive_interval` 和 `keepalive_count_max` 参数。asyncssh 原生支持这些参数，仅需传入配置即可。

```python
self.connection = await asyncssh.connect(
    ...,
    keepalive_interval=30,   # 每 30s 发一次心跳
    keepalive_count_max=3,   # 连续 3 次失败视为断连
)
```

**实现估算**: ~10 行，无新依赖 (asyncssh 原生支持)。UI 上可在站点编辑器中添加可选的保活配置。

---

#### - [ ] FEAT-4: 同步浏览 (Synchronized Browsing)

**灵感**: WinSCP, FileZilla (最受欢迎功能之一)

**现状**: 左侧本地面板和右侧远端面板独立导航，用户需要手动在两面板中定位到同一目录。

**建议**: 添加一个切换按钮，开启后本地面板切换目录时自动在远端执行 `cd` 到对应路径（文件名匹配），反之亦然。

**实现估算**: ~80 行。监听 `LocalFileWidget.path_change` 信号 → 映射到远端路径 → 自动 `chdir` + `refresh`。

---

#### - [ ] FEAT-5: 终端日志记录 (Session Logging)

**灵感**: SecureCRT, MobaXterm

**现状**: 终端输出仅实时显示，无持久化记录。

**建议**: 在 `TerminalBridge.output` 信号处理中增加一个可选的文件写入器，按日期/站点自动创建日志文件。在终端面板加一个"开始记录"按钮。

**实现估算**: ~60 行。纯 Python `open/write/flush`，无新依赖。

---

#### - [ ] FEAT-6: 传输队列增强 — 重试与任务历史

**灵感**: FileZilla, WinSCP

**现状**: `TransportControlWidget` 已有任务列表，失败文件会弹窗提示。但：① 失败后无法一键重试；② 传输完成后任务自动清除，无历史记录。

**建议**: 
- 失败任务保留在列表中，添加"重试"按钮
- 完成后不自动清除，而是标记"✅ 已完成"
- 列表底部显示总计 (成功 X / 失败 Y / 总计 Z)

**实现估算**: ~100 行。在 `ProgressBar` 中增加重试按钮，`TransportControlWidget` 中增加状态管理。

---

#### - [ ] FEAT-12: 命令历史与搜索 (Command History)

**灵感**: Termius (History panel — "改变游戏规则的功能")

**现状**: 终端命令执行后即消失，无任何历史记录。用户无法回顾或复用之前执行过的命令。

**建议**: 
- 在终端面板右侧（或 Snippets 面板旁）添加"历史"标签页
- 自动记录每条执行的命令到可搜索列表
- 支持"保存为快捷命令 (Snippet)"一键转换
- 按时间倒序排列，支持关键词搜索

**实现估算**: ~100 行。纯 PySide6 `QListWidget` + Python `list` / `json` 持久化。无需新依赖。

---

#### - [ ] FEAT-13: SSH 密钥生成器 (Keygen + Deploy)

**灵感**: Termius (Keychain)

**现状**: 用户需要手动用 `ssh-keygen` 生成密钥对，然后手动复制公钥到服务器。

**建议**:
- "生成新密钥对"对话框 — 选择类型 (ed25519/rsa)、位数、保存路径
- "部署到服务器" — 一键将公钥追加到远端 `~/.ssh/authorized_keys`
- 自动将新密钥注册到站点管理器

```python
import asyncssh
key = asyncssh.generate_private_key("ssh-ed25519")
public_key = key.export_public_key()
```

**实现估算**: ~100 行。asyncssh 原生支持密钥生成，无需额外依赖。

---

#### - [ ] FEAT-14: 批量重命名 (Batch Rename)

**灵感**: FileZilla, WinSCP

**现状**: 远端文件只能逐个重命名。

**建议**: 选中多个文件 → 右键"批量重命名"。提供规则：
- 查找替换 (regex)
- 序号插入 `{n}`, `{n:03}`
- 大小写转换
- 前后缀添加
- 预览窗口 (原名 → 新名)

**实现估算**: ~150 行。Python `re` 模块 (stdlib)，通过 `sftp.rename()` 执行。

---

#### - [ ] FEAT-15: 启动片段 & 自动重连

**灵感**: Termius (Startup Snippets + Auto-reconnect)

**现状**: 连接后需手动操作；断连后需手动重连。

**建议**:
- **启动片段**: 站点配置中指定"连接后自动执行"的命令（如 `cd /var/log`, `tmux a`）
- **自动重连**: `core/session.py` 中检测断连 → 指数退避重试 → UI 显示"重新连接中..."

**实现估算**: ~80 行。启动片段复用现有 snippet 引擎；重连利用 asyncssh 的 `DisconnectError`。

---

### 🥈 Level 2 — 建议中期追加 (高价值, 中等成本)

#### - [ ] FEAT-7: 目录比较 (Directory Diff)

**灵感**: WinSCP, FileZilla

**现状**: 无文件差异比较能力。

**建议**: 对当前本地目录和远端目录做对比，用颜色高亮标记：
- 🟢 绿色：两边都有且一致 (或不显示)
- 🔵 蓝色：仅本地有
- 🟠 橙色：仅远端有
- 🔴 红色：两边都有但大小/时间不同

**实现估算**: ~200 行。本地用 `os.scandir` / 远端用 `sftp.scandir` 收集文件列表后做集合运算 + 大小比较。可能需要新增一个 "比较模式" 的树视图。

---

#### - [ ] FEAT-8: SSH 端口转发 UI (Port Forwarding)

**灵感**: Termius, MobaXterm, SecureCRT

**现状**: 无端口转发功能。

**建议**: 在 `core/session.py` 中利用 asyncssh 的 `forward_local_port` / `forward_remote_port` API。UI 上在站点编辑器中添加"隧道"标签页，管理本地转发 (L) 和远程转发 (R) 规则列表。显示格式：`L 8080 -> example.com:80`。

**实现估算**: ~300 行。asyncssh 原生支持，无需额外依赖。主要在 UI 层的列表管理。

---

#### - [ ] FEAT-9: 文件传输过滤 (File Masks)

**灵感**: WinSCP, FileZilla

**现状**: 传输时无条件传输所有文件。

**建议**: 在传输配置面板 (TransferSetupWidget) 中添加"排除模式"输入框：
- `*.pyc;__pycache__;.git;node_modules` — 排除这些
- `*.py;*.txt` — 仅传输这些

**实现估算**: ~80 行。在 `search_transport_file` 递归遍历时过滤。

---

#### - [ ] FEAT-10: 多会话同步执行 (Multi-Execution)

**灵感**: MobaXterm (MultiExec), SecureCRT (Command Window)

**现状**: 每个终端独立操作。

**建议**: 添加一个"广播模式"按钮，开启后在一个终端输入的命令同步发送到所有打开的会话终端。

**实现估算**: ~80 行。在 `TerminalPanel` 中管理一个 `broadcast_targets` 列表，拦截 `on_input` 信号并广播。

---

#### - [ ] FEAT-11: 连接健康指示器

**灵感**: Termius, Tabby

**现状**: 无法直观看到连接延迟或状态。

**建议**: 在标签页标题旁显示小圆点：🟢 连接正常 / 🟡 延迟高 / 🔴 已断开。通过定时 ping 或检查 event loop 状态更新。

**实现估算**: ~60 行。利用 `sftp.getcwd()` 作为轻量探活。每 30s 一次。

---

#### - [ ] FEAT-16: 传输完成动作 (Queue Completion Actions)

**灵感**: FileZilla (完成后关机/通知/执行命令)

**现状**: 传输完成后无任何反馈。

**建议**: 在传输面板添加"完成后"下拉菜单：静默 / 系统通知 / 播放声音 / 关闭标签页。利用 PySide6 的 `QSystemTrayIcon.showMessage()` 发系统通知。

**实现估算**: ~50 行。纯 PySide6 内置 API，无新依赖。

---

#### - [ ] FEAT-17: 自定义命令 (Custom Commands with Pattern Substitution)

**灵感**: WinSCP (自定义命令 + 模式替换)

**现状**: Snippets 仅支持固定的预设命令。

**建议**: 增强 Snippets — 支持运行时变量替换：
- `!` → 当前选中的文件路径
- `!S` → 当前会话 URL  
- `!?提示词!` → 运行时弹出输入框

例如：`tar -czf !.tar.gz !` 或 `diff !?本地文件! !`

**实现估算**: ~80 行。在 `SnippetWidget.execute_item()` 中做字符串模板替换。

---

### 🥉 Level 3 — 长期愿景 (高价值, 高成本)

| 功能 | 灵感 | 成本估算 | 备注 |
|------|------|---------|------|
| **跳板机/代理连接** | Termius, WinSCP | ~400 行 | asyncssh 支持 `tunnel` 参数和 SSH 隧道作为跳板 |
| **云存储集成 (S3/GCS)** | WinSCP, Cyberduck | ~800 行 | 需引入 `boto3`，可能偏离轻量定位 |
| **终端宏录制** | SecureCRT | ~300 行 | 录制键盘输入序列并回放 |
| **自动化脚本接口** | WinSCP, SecureCRT | ~500 行 | 暴露 headless API 供外部脚本调用 (`python -m quickstfp script`) |
| **暗色 xterm.js 主题** | Tabby | ~50 行 | xterm.js 本身支持主题，在 HTML 中配置即可 |
| **插件系统** | Tabby | ~600 行 | 设计插件接口，允许社区贡献扩展 |
| **主密码 (Master Password)** | Termius, MobaXterm | ~100 行 | 用 Argon2id 派生密钥加密 `.secret.key` 本身 |
| **命令面板 (⌘K/⌃K)** | VS Code, Tabby | ~200 行 | 全局搜索式动作调度器，输入关键词即可触发任意功能 |
| **tmux 自动挂载** | 运维场景 | ~50 行 | 连接后自动 `tmux new -A -s quickstfp-{host}` |
| **工作区保存/恢复** | Termius, Tabby | ~200 行 | 保存当前打开的标签页布局，下次启动一键恢复 |

---

### 🔮 前瞻方向 — AI 与 MCP 集成 (2026 趋势)

> 这是当前 SSH 客户端领域最前沿的方向。多个新兴项目 (VibeShell, Tabby-MCP, Oryxis) 正在探索让 AI 编码代理 (Claude Code, Codex, Cursor) 通过 [MCP 协议](https://modelcontextprotocol.io/) 控制 SSH 会话。

**quickstfp 的天然优势**:
- ✅ Python 原生代码库 — Python 有 MCP SDK 一等支持
- ✅ `TerminalBridge` QWebChannel 架构已经是 "agent-style"
- ✅ 所有核心操作 (exec, upload, download, list) 都可映射为 MCP Tools

**建议方向** (v2.0+):

#### - [ ] MCP-1: MCP Server — 让 AI 代理控制 SSH 会话

将 SSH/SFTP 操作暴露为 MCP 工具，AI 代理可直接调用：

```python
# 暴露的工具示例
mcp.tool("ssh_exec", host, cmd)        → stdout/stderr
mcp.tool("sftp_list", host, path)       → file entries
mcp.tool("sftp_download", host, src, dst)
mcp.tool("sftp_upload", host, src, dst)
mcp.tool("port_forward", host, local, remote)
```

**实现估算**: ~250 行。使用 `mcp` Python SDK（纯 Python，无原生依赖）。这会让 quickstfp 成为首个支持 MCP 的 Python SSH 客户端。

#### - [ ] MCP-2: AI 助手侧边栏 (远期)

在终端面板旁添加 AI 聊天侧边栏，连接 OpenAI/Claude API：
- 自动读取终端上下文（最近 20 行输出）
- 用户可提问："刚才的 error 是什么意思？""帮我写一条修复命令"
- 一键发送 AI 建议的命令到终端

**实现估算**: ~400 行。需要 `openai` 或 `anthropic` 依赖。属于重型功能，建议等待 MCP 基础设施成熟后再考虑。

---

### 🚫 不建议追加的功能 (反臃肿护栏)

以下功能明确**不建议**加入，以避免项目偏离"轻巧易用"定位：

| 功能 | 理由 |
|------|------|
| X11 转发 (MobaXterm) | 依赖 XQuartz/WSL，跨平台复杂度极高 |
| 内置 FTP/HTTP 服务器 (MobaXterm) | 偏离核心功能，且安全隐患大 |
| 云同步 / 团队共享 (Termius) | 需要后端服务 + 用户系统，完全改变产品形态。替代方案：加密导出文件 + 用户自行放云盘 |
| 内置文件编辑器 IDE 化 | 已有外部编辑器集成，无需重造轮子 |
| 内置 AI 助手 (Warp/Tabby AI) | MCP Server 是更优雅的替代方案——让外部 AI 代理来控制，而非内置 LLM 依赖 |

> 注：上表中"云同步"指服务端托管方案。**加密导出/导入**（FEAT Level 1 安全增强）是轻量可行的替代：用户将加密后的配置 JSON 放入自己的 Dropbox/Syncthing，实现"自托管同步"。

---

### 📊 功能追加路线图 (与问题修复协同)

**Phase A: 零成本速赢** (1-2 天)
- FEAT-3: SSH 保活 (10行)
- FEAT-1: 站点分组 (150行)
- FEAT-2: 暗色模式 (130行)
- FEAT-5: 终端日志 (60行)
- FEAT-15: 启动片段 + 自动重连 (80行)

**Phase B: 体验跃升** (3-5 天)
- FEAT-6: 传输重试 + 历史 (100行)
- FEAT-4: 同步浏览 (80行)
- FEAT-11: 健康指示器 (60行)
- FEAT-12: 命令历史与搜索 (100行)
- FEAT-13: SSH 密钥生成器 (100行)
- FEAT-16: 传输完成动作 (50行)

**Phase C: 专业能力** (1-2 周)
- FEAT-7: 目录比较 (200行)
- FEAT-8: 端口转发 (300行)
- FEAT-9: 文件过滤 (80行)
- FEAT-10: 多会话同步执行 (80行)
- FEAT-14: 批量重命名 (150行)
- FEAT-17: 自定义命令模板 (80行)

**Phase D: 差异化** (长期)
- 跳板机 / 云存储 / 宏录制 / 自动化接口
- 主密码 / 命令面板 / 工作区恢复 / tmux 自动挂载
- MCP Server (AI 代理集成)

> 总预估：追加 ~3000 行代码即可覆盖 Phase A-C (17 个功能)，总项目控制在 ~7000 行以内，仍保持轻量定位。每个功能均无新增依赖或仅需 stdlib。

