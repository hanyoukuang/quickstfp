# QuickSFTP 代码审查报告

> 审查日期：2026-06-03 | 代码量：~5,500 行 Python（29 文件）| Python 3.12 / PySide6 6.11

---

## 目录

1. [严重 Bug（需立即修复）](#1-严重-bug需立即修复)
2. [代码质量](#2-代码质量)
3. [架构问题](#3-架构问题)
4. [UI 一致性](#4-ui-一致性)
5. [可测试性](#5-可测试性)
6. [改进路线图](#6-改进路线图)

---

## 1. 严重 Bug（需立即修复）

### 🔴 1.1 `_port_fwd_dialog` 未初始化导致 AttributeError

**文件**：`main.py` 第 55 行

```python
def _open_port_forward(self):
    if self._port_fwd_dialog is None:   # ← AttributeError!
```

`_port_fwd_dialog` 仅在 `open_site_manager()`（第 106 行）中被赋值为 `None`。如果用户在打开站点管理器之前就点击「🔗 端口转发」，程序直接崩溃。

**修复**：在 `MainWindow.__init__` 中初始化 `self._port_fwd_dialog = None`。

---

### 🔴 1.2 上传进度追踪完全失效 — 缺少 `await`

**文件**：`core/transport.py` 第 427 行

```python
# PUT._transport_file (上传)
tracker(b'', b'', now_size, local_size)   # ← 缺少 await！

# GET._transport_file (下载) 第 343 行 — 正确
await tracker(b'', b'', now_size, remote_size)
```

`ProgressTracker.__call__` 是 `async` 方法。上传时没有 `await`，协程从未被调度执行 → **上传进度条永远不更新**。

**修复**：在上传路径添加 `await`。

---

### 🟡 1.3 `_parse_port` 类型签名错误

**文件**：`ui/views/site_manager.py` 第 329 行

```python
def _parse_port(text: str) -> int:    # 声称返回 int
    ...
    return None                        # 实际返回 None
```

非法输入时返回 `None`，与类型声明矛盾。调用方（第 359、400 行）通过 `if not port:` 检查避免了崩溃，但签名应反映实际情况。

**修复**：改为 `-> Optional[int]`。

---

### 🟡 1.4 启动命令错误被静默吞没

**文件**：`core/session.py` 第 152–153 行

```python
except Exception:
    pass    # startup_commands 写入失败被完全忽略
```

配置了启动命令但不生效时，用户得不到任何反馈。

**修复**：至少添加日志记录。

---

## 2. 代码质量

### 2.1 异常处理 — 11 处静默吞没

**模式**：`except Exception: pass` 零日志，覆盖以下场景：

| 文件 | 行号 | 场景 | 影响 |
|------|:---:|------|------|
| `core/session.py` | 152 | 启动命令失败 | 用户无反馈 |
| `core/transport.py` | 274 | 取消错误 | 可能泄露协程 |
| `ui/views/sftp_tab_widget.py` | 90 | 健康检查失败 | 🟢 变 🔴 无日志 |
| `ui/views/user_widgets.py` | 141 | 同步浏览导航失败 | 静默无响应 |
| `ui/views/user_widgets.py` | 218 | 本地文件扫描失败 | 目录比较为空 |
| `ui/views/user_widgets.py` | 232 | 远端文件读取失败 | 目录比较远端列为空 |
| `ui/views/remote_file_widget.py` | 300 | 批量重名单文件失败 | 部分文件未改名 |

**建议**：全部添加 `logger.warning()`。

---

### 2.2 代码重复 — 4 处高价值可提取

**(a) QEventLoop + QTimer 轮询模式**（`core/session.py` 第 54–85 行 vs 第 87–119 行）

`wait_for_connection` 和 `_wait_future` 使用几乎完全相同的 QTimer 轮询 + 超时模式（仅轮询间隔不同：50ms vs 20ms）。可提取为 `_run_event_loop_with_timeout(future, timeout, poll_ms)`，**消除 ~60 行重复**。

**(b) 文件传输核心循环**（`core/transport.py` 第 317–353 行 vs 第 397–435 行）

`GET._transport_file` 和 `PUT._transport_file` 结构 75% 相同：`try/except`、`ProgressTracker`、`chunk_size`、`pause_event.wait()` 循环、`limiter.consume()`。仅读写方向不同。

**(c) 远端目录拉取**（`ui/views/base_remote_tree.py` 第 147–156 行 vs 第 167–176 行）

`fetch_current_dir` 和 `fetch_sub_dir` 几乎相同的 `async for entry in scandir` 循环。

**(d) 树节点构建**（`ui/views/base_remote_tree.py` 第 212–243 行 vs 第 179–209 行）

`add_new_file` 和 `on_sub_folder_loaded` 构建完全相同的 5 列行结构，**~50 行重复**。

---

### 2.3 类型注解 — 全面缺失

- **13 个 `__init__`** 方法缺少 `-> None`
- `core/session.py` 的 `wait_for_connection`、`_wait_future`、`_run_sync` 均无返回类型
- `database/user_model.py:17` — `key_file: str = None` 应为 `Optional[str]`
- `database/user_model.py:52` — `db_path: str = None` 同上
- `batch_rename_dialog.py:13` — `filenames: List[str] = None` 同上

**建议**：至少为所有 `__init__` 和公共方法添加返回类型。

---

### 2.4 其他

- **无 `TODO`/`FIXME`/`HACK` 标记** → 技术债未被记录 ✅
- **无裸 `except:`** ✅
- **`import os` 位置错误**（`user_widgets.py` 第 12–13 行，应在 stdlib 区）
- **函数内 import**（`transport.py` 第 303 行 `from fnmatch import fnmatch`）
- **方法内定义 class**（`base_remote_tree.py` 第 132 行 `class SearchEntry`）
- **混用 `time.time()` 和 `time.monotonic()`** — 速度计算应统一用 `monotonic()`

---

## 3. 架构问题

### 3.1 缺失 `__init__.py` — 6 个包未正式声明

| 目录 | 状态 |
|------|:---:|
| `core/` | ❌ |
| `database/` | ❌ |
| `utils/` | ❌ |
| `ui/` | ❌ |
| `ui/components/` | ❌ |
| `ui/views/` | ✅ |
| `ui/terminal/` | ✅ |

影响：无法做包级别导出、部分工具可能误判导入。

**建议**：为每个目录添加 `__init__.py`，在 `core/__init__.py` 中导出 `SSHSFTPInfo`，`ui/__init__.py` 中导出主要组件。

---

### 3.2 上帝对象 — `SSHSFTPInfo` 承担 5+ 职责

`core/session.py`（270 行）的 `SSHSFTPInfo` 同时是：

- 🧵 QThread（线程管理）
- 🔁 asyncio 事件循环宿主
- 🔌 SSH 连接管理器
- 📂 SFTP 文件操作代理（13 个方法）
- 🔀 端口转发管理器
- ⏱️ 同步等待 + UI 轮询

**建议拆分**：

```
SSHConnection        — 纯异步 SSH 连接
AsyncLoopThread      — QThread + asyncio 事件循环
SFTPClientProxy      — 同步包装（run_coroutine_threadsafe）
PortForwardManager   — 端口转发
SSHSFTPInfo          — 薄门面（向后兼容）
```

---

### 3.3 上帝组件 — `SiteManagerWidget`（434 行）和 `RemoteFileWidget`（305 行）

- `SiteManagerWidget`：UI 布局 + CRUD + JSON 导入导出 + 密钥生成协调 + 连接参数组装
- `RemoteFileWidget`：文件树显示 + 9 个上下文菜单操作 + 外部编辑器管理 + 权限管理 + 批量重命名 + 拖放

**建议**：提取 `SiteRepository`、`RemoteFileService`。

---

### 3.4 UI 层直接访问业务对象 — 无中间层

7 个文件直接引用 `self.info`（`SSHSFTPInfo` 实例）：

```python
self.info.is_file(path)       # remote_file_widget.py
self.info.getcwd()             # user_widgets.py
self.info.sftp                 # base_remote_tree.py
self.info.loop                 # terminal_widget.py
```

没有 ViewModel / Presenter / Service 层。UI 代码直接访问 asyncio 事件循环。

**建议**：定义 `class SSHSession(Protocol)` 抽象接口，通过依赖注入传入视图。

---

### 3.5 测试覆盖 — 严重不足

| 模块 | 测试 | 覆盖率 |
|------|:---:|:---:|
| `core/session.py` | 0 | 0% |
| `core/transport.py`（GET/PUT） | 0 | 0% |
| `database/user_model.py`（UserInfoDB） | 0 | 0% |
| `ui/*`（全部） | 0 | 0% |
| `core/transport.py`（SpeedLimiter） | 1 | 基本 |
| `database/user_model.py`（CryptoManager） | 3 | 基本 |
| `utils/file_utils.py` | 3 | 基本 |

**总计**：2 个测试文件，96 行测试 → 5,500+ 行代码，覆盖率约 2%。

---

## 4. UI 一致性

### 4.1 语言混用

| 位置 | 中文 | 英文 | 问题 |
|------|:---:|:---:|------|
| 进度条按钮 | 「重试」 | 「Pause」「Cancel」「Resume」 | **最严重** — 同一行按钮中英文混杂 |
| 终端右键菜单 | — | 「Copy」「Paste」「Zoom In」「Zoom Out」 | 全英文孤岛 |
| 表单标签 | 「密码」「私钥文件」 | 「Passphrase:」 | 同行不一致 |
| SSH 密钥类型 | 「Ed25519 (推荐)」 | 「RSA 2048」 | 英文+中文注解混排 |

### 4.2 图标使用不均

| 区域 | 有图标 | 无图标 |
|------|:---:|:---:|
| 快捷命令右键菜单 | ✅ `➕ 🚀 ✏️ 🗑️` | — |
| 主工具栏 | ✅ `🌙 🔗` | ❌ `新建连接` |
| 文件操作用户栏 | ✅ `👁️ 🔗 📊` | ❌ `下载选定` `高级上传` `返回上级` |
| 站点管理器按钮栏 | — | ❌ 全部 6 个按钮 |
| 端口转发按钮栏 | — | ❌ 全部 2 个按钮 |
| 远端文件右键菜单 | — | ❌ 全部 14 个菜单项 |
| 本地文件右键菜单 | — | ❌ 全部 7 个菜单项 |
| 快捷命令按钮栏 | — | ❌ `添加` `编辑` `删除` |

### 4.3 对话框标题不一致

| 操作 | 标题 | 不一致处 |
|------|------|------|
| 删除站点 | `确认` | 仅 2 字，过于简略 |
| 删除快捷命令 | `确认删除` | 更详细 |
| 删除远端文件 | `删除` | 仅 1 字 |
| 删除本地文件 | `删除` | 同上 |
| 权限修改成功 | `成功` | 过于通用 |
| 导出成功 | `导出成功` | 更具体的描述 |

### 4.4 建议统一方案

| 当前文字 | 建议改为 |
|------|------|
| `新建连接 / 站点管理` | `🔌 新建连接` |
| `新建站点` | `➕ 新建站点` |
| `删除站点` | `🗑️ 删除站点` |
| `新建分组` | `📁 新建分组` |
| `导入` / `导出` | `📥 导入` / `📤 导出` |
| `保存` | `💾 保存` |
| `连接` | `🔌 连接` |
| `返回上级` | `⬆️ 返回上级` |
| `下载选定` | `⬇️ 下载` |
| `高级上传` | `⬆️ 上传` |
| `开始传输` | `▶️ 开始传输` |
| `添加隧道` | `🔀 添加隧道` |
| `生成密钥` | `🔐 生成密钥` |
| `新建文件夹` | `📁 新建文件夹` |
| `新文件` | `📄 新文件` |
| `刷新` | `🔄 刷新` |
| `删除` | `🗑️ 删除` |
| `重命名` | `✏️ 重命名` |
| `下载` | `⬇️ 下载` |
| `粘贴` | `📋 粘贴` |
| `Pause` | `⏸️ 暂停` |
| `Resume` | `▶️ 继续` |
| `Cancel` | `⏹️ 取消` |
| `重试` | `🔄 重试` |
| `Copy` | `📋 复制` |
| `Paste` | `📋 粘贴` |
| `Zoom In` | `🔍 放大` |
| `Zoom Out` | `🔎 缩小` |
| `Reset Zoom` | `↩️ 重置缩放` |

---

## 5. 可测试性

### 当前状态

```
测试用例: 13 个 (13 passed)
  - crypto: 3 个 (CryptoManager 加解密往返测试)
  - transport: 10 个 (SpeedLimiter, is_binary, path_stand, _resume_state)
  - 无 asyncssh 集成测试
  - 无 UI 测试
```

### 建议优先覆盖

1. **P0**：`SSHConnection`（拆分后）— 使用 `unittest.mock` 模拟 asyncssh
2. **P0**：`GET._transport_file` / `PUT._transport_file` — 异步文件流测试
3. **P1**：`UserInfoDB` — 使用内存 SQLite（`:memory:`）
4. **P1**：`ProgressTracker` — 进度更新逻辑
5. **P2**：关键 UI 组件 — 使用 `pytest-qt`

---

## 6. 改进路线图

### P0 — 立即修复（1–2 小时）

- [ ] 修复 `_port_fwd_dialog` AttributeError（`main.py` 加初始化）
- [ ] 修复上传进度追踪 `await` 缺失（`transport.py:427`）
- [ ] 修复 `_parse_port` 返回类型（`-> Optional[int]`）
- [ ] 为 `startup_commands` 异常添加日志

### P1 — 代码质量（3–5 小时）

- [ ] 为 11 处 `except Exception: pass` 添加日志
- [ ] 提取 `wait_for_connection` / `_wait_future` 共用模式
- [ ] 为所有 `__init__` 和公共方法添加 `-> None` 返回类型
- [ ] 修复 `time.time()` → `time.monotonic()`
- [ ] 修复 import 顺序（`user_widgets.py`）和位置（`transport.py`）

### P2 — UI 一致性（2–3 小时）

- [ ] 终端右键菜单中文化 + 添加图标
- [ ] 进度条按钮统一中文 + 图标
- [ ] 远端/本地文件右键菜单添加图标
- [ ] 站点管理器、端口转发按钮添加图标
- [ ] 统一对话框标题风格

### P3 — 架构重构（1–2 周）

- [ ] 为所有包添加 `__init__.py`
- [ ] 拆分 `SSHSFTPInfo` God Object
- [ ] 定义 `SSHSession` 协议接口
- [ ] 提取 `SiteRepository`、`RemoteFileService`
- [ ] 添加 UI 集成测试

### P4 — 测试覆盖（持续）

- [ ] `core/session.py` 异步测试
- [ ] `core/transport.py` 传输流程测试
- [ ] `database/user_model.py` DAO 测试
- [ ] 关键 UI 组件烟雾测试

---

## 附录：值得保留的优秀实践

1. **信号解耦** — `Transport` 仅通过 `Signal`/`Slot` 与 UI 通信 ✅
2. **Mixin 模式** — `RemoteDragDropMixin` 拖放逻辑独立可复用 ✅
3. **基类/子类分离** — `BaseRemoteTreeWidget` → `RemoteFileWidget` ✅
4. **配置集中** — `core/config.py` 统一管理路径 ✅
5. **异步基础设施** — `SpeedLimiter` + `ImmediateSchedulerPool` 设计良好 ✅
6. **零循环依赖** — 依赖图是 DAG ✅
7. **无 TODO 债务** — 代码中无技术债标记 ✅
