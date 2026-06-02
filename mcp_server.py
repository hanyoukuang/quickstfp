"""
MCP Server for quickstfp — exposes SSH/SFTP operations as MCP tools.
Usage: uv run mcp dev mcp_server.py   or configure in claude_desktop_config.json
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.user_model import UserInfoDB


def _get_session(host: str):
    """获取或创建 SSH 会话"""
    from core.session import SSHSFTPInfo

    db = UserInfoDB()
    for row in db.query_all_password():
        if row[1] == host:
            session = SSHSFTPInfo(host=row[1], port=row[2], username=row[3], password=row[4])
            session.start()
            session.wait_for_connection(timeout=10)
            db.close()
            return session
    for row in db.query_all_key():
        if row[1] == host:
            session = SSHSFTPInfo(
                host=row[1], port=row[2], username=row[3],
                client_keys=[row[4]], passphrase=row[5] if row[5] else None,
            )
            session.start()
            session.wait_for_connection(timeout=10)
            db.close()
            return session
    db.close()
    raise ValueError(f"No credentials found for host: {host}")


def _get_saved_sites() -> list:
    """Return list of saved SSH sites"""
    db = UserInfoDB()
    sites = []
    for row in db.query_all_password():
        sites.append({"host": row[1], "port": row[2], "username": row[3], "auth": "password"})
    for row in db.query_all_key():
        sites.append({"host": row[1], "port": row[2], "username": row[3], "auth": "key"})
    db.close()
    return sites


def register_tools(mcp):
    """Register MCP tools on the given MCP server instance."""

    @mcp.tool()
    def list_sites() -> str:
        """列出所有已保存的 SSH 站点"""
        sites = _get_saved_sites()
        return json.dumps(sites, ensure_ascii=False, indent=2)

    @mcp.tool()
    def ssh_exec(host: str, command: str) -> str:
        """在远端服务器执行命令并返回输出"""
        session = _get_session(host)
        try:
            result = session._run_sync(session.connection.run(command))
            output = result.stdout or ""
            if result.stderr:
                output += f"\n[stderr]\n{result.stderr}"
            return output if output.strip() else "(no output)"
        finally:
            session.close_session()
            session.quit()
            session.wait(3000)

    @mcp.tool()
    def sftp_list(host: str, path: str = ".") -> str:
        """列出远端目录下的文件和子目录"""
        session = _get_session(host)
        try:
            entries = []
            session._run_sync(session.sftp.chdir(path))
            entries_future = session.loop.create_task(_list_entries(session))
            entries = session._wait_future(entries_future)
            return json.dumps(entries, ensure_ascii=False, indent=2)
        finally:
            session.close_session()
            session.quit()
            session.wait(3000)

    @mcp.tool()
    def sftp_read(host: str, path: str) -> str:
        """读取远端文件内容（仅限文本文件）"""
        session = _get_session(host)
        try:
            content = session.read_file(path)
            if len(content) > 50000:
                content = content[:50000] + "\n... (truncated)"
            return content
        finally:
            session.close_session()
            session.quit()
            session.wait(3000)


async def _list_entries(session) -> list:
    entries = []
    async for entry in session.sftp.scandir("."):
        if entry.filename not in (".", ".."):
            entries.append({
                "name": entry.filename,
                "type": "dir" if entry.attrs.type == 2 else "file",
                "size": getattr(entry.attrs, "size", 0),
            })
    return sorted(entries, key=lambda e: (e["type"], e["name"]))


def main():
    """Entry point for MCP server when run as a script"""
    try:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("quickstfp")
        register_tools(mcp)
        mcp.run()
    except ImportError:
        print("mcp package not installed. Run: pip install mcp")
        sys.exit(1)


if __name__ == "__main__":
    main()
