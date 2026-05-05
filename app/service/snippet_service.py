import json
import os
from typing import Optional


class Snippet:
    def __init__(self, name: str, cmd: str):
        self.name = name
        self.cmd = cmd

    def to_dict(self) -> dict:
        return {"name": self.name, "cmd": self.cmd}

    @classmethod
    def from_dict(cls, data: dict) -> "Snippet":
        return cls(name=data.get("name", ""), cmd=data.get("cmd", ""))


class SnippetService:
    def __init__(self, snippets_file: str = "quick_snippets_v2.json"):
        self.snippets_file = snippets_file
        self.data: dict = {"global": [], "sites": {}}
        self._ensure_site("")

    def _load(self):
        if os.path.exists(self.snippets_file):
            try:
                with open(self.snippets_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    self.data["global"] = loaded.get("global", [])
                    self.data["sites"] = loaded.get("sites", {})
            except (json.JSONDecodeError, IOError):
                self.data = {"global": [], "sites": {}}

    def _save(self):
        os.makedirs(os.path.dirname(self.snippets_file) or ".", exist_ok=True)
        with open(self.snippets_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=4)

    def _ensure_site(self, site_id: str):
        if site_id not in self.data["sites"]:
            self.data["sites"][site_id] = []

    def get_snippets(self, site_id: str = "") -> dict:
        self._load()
        self._ensure_site(site_id)
        result = {
            "global": [Snippet.from_dict(s).to_dict() for s in self.data["global"]],
            "site": [Snippet.from_dict(s).to_dict() for s in self.data["sites"][site_id]],
        }
        return result

    def add_snippet(self, name: str, cmd: str, scope: str = "global", site_id: str = "") -> dict:
        self._load()
        self._ensure_site(site_id)

        snippet_dict = {"name": name, "cmd": cmd}
        if scope == "global":
            self.data["global"].append(snippet_dict)
            index = len(self.data["global"]) - 1
        else:
            self.data["sites"][site_id].append(snippet_dict)
            index = len(self.data["sites"][site_id]) - 1

        self._save()
        return {"index": index, "scope": scope, "snippet": snippet_dict}

    def update_snippet(self, index: int, name: str, cmd: str, scope: str = "global", site_id: str = "") -> Optional[dict]:
        self._load()
        self._ensure_site(site_id)

        if scope == "global":
            if index < 0 or index >= len(self.data["global"]):
                return None
            self.data["global"][index] = {"name": name, "cmd": cmd}
        else:
            if index < 0 or index >= len(self.data["sites"][site_id]):
                return None
            self.data["sites"][site_id][index] = {"name": name, "cmd": cmd}

        self._save()
        return {"name": name, "cmd": cmd}

    def delete_snippet(self, index: int, scope: str = "global", site_id: str = "") -> bool:
        self._load()
        self._ensure_site(site_id)

        if scope == "global":
            if index < 0 or index >= len(self.data["global"]):
                return False
            self.data["global"].pop(index)
        else:
            if index < 0 or index >= len(self.data["sites"][site_id]):
                return False
            self.data["sites"][site_id].pop(index)

        self._save()
        return True
