"""standards/mois49.yml 과 fixes.yml 을 읽는다."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent.parent


class Standard:
    def __init__(self, base: Path = BASE):
        data = yaml.safe_load((base / "standards" / "mois49.yml").read_text(encoding="utf-8"))
        self.categories: dict[str, str] = data["categories"]
        self.items: list[dict] = data["items"]
        self.extras: list[dict] = data["extras"]
        self.by_id = {i["id"]: i for i in self.items + self.extras}
        self._cwe = {}
        for i in self.items + self.extras:
            for c in i.get("cwe", []):
                self._cwe.setdefault(int(c), i["id"])
        self.fixes: dict = yaml.safe_load((base / "standards" / "fixes.yml").read_text(encoding="utf-8"))

    def item_for_cwe(self, cwe) -> str | None:
        """Semgrep 레지스트리 규칙의 CWE 메타데이터("CWE-89: ..." 또는 목록)를 항목 ID로 바꾼다."""
        if not cwe:
            return None
        values = cwe if isinstance(cwe, list) else [cwe]
        for v in values:
            m = re.search(r"CWE-(\d+)", str(v))
            if m and int(m.group(1)) in self._cwe:
                return self._cwe[int(m.group(1))]
        return None

    def name(self, item_id: str) -> str:
        i = self.by_id.get(item_id)
        return i["name"] if i else "기타"

    def fix(self, item_id: str) -> dict:
        return self.fixes.get(item_id) or self.fixes["_default"]
