"""스캐너 결과를 하나의 Finding 형식으로 모은다."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .standards import Standard

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

# 따옴표 안 긴 문자열·토큰 모양 문자열을 가린다
_QUOTED = re.compile(r"""(['"`])([^'"`\n]{8,})\1""")
# 숫자와 문자가 섞인 24자 이상 → 키·토큰으로 본다 (긴 식별자 dangerouslySetInnerHTML 등은 제외)
_TOKENISH = re.compile(r"(?=[A-Za-z0-9_\-+/=]*\d)(?=[A-Za-z0-9_\-+/=]*[A-Za-z])[A-Za-z0-9_\-+/=]{24,}")


# 이 항목들은 줄 자체가 비밀값을 담고 있으므로 따옴표 안 문자열까지 전부 가린다
SECRET_ITEMS = {"SF-06", "VC-01"}


def mask_tokens(text: str) -> str:
    return _TOKENISH.sub(lambda m: m.group(0)[:4] + "*" * 12, text)


def mask_secret(text: str) -> str:
    def _q(m: re.Match) -> str:
        v = m.group(2)
        return f"{m.group(1)}{v[:4]}{'*' * min(len(v) - 4, 12)}{m.group(1)}"

    return mask_tokens(_QUOTED.sub(_q, text))


@dataclass
class Finding:
    item: str            # 행안부 항목 ID 또는 VC-xx
    rule: str
    tool: str            # semgrep / gitleaks / osv / ksc
    severity: str        # high / medium / low
    confidence: str      # HIGH / MEDIUM
    path: str
    line: int
    message: str
    snippet: str = ""
    extra: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.rule, self.path, self.line)

    def to_dict(self) -> dict:
        return asdict(self)


def _rel(path: str, root: Path) -> str:
    p = Path(path)
    try:
        p = p.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    return p.as_posix()


def _read_line(root: Path, rel: str, line: int) -> str:
    try:
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
    except OSError:
        return ""


def from_semgrep(path: Path, root: Path, std: Standard) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        item = meta.get("mois") or std.item_for_cwe(meta.get("cwe"))
        rel = _rel(r["path"], root)
        line = r["start"]["line"]
        out.append(Finding(
            item=item or "ETC",
            rule=r["check_id"].split(".")[-1],
            tool="semgrep",
            severity=_SEMGREP_SEV.get(r["extra"].get("severity", "WARNING"), "medium"),
            confidence=str(meta.get("confidence", "MEDIUM")).upper(),
            path=rel,
            line=line,
            message=r["extra"].get("message", ""),
            # semgrep OSS는 extra.lines 를 주지 않으므로 직접 읽는다
            snippet=(mask_secret if item in SECRET_ITEMS else mask_tokens)(_read_line(root, rel, line)),
        ))
    return out


def from_gitleaks(path: Path, root: Path) -> list[Finding]:
    raw = path.read_text(encoding="utf-8").strip()
    data = json.loads(raw) if raw else []
    out = []
    for r in data or []:
        rel = _rel(r.get("File", ""), root)
        commit = r.get("Commit", "")
        out.append(Finding(
            item="SF-06",
            rule=f"gitleaks:{r.get('RuleID', 'secret')}",
            tool="gitleaks",
            severity="high",
            confidence="HIGH",
            path=rel,
            line=int(r.get("StartLine") or 0),
            message=f"비밀값({r.get('Description') or r.get('RuleID')})이 코드에 들어 있습니다."
                    + (" 과거 커밋에만 남아 있어도 이미 노출된 것으로 보고 키를 교체해야 합니다." if commit else ""),
            # Secret·Match 필드는 절대 쓰지 않는다. 해당 줄을 읽어 마스킹한다
            snippet=mask_secret(_read_line(root, rel, int(r.get("StartLine") or 0))) if not commit else "",
            extra={"commit": commit[:12]} if commit else {},
        ))
    return out


def _osv_severity(group: dict, vuln: dict) -> str:
    try:
        score = float(group.get("max_severity") or 0)
    except ValueError:
        score = 0.0
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    label = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    return {"CRITICAL": "high", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}.get(label, "medium")


def from_osv(path: Path, root: Path) -> list[Finding]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    data = json.loads(raw)
    out = []
    # 권고(advisory) 하나당 한 건이면 결과가 의존성으로 뒤덮인다 → 패키지 단위로 묶는다
    for res in data.get("results", []):
        src = _rel(res.get("source", {}).get("path", ""), root)
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            groups = pkg.get("groups", []) or [{"ids": [i]} for i in vulns]
            if not groups:
                continue
            sevs, ids, fixed, summaries = [], [], set(), []
            for g in groups:
                gids = g.get("ids", [])
                v = next((vulns[i] for i in gids if i in vulns), {})
                sevs.append(_osv_severity(g, v))
                ids.append(next((i for i in gids if i.startswith("GHSA")), gids[0] if gids else ""))
                if v.get("summary"):
                    summaries.append(v["summary"])
                fixed |= _fixed_versions(v, p.get("name"))
            worst = min(sevs, key=lambda s: SEV_ORDER[s])
            fix_txt = f" 고쳐진 버전: {', '.join(sorted(fixed, key=_ver_key)[-1:])} 이상." if fixed else ""
            out.append(Finding(
                item="AM-02",
                rule=f"osv:{p.get('name')}",
                tool="osv",
                severity=worst,
                confidence="HIGH",
                path=src,
                line=0,
                message=f"{p.get('name')}@{p.get('version')}: 알려진 취약점 {len(groups)}건"
                        + (f" (예: {summaries[0]})" if summaries else "") + "." + fix_txt,
                extra={"package": p.get("name"), "version": p.get("version"), "ids": ids,
                       "advisories": len(groups), "fixed": sorted(fixed, key=_ver_key)},
            ))
    return out


def _ver_key(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v))


def _fixed_versions(vuln: dict, name: str | None) -> set[str]:
    out = set()
    for aff in vuln.get("affected", []):
        if name and aff.get("package", {}).get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if ev.get("fixed"):
                    out.add(ev["fixed"])
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.key() in seen:
            continue
        seen.add(f.key())
        out.append(f)
    out.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.item, f.path, f.line))
    return out
