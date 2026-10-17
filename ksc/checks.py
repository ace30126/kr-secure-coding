"""Semgrep으로 표현하기 어려운 저장소 단위 검사(바이브코딩 SaaS 특화)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .findings import Finding

SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "out", ".vercel", "coverage", ".venv", "vendor"}

_CREATE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)", re.I)
_RLS = re.compile(r"alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)\s+enable\s+row\s+level\s+security", re.I)
_OPEN_POLICY = re.compile(r"create\s+policy[^;]*?using\s*\(\s*true\s*\)", re.I | re.S)
_FB_OPEN = re.compile(r"allow\s+[\w\s,]+:\s*if\s+true\s*;|allow\s+[\w\s,]+;", re.I)
_MUTATING_EXPORT = re.compile(r"export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=")
_AUTH_HINT = re.compile(
    r"auth\(|getUser|getSession|getServerSession|currentUser|clerk|withAuth|requireAuth|requireUser|"
    r"verifyToken|jwt\.verify|jwtVerify|authorization|x-api-key|apiKey|webhook|signature|svix|stripe\.webhooks",
    re.I,
)
# 로그인 전에 불려야 정상인 경로는 인증 누락으로 보지 않는다
_PUBLIC_ROUTE = re.compile(r"/(login|signin|sign-in|signup|sign-up|register|auth|callback|logout|forgot|reset|webhooks?|health)(/|\b)", re.I)
_ENV_FILE =re.compile(r"^\.env(\..+)?$")
_ENV_SAFE = re.compile(r"example|sample|template|dist|defaults?$", re.I)


def _files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts[:-1]) & SKIP_DIRS):
            yield p


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _table_key(name: str) -> str:
    name = name.replace('"', "").lower()
    return name if "." in name else f"public.{name}"


def supabase_rls(root: Path, files: list[Path]) -> list[Finding]:
    created: dict[str, tuple[str, int]] = {}
    enabled: set[str] = set()
    out: list[Finding] = []
    for p in files:
        if p.suffix.lower() != ".sql":
            continue
        rel = p.relative_to(root).as_posix()
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in _CREATE.finditer(text):
            created.setdefault(_table_key(m.group(1)), (rel, _line_of(text, m.start())))
        for m in _RLS.finditer(text):
            enabled.add(_table_key(m.group(1)))
        for m in _OPEN_POLICY.finditer(text):
            out.append(Finding("VC-02", "ksc-supabase-policy-true", "ksc", "medium", "MEDIUM", rel,
                               _line_of(text, m.start()),
                               "RLS 정책 조건이 using (true)라 사실상 모두에게 열려 있습니다. 공개 게시물처럼 의도한 경우가 아니면 auth.uid() 조건을 넣으세요.",
                               m.group(0).splitlines()[0][:160]))
    for table, (rel, line) in created.items():
        # Supabase API로 노출되는 건 public 스키마다
        if table.startswith("public.") and table not in enabled:
            out.append(Finding("VC-02", "ksc-supabase-no-rls", "ksc", "high", "HIGH", rel, line,
                               f"{table} 테이블에 RLS(row level security)를 켠 기록이 없습니다. 앱에 들어 있는 anon 키만으로 이 테이블 전체를 읽고 쓸 수 있습니다.",
                               f"create table {table}"))
    return out


def firebase_rules(root: Path, files: list[Path]) -> list[Finding]:
    out = []
    for p in files:
        rel = p.relative_to(root).as_posix()
        if p.name in ("firestore.rules", "storage.rules"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for m in _FB_OPEN.finditer(text):
                out.append(Finding("VC-02", "ksc-firebase-open-rules", "ksc", "high", "HIGH", rel,
                                   _line_of(text, m.start()),
                                   "Firebase 보안 규칙이 조건 없이 읽기/쓰기를 허용합니다. 누구나 DB·스토리지 전체를 읽고 지울 수 있습니다.",
                                   m.group(0).strip()))
        elif p.name == "database.rules.json":
            try:
                rules = json.loads(p.read_text(encoding="utf-8")).get("rules", {})
            except (ValueError, AttributeError):
                continue
            for k in (".read", ".write"):
                if rules.get(k) in (True, "true"):
                    out.append(Finding("VC-02", "ksc-firebase-open-rules", "ksc", "high", "HIGH", rel, 1,
                                       f"Realtime Database 최상위 {k} 가 true 입니다. 누구나 전체 데이터에 접근합니다.",
                                       f'"{k}": true'))
    return out


def unauth_routes(root: Path, files: list[Path]) -> list[Finding]:
    has_middleware = any(p.relative_to(root).as_posix() in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js")
                         for p in files)
    out = []
    for p in files:
        rel = p.relative_to(root).as_posix()
        is_app_route = re.search(r"(^|/)app/.*route\.(t|j)sx?$", rel)
        is_pages_api = re.search(r"(^|/)pages/api/.*\.(t|j)sx?$", rel)
        if not (is_app_route or is_pages_api) or _PUBLIC_ROUTE.search(rel):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if _AUTH_HINT.search(text):
            continue
        methods = [m.group(1) or m.group(2) for m in _MUTATING_EXPORT.finditer(text)]
        if is_pages_api and not methods and "export default" in text:
            methods = ["(handler)"]
        if not methods:
            continue
        m = _MUTATING_EXPORT.search(text)
        out.append(Finding(
            "SF-01", "ksc-route-without-auth", "ksc",
            "low" if has_middleware else "medium", "MEDIUM", rel,
            _line_of(text, m.start()) if m else 1,
            f"데이터를 바꾸는 API({', '.join(methods)})에서 로그인·권한 확인 코드를 찾지 못했습니다."
            + (" middleware 가 있어 거기서 막고 있을 수 있으니 확인하세요." if has_middleware else ""),
            (m.group(0) if m else "export default")[:120],
        ))
    return out


def committed_env(root: Path, files: list[Path]) -> list[Finding]:
    out = []
    for p in files:
        if _ENV_FILE.match(p.name) and not _ENV_SAFE.search(p.name):
            out.append(Finding("VC-01", "ksc-env-file-committed", "ksc", "high", "HIGH",
                               p.relative_to(root).as_posix(), 1,
                               f"{p.name} 파일이 저장소에 들어 있습니다. 안의 키는 모두 노출된 것으로 보고 교체한 뒤, 파일을 지우고 .gitignore에 추가하세요.",
                               "(값은 표시하지 않음)"))
    return out


def run_all(root: Path) -> list[Finding]:
    files = list(_files(root))
    return supabase_rls(root, files) + firebase_rules(root, files) + unauth_routes(root, files) + committed_env(root, files)
