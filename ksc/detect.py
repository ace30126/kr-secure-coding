"""저장소의 언어 구성을 판별한다. 사용자가 언어를 고르지 않아도 보고서가 점검 범위를 정직하게 밝히게 한다."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .checks import SKIP_DIRS

# 확장자 → (언어 키, 표시 이름)
EXT = {
    ".js": ("js", "JavaScript"), ".jsx": ("js", "JavaScript"), ".mjs": ("js", "JavaScript"), ".cjs": ("js", "JavaScript"),
    ".ts": ("js", "TypeScript"), ".tsx": ("js", "TypeScript"), ".mts": ("js", "TypeScript"), ".cts": ("js", "TypeScript"),
    ".vue": ("js", "Vue"), ".svelte": ("js", "Svelte"),
    ".py": ("py", "Python"),
    ".java": ("java", "Java"), ".kt": ("java", "Kotlin"),
    ".go": ("go", "Go"), ".rb": ("rb", "Ruby"), ".php": ("php", "PHP"),
    ".cs": ("cs", "C#"), ".rs": ("rs", "Rust"), ".swift": ("swift", "Swift"), ".dart": ("dart", "Dart"),
    ".c": ("c", "C"), ".cpp": ("c", "C++"), ".h": ("c", "C/C++"),
}
# 규칙이 있는 언어
SUPPORTED = {"js"}
# 프레임워크 단서 (파일 이름 → 표시)
MARKERS = {
    "next.config.js": "Next.js", "next.config.mjs": "Next.js", "next.config.ts": "Next.js",
    "vite.config.ts": "Vite", "vite.config.js": "Vite", "nuxt.config.ts": "Nuxt",
    "supabase": "Supabase", "firebase.json": "Firebase", "firestore.rules": "Firebase",
    "requirements.txt": "Python(pip)", "pyproject.toml": "Python", "manage.py": "Django",
    "app.json": "Expo/React Native", "vercel.json": "Vercel",
}
_MAX_BYTES = 1_000_000  # 번들·생성 파일이 비율을 왜곡하지 않게 큰 파일은 뺀다


def detect(root: Path) -> dict:
    size = Counter()
    names: dict[str, Counter] = {}
    stacks = set()
    for p in root.rglob("*"):
        rel_parts = p.relative_to(root).parts
        if set(rel_parts[:-1]) & SKIP_DIRS:
            continue
        if p.name in MARKERS and (p.is_file() or p.is_dir()):
            stacks.add(MARKERS[p.name])
        if not p.is_file() or p.suffix.lower() not in EXT or p.name.endswith((".min.js", ".d.ts")):
            continue
        try:
            n = p.stat().st_size
        except OSError:
            continue
        if n > _MAX_BYTES:
            continue
        key, label = EXT[p.suffix.lower()]
        size[key] += n
        names.setdefault(key, Counter())[label] += n

    total = sum(size.values())
    langs = []
    for key, n in size.most_common():
        pct = round(n * 100 / total, 1) if total else 0
        langs.append({
            "key": key,
            "name": " / ".join(lbl for lbl, _ in names[key].most_common()),
            "percent": pct,
            "supported": key in SUPPORTED,
        })
    covered = round(sum(l["percent"] for l in langs if l["supported"]), 1)
    return {"languages": langs, "covered_percent": covered if total else 0.0,
            "stacks": sorted(stacks), "has_code": bool(total)}
