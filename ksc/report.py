"""Finding 목록 → 상세 HTML 보고서 / 공개용 요약(개수만) / SARIF."""
from __future__ import annotations

import base64
import html
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .detect import detect
from .findings import Finding
from .standards import BASE, Standard

SEV_KO = {"high": "높음", "medium": "중간", "low": "낮음"}
JS_KO = {"auto": "자동", "partial": "부분 자동", "na": "해당 없음", "manual": "문답 확인"}
ANS_KO = {"yes": "예", "no": "아니오", "na": "해당 없음", None: "미응답"}


# ───────────────────────── 문답 체크리스트 ─────────────────────────
def load_checklist(root: Path) -> tuple[dict, list[dict], dict]:
    spec = yaml.safe_load((BASE / "standards" / "checklist.yml").read_text(encoding="utf-8"))
    answers = {}
    for name in ("checklist.yml", "checklist.yaml"):
        p = root / ".kr-secure-coding" / name
        if p.exists():
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            # yes/no 는 YAML에서 bool 로 읽히므로 되돌린다
            for k, v in (raw.get("answers", raw) or {}).items():
                answers[str(k)] = {True: "yes", False: "no"}.get(v, str(v).lower() if v is not None else None)
            break
    return spec["areas"], spec["questions"], answers


# ───────────────────────── 수정 프롬프트 ─────────────────────────
def fix_prompt(f: Finding, std: Standard) -> str:
    fx = std.fix(f.item)
    loc = f"{f.path}:{f.line}" if f.line else f.path
    lines = [
        f"[보안 수정 요청] {std.name(f.item)} ({f.item})",
        f"위치: {loc}",
        f"문제: {f.message}",
    ]
    if f.snippet:
        lines.append(f"해당 코드: {f.snippet}")
    lines += [f"요청: {fx['how']}", "기존 기능은 그대로 유지하고, 무엇을 왜 바꿨는지 짧게 설명해줘."]
    return "\n".join(lines)


# ───────────────────────── 집계 ─────────────────────────
def build_model(findings: list[Finding], std: Standard, root: Path, meta: dict) -> dict:
    by_item = Counter(f.item for f in findings)
    areas, questions, answers = load_checklist(root)
    manual_ans = {q["mois"]: answers.get(q["id"]) for q in questions if q.get("mois")}

    coverage = []
    for it in std.items:
        n = by_item.get(it["id"], 0)
        js = it["js"]
        if n:
            status, cls = f"발견 {n}건", "bad"
        elif js == "auto":
            status, cls = "자동 점검 통과", "ok"
        elif js == "partial":
            status, cls = "자동 범위 통과 · 일부 수동 확인", "warn"
        elif js == "manual":
            a = manual_ans.get(it["id"])
            status, cls = f"문답: {ANS_KO.get(a, a)}", {"yes": "ok", "no": "bad"}.get(a, "warn")
        else:
            status, cls = "해당 없음", "na"
        coverage.append({**it, "status": status, "cls": cls, "count": n,
                         "category_name": std.categories[it["id"][:2]]})

    js_counts = Counter(i["js"] for i in std.items)
    sev = Counter(f.severity for f in findings if f.tool != "osv")
    return {
        "meta": meta,
        "findings": findings,
        # sev 는 코드·설정 발견만 센다. 의존성은 deps 로 따로 보여준다
        "sev": {k: sev.get(k, 0) for k in ("high", "medium", "low")},
        "coverage": coverage,
        "js_counts": js_counts,
        "extras": [{**e, "count": by_item.get(e["id"], 0)} for e in std.extras],
        "checklist": {"areas": areas, "questions": questions, "answers": answers},
        "deps": [f for f in findings if f.tool == "osv"],
        "lang": detect(root),
    }


# ───────────────────────── 공개용 요약 (개수만) ─────────────────────────
def summary_md(model: dict) -> str:
    s, js = model["sev"], model["js_counts"]
    deps = model["deps"]
    total = sum(s.values()) + len(deps)
    ans = model["checklist"]["answers"]
    answered = sum(1 for q in model["checklist"]["questions"] if ans.get(q["id"]))
    return "\n".join([
        "## 🔐 kr-secure-coding 점검 결과",
        "",
        f"| 코드·설정 | 건수 |\n|---|---|\n| 높음 | **{s['high']}** |\n| 중간 | {s['medium']} |\n| 낮음 | {s['low']} |",
        "",
        f"- 취약한 의존성: 패키지 {len(deps)}개 (그중 높음 {sum(1 for f in deps if f.severity == 'high')}개)",
        lang_line(model["lang"]),
        f"- 기준: 행안부 SW 보안약점 49개 항목(자동 {js['auto']} · 부분 {js['partial']} · 문답 {js['manual']} · 해당 없음 {js['na']}) + 바이브코딩 SaaS 특화 점검",
        f"- 관리·인적·물리 문답: {answered}/{len(model['checklist']['questions'])}개 응답",
        "",
        "상세 내용(파일 위치·수정 프롬프트)은 공개 로그에 싣지 않습니다. "
        + ("저장소 **Security 탭**(쓰기 권한자만 열람) 또는 워크플로 아티팩트의 보고서를 확인하세요." if total else "발견된 항목이 없습니다."),
    ]) + "\n"


def _lang_text(lang: dict) -> str:
    parts = [f"{l['name']} {l['percent']:g}%" for l in lang["languages"][:4]]
    stacks = f" ({', '.join(lang['stacks'])})" if lang["stacks"] else ""
    return " · ".join(parts) + stacks


def lang_line(lang: dict) -> str:
    if not lang["has_code"]:
        return "- 감지된 코드: 없음"
    line = f"- 감지된 구성: {_lang_text(lang)} → 이번 점검 범위 {lang['covered_percent']:g}%"
    missing = [l["name"] for l in lang["languages"] if not l["supported"]]
    return line + (f" ({', '.join(missing)} 규칙은 아직 없음)" if missing else "")


def lang_html(lang: dict) -> str:
    if not lang["has_code"]:
        return '<p class="langbar warn">점검할 소스 코드를 찾지 못했습니다. path 입력이 맞는지 확인하세요.</p>'
    missing = [l["name"] for l in lang["languages"] if not l["supported"]]
    warn = (f" <b>{_e(', '.join(missing))}</b> 코드는 아직 전용 규칙이 없어 비밀값·의존성·설정만 점검했습니다."
            if missing else "")
    return (f'<p class="langbar{" warn" if missing else ""}">감지된 구성: {_e(_lang_text(lang))}. '
            f'코드 규칙 점검 범위 <b>{lang["covered_percent"]:g}%</b>.{warn}</p>')


# ───────────────────────── SARIF ─────────────────────────
def sarif(model: dict, std: Standard) -> dict:
    level = {"high": "error", "medium": "warning", "low": "note"}
    rules, results = {}, []
    for f in model["findings"]:
        if f.rule not in rules:
            fx = std.fix(f.item)
            rules[f.rule] = {
                "id": f.rule,
                "name": f.rule,
                "shortDescription": {"text": f"{std.name(f.item)} ({f.item})"},
                "fullDescription": {"text": fx["why"]},
                "help": {"text": fx["how"], "markdown": fx["how"]},
                "properties": {"tags": ["security", f.item, f"행안부:{std.name(f.item)}"],
                               "security-severity": {"high": "8.0", "medium": "5.0", "low": "2.0"}[f.severity]},
            }
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.path or "."}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule,
            "level": level[f.severity],
            "message": {"text": f"{f.message}\n\n[AI 수정 프롬프트]\n{fix_prompt(f, std)}"},
            "locations": [loc],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "kr-secure-coding", "informationUri": "https://github.com/ace30126/kr-secure-coding",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }


# ───────────────────────── HTML ─────────────────────────
def _e(s) -> str:
    return html.escape(str(s), quote=True)


def report_html(model: dict, std: Standard) -> str:
    m, s = model["meta"], model["sev"]
    js = model["js_counts"]
    parts = []

    # 바이브코딩 핵심 위험
    vc = "".join(
        f'<li class="{"bad" if e["count"] else "ok"}"><b>{_e(e["name"])}</b>'
        f'<span>{"발견 " + str(e["count"]) + "건" if e["count"] else "발견 없음"}</span></li>'
        for e in model["extras"])
    parts.append(f'<section><h2>바이브코딩에서 사고가 잦은 4가지</h2><ul class="vc">{vc}</ul></section>')

    # 상세 발견
    cards = []
    for idx, f in enumerate(f for f in model["findings"] if f.tool != "osv"):
        fx = std.fix(f.item)
        loc = f"{f.path}:{f.line}" if f.line else f.path
        cards.append(f"""
<article class="card sev-{f.severity}">
  <header><span class="badge {f.severity}">{SEV_KO[f.severity]}</span>
    <b>{_e(std.name(f.item))}</b> <code class="id">{_e(f.item)}</code>
    {'<span class="conf">확인 필요</span>' if f.confidence != "HIGH" else ''}</header>
  <p class="loc"><code>{_e(loc)}</code></p>
  <p>{_e(f.message)}</p>
  {f'<pre class="snip">{_e(f.snippet)}</pre>' if f.snippet else ''}
  <details><summary>왜 위험한가요?</summary><p>{_e(fx['why'])}</p></details>
  <div class="prompt"><div class="ph"><span>AI 코딩 도구에 붙여넣을 수정 프롬프트</span>
    <button type="button" data-copy="p{idx}">복사</button></div>
    <pre id="p{idx}">{_e(fix_prompt(f, std))}</pre></div>
</article>""")
    parts.append('<section><h2>발견 항목</h2>' + ("".join(cards) or '<p class="empty">코드에서 발견된 항목이 없습니다.</p>') + '</section>')

    # 의존성
    if model["deps"]:
        rows = "".join(
            f'<tr><td><span class="badge {f.severity}">{SEV_KO[f.severity]}</span></td><td><code>{_e(f.extra.get("package"))}@{_e(f.extra.get("version"))}</code></td>'
            f'<td>{f.extra.get("advisories", 1)}건</td><td>{_e(f.extra["fixed"][-1] + " 이상") if f.extra.get("fixed") else "-"}</td>'
            f'<td><code>{_e(", ".join(f.extra.get("ids", [])[:2]))}</code>{" 외" if len(f.extra.get("ids", [])) > 2 else ""}</td></tr>'
            for f in model["deps"])
        parts.append(f'<section><h2>취약한 의존성 <small>(AM-02 취약한 API 사용)</small></h2>'
                     f'<div class="tw"><table><thead><tr><th>위험도</th><th>패키지</th><th>알려진 취약점</th><th>올릴 버전</th><th>권고 ID</th></tr></thead><tbody>{rows}</tbody></table></div>'
                     f'<p class="note">한 번에 고치려면 AI 도구에 「package.json 의 위 패키지들을 취약점이 고쳐진 버전으로 올리고 깨지는 코드를 고쳐줘」라고 요청하세요.</p></section>')

    # 49 커버리지
    rows, last = [], None
    for c in model["coverage"]:
        if c["category_name"] != last:
            rows.append(f'<tr class="cat"><td colspan="3">{_e(c["category_name"])}</td></tr>')
            last = c["category_name"]
        rows.append(f'<tr><td><code>{_e(c["id"])}</code> {_e(c["name"])}</td><td>{JS_KO[c["js"]]}</td>'
                    f'<td class="st {c["cls"]}">{_e(c["status"])}'
                    f'{"<small>" + _e(c["note"]) + "</small>" if c.get("note") else ""}</td></tr>')
    parts.append(f'<section><h2>행안부 49개 항목별 결과</h2>'
                 f'<p class="note">JS/TS 기준 자동 {js["auto"]} · 부분 자동 {js["partial"]} · 문답 {js["manual"]} · 해당 없음 {js["na"]}. '
                 f'"자동 점검 통과"는 규칙이 아는 패턴이 없다는 뜻이지, 안전이 증명됐다는 뜻은 아닙니다.</p>'
                 f'<div class="tw"><table><thead><tr><th>항목</th><th>점검 방식</th><th>결과</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>')

    # 문답
    ck = model["checklist"]
    qrows = []
    for area, area_name in ck["areas"].items():
        for q in (q for q in ck["questions"] if q["area"] == area):
            a = ck["answers"].get(q["id"])
            cls = {"yes": "ok", "no": "bad", "na": "na"}.get(a, "warn")
            qrows.append(f'<tr><td>{_e(area_name)}</td><td>{_e(q["q"])}<small>{_e(q["why"])} · ISMS-P {_e(q["isms"])}</small></td>'
                         f'<td class="st {cls}">{ANS_KO.get(a, a)}</td></tr>')
    parts.append('<section><h2>관리·인적·물리 보안 문답</h2>'
                 '<p class="note">코드로 알 수 없는 항목입니다. 저장소에 <code>.kr-secure-coding/checklist.yml</code> 을 만들어 '
                 '<code>AD-01: yes</code> 처럼 답을 적으면 다음 점검부터 반영됩니다.</p>'
                 f'<div class="tw"><table><thead><tr><th>영역</th><th>질문</th><th>답</th></tr></thead><tbody>{"".join(qrows)}</tbody></table></div></section>')

    parts.append('<section class="disc"><h2>이 보고서의 한계</h2><ul>'
                 '<li>정적 분석은 알려진 패턴만 찾습니다. 발견 0건이 안전하다는 뜻은 아닙니다.</li>'
                 '<li>"확인 필요" 표시는 맥락에 따라 오탐일 수 있는 항목입니다.</li>'
                 '<li>비밀값은 마스킹했습니다. 그래도 이 보고서는 공격 지도가 될 수 있으니 공개 장소에 올리지 마세요.</li>'
                 '<li>행안부 항목 매핑은 「소프트웨어 보안약점 진단가이드(2021)」 기준이며 공식 진단을 대신하지 않습니다.</li></ul></section>')

    total = sum(s.values()) + len(model["deps"])
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>보안 점검 보고서 - {_e(m['repo'])}</title>
<style>{CSS}</style></head><body><main>
<header class="top"><p class="eyebrow">kr-secure-coding 보안 점검 보고서</p><h1>{_e(m['repo'])}</h1>
<p class="meta"><code>{_e(m['ref'])}</code> · <code>{_e(m['sha'][:10])}</code> · {_e(m['time'])}</p></header>
<section class="kpi">
 <div class="k high"><b>{s['high']}</b><span>높음</span></div>
 <div class="k medium"><b>{s['medium']}</b><span>중간</span></div>
 <div class="k low"><b>{s['low']}</b><span>낮음</span></div>
 <div class="k"><b>{len(model['deps'])}</b><span>취약 의존성</span></div>
</section>
{lang_html(model["lang"])}
<p class="lead">{'<b>높음</b> 항목부터 고치세요. 각 항목의 수정 프롬프트를 복사해 Cursor·Claude·Copilot에 붙여넣으면 됩니다.' if total else '알려진 패턴의 보안약점은 발견되지 않았습니다. 아래 문답 항목도 확인해 보세요.'}</p>
{''.join(parts)}
</main><script>{JS}</script></body></html>"""


CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e3e2dc;--hi:#c62828;--md:#b26a00;--lo:#3d6fb6;--ok:#2e7d32;--code:#f0efe9}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#a3a29b;--card:#20201e;--line:#34332f;--hi:#ef6b6b;--md:#e0a23a;--lo:#7aa7e8;--ok:#6cc070;--code:#2a2a27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.65 -apple-system,"Pretendard","Apple SD Gothic Neo","Malgun Gothic",sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 80px}h1{margin:.1em 0;font-size:1.7rem}h2{font-size:1.15rem;margin:2.2em 0 .8em;padding-bottom:.4em;border-bottom:1px solid var(--line)}
h2 small{color:var(--mut);font-weight:400}.eyebrow{margin:0;color:var(--mut);font-size:.85rem}.meta{color:var(--mut);margin:0}.lead{margin:1em 0 0}
code{font:.86em ui-monospace,SFMono-Regular,Consolas,monospace;background:var(--code);padding:.1em .35em;border-radius:4px;word-break:break-all}
.kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:20px}.k{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;text-align:center}
.k b{display:block;font-size:1.9rem;line-height:1.1}.k span{color:var(--mut);font-size:.85rem}.k.high b{color:var(--hi)}.k.medium b{color:var(--md)}.k.low b{color:var(--lo)}
.vc{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.vc li{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;display:flex;justify-content:space-between;gap:8px}
.vc li.bad{border-left:4px solid var(--hi)}.vc li.ok{border-left:4px solid var(--ok)}.vc span{color:var(--mut);white-space:nowrap}
.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--lo);border-radius:10px;padding:14px 16px;margin:12px 0}
.card.sev-high{border-left-color:var(--hi)}.card.sev-medium{border-left-color:var(--md)}.card header{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.card p{margin:.5em 0}.loc{margin:.3em 0 0!important}.badge{font-size:.75rem;font-weight:700;padding:2px 8px;border-radius:99px;color:#fff;background:var(--lo)}
.badge.high{background:var(--hi)}.badge.medium{background:var(--md)}.id{font-size:.75rem}.conf{font-size:.75rem;color:var(--md);border:1px solid var(--md);border-radius:99px;padding:0 7px}
pre{white-space:pre-wrap;word-break:break-word;margin:0;font:.84rem/1.55 ui-monospace,Consolas,monospace}.snip{background:var(--code);padding:8px 10px;border-radius:6px}
details{margin:.4em 0}summary{cursor:pointer;color:var(--mut);font-size:.9rem}.prompt{border:1px dashed var(--line);border-radius:8px;margin-top:10px}
.ph{display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border-bottom:1px dashed var(--line);font-size:.8rem;color:var(--mut)}
.prompt pre{padding:10px}button{font:inherit;font-size:.8rem;padding:3px 12px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg);cursor:pointer}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--card);font-size:.9rem}th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600}tr.cat td{background:var(--code);font-weight:700}td small{display:block;color:var(--mut);font-size:.8rem}
.st.ok{color:var(--ok)}.st.bad{color:var(--hi);font-weight:700}.st.warn{color:var(--md)}.st.na{color:var(--mut)}.note{color:var(--mut);font-size:.88rem}.empty{color:var(--mut)}
.langbar{margin:16px 0 0;padding:10px 12px;border-radius:8px;background:var(--card);border:1px solid var(--line);font-size:.9rem}.langbar.warn{border-color:var(--md)}
.disc ul{color:var(--mut);font-size:.9rem;padding-left:1.2em}
@media (max-width:560px){.kpi{grid-template-columns:repeat(2,1fr)}.vc{grid-template-columns:1fr}}
@media print{button{display:none}.card{break-inside:avoid}}
"""

JS = """document.addEventListener('click',e=>{const b=e.target.closest('button[data-copy]');if(!b)return;
const t=document.getElementById(b.dataset.copy).innerText;navigator.clipboard.writeText(t).then(()=>{b.textContent='복사됨';setTimeout(()=>b.textContent='복사',1500)})});"""


# ───────────────────────── 비밀번호 암호화 래퍼 ─────────────────────────
_ITER = 310_000


def encrypt_html(page: str, password: str) -> str:
    """공개 저장소 아티팩트용. 브라우저 WebCrypto로 복호화하는 단일 HTML을 만든다."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_ITER).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, page.encode("utf-8"), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>보안 점검 보고서 (암호화됨)</title><style>body{{font:16px -apple-system,"Malgun Gothic",sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f7f7f5;color:#1d1d1b}}
form{{background:#fff;padding:28px;border-radius:12px;border:1px solid #e3e2dc;max-width:360px;width:calc(100% - 32px)}}input,button{{box-sizing:border-box;font:inherit;width:100%;padding:10px;margin-top:10px;border-radius:8px;border:1px solid #ccc}}
button{{background:#1d1d1b;color:#fff;border:0;cursor:pointer}}#err{{color:#c62828;font-size:.9rem}}</style></head><body>
<form id="f"><b>보안 점검 보고서</b><p style="color:#6b6b66;font-size:.9rem">저장소 시크릿 KSC_REPORT_PASSWORD 에 넣은 비밀번호를 입력하세요.</p>
<input id="pw" type="password" autocomplete="off" placeholder="비밀번호"><button>열기</button><p id="err"></p></form>
<script>const D={{s:"{b64(salt)}",i:"{b64(iv)}",c:"{b64(ct)}",n:{_ITER}}};const u=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
document.getElementById('f').onsubmit=async e=>{{e.preventDefault();try{{const pw=new TextEncoder().encode(document.getElementById('pw').value);
const base=await crypto.subtle.importKey('raw',pw,'PBKDF2',false,['deriveKey']);
const key=await crypto.subtle.deriveKey({{name:'PBKDF2',salt:u(D.s),iterations:D.n,hash:'SHA-256'}},base,{{name:'AES-GCM',length:256}},false,['decrypt']);
const pt=await crypto.subtle.decrypt({{name:'AES-GCM',iv:u(D.i)}},key,u(D.c));document.open();document.write(new TextDecoder().decode(pt));document.close();
}}catch(_){{document.getElementById('err').textContent='비밀번호가 맞지 않습니다.'}}}};</script></body></html>"""


def write_all(model: dict, std: Standard, out: Path, password: str | None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(summary_md(model), encoding="utf-8")
    (out / "results.sarif").write_text(json.dumps(sarif(model, std), ensure_ascii=False, indent=1), encoding="utf-8")
    page = report_html(model, std)
    encrypted = bool(password)
    (out / "report.html").write_text(encrypt_html(page, password) if password else page, encoding="utf-8")
    return {"encrypted": encrypted, **model["sev"], "deps": len(model["deps"])}


def now_kst() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
