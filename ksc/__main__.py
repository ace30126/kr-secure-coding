"""python -m ksc --root <저장소> --out <출력 폴더> [--semgrep s.json] [--gitleaks g.json] [--osv o.json]"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import checks
from .findings import dedupe, from_gitleaks, from_osv, from_semgrep, SEV_ORDER
from .report import build_model, now_kst, write_all
from .standards import Standard


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="kr-secure-coding")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="ksc-out")
    ap.add_argument("--semgrep")
    ap.add_argument("--gitleaks")
    ap.add_argument("--osv")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", Path.cwd().name))
    ap.add_argument("--ref", default=os.environ.get("GITHUB_REF_NAME", "local"))
    ap.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "-"))
    ap.add_argument("--password-env", default="KSC_REPORT_PASSWORD",
                    help="이 환경변수에 값이 있으면 report.html 을 암호화한다")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never")
    a = ap.parse_args(argv)

    root = Path(a.root).resolve()
    std = Standard()
    findings = checks.run_all(root)
    if a.semgrep and Path(a.semgrep).exists():
        findings += from_semgrep(Path(a.semgrep), root, std)
    if a.gitleaks and Path(a.gitleaks).exists():
        findings += from_gitleaks(Path(a.gitleaks), root)
    if a.osv and Path(a.osv).exists():
        findings += from_osv(Path(a.osv), root)
    findings = dedupe(findings)

    model = build_model(findings, std, root, {"repo": a.repo, "ref": a.ref, "sha": a.sha, "time": now_kst()})
    stats = write_all(model, std, Path(a.out), os.environ.get(a.password_env) or None)
    # 공개 로그에는 개수만 찍는다
    print(json.dumps(stats, ensure_ascii=False))

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            for k, v in stats.items():
                fh.write(f"{k}={str(v).lower() if isinstance(v, bool) else v}\n")

    if a.fail_on != "never":
        limit = SEV_ORDER[a.fail_on]
        if any(SEV_ORDER[f.severity] <= limit for f in findings):
            print(f"::error::{a.fail_on} 이상 위험도 항목이 있어 실패 처리합니다.")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
