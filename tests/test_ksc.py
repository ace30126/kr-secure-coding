import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ksc import checks  # noqa: E402
from ksc.findings import from_semgrep, mask_secret, Finding  # noqa: E402
from ksc.report import build_model, encrypt_html, fix_prompt, report_html, sarif, summary_md  # noqa: E402
from ksc.standards import Standard  # noqa: E402

SAMPLE = ROOT / "examples" / "vuln-next-supabase"

# 샘플 앱에서 반드시 잡혀야 하는 규칙 (규칙을 고치다 놓치면 여기서 깨진다)
EXPECTED_SEMGREP = {
    "ksc-sql-string-build", "ksc-code-eval", "ksc-taint-request-to-sink", "ksc-xss-dangerously-set",
    "ksc-os-command", "ksc-open-redirect", "ksc-ssrf", "ksc-weak-hash", "ksc-hardcoded-jwt-secret",
    "ksc-insecure-random", "ksc-jwt-decode-no-verify", "ksc-tls-verify-off", "ksc-unsalted-password-hash",
    "ksc-error-leak", "ksc-empty-catch", "ksc-debug-leftover", "ksc-public-env-secret",
    "ksc-service-role-in-client", "ksc-cors-wildcard",
}
EXPECTED_CHECKS = {"ksc-supabase-no-rls", "ksc-supabase-policy-true", "ksc-firebase-open-rules", "ksc-route-without-auth"}


class StandardTest(unittest.TestCase):
    def test_49_items(self):
        std = Standard()
        self.assertEqual(len(std.items), 49)
        self.assertEqual(len({i["id"] for i in std.items}), 49)

    def test_cwe_mapping(self):
        std = Standard()
        self.assertEqual(std.item_for_cwe("CWE-89: Improper Neutralization"), "IV-01")
        self.assertEqual(std.item_for_cwe(["CWE-918: SSRF"]), "IV-12")
        self.assertIsNone(std.item_for_cwe("CWE-99999"))


class ChecksTest(unittest.TestCase):
    def test_sample_repo_checks(self):
        rules = {f.rule for f in checks.run_all(SAMPLE)}
        self.assertTrue(EXPECTED_CHECKS <= rules, EXPECTED_CHECKS - rules)

    def test_rls_enabled_table_not_flagged(self):
        found = [f for f in checks.run_all(SAMPLE) if f.rule == "ksc-supabase-no-rls"]
        self.assertEqual([f.message.split(" ")[0] for f in found], ["public.profiles"])

    def test_login_route_not_flagged_as_unauth(self):
        paths = {f.path for f in checks.run_all(SAMPLE) if f.rule == "ksc-route-without-auth"}
        self.assertNotIn("app/api/login/route.ts", paths)

    def test_env_file_flagged_without_value(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".env").write_text("SECRET=abcd1234abcd1234abcd1234\n")
            Path(d, ".env.example").write_text("SECRET=\n")
            fs = checks.run_all(Path(d))
            self.assertEqual([f.path for f in fs], [".env"])
            self.assertNotIn("abcd1234", fs[0].snippet + fs[0].message)


class DetectTest(unittest.TestCase):
    def test_sample_is_ts_with_stacks(self):
        from ksc.detect import detect
        r = detect(SAMPLE)
        self.assertEqual(r["languages"][0]["key"], "js")
        self.assertEqual(r["covered_percent"], 100.0)
        self.assertIn("Supabase", r["stacks"])
        self.assertIn("Firebase", r["stacks"])

    def test_mixed_repo_reports_uncovered_python(self):
        from ksc.detect import detect
        from ksc.report import lang_line
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.ts").write_text("x" * 800)
            Path(d, "worker.py").write_text("y" * 200)
            Path(d, "node_modules").mkdir()
            Path(d, "node_modules", "big.js").write_text("z" * 5000)  # 제외돼야 한다
            r = detect(Path(d))
            self.assertEqual(r["covered_percent"], 80.0)
            self.assertIn("Python 규칙은 아직 없음", lang_line(r))


class MaskTest(unittest.TestCase):
    def test_mask(self):
        out = mask_secret('jwt.sign(p, "my-super-secret-jwt-key")')
        self.assertNotIn("super-secret", out)
        self.assertIn("my-s", out)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9abcdefghij", mask_secret("k=eyJhbGciOiJIUzI1NiJ9abcdefghij"))


@unittest.skipUnless(shutil.which("semgrep") or (ROOT / ".venv" / "Scripts" / "semgrep.exe").exists(), "semgrep 없음")
class SemgrepRulesTest(unittest.TestCase):
    def test_sample_detected(self):
        exe = shutil.which("semgrep") or str(ROOT / ".venv" / "Scripts" / "semgrep.exe")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "s.json")
            env = {**os.environ, "PYTHONUTF8": "1"}
            subprocess.run([exe, "--config", str(ROOT / "rules"), "--metrics=off", "--json", "-q", "-o", str(out), str(SAMPLE)],
                           check=True, env=env)
            found = from_semgrep(out, SAMPLE, Standard())
        rules = {f.rule for f in found}
        self.assertTrue(EXPECTED_SEMGREP <= rules, EXPECTED_SEMGREP - rules)
        self.assertTrue(all(f.item != "ETC" for f in found))


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.std = Standard()
        self.findings = checks.run_all(SAMPLE) + [
            Finding("SF-06", "gitleaks:generic-api-key", "gitleaks", "high", "HIGH", "lib/db.ts", 6, "비밀값", 'const A = "a8f5****"'),
            Finding("AM-02", "osv:next", "osv", "high", "HIGH", "package-lock.json", 0, "next@13.4.0: 알려진 취약점 3건.",
                    extra={"package": "next", "version": "13.4.0", "ids": ["GHSA-x"], "advisories": 3, "fixed": ["14.2.32"]}),
        ]
        self.model = build_model(self.findings, self.std, SAMPLE, {"repo": "t/r", "ref": "main", "sha": "abc", "time": "now"})

    def test_summary_has_counts_only(self):
        md = summary_md(self.model)
        self.assertNotIn("lib/db.ts", md)
        self.assertNotIn("supabase/migrations", md)
        self.assertIn("패키지 1개", md)

    def test_checklist_answers_applied(self):
        cov = {c["id"]: c["status"] for c in self.model["coverage"]}
        self.assertEqual(cov["SF-09"], "문답: 아니오")   # AD-02: no
        self.assertEqual(cov["SF-16"], "문답: 미응답")

    def test_fix_prompt(self):
        p = fix_prompt(self.findings[0], self.std)
        self.assertIn("[보안 수정 요청]", p)
        self.assertIn("요청:", p)

    def test_sarif_valid_shape(self):
        s = sarif(self.model, self.std)
        self.assertEqual(s["version"], "2.1.0")
        ids = {r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]}
        self.assertTrue(all(r["ruleId"] in ids for r in s["runs"][0]["results"]))

    def test_html_and_encryption(self):
        page = report_html(self.model, self.std)
        self.assertIn("행안부 49개 항목별 결과", page)
        enc = encrypt_html(page, "pw")
        self.assertNotIn("행안부 49개 항목별 결과", enc)
        self.assertNotIn("lib/db.ts", enc)


if __name__ == "__main__":
    unittest.main()
