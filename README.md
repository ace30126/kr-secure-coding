# kr-secure-coding

바이브코딩으로 만든 JS/TS SaaS를 **행정안전부 SW 보안약점 49개 항목** 기준으로 점검하고, 한국어 보고서와 **AI 코딩 도구에 그대로 붙여넣는 수정 프롬프트**를 만들어 주는 GitHub Action입니다.

## 무엇을 점검하나

| 영역 | 도구 | 예 |
|---|---|---|
| 행안부 49개 항목 | Semgrep 규칙 27개(`rules/`) | SQL 삽입, XSS, 명령어 삽입, SSRF, 하드코드된 비밀키, 약한 난수 |
| 바이브코딩 SaaS 특화 | 자체 검사(`ksc/checks.py`) | Supabase RLS 미설정, Firebase `if true` 규칙, `NEXT_PUBLIC_` 비밀키, 인증 없는 API 라우트, 커밋된 `.env` |
| 비밀값 | gitleaks | API 키, 토큰 (원문은 결과에 남기지 않음) |
| 의존성 | osv-scanner | 알려진 취약점이 있는 npm 패키지 |
| 관리·인적·물리 | 문답 체크리스트 | 관리자 MFA, 퇴사자 권한 회수, 백업 복구, 개인정보 처리방침 |

보고서 첫 화면에서 49개 항목 각각이 **자동 점검 / 부분 자동 / 문답 확인 / 해당 없음** 중 무엇인지 보여줍니다. JS/TS에서 성립하지 않는 항목(메모리 버퍼 오버플로우 등)은 "해당 없음"으로 표시하고, 통과한 척하지 않습니다.

## 사용법

`.github/workflows/kr-secure-coding.yml`:

```yaml
name: 보안 점검
on:
  push: { branches: [main] }
  schedule: [{ cron: "0 0 * * 1" }]
  workflow_dispatch:
permissions:
  contents: read
  security-events: write
  actions: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: ace30126/kr-secure-coding@v1
        with:
          report-password: ${{ secrets.KSC_REPORT_PASSWORD }}
```

| 입력 | 기본값 | 설명 |
|---|---|---|
| `path` | `.` | 점검할 디렉터리 |
| `fail-on` | `never` | `high`·`medium`·`low` 이상이 있으면 실패 처리 |
| `upload-sarif` | `auto` | Security 탭 업로드. `auto`는 공개 저장소만(비공개는 GitHub Code Security 필요) |
| `report-password` | | 상세 보고서를 이 비밀번호로 암호화 |
| `public-report` | `false` | 공개 저장소에서도 평문 보고서를 아티팩트로 남김(권장하지 않음) |
| `scan-git-history` | `false` | 비밀값 검사를 git 기록 전체로 확장(`fetch-depth: 0` 필요) |
| `semgrep-extra-configs` | | 추가 Semgrep 설정. 결과의 CWE를 행안부 항목으로 자동 매핑 |

## 결과는 어디서 보나

점검 결과 자체가 공격 지도가 될 수 있어서, **공개된 곳에는 개수만** 남깁니다.

| 위치 | 내용 | 누가 보나 |
|---|---|---|
| Actions 로그·Job Summary | 위험도별 개수만 | 공개 저장소면 누구나 |
| Security 탭 | 위치·설명·수정 프롬프트 | 쓰기 권한자만 |
| 아티팩트 `report.html` | 전체 보고서 | 비공개 저장소면 그대로, 공개 저장소면 `report-password`로 암호화했을 때만 남김 |

PR마다 돌리는 것도 가능하지만, 공개 저장소에서는 PR 주석을 누구나 볼 수 있으니 기본값에서 뺐습니다.

## 관리·인적·물리 문답

저장소에 `.kr-secure-coding/checklist.yml`을 만들어 답을 적으면 보고서에 반영됩니다. 질문 목록은 [standards/checklist.yml](standards/checklist.yml)에 있습니다.

```yaml
answers:
  AD-01: yes   # 관리자 계정 MFA
  AD-02: no    # 비밀번호 최소 길이 규칙
  PH-01: yes   # 인증받은 클라우드 사용
```

## 비슷한 도구와의 차이

- [saige-secure-coding-kr](https://github.com/servantcdh/saige-secure-coding-kr): 같은 행안부 49 + TS 기준이지만, Claude Code 플러그인 형태로 개발 중 diff를 LLM이 판정합니다. 이 도구는 CI에서 결정적 규칙으로 돌고 LLM이 필요 없으며, Supabase·Firebase 같은 BaaS 설정과 관리적 보안까지 봅니다.
- Semgrep·CodeQL·Snyk: 범용 도구입니다. 이 도구는 그 위에 국내 기준 매핑, 한국어 설명, 바이브코더용 수정 프롬프트를 얹은 것입니다.

## 한계

- 정적 분석은 알려진 패턴만 찾습니다. 0건이 안전 증명은 아닙니다.
- 행안부 항목 매핑은 「소프트웨어 보안약점 진단가이드(2021)」 기준이며 공식 진단을 대신하지 않습니다.
- 현재 JS/TS만 지원합니다. Python은 다음 단계입니다.

## 개발

```bash
python -m venv .venv && .venv/Scripts/pip install semgrep pyyaml cryptography
python -m unittest discover -s tests
```

`examples/vuln-next-supabase/`는 규칙 회귀 테스트용 취약 샘플입니다(키는 모두 가짜).
