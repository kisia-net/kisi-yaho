# 웹 서버 (nginx + ModSecurity) — 하서휘 담당

계층도 rev.4 의 **1번 칸 왼쪽 두 상자**입니다.

```
웹 서버(nginx) ── 웹 방화벽(ModSecurity)  →  WAF 경보 · 요청 payload
        └────────── Wazuh Agent ──(1514/tcp)──▶ SIEM(Wazuh, 10.0.10.123)
```

내가 책임지는 서버는 하나입니다 — `web` / `i-0629c84bb40895441` / `10.0.1.201`
(퍼블릭 서브넷, 유일하게 인터넷에 열린 서버 = **공격받는 게 역할**).

김세현이 넘겨준 "빈 서버" 위에 **오픈소스를 깔고 설정해서, 실제 공격 로그를
SIEM 으로 흘려보내는 것** 까지가 내 몫입니다.

---

## 무엇이 나오면 끝인가 (완료 판정)

역할분담 원칙 3번 — 완료 판정이 없는 일은 끝나지 않습니다.

- [ ] `curl http://<web>/portal/index.php?page=about` 가 200 을 돌려준다 (nginx+php 살아있음)
- [ ] 공격 요청이 `/var/log/modsec_audit.json` 에 **JSON 한 줄씩** 쌓인다 (WAF 살아있음)
- [ ] 그 JSON 안에 **요청 본문(payload)** 이 들어 있다 (`grep -c '"C":'` 가 0 이 아님)
      ← 구성도에 "요청 payload" 라고 적힌 상자가 우리 상자입니다. 이게 핵심 산출물.
- [ ] Wazuh Manager 에서 `agent_control -l` 에 `web-01` 이 **Active** 로 뜬다
- [ ] SIEM 대시보드에 web 서버발 nginx·modsec 로그가 검색된다
- [ ] `WAF 탐지 + 웹서버 200` 사례와 `WAF 탐지 + 404` 사례가 **둘 다** 로그에 있다
      (경보 룰 3번이 판정할 재료. 통과=위험, 막힘=하향)

---

## 설치 순서

저장소가 비공개라 서버에서 바로 `git clone` 이 안 됩니다. 팀 S3 버킷을
경유해 파일을 올립니다. web 서버 IAM 역할에 web/ 경로 읽기 권한이
붙어 있습니다(`infra/terraform/iam.tf` 의 `web_artifact_read`).

```powershell
# 내 PC — infra/web 을 S3 로 업로드 (버킷 이름은 backend.tf 의 것: kisia-net1-s3)
aws s3 cp infra\web s3://kisia-net1-s3/web/ --recursive
```

빈 Ubuntu 22.04 서버에 접속한 뒤:

```bash
# 0) S3 에서 설치 파일 받기
sudo aws s3 cp s3://kisia-net1-s3/web/ /opt/kisiyaho-web/ --recursive
sudo chmod +x /opt/kisiyaho-web/*.sh /opt/kisiyaho-web/**/*.sh

# 1) nginx + ModSecurity + CRS + 취약 포털 한 번에
sudo REPO_DIR=/opt/kisiyaho-web bash /opt/kisiyaho-web/setup.sh
#    → 소스 빌드라 15~25분. 끝나면 안내대로 curl 로 확인.

# 2) Wazuh Agent (SIEM 으로 로그 전송)
sudo WAZUH_MANAGER=10.0.10.123 WAZUH_AGENT_NAME=web-01 \
     bash /opt/kisiyaho-web/wazuh/install-agent.sh
#    Manager 쪽에서 등록 수락(민석형/효찬)이 되어야 Active 가 됩니다.

# 3) 실제 공격을 쳐서 진짜 로그 만들기
bash /opt/kisiyaho-web/attack/replay.sh http://localhost
#    payload·상관분석 재료가 이때 생깁니다.

# 4) 만든 진짜 로그를 파이프라인 시나리오로 넘기기
bash /opt/kisiyaho-web/attack/capture-to-scenario.sh web_real_capture
```

---

## 파일 안내

| 파일 | 하는 일 |
|---|---|
| `setup.sh` | nginx 소스 빌드 + libmodsecurity + CRS + 앱까지 전부 |
| `nginx/portal.conf` | 사이트 설정. **로그 포맷 combined 고정**(파이프라인 정규식이 여기 맞춰짐) |
| `nginx/log_format.conf` | 사람용 확장 로그(별도). 파이프라인은 안 읽음 |
| `modsec/main.conf` | ModSecurity 진입점 (읽는 순서 = 우선순위) |
| `modsec/overrides.conf` | **우리가 바꾼 것 전부.** payload·JSON·Serial 설정이 여기 |
| `app/portal/` | 일부러 취약한 포털 (LFI·SQLi). 봉쇄는 open_basedir 로 |
| `app/portal.pool.conf` | PHP-FPM 풀. open_basedir 가 봉쇄선 |
| `app/seed.sh` | 더미 계정 DB. **가짜 계정만** |
| `decoy/etc/passwd` | 미끼. LFI 가 "성공한 척" 하되 진짜는 안 새게 |
| `wazuh/localfile.xml` | Agent 가 읽어 보낼 로그 3개 (nginx access/error, modsec) |
| `wazuh/install-agent.sh` | Wazuh Agent 설치 + ossec.conf 등록 |
| `attack/replay.sh` | 실제 공격 재현 (traversal·SQLi·brute force) |
| `attack/capture-to-scenario.sh` | 진짜 로그 → 파이프라인 시나리오 |

---

## 왜 이렇게 했나 (발표 예상 질문 대비)

- **왜 nginx 를 소스로 빌드했나** — apt 판 nginx 에는 ModSecurity 동적 모듈이
  없습니다. connector 를 붙이려면 `--add-dynamic-module` 로 같이 빌드해야 합니다.
- **왜 감사 로그를 JSON·Serial 로 했나** — 파이프라인의 `ModSecurityAdapter`
  (`hawki_alert_analysis/adapters.py:503`)가 "한 줄에 JSON 하나" 를 읽습니다.
  텍스트(Native)나 Concurrent 로 두면 ingest 가 못 읽습니다.
- **왜 취약점을 일부러 남겼나** — 공격이 성공(200)해야 경보 룰 3번(WAF+200 상관분석)
  이 판정할 "통과" 사례가 생깁니다. 대신 open_basedir + 미끼 트리로 실제 유출은 없습니다.
- **payload 를 켜면 로그가 커지지 않나** — 커집니다. `SecRequestBodyLimit`,
  `SecResponseBodyLimit` 로 상한을 둡니다. 재현 후 `du -h /var/log/modsec_audit.json`
  으로 증가폭을 재서 팀장에게 넘기면 확장성(§9) 답변에 씁니다.
- **차단(On) 과 탐지만(DetectionOnly) 중 뭘 쓰나** — 기본 On(차단, 403).
  "통과 사례" 를 만들 때만 잠깐 DetectionOnly 로 내려 200 이 나오게 합니다.

---

## 주의

- 이 서버는 인터넷에 열려 있습니다. **진짜 개인정보·팀 비밀값을 두지 마십시오**
  (terraform 전체개방 조건 3번). 계정은 전부 `seed.sh` 의 가짜입니다.
- 공인 IP 는 껐다 켜면 바뀝니다. 문서에 IP 를 박지 말고 `terraform output web_public_ip`.
- 작업할 때만 켭니다 (`siem_running=false` 가 기본).
