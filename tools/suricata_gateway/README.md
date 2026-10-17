# Suricata 배포 게이트웨이

HAW-KI 승인 대기열에서 **승인한 Suricata 룰을 센서에 적용**하고, 사이드바의 Suricata 상태를 알려 주는 작은 서비스입니다. 센서 VM(10.0.10.235)에서 실행합니다.

```
HAW-KI 승인 ──POST /actions (토큰)──▶ 게이트웨이 ──▶ hawki.rules 쓰기 ─▶ suricata -T ─▶ 룰 다시 읽기
HAW-KI 상태 ──GET /health──────────▶ 게이트웨이 ──▶ Suricata 프로세스 확인
```

## 지키는 것

- 토큰이 맞는 요청만 받습니다. 토큰은 24자 이상이어야 합니다.
- Suricata 룰 조치(`suricata_rule`, `suricata_rule_disable`)만 받습니다.
- 룰은 한 줄이어야 하고, 룰 안의 `sid`와 조치의 SID가 같아야 합니다.
- 센서가 탐지 전용이라 기본은 `alert`만 허용합니다. `drop`·`reject`·`pass`는 거부합니다.
- 조치의 호스트·인터페이스가 이 센서와 다르면 거부합니다.
- 새 룰 묶음을 **먼저 `suricata -T`로 검사**합니다. 실패하면 파일을 바꾸지 않습니다.
- 다시 읽기 요청이 실패하면 이전 파일(`.bak`)로 되돌립니다.
- 같은 조치 ID가 다시 와도 두 번 적용하지 않습니다.
- `hawki.rules`만 다룹니다. ET Open 등 다른 룰 파일은 건드리지 않습니다.

## 1. 센서 준비 (한 번만)

```bash
# 설치 방식 확인 (서비스 / 컨테이너)
systemctl status suricata --no-pager | head -3
suricata -V

# 룰 경로와 원격 명령 소켓
grep -nE "default-rule-path|rule-files|unix-command" -A3 /etc/suricata/suricata.yaml
```

`/etc/suricata/suricata.yaml`에서 두 가지를 확인합니다.

```yaml
default-rule-path: /etc/suricata/rules   # 우리 센서: suricata.rules 는 /var/lib/... 로 가는 링크
rule-files:
  - suricata.rules
  - hawki.rules          # ← 없으면 추가

unix-command:
  enabled: yes           # ← suricatasc 로 룰 다시 읽기에 필요
```

```bash
sudo install -m 644 /dev/null /etc/suricata/rules/hawki.rules
# 시험 실행은 반드시 unix-command 를 끕니다. 켠 채로 -T 를 돌리면 운영 중인 Suricata 의 소켓을 덮어씁니다.
sudo suricata --set unix-command.enabled=no -T -v -c /etc/suricata/suricata.yaml   # 설정 검사 (ET 룰이면 2~3분)
sudo systemctl restart suricata                      # yaml 을 바꿨을 때만 (룰 적재 2~3분 동안 탐지 공백)
sudo suricatasc -c uptime /var/run/suricata-command.socket   # 소켓 응답 확인
```

## 2. 게이트웨이 설치

```bash
sudo mkdir -p /opt/hawki-gateway /etc/hawki /var/lib/hawki-gateway
sudo cp gateway.py /opt/hawki-gateway/gateway.py
sudo cp hawki-suricata-gateway.service /etc/systemd/system/
sudo cp suricata-gateway.env.example /etc/hawki/suricata-gateway.env
sudo chmod 600 /etc/hawki/suricata-gateway.env
sudo nano /etc/hawki/suricata-gateway.env            # HAWKI_GW_TOKEN 채우기
sudo systemctl daemon-reload
sudo systemctl enable --now hawki-suricata-gateway
curl -s http://10.0.10.235:8095/health; echo
```

토큰은 `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`로 만듭니다. 이 값은 센서 env 파일과 HAW-KI `.env` 두 곳에만 넣고, 채팅·Git·Notion에는 올리지 않습니다.

## 3. 네트워크

센서 보안 그룹(`sg-vm`)에 **HAW-KI 서버에서 오는 TCP 8095만** 허용하는 인바운드 규칙을 추가해야 합니다. 0.0.0.0/0으로 열면 안 됩니다. Terraform `infra/terraform/security_servers.tf`의 `aws_security_group.vm`에 넣고, main 브랜치에서 승인을 받아 적용합니다.

## 4. HAW-KI 설정

`/opt/hawki/.env`에 추가하고 `sudo docker compose up -d hawki-web`로 재시작합니다.

```
SURICATA_GATEWAY_URL=http://10.0.10.235:8095
SURICATA_GATEWAY_TOKEN=<센서와 같은 토큰>
ENABLE_RESPONSE_ACTIONS=true
```

- `ENABLE_RESPONSE_ACTIONS`를 켜지 않으면 승인해도 지금처럼 "승인됨 · 실행 안 됨"으로 남습니다.
- `VELOCIRAPTOR_GATEWAY_URL`이 비어 있으면 Velociraptor 승인 건은 이 스위치와 관계없이 전송되지 않습니다.
- 끄려면 `ENABLE_RESPONSE_ACTIONS=false`로 바꾸고 재시작합니다.

## 5. 확인

1. 사이드바 Suricata가 "연결됨"으로 바뀝니다.
2. Suricata 룰 화면에서 `alert` 룰을 저장 → 승인 요청 → 승인 대기열에서 승인합니다.
3. 상태가 "제출됨", 룰 상태가 "적용 중"으로 바뀌면 센서에 들어간 것입니다.
4. 센서에서 `sudo cat /etc/suricata/rules/hawki.rules`로 확인합니다.
5. 기록: `sudo tail /var/lib/hawki-gateway/applied.jsonl`, `journalctl -u hawki-suricata-gateway -n 50`.

거부되면 승인 대기열에 "전송 실패"로 남고 룰 상태는 "오류"가 됩니다. 이유는 `applied.jsonl`의 `error`와 `detail`에 있습니다.

## Suricata를 컨테이너로 돌릴 때

env 파일에서 `HAWKI_GW_TEST_CMD`, `HAWKI_GW_RELOAD_CMD`, `HAWKI_GW_STATUS_CMD`를 `docker exec <컨테이너>` 형태로 바꿉니다(예시는 env 파일에 있음). 값은 JSON 목록이고, systemd가 큰따옴표를 지우므로 **값 전체를 작은따옴표로** 감쌉니다. 이때 `HAWKI_GW_RULES_FILE`의 폴더가 컨테이너 안에서도 **같은 경로로** 보이도록 마운트되어 있어야 합니다.

## 시험

```bash
python3 -m pytest tests/test_suricata_gateway.py tests/test_suricata_status.py
```
