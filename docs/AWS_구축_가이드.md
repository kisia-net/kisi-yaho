# AWS 접속 가이드 — 팀원용

> 담당 서버에 들어가서 소프트웨어를 설치하기까지의 안내입니다.
> AWS 를 처음 쓰셔도 따라오실 수 있게 썼습니다.
>
> **Terraform 은 설치하지 않으셔도 됩니다.** 서버를 만들고 켜고 끄는 것은 팀장이 합니다.
> 여러분은 이미 켜져 있는 서버에 **들어가서 작업만** 하시면 됩니다.

---

## 0. 전체 그림

```
   내 노트북                         AWS
  ┌─────────┐                  ┌──────────────────┐
  │ AWS CLI │ ──SSM 통로──▶   │  담당 서버        │
  └─────────┘                  │  (Ubuntu 22.04)   │
                               └──────────────────┘
```

**SSH 키도, 비밀번호도, 열린 포트도 없습니다.** AWS 내부 통로(SSM Session Manager)로만 들어갑니다. 그래서 준비물이 두 개뿐이에요.

---

## 1. 준비물 두 가지 (30분)

둘 다 설치한 뒤 **PowerShell 을 새로 열어야** 합니다. 환경변수가 반영되려면 필요합니다.

### ① AWS CLI

[AWS CLI 설치 페이지](https://awscli.amazonaws.com/AWSCLIV2.msi) 에서 받아 그냥 다음만 누르면 됩니다.

```powershell
aws --version
# aws-cli/2.x.x ... 나오면 성공
```

### ② Session Manager 플러그인 ★ 이게 없으면 서버에 못 들어갑니다

[플러그인 설치 페이지](https://s3.amazonaws.com/session-manager-downloads/plugin/latest/windows/SessionManagerPluginSetup.exe) 에서 받아 설치합니다.

```powershell
session-manager-plugin
# "The Session Manager plugin is installed successfully" 나오면 성공
```

> 이 둘은 별개입니다. AWS CLI 만 깔면 `aws ssm start-session` 이 "plugin was not found" 로 실패합니다.

---

## 2. 접속 키 설정

**액세스 키는 팀장이 개인 DM 으로 보내드립니다.** 단톡방에는 올라오지 않습니다.

```powershell
aws configure
```

물어보는 대로 넣으시면 됩니다.

```
AWS Access Key ID     : (DM 으로 받은 값)
AWS Secret Access Key : (DM 으로 받은 값)
Default region name   : ap-northeast-2
Default output format : json
```

확인

```powershell
aws sts get-caller-identity
```

계정 정보가 나오면 준비 끝입니다.

### 🚨 키 취급 세 가지

1. **코드나 `.env` 에 적지 마세요.** `aws configure` 로만 넣습니다
2. **캡처해서 단톡방·노션·깃허브에 올리지 마세요**
3. 팀 공용 키라 **한 명이 유출하면 전원이 다시 설정**해야 합니다

깃허브에 올라간 키를 긁어가는 봇이 상시 돌아다닙니다. 몇 분 안에 GPU 인스턴스 수십 대가 뜨고 요금은 우리 계정에서 나갑니다. 농담이 아닙니다.

---

## 3. 내 서버에 들어가기

| 서버 | 인스턴스 ID | 담당 | 올릴 것 |
| --- | --- | --- | --- |
| `siem` | `i-0d3f61f22252b1fbb` | 권민석 · 이효찬 | Wazuh Manager · Indexer · Dashboard · Velociraptor Server |
| `web` | `i-0629c84bb40895441` | 하서휘 | nginx · ModSecurity · Wazuh Agent |
| `vm` | `i-00cee9b7e43c531d1` | 엄수현 | Suricata · Sysmon for Linux · Wazuh Agent |

셋 다 들어가는 방법이 같습니다.

```powershell
aws ssm start-session --target <위 인스턴스 ID>
```

```bash
sudo su - ubuntu
```

> **왜 `sudo su - ubuntu` 를 하나** — SSM 은 `ssm-user` 라는 계정으로 붙습니다. 이 계정은 docker 같은 걸 쓸 권한이 없어서, 기본 계정으로 바꿔줘야 합니다.

### 안 될 때

| 증상 | 원인 |
| --- | --- |
| `TargetNotConnected` | 서버가 꺼져 있습니다. 팀장에게 켜달라고 하세요 |
| 켠 직후 접속 실패 | 부팅 + SSM 등록에 1~2분 걸립니다. 기다렸다 다시 |
| `Unable to locate credentials` | 2번 `aws configure` 가 안 된 것입니다 |
| `plugin was not found` | 1-② 플러그인이 안 깔린 것입니다 |

지금 어떤 서버가 붙어 있는지는 이걸로 봅니다.

```powershell
aws ssm describe-instance-information --query "InstanceInformationList[].{ID:InstanceId,Ping:PingStatus}" --output table
```

---

## 4. 담당별 설치

### `siem` — 권민석 · 이효찬

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

설치가 끝나면 화면에 관리자 비밀번호가 찍힙니다. **꼭 적어두세요.**

대시보드는 포트를 안 열어둬서 터널로 봅니다. 새 PowerShell 창에 붙이고 그 창은 열어두세요.

```powershell
aws ssm start-session --target i-0d3f61f22252b1fbb --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443
```

브라우저에서 `https://127.0.0.1:8443` — 인증서 경고는 넘기시면 됩니다.

그다음 `web` 과 `vm` 의 Agent 등록을 수락하고, 로그가 실제로 올라오는지 확인합니다. **여기까지 되면 1차 목표 달성입니다.**

### `web` — 하서휘

nginx + ModSecurity + Wazuh Agent 를 올립니다.

⚠️ **이 서버는 인터넷에 열려 있습니다 (80/443).**

- nginx 만 올리고 방치하지 마세요. **ModSecurity(OWASP CRS)까지 같이** 올려주세요
- 이 서버에 `.env`, 비밀번호, API 키 같은 실제 값을 두지 마세요. 털릴 수 있다고 가정하고 쓰는 기계입니다

### `vm` — 엄수현

Suricata + Sysmon for Linux + Wazuh Agent 를 올립니다.

```bash
# Sysmon for Linux
curl -sSL https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o p.deb
sudo dpkg -i p.deb && sudo apt update
sudo apt install -y sysmonforlinux
```

Suricata 설정에서 **payload 를 켜주세요.** 지금 우리 로그에는 payload 가 한 건도 없습니다 (3,854줄 전수 확인). `/etc/suricata/suricata.yaml` 의 `outputs → eve-log → types → alert` 아래입니다.

```yaml
- alert:
    payload: yes
    payload-printable: yes    # 발표에 쓸 것
    payload-buffer-size: 4kb
    http-body: yes
    http-body-printable: yes
```

### Wazuh Agent (`web`, `vm` 공통)

**Manager 주소는 `10.0.10.123`** 입니다. Agent 설정에 이 값을 넣어야 로그가 SIEM 으로 갑니다.

Agent 설치는 각자 하시고, **등록 수락은 `siem` 담당(권민석·이효찬)** 이 합니다. 전화 연결처럼 거는 쪽과 받는 쪽이 있습니다.

---

## 5. 작업 규칙

**서버 작업 전에 카톡에 한 줄 남겨주세요.**

> "web 서버에서 nginx 설치합니다"

지금 팀 공용 계정이라 AWS 기록에 이름이 안 남습니다. 문제가 생겼을 때 **카톡이 유일한 단서**입니다.

**작업이 끝나면 카톡에 알려주세요.** 마지막 분이 끝나면 팀장이 서버를 끕니다. 켜두면 하루 1만 3천원이 나갑니다.

**서버가 꺼져 있으면 팀장에게 요청하세요.** 켜고 끄는 것은 팀장이 합니다.

---

## 6. 자주 쓰는 명령어

```powershell
# 내 자격증명 확인
aws sts get-caller-identity

# 지금 붙을 수 있는 서버 목록
aws ssm describe-instance-information --query "InstanceInformationList[].{ID:InstanceId,Ping:PingStatus}" --output table

# 서버 접속
aws ssm start-session --target <인스턴스 ID>

# 웹 서버 공인 IP (켤 때마다 바뀝니다)
aws ec2 describe-instances --instance-ids i-0629c84bb40895441 --query "Reservations[].Instances[].PublicIpAddress" --output text
```

서버 안에서

```bash
sudo su - ubuntu          # 기본 계정으로 전환
sudo apt update           # 인터넷이 되는지 확인도 겸함
df -h                     # 디스크 여유
free -h                   # 메모리
```

---

## 7. 막혔을 때

먼저 [`RUNBOOK.md`](RUNBOOK.md) 의 「오류별 대처」를 보세요. 지금까지 실제로 겪은 오류가 거의 다 정리되어 있습니다.

그래도 안 되면 **화면을 캡처해서** 올려주세요. 오류 메시지 전문이 있어야 원인을 짚을 수 있습니다.

---

## 관련 문서

| 문서 | 내용 |
| --- | --- |
| [`RUNBOOK.md`](RUNBOOK.md) | 노트북에서 앱 실행 · 서버 목록 · 오류별 대처 |
| [`ROLES.md`](ROLES.md) | 역할 분담 상세 |
| [`STATUS.md`](STATUS.md) | 프로젝트 현황 |
| [`diagrams/`](diagrams/) | 네트워크 구성도 · 계층도 |
