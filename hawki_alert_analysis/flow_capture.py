"""경보 하나의 데이터 흐름 캡처 (서버별 원본 → 이벤트 → 경보 → 증거 패키지 → AI → 조치).

같은 데이터가 단계를 지나며 어떤 모양이 되는지 한 문서로 남깁니다.

- 원본·이벤트·경보 단계는 증거 패키지 안의 Wazuh 문서에서 다시 만듭니다.
  Wazuh 는 원본 한 줄을 full_log 로 보존하고, 디코더가 쪼갠 값을 data.* 에,
  룰이 걸리면 rule.* 를 붙입니다. 그래서 한 문서에서 세 단계를 나눠 볼 수
  있습니다.
- 증거 패키지는 경보 id 만 있으면 언제든 같은 규칙으로 다시 만들어집니다.
- AI 증거 수집과 AI 판단은 실행할 때마다 달라질 수 있어, 분석을 실행한 그
  순간에 FlowCaptureStore 에 저장합니다 (app.py api_analyze_alert).

이 파일은 Indexer 나 모델을 부르지 않습니다. 받은 값을 정리만 합니다.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redteam_bridge import sha256_json

FLOW_CAPTURE_SCHEMA = "hawki.flow-capture/v1"
# Every line of the package is kept; the page shows this many and folds the rest.
RAW_PREVIEW_LINES = 3
MAX_FIELD_PATHS = 60
EVIDENCE_ID = re.compile(r"\b(?:TRIGGER|CTX-\d{3})\b")

# 위치(location) 로 원본 로그의 종류를 사람이 읽는 이름으로 바꿉니다.
SOURCE_LABELS: tuple[tuple[str, str], ...] = (
    ("nginx/access", "nginx 접근 로그"),
    ("nginx/error", "nginx 오류 로그 (ModSecurity 차단 포함)"),
    ("modsec_audit", "ModSecurity 감사 로그"),
    ("suricata", "Suricata eve.json"),
    ("eve.json", "Suricata eve.json"),
    ("sysmon", "Sysmon"),
    ("eventchannel", "Windows 이벤트 로그"),
    ("journald", "시스템 저널 (journald)"),
    ("auth.log", "인증 로그"),
    ("secure", "인증 로그"),
    ("syslog", "syslog"),
)

STAGES = (
    ("raw", "① 서버별 원본 로그", "각 서버의 로그 파일 → Wazuh Agent 가 그대로 전송 (full_log)"),
    ("event", "② 이벤트 (디코딩)", "wazuh-archives-* · Manager 디코더가 data.* 로 쪼갬"),
    ("alert", "③ 경보", "wazuh-alerts-* · 룰에 걸린 이벤트에 rule.* 가 붙음"),
    ("evidence", "④ 증거 패키지", "HAW-KI · 요청 때마다 같은 규칙으로 생성 (저장 안 함)"),
    ("ai_retrieval", "⑤ AI 증거 수집", "HAW-KI · 모델이 읽기 전용 도구로 증거를 더 가져옴"),
    ("ai_judgment", "⑥ AI 판단", "HAW-KI · 모델 응답을 검증된 assessment 로 정리"),
    ("response", "⑦ 조치 제안 · 승인 상태", "HAW-KI 승인 대기열 · 실행 결과(수집·룰)는 아직 이 흐름에 연결되지 않음"),
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return 0


def field_paths(value: Any, prefix: str = "", *, limit: int = MAX_FIELD_PATHS) -> list[str]:
    """중첩된 dict 의 잎 필드 경로 (data.http.url 처럼). 목록은 path[] 로 씁니다."""
    paths: list[str] = []

    def walk(node: Any, path: str) -> None:
        if len(paths) >= limit:
            return
        if isinstance(node, dict) and node:
            for key in sorted(node):
                walk(node[key], f"{path}.{key}" if path else str(key))
        elif isinstance(node, list) and node and isinstance(node[0], dict):
            walk(node[0], f"{path}[]")
        elif path:
            paths.append(path + ("[]" if isinstance(node, list) else ""))

    walk(value, prefix)
    return paths


def source_label(location: str, decoder: str) -> str:
    text = f"{location} {decoder}".lower()
    for needle, label in SOURCE_LABELS:
        if needle in text:
            return label
    return location or decoder or "알 수 없는 출처"


def raw_format(full_log: Any) -> str:
    text = str(full_log or "").strip()
    if text.startswith("{"):
        try:
            json.loads(text)
            return "JSON 한 줄"
        except ValueError:
            pass
    return "텍스트 한 줄" if text else "원문 없음"


def _items(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    trigger = _mapping(bundle.get("trigger"))
    context = [item for item in bundle.get("investigation_context") or [] if isinstance(item, dict)]
    return ([trigger] if trigger else []) + context


def _server(item: dict[str, Any]) -> tuple[str, str]:
    agent = _mapping(item.get("agent"))
    return str(agent.get("name") or agent.get("id") or "알 수 없는 서버"), str(agent.get("ip") or "")


def _origin(item: dict[str, Any]) -> str:
    if item.get("evidence_id") == "TRIGGER":
        return "trigger"
    return str(_mapping(item.get("retrieval")).get("origin") or "same_agent")


def raw_stage(bundle: dict[str, Any]) -> dict[str, Any]:
    servers: dict[str, dict[str, Any]] = {}
    for item in _items(bundle):
        name, ip = _server(item)
        decoder = str(_mapping(item.get("decoder")).get("name") or "")
        location = str(item.get("location") or "")
        server = servers.setdefault(name, {"server": name, "ip": ip, "sources": {}, "count": 0})
        source = server["sources"].setdefault(location or decoder, {
            "label": source_label(location, decoder),
            "location": location,
            "format": raw_format(item.get("full_log")),
            "count": 0,
            "samples": [],
        })
        server["count"] += 1
        source["count"] += 1
        sample = {
            "evidence_id": item.get("evidence_id"),
            "timestamp": item.get("timestamp"),
            "full_log": item.get("full_log"),
        }
        if item.get("evidence_id") == "TRIGGER":
            source["samples"].insert(0, sample)
        else:
            source["samples"].append(sample)
    return {
        "servers": [
            {**server, "sources": list(server["sources"].values())}
            for server in sorted(servers.values(), key=lambda value: -value["count"])
        ],
        "line_count": sum(server["count"] for server in servers.values()),
        "preview_lines": RAW_PREVIEW_LINES,
        "size_chars": sum(len(str(item.get("full_log") or "")) for item in _items(bundle)),
    }


def event_stage(bundle: dict[str, Any]) -> dict[str, Any]:
    """디코더별 대표 이벤트 하나: 원문이 어떤 필드로 쪼개졌는지."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for item in _items(bundle):
        name, _ip = _server(item)
        decoder = str(_mapping(item.get("decoder")).get("name") or "")
        key = (name, decoder)
        data = _mapping(item.get("data"))
        event = {
            "evidence_id": item.get("evidence_id"),
            "timestamp": item.get("timestamp"),
            "agent": _mapping(item.get("agent")),
            "decoder": _mapping(item.get("decoder")),
            "location": item.get("location"),
            "data": data,
        }
        group = groups.get(key)
        if group is None:
            groups[key] = {
                "server": name,
                "decoder": decoder,
                "label": source_label(str(item.get("location") or ""), decoder),
                "count": 1,
                "data_fields": field_paths(data, "data"),
                "example": event,
            }
        else:
            group["count"] += 1
            if item.get("evidence_id") == "TRIGGER":
                group.update(example=event, data_fields=field_paths(data, "data"))
    return {
        "decoders": list(groups.values()),
        "event_count": sum(group["count"] for group in groups.values()),
        # Every event as Wazuh stores it: the original line plus the decoded fields.
        "size_chars": sum(
            _size({key: item.get(key) for key in ("timestamp", "agent", "decoder", "location", "data", "full_log")})
            for item in _items(bundle)
        ),
    }


def alert_stage(bundle: dict[str, Any]) -> dict[str, Any]:
    trigger = _mapping(bundle.get("trigger"))
    rule = _mapping(trigger.get("rule"))
    alerts = [item for item in _items(bundle) if _mapping(item.get("rule")).get("id")]
    related: dict[str, dict[str, Any]] = {}
    unmatched = 0
    for item in bundle.get("investigation_context") or []:
        item_rule = _mapping(_mapping(item).get("rule"))
        if not item_rule.get("id"):
            unmatched += 1
            continue
        entry = related.setdefault(str(item_rule.get("id")), {
            "rule_id": str(item_rule.get("id")),
            "level": item_rule.get("level"),
            "description": item_rule.get("description"),
            "count": 0,
            "evidence_ids": [],
        })
        entry["count"] += 1
        if len(entry["evidence_ids"]) < 5:
            entry["evidence_ids"].append(item.get("evidence_id"))
    return {
        "trigger": {
            "id": trigger.get("id"),
            "index": trigger.get("index"),
            "timestamp": trigger.get("timestamp"),
            "timestamp_kst": trigger.get("timestamp_kst"),
            "agent": _mapping(trigger.get("agent")),
            "rule": rule,
        },
        "rule_fields": field_paths(rule, "rule"),
        "related_rules": sorted(related.values(), key=lambda value: -value["count"]),
        "context_without_rule": unmatched,
        "alert_count": len(alerts),
        # Only the events a rule matched, each with its rule block.
        "size_chars": sum(
            _size({key: item.get(key) for key in ("timestamp", "agent", "decoder", "location", "data", "full_log", "rule")})
            for item in alerts
        ),
    }


def evidence_stage(bundle: dict[str, Any]) -> dict[str, Any]:
    context = [item for item in bundle.get("investigation_context") or [] if isinstance(item, dict)]
    origins: dict[str, int] = {}
    for item in context:
        origins[_origin(item)] = origins.get(_origin(item), 0) + 1
    outcomes = [
        {
            "evidence_id": outcome.get("evidence_id"),
            "detection": outcome.get("detection_status"),
            "control": outcome.get("preventive_control"),
            "control_status": outcome.get("control_status"),
            "http_status": outcome.get("http_status"),
        }
        for outcome in bundle.get("control_outcomes") or []
        if isinstance(outcome, dict)
    ]
    control_summary: dict[str, int] = {}
    for outcome in outcomes:
        key = str(outcome.get("control_status") or "UNKNOWN")
        control_summary[key] = control_summary.get(key, 0) + 1
    retrieval = _mapping(bundle.get("retrieval"))
    assets = _mapping(bundle.get("assets"))
    intel = _mapping(bundle.get("threat_intelligence"))
    priority = _mapping(bundle.get("priority"))
    return {
        "schema": bundle.get("schema"),
        "blocks": sorted(key for key in bundle if key not in {"evidence_handling"}),
        "trigger": 1 if bundle.get("trigger") else 0,
        "context_count": len(context),
        "context_by_origin": origins,
        "control_outcomes": outcomes,
        "control_summary": control_summary,
        "priority": {key: priority.get(key) for key in ("band", "score", "primary_asset_id") if key in priority},
        "assets": [
            {key: match.get(key) for key in ("id", "hostname", "criticality", "exposure")}
            for match in assets.get("matches") or [] if isinstance(match, dict)
        ],
        "threat_intelligence": [
            {key: match.get(key) for key in ("value", "type", "feed", "verdict", "confidence", "match")}
            for match in intel.get("matches") or [] if isinstance(match, dict)
        ],
        "retrieval": {
            key: retrieval.get(key)
            for key in ("profile", "window_seconds", "candidate_count", "selected_count",
                        "suppressed_routine_count", "context_fit")
            if key in retrieval
        },
        "lineage_edges": len(_mapping(bundle.get("lineage")).get("edges") or []),
        "size_chars": _size(bundle),
    }


# Why ⑤ looks the way it does. "disabled" and "not_in_auto_report" are written
# by the app at capture time; the others are the evidence agent's own `stopped`.
RETRIEVAL_STATUS = {
    "disabled": "꺼져 있음 (AGENT_TOOL_LOOP_ENABLED=false 또는 AGENT_MAX_TOOL_CALLS=0)",
    "not_in_auto_report": "자동 보고서는 AI 증거 수집을 하지 않음",
    "no_room": "처음 패키지가 이미 문맥 한도를 넘어 건너뜀",
    "context_limit_reverted": "가져온 증거가 문맥 한도를 넘어 되돌림",
    "error": "도구 실행 중 오류로 중단",
    "finish": "모델이 증거가 충분하다고 판단해 종료",
    "no_tool_call": "모델이 도구를 부르지 않음",
    "max_calls": "호출 횟수 상한에 도달",
    "unknown": "기록 없음 (이 기능 이전 캡처)",
}


def ai_retrieval_stage(bundle: dict[str, Any], snapshots: dict[str, Any] | None) -> dict[str, Any]:
    trace = _mapping(bundle.get("agent_retrieval"))
    snapshots = snapshots or {}
    if not trace and not snapshots:
        return {"ran": False}
    status = str(snapshots.get("agent_status") or trace.get("stopped") or "unknown")
    calls = []
    for call in trace.get("calls") or []:
        if not isinstance(call, dict):
            continue
        calls.append({
            key: call.get(key)
            for key in ("tool", "arguments", "accepted", "refused_reason", "added_evidence_ids",
                        "result_count", "error")
            if key in call
        })
    return {
        "ran": bool(trace),
        "calls": calls,
        "added_evidence_ids": trace.get("added_evidence_ids") or [],
        "stopped": trace.get("stopped"),
        "status": status,
        "status_label": RETRIEVAL_STATUS.get(status, status),
        "before": snapshots.get("initial"),
        "after_agent": snapshots.get("after_agent"),
        "sent_to_model": snapshots.get("sent"),
    }


def ai_judgment_stage(bundle: dict[str, Any], result: dict[str, Any] | None) -> dict[str, Any]:
    if not result:
        return {"ran": False}
    assessment = _mapping(result.get("assessment"))
    cited: list[str] = []
    for value in (assessment.get("supporting_evidence"), assessment.get("contradictory_evidence"),
                  assessment.get("attack_techniques")):
        for match in EVIDENCE_ID.findall(json.dumps(value or [], ensure_ascii=False)):
            if match not in cited:
                cited.append(match)
    by_id = {str(item.get("evidence_id")): item for item in _items(bundle)}
    citations = [
        {
            "evidence_id": evidence_id,
            "exists": evidence_id in by_id,
            "server": _server(by_id[evidence_id])[0] if evidence_id in by_id else None,
            "full_log": by_id[evidence_id].get("full_log") if evidence_id in by_id else None,
        }
        for evidence_id in cited
    ]
    review = _mapping(result.get("assessment_review"))
    return {
        "ran": True,
        "model": result.get("model"),
        "demo": bool(result.get("demo")),
        "analysis_id": result.get("analysis_id"),
        "answer": result.get("answer"),
        "assessment": assessment,
        "assessment_fields": sorted(assessment),
        "citations": citations,
        "unknown_citations": [item["evidence_id"] for item in citations if not item["exists"]],
        "review": {key: review.get(key) for key in ("complete", "missing_sections", "unknown_event_ids",
                                                    "repair_attempted") if key in review},
        "size_chars": _size(assessment) + len(str(result.get("answer") or "")),
    }


def response_stage(result: dict[str, Any] | None, queued: list[dict[str, Any]] | None) -> dict[str, Any]:
    proposed = [
        {key: action.get(key) for key in ("type", "title", "target", "artifact", "reason")}
        for action in _mapping(result).get("actions") or [] if isinstance(action, dict)
    ]
    records = [
        {key: record.get(key) for key in ("id", "type", "status", "created_at", "updated_at", "title", "target")}
        for record in queued or [] if isinstance(record, dict)
    ]
    return {"proposed": proposed, "queued": records}


def snapshot(bundle: dict[str, Any]) -> dict[str, Any]:
    """증거 패키지가 단계마다 얼마나 커지고 줄었는지 비교할 숫자."""
    return {
        "context_count": len(bundle.get("investigation_context") or []),
        "size_chars": _size(bundle),
    }


def build_flow(
    alert_id: str,
    bundle: dict[str, Any],
    *,
    result: dict[str, Any] | None = None,
    snapshots: dict[str, Any] | None = None,
    queued_actions: list[dict[str, Any]] | None = None,
    captured_at: str | None = None,
    mode: str = "live",
    record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """mode "captured": the bundle is the one sent to the model (after the
    evidence agent and the context fit). mode "live": rebuilt now, every
    selected context event, no AI stages. mode "last_analysis": rebuilt now,
    with ⑤ ⑥ taken from the last saved analysis result.

    `record` keeps what makes a capture checkable later: the whole evidence
    package sent to the model, the model's reply text, the analysis id and
    the hashes the audit log recorded for that analysis."""
    stages = {
        "raw": raw_stage(bundle),
        "event": event_stage(bundle),
        "alert": alert_stage(bundle),
        "evidence": {**evidence_stage(bundle), "dropped": list(_mapping(record).get("dropped_evidence") or [])},
        "ai_retrieval": ai_retrieval_stage(bundle, snapshots),
        "ai_judgment": ai_judgment_stage(bundle, result),
        "response": response_stage(result, queued_actions),
    }
    return {
        "schema": FLOW_CAPTURE_SCHEMA,
        "alert_id": alert_id,
        "mode": mode,
        "captured_at": captured_at or datetime.now(timezone.utc).isoformat(),
        "stage_order": [{"key": key, "label": label, "where": where} for key, label, where in STAGES],
        "stages": stages,
        "basis": BASIS.get(mode, BASIS["live"]),
        "record": record or {},
        "counts": {
            "raw": stages["raw"]["line_count"],
            "event": stages["event"]["event_count"],
            "alert": stages["alert"]["alert_count"],
            "evidence": stages["evidence"]["trigger"] + stages["evidence"]["context_count"],
            "ai_retrieval": len(stages["ai_retrieval"].get("added_evidence_ids") or []) if stages["ai_retrieval"].get("ran") else None,
            "ai_judgment": len(stages["ai_judgment"].get("citations") or []) if stages["ai_judgment"].get("ran") else None,
            "response": len(stages["response"]["proposed"]) + len(stages["response"]["queued"]),
        },
        "sizes": {
            "raw": stages["raw"]["size_chars"],
            "event": stages["event"]["size_chars"],
            "alert": stages["alert"]["size_chars"],
            "evidence": stages["evidence"]["size_chars"],
            "ai_judgment": stages["ai_judgment"].get("size_chars"),
        },
    }


BASIS = {
    "captured": "모델에 보낸 증거 기준 (분석 실행 시점 저장)",
    "live": "지금 다시 고른 증거 전체 기준 (AI 단계 없음)",
    "last_analysis": "①~④ 는 지금 다시 만든 것 · ⑤ ⑥ 은 마지막 분석 결과 (당시 모델에 보낸 증거와 다를 수 있음)",
}


def capture_record(
    *,
    source: str,
    bundle: dict[str, Any],
    result: dict[str, Any],
    request_text: str,
    model_replies: list[dict[str, Any]] | None,
    dropped_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    hashes = _mapping(result.get("hashes"))
    return {
        "source": source,
        "analysis_id": result.get("analysis_id"),
        "bundle_sha256": hashes.get("bundle_sha256"),
        "prompt_sha256": hashes.get("prompt_sha256"),
        "request_text": request_text,
        "evidence_package": bundle,
        "model_replies": list(model_replies or []),
        "dropped_evidence": list(dropped_evidence or []),
    }


def dropped_by_fit(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    """Context items the fit step removed: in `before`, named in the fit report of `after`.

    They never reached the model, so the capture (the model's view) would lose
    them entirely; they are kept beside it with what the analyst needs to read them.
    """
    fit = _mapping(_mapping(after.get("retrieval")).get("context_fit"))
    names = {str(value) for value in fit.get("dropped_evidence_ids") or []}
    kept = {str(_mapping(item).get("evidence_id")) for item in after.get("investigation_context") or []}
    dropped = []
    for item in before.get("investigation_context") or []:
        evidence_id = str(_mapping(item).get("evidence_id"))
        if evidence_id in names and evidence_id not in kept:
            rule = _mapping(item.get("rule"))
            dropped.append({
                "evidence_id": evidence_id,
                "timestamp": item.get("timestamp"),
                "server": _server(item)[0],
                "location": item.get("location"),
                "decoder": _mapping(item.get("decoder")).get("name"),
                "rule": {key: rule.get(key) for key in ("id", "level", "description") if key in rule},
                "relevance_score": _mapping(item.get("retrieval")).get("relevance_score"),
                "full_log": item.get("full_log"),
            })
    return dropped


def verify_capture(doc: dict[str, Any], audit_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Is this the package the model was given, by the audit log's own record?

    1. The saved package is hashed the way the analysis hashed it.
    2. That hash is compared with the one stored in the capture and with the
       one the audit log wrote for the same analysis id.
    """
    record = _mapping(doc.get("record"))
    package = record.get("evidence_package")
    if not isinstance(package, dict):
        return {"checked": False, "reason": "이 캡처에는 증거 패키지 원본이 없습니다 (이전 형식이거나 마지막 분석 결과에서 만든 흐름)."}
    recomputed = sha256_json(package)
    analysis_id = str(record.get("analysis_id") or "")
    audited = None
    for entry in audit_records:
        detail = _mapping(entry.get("detail"))
        if analysis_id and str(detail.get("analysis_id") or "") == analysis_id and detail.get("bundle_sha256"):
            audited = {"event_type": entry.get("event_type"), "timestamp": entry.get("timestamp"),
                       "bundle_sha256": detail.get("bundle_sha256"), "prompt_sha256": detail.get("prompt_sha256")}
    return {
        "checked": True,
        "recomputed_bundle_sha256": recomputed,
        "matches_capture": recomputed == record.get("bundle_sha256"),
        "audit_record": audited,
        "matches_audit": bool(audited) and recomputed == audited.get("bundle_sha256"),
        # No audit record is not the same as a different hash: the log may
        # have been rotated or replaced since the analysis.
        "status": ("audit_missing" if not audited else
                   "verified" if recomputed == record.get("bundle_sha256") == audited.get("bundle_sha256") else
                   "mismatch"),
        "demo": bool(_mapping(_mapping(doc.get("stages")).get("ai_judgment")).get("demo")),
        "model_reply_count": len(record.get("model_replies") or []),
    }


class FlowCaptureStore:
    """분석을 실행한 순간의 흐름 캡처. 경보마다 최근 keep 개만 둡니다."""

    def __init__(self, root: Path, *, keep: int = 5):
        self.root = Path(root)
        self.keep = max(1, int(keep))

    def _dir(self, alert_id: str) -> Path:
        return self.root / hashlib.sha256(str(alert_id).encode("utf-8")).hexdigest()[:40]

    def save(self, doc: dict[str, Any]) -> Path | None:
        try:
            folder = self._dir(str(doc.get("alert_id")))
            folder.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            # The source is in the name so the LLM 분석 button and the
            # automatic reports each keep their own `keep` newest captures.
            source = re.sub(r"[^a-z_]", "", str(_mapping(doc.get("record")).get("source") or "manual"))[:20] or "manual"
            path = folder / f"{stamp}-{source}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(doc, ensure_ascii=False, default=str), encoding="utf-8")
            temporary.replace(path)
            same_source = [item for item in folder.glob("*.json") if self._source(item) == source]
            for old in sorted(same_source)[:-self.keep]:
                old.unlink(missing_ok=True)
            return path
        except OSError:
            return None

    @staticmethod
    def _source(path: Path) -> str:
        # Captures saved before the source was in the name count as manual.
        return path.stem.split("-", 1)[1] if "-" in path.stem else "manual"

    def list(self, alert_id: str) -> list[dict[str, Any]]:
        folder = self._dir(alert_id)
        captures = []
        for path in sorted(folder.glob("*.json"), reverse=True) if folder.exists() else []:
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            captures.append({"capture_id": path.stem, **doc})
        return captures

    def latest(self, alert_id: str) -> dict[str, Any] | None:
        captures = self.list(alert_id)
        return captures[0] if captures else None


VERIFY_LABELS = {
    "verified": "검증됨 (캡처·감사 로그 해시 모두 일치)",
    "mismatch": "불일치 (저장된 패키지가 기록된 해시와 다름)",
    "audit_missing": "감사 기록 없음 (해시는 캡처와 비교만 함. 감사 로그가 교체·삭제됐을 수 있음)",
}

MODE_LABELS = {
    "captured": "분석 실행 시점 저장",
    "live": "지금 다시 생성 (AI 단계 없음)",
    "last_analysis": "지금 다시 생성 + 마지막 분석 결과",
}


def briefing(answer: Any) -> str:
    """The model's own briefing: the app appends its rendered judgement after a rule."""
    return re.split(r"\n\s*---", str(answer or ""))[0].strip()[:600]


def _code(value: Any, lang: str = "") -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return f"```{lang}\n{text}\n```"


def to_markdown(doc: dict[str, Any]) -> str:
    """결과 자료: 단계마다 같은 데이터가 어떤 모양이었는지 나란히."""
    stages = _mapping(doc.get("stages"))
    sizes = _mapping(doc.get("sizes"))
    lines = [
        f"# 데이터 흐름 캡처 · 경보 {doc.get('alert_id')}",
        "",
        f"- 캡처 시각: {doc.get('captured_at')}",
        f"- 방식: {MODE_LABELS.get(str(doc.get('mode')), str(doc.get('mode')))}",
        f"- 기준: {doc.get('basis') or '—'}",
        "",
        "| 단계 | 저장 위치 | 건수 | 크기(문자) |",
        "|---|---|---|---|",
    ]
    counts = _mapping(doc.get("counts"))
    for stage in doc.get("stage_order") or []:
        size = sizes.get(stage["key"])
        count = counts.get(stage["key"])
        lines.append(f"| {stage['label']} | {stage['where']} | {count if count is not None else '—'} | {size if size is not None else '—'} |")

    raw = _mapping(stages.get("raw"))
    lines += ["", "## ① 서버별 원본 로그", ""]
    for server in raw.get("servers") or []:
        lines.append(f"### {server['server']} ({server.get('ip') or 'IP 없음'}) · {server['count']}줄")
        for source in server.get("sources") or []:
            lines.append(f"- **{source['label']}** `{source['location']}` · {source['format']} · {source['count']}줄")
            for sample in source.get("samples") or []:
                lines.append(f"  - `{sample.get('evidence_id')}` {sample.get('timestamp')}")
                lines.append("")
                lines.append(_code(sample.get("full_log") or ""))
        lines.append("")

    event = _mapping(stages.get("event"))
    lines += ["## ② 이벤트 (디코딩)", ""]
    for group in event.get("decoders") or []:
        lines.append(f"### {group['server']} · 디코더 `{group['decoder']}` · {group['count']}건")
        lines.append(f"쪼개진 필드: {', '.join(f'`{path}`' for path in group.get('data_fields') or []) or '없음'}")
        lines.append("")
        lines.append(_code(group.get("example"), "json"))
        lines.append("")

    alert = _mapping(stages.get("alert"))
    lines += ["## ③ 경보", "", "트리거 경보의 룰 정보 (이벤트에 붙은 부분):", "", _code(_mapping(alert.get("trigger")).get("rule"), "json"), ""]
    if alert.get("related_rules"):
        lines += ["같은 증거 안의 다른 경보:", "", "| 룰 | 레벨 | 설명 | 건수 |", "|---|---|---|---|"]
        for item in alert["related_rules"]:
            lines.append(f"| {item['rule_id']} | {item.get('level')} | {item.get('description')} | {item['count']} |")
        lines.append("")
    lines.append(f"룰에 걸리지 않은 원시 이벤트: {alert.get('context_without_rule', 0)}건")

    evidence = _mapping(stages.get("evidence"))
    lines += ["", "## ④ 증거 패키지", "",
              f"- 스키마 `{evidence.get('schema')}` · 블록 {', '.join(f'`{b}`' for b in evidence.get('blocks') or [])}",
              f"- TRIGGER 1 + CTX {evidence.get('context_count')}건 · 출처별 {json.dumps(evidence.get('context_by_origin'), ensure_ascii=False)}",
              f"- 차단 판정 {json.dumps(evidence.get('control_summary'), ensure_ascii=False)} · 우선순위 {json.dumps(evidence.get('priority'), ensure_ascii=False)}",
              f"- 출처 연결(lineage) {evidence.get('lineage_edges')}개 · 수집 조건 {json.dumps(evidence.get('retrieval'), ensure_ascii=False, default=str)}",
              ""]
    dropped = evidence.get("dropped") or []
    if dropped:
        lines += [f"### 문맥 한도 때문에 모델에 보내지 않은 증거 {len(dropped)}건", "",
                  "아래 ①~③ 에는 없는 증거입니다. 고른 증거였지만 문맥 맞추기에서 관련도가 낮은 것부터 빠졌습니다.", ""]
        for item in dropped:
            rule = _mapping(item.get("rule"))
            lines += [f"- `{item.get('evidence_id')}` · {item.get('server')} `{item.get('location')}` · "
                      f"룰 {rule.get('id') or '—'} · 관련도 {item.get('relevance_score')}", "", _code(item.get("full_log") or ""), ""]

    retrieval = _mapping(stages.get("ai_retrieval"))
    lines += ["## ⑤ AI 증거 수집", ""]
    if retrieval.get("status_label"):
        lines.append(f"- 상태: {retrieval.get('status_label')}")
    if retrieval.get("ran"):
        for call in retrieval.get("calls") or []:
            lines.append(f"- `{call.get('tool')}` {json.dumps(call.get('arguments'), ensure_ascii=False)} → 추가 {call.get('added_evidence_ids') or []}")
        lines.append(f"- 추가된 증거 {retrieval.get('added_evidence_ids')} · 멈춘 이유 `{retrieval.get('stopped')}`")
        lines.append(f"- 크기 변화: 처음 {retrieval.get('before')} → 수집 후 {retrieval.get('after_agent')} → 모델에 보낸 것 {retrieval.get('sent_to_model')}")
    else:
        lines.append("도구 호출 없음." if retrieval.get("status_label") else "실행 기록 없음 (분석을 실행하면 이 단계가 저장됩니다).")

    judgment = _mapping(stages.get("ai_judgment"))
    lines += ["", "## ⑥ AI 판단", ""]
    if judgment.get("ran"):
        lines += [f"- 모델 `{judgment.get('model')}`{' (데모)' if judgment.get('demo') else ''} · 분석 id `{judgment.get('analysis_id')}`",
                  f"- 응답 요약: {briefing(judgment.get('answer'))}", "", "인용한 증거와 그 원본:", ""]
        for item in judgment.get("citations") or []:
            mark = "" if item["exists"] else " ⚠️ 증거에 없는 id"
            lines.append(f"- `{item['evidence_id']}` · {item.get('server') or '—'}{mark}")
            if item.get("full_log"):
                lines.append("")
                lines.append(_code(item["full_log"]))
        lines += ["", "assessment:", "", _code(judgment.get("assessment"), "json")]
    else:
        lines.append("실행 기록 없음.")

    record = _mapping(doc.get("record"))
    verification = _mapping(doc.get("verification"))
    lines += ["", "### 모델 응답 원문", ""]
    replies = record.get("model_replies") or []
    if replies:
        for reply in replies:
            lines += [f"- `{reply.get('stage')}` · {reply.get('chars')}자{' (잘림)' if reply.get('truncated') else ''}", "",
                      _code(reply.get("content") or ""), ""]
    else:
        lines.append("저장된 원문 없음.")
    lines += ["", "### 검증 (감사 로그 대조)", ""]
    if verification.get("checked"):
        audit = _mapping(verification.get("audit_record"))
        lines += [
            f"- 분석 id `{record.get('analysis_id')}` · 경로 `{record.get('source')}`",
            f"- 저장된 증거 패키지를 다시 계산한 해시 `{verification.get('recomputed_bundle_sha256')}`",
            f"- 캡처에 기록된 해시와 일치: {'예' if verification.get('matches_capture') else '아니오'}",
            f"- 판정: {VERIFY_LABELS.get(str(verification.get('status')), verification.get('status'))}"
            f"{' · AI 판단은 데모 응답 (모델 미연결)' if verification.get('demo') else ''}",
            f"- 감사 로그 `{audit.get('event_type') or '—'}` ({audit.get('timestamp') or '기록 없음'}) 의 해시와 일치: "
            f"{'예' if verification.get('matches_audit') else '아니오'}",
        ]
    else:
        lines.append(str(verification.get("reason") or "검증하지 않음."))

    response = _mapping(stages.get("response"))
    lines += ["", "## ⑦ 조치 제안 · 승인 상태", "",
              "실행 결과(Velociraptor 수집, Suricata 룰)는 아직 이 흐름에 연결되지 않았습니다. 제안과 승인 상태만 보여 줍니다.", ""]
    for action in response.get("proposed") or []:
        lines.append(f"- 제안: `{action.get('type')}` {action.get('title') or ''} → {action.get('target') or ''}")
    for record in response.get("queued") or []:
        lines.append(f"- 대기열: `{record.get('id')}` `{record.get('type')}` 상태 `{record.get('status')}`")
    if not response.get("proposed") and not response.get("queued"):
        lines.append("제안된 조치 없음.")
    return "\n".join(lines) + "\n"
