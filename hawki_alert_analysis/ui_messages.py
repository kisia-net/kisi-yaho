"""Korean text for messages the server writes for people to read.

The API keeps answering in English internally. Translation happens once, on
the way out (app.localize_api_error), so:

- the English text stays in the code next to the check that raises it, and
  every test and log line that knows it keeps working;
- the response carries both: `error` in Korean for the screen, `error_en`
  with the original, and the machine-readable `code` untouched. A red-team
  or monitoring check should key on `code` or HTTP status; one that matched
  the English sentence can read `error_en` instead;
- API_MESSAGE_LANGUAGE=en turns it off entirely.

tests/test_ui_messages.py fails when app.py gains an error message that has no
entry here, so a new English sentence cannot slip onto the Korean screen.
"""

from __future__ import annotations

from typing import Any

ERROR_MESSAGES_KO: dict[str, str] = {
    "A DetectionSpec object is required.": "DetectionSpec 객체가 필요합니다.",
    "A message is required.": "메시지를 입력해 주세요.",
    "Action not found.": "조치를 찾을 수 없습니다.",
    "Active rules must be disabled before deletion.": "적용 중인 룰은 비활성화한 뒤 삭제할 수 있습니다.",
    "Alert not found.": "경보를 찾을 수 없습니다.",
    "Authentication required.": "로그인이 필요합니다.",
    "Chat session ID is invalid.": "대화 세션 ID가 올바르지 않습니다.",
    "Chat session exceeds the allowed storage size.": "대화 세션이 저장 가능한 크기를 넘었습니다.",
    "Chat session mode is invalid.": "대화 세션의 작업 모드가 올바르지 않습니다.",
    "Decision must be approve or reject.": "결정은 승인 또는 반려여야 합니다.",
    "DetectionSpec SID or revision is invalid.": "DetectionSpec의 SID 또는 rev 값이 올바르지 않습니다.",
    "Insufficient account permission.": "계정 권한이 부족합니다.",
    "Invalid or missing CSRF token.": "보안 토큰(CSRF)이 없거나 올바르지 않습니다. 페이지를 새로고침해 주세요.",
    "Invalid or unsupported action proposal.": "올바르지 않거나 지원하지 않는 조치 제안입니다.",
    "Maximum results must be an integer.": "최대 결과 수는 정수여야 합니다.",
    "Message is empty or exceeds the allowed length.": "메시지가 비어 있거나 허용된 길이를 넘었습니다.",
    "Native Wazuh evidence is available only in Wazuh mode.": "Wazuh 원본 증거는 Wazuh 모드에서만 볼 수 있습니다.",
    "Only Suricata rule identifiers are editable.": "Suricata 룰 식별자만 수정할 수 있습니다.",
    "Only pending actions can be decided.": "검토 대기 중인 조치만 결정할 수 있습니다.",
    "Only pending actions can be edited.": "검토 대기 중인 조치만 수정할 수 있습니다.",
    "Raw Wazuh context is available only in Wazuh mode.": "Wazuh 원시 맥락은 Wazuh 모드에서만 볼 수 있습니다.",
    "Rule SID or identifier already exists.": "같은 SID 또는 식별자의 룰이 이미 있습니다.",
    "Rule identifier or SID conflicted during inventory persistence.": "룰 목록에 저장하는 중 식별자 또는 SID가 충돌했습니다.",
    "Rule must pass current deterministic verification before it can be staged.": "승인 요청 전에 현재 기준의 룰 검증을 통과해야 합니다.",
    "SID and revision can only be changed for Suricata rule actions.": "SID와 rev는 Suricata 룰 조치에서만 바꿀 수 있습니다.",
    "Suricata action failed the inventory verification boundary.": "Suricata 조치가 룰 목록 검증 단계를 통과하지 못했습니다.",
    "Suricata action failed the verified inventory boundary.": "Suricata 조치가 검증된 룰 목록 기준을 통과하지 못했습니다.",
    "Suricata actions cannot be queued directly. Persist the verified rule in the rule inventory and stage it through the rule staging endpoint.":
        "Suricata 조치는 바로 대기열에 넣을 수 없습니다. 검증된 룰을 룰 목록에 저장한 뒤 승인 요청을 올려 주세요.",
    "Suricata actions cannot be resent from an old snapshot. Stage the current verified inventory rule instead.":
        "이전 스냅샷으로는 Suricata 조치를 다시 보낼 수 없습니다. 현재 검증된 룰로 승인 요청을 올려 주세요.",
    "Suricata approval snapshots are immutable. Edit the inventory rule, re-verify it, and stage it again.":
        "Suricata 승인 스냅샷은 수정할 수 없습니다. 룰 목록에서 수정하고 다시 검증한 뒤 승인 요청을 올려 주세요.",
    "The LLM endpoint could not analyze the alert evidence.": "LLM 서버가 경보 증거를 분석하지 못했습니다.",
    "The LLM endpoint could not be reached.": "LLM 서버에 연결할 수 없습니다.",
    "The LLM endpoint could not complete the request.": "LLM 서버가 요청을 끝내지 못했습니다.",
    "The agent received or produced data that could not be processed.": "에이전트가 처리할 수 없는 데이터를 받거나 만들었습니다.",
    "The alert analysis response could not be processed.": "경보 분석 결과를 처리하지 못했습니다.",
    "The index pattern contains unsupported characters.": "인덱스 패턴에 사용할 수 없는 문자가 있습니다.",
    "The search period must be a relative time like now-24h or a full date and time with a time zone.":
        "기간은 now-24h 같은 상대 시간이거나 시간대가 붙은 날짜·시각이어야 합니다.",
    "The verified Suricata inventory target is not configured correctly.": "검증된 Suricata 룰 목록 대상이 올바르게 설정되지 않았습니다.",
    "This action is already pending approval.": "이미 승인 대기 중인 조치입니다.",
    "Unsupported DetectionSpec schema.": "지원하지 않는 DetectionSpec 형식입니다.",
    "Unsupported agent mode.": "지원하지 않는 에이전트 작업 모드입니다.",
    "Unsupported investigation pivot.": "지원하지 않는 조사 바로가기입니다.",
    "Unsupported alert category.": "지원하지 않는 경보 구분입니다.",
    "Unsupported search target.": "지원하지 않는 검색 대상입니다.",
    "Invalid alert id.": "경보 ID 형식이 올바르지 않습니다.",
    "Invalid host name.": "호스트 이름 형식이 올바르지 않습니다.",
    "The query must be between 1 and 1000 characters.": "쿼리는 1자 이상 1000자 이하여야 합니다.",
    "Unsupported alert period.": "지원하지 않는 경보 기간입니다.",
    "Verified Suricata import failed.": "검증된 Suricata 룰 가져오기에 실패했습니다.",
    "Verifier returned a rule that failed local structural validation.": "검증기가 돌려준 룰이 구조 검증을 통과하지 못했습니다.",
    "Wazuh Indexer request failed.": "Wazuh Indexer 요청에 실패했습니다.",
    "Wazuh Indexer search is disabled by server policy.": "서버 정책으로 Wazuh Indexer 검색이 꺼져 있습니다.",
    "Wazuh alert enrichment query failed.": "Wazuh 경보 보강 정보 조회에 실패했습니다.",
    "Wazuh alert lookup failed.": "Wazuh 경보 조회에 실패했습니다.",
    "Wazuh archive context lookup failed.": "Wazuh 아카이브 맥락 조회에 실패했습니다.",
    "Wazuh dashboard summary failed.": "Wazuh 대시보드 요약을 가져오지 못했습니다.",
    "Wazuh evidence retrieval failed.": "Wazuh 증거를 가져오지 못했습니다.",
    "Wazuh host alert query failed.": "Wazuh 호스트 경보 조회에 실패했습니다.",
    "Wazuh host inventory query failed.": "Wazuh 호스트 목록 조회에 실패했습니다.",
    "Wazuh host security-index query failed.": "Wazuh 호스트 보안 인덱스 조회에 실패했습니다.",
    "Wazuh host security-state query failed.": "Wazuh 호스트 보안 상태 조회에 실패했습니다.",
    "Wazuh host-state query failed.": "Wazuh 호스트 상태 조회에 실패했습니다.",
    "Wazuh raw context query failed.": "Wazuh 원시 맥락 조회에 실패했습니다.",
    "Wazuh scenario aggregation failed.": "Wazuh 시나리오 집계에 실패했습니다.",
    "Wazuh vulnerability query failed.": "Wazuh 취약점 조회에 실패했습니다.",
    "min_level must be an integer.": "최소 레벨(min_level)은 정수여야 합니다.",
    "window and limit must be integers.": "window와 limit은 정수여야 합니다.",
    "Analysis ID is invalid.": "분석 ID가 올바르지 않습니다.",
    "The red team runner is not configured.": "레드팀 실행기가 설정되지 않았습니다.",
    "The red team runner could not be reached.": "레드팀 실행기에 연결할 수 없습니다.",
    "Red team job not found.": "레드팀 검사 작업을 찾을 수 없습니다.",
    "The red team runner returned an error.": "레드팀 실행기가 오류를 반환했습니다.",
    "Report not found.": "보고서를 찾을 수 없습니다.",
    "Report ID is invalid.": "보고서 ID가 올바르지 않습니다.",
    "Review status is invalid.": "검토 상태 값이 올바르지 않습니다.",
    "Verdict is invalid.": "판정 값이 올바르지 않습니다.",
    "Automatic analysis is disabled.": "자동 분석이 꺼져 있습니다. AUTO_ANALYSIS_ENABLED=true로 바꾼 뒤 컨테이너를 다시 만들어 주세요.",
}

# Assessment review notes: stable codes for the interface, Korean for people.
REVIEW_NOTE_CODES: dict[str, str] = {
    "No contradictory evidence was reported.": "no_contradictory_evidence",
    "No evidence entry cited an event id.": "no_citations",
}
REVIEW_NOTES_KO: dict[str, str] = {
    "no_contradictory_evidence": "반대 증거가 보고되지 않았습니다. 모델이 반대 증거를 찾지 않은 것인지, 실제로 없는 것인지 확인해 주세요.",
    "no_citations": "어떤 증거 항목도 이벤트 ID를 인용하지 않았습니다.",
}


def localize_error_payload(body: Any, language: str) -> Any:
    """Return the body with a Korean `error` and the original in `error_en`."""
    if language != "ko" or not isinstance(body, dict):
        return body
    message = body.get("error")
    if not isinstance(message, str):
        return body
    translated = ERROR_MESSAGES_KO.get(message)
    if not translated:
        return body
    return {**body, "error": translated, "error_en": message}
