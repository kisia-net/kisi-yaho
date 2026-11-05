"""Conversation workspace adapters; existing analysis and response routes remain separate."""
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

import requests
from flask import g, jsonify, request


def selected_scope(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {"host", "alert_id", "start_time", "end_time"}:
        raise ValueError("Invalid request context.")
    result = {}
    for key, raw in value.items():
        if not isinstance(raw, str) or len(raw) > 500:
            raise ValueError("Invalid context value.")
        if raw.strip():
            result[key] = raw.strip()
    for key in ("start_time", "end_time"):
        if key in result:
            try:
                parsed = datetime.fromisoformat(result[key].replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("Invalid selected date.") from None
            if parsed.tzinfo is None:
                raise ValueError("Selected dates must include a timezone.")
            result[key] = parsed.astimezone(timezone.utc).isoformat()
    if bool(result.get("start_time")) != bool(result.get("end_time")):
        raise ValueError("Select both dates or clear the date selection.")
    if result.get("start_time"):
        interval = datetime.fromisoformat(result["end_time"]) - datetime.fromisoformat(result["start_time"])
        if interval.total_seconds() <= 0 or interval.total_seconds() > 31 * 86400:
            raise ValueError("Select a time window greater than zero and no longer than 31 days.")
    return result


def install(app, *, config, db_get, session_payload, role_required,
            service, clean_history, extract_content, audit):
    from hawki_chat_agent import (
        run_chat, investigation_begin, investigation_finish,
        investigation_release, investigation_memory, InvestigationError,
    )

    from hawki_workspace_hermes import settings as hermes_settings, readiness as hermes_ready
    from hawki_workspace_hermes import start as hermes_start, reconcile as hermes_reconcile

    from hawki_collection_review_v1 import install as install_collection_review
    install_collection_review(app, db_get, role_required, audit)
    from hawki_workspace_evidence_v1 import install as install_evidence_archive
    install_evidence_archive(app, db_get, role_required)

    def owned(session_id):
        row = db_get().execute(
            "SELECT * FROM chat_sessions WHERE id = ? AND user_id = ?",
            (session_id, g.user["id"]),
        ).fetchone()
        if row is None:
            raise InvestigationError("Conversation session was not found.", 404)
        return row

    def fail(exc):
        return jsonify({"error": str(exc), "code": "workspace_state_error"}), exc.status

    @app.get("/api/agent/workspace/bootstrap")
    @role_required("analyst")
    def workspace_bootstrap():
        model = str(config["llm_model"])
        status, ready = "unreachable", False
        headers = {}
        if config.get("llm_api_key"):
            headers["Authorization"] = "Bearer " + config["llm_api_key"]
        url = str(config["llm_api_url"]).rstrip("/")
        base = (url[:-len("/chat/completions")] if url.endswith("/chat/completions")
                else str(config.get("llm_base_url", "")).rstrip("/"))
        try:
            response = requests.get(base + "/models", headers=headers,
                                    timeout=(2, 4), allow_redirects=False)
            response.raise_for_status()
            body = response.json()
            names = {item.get("id") for item in body.get("data", []) if isinstance(item, dict)}
            ready = model in names
            status = "available" if ready else "model_not_listed"
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            pass
        runtime = hermes_settings()
        if runtime and not hermes_ready(runtime):
            ready, status = False, "runtime_unavailable"
        return jsonify({
            "version": "workspace-hermes-1" if runtime else "workspace-1", "default_model": model,
            "models": [{"id": model, "label": "Qwen3.5 27B" if runtime else model,
                        "ready": ready, "status": status}],
            "capabilities": {"read_tools": True, "response_execution": False,
                             "engine": "hermes" if runtime else "legacy",
                             "background_turns": bool(runtime)},
        })

    @app.get("/api/agent/workspace/sessions/<session_id>")
    @role_required("analyst")
    def workspace_session(session_id):
        try:
            row = owned(session_id)
            runtime = hermes_settings()
            progress = (hermes_reconcile(db_get(), g.user["id"], session_id, runtime, audit)
                        if runtime and row["mode"] == "conversation" else None)
            row = owned(session_id)
            payload = session_payload(row)
            if progress:
                payload.setdefault("investigation", {}).update(progress)
            records = []
            exists = db_get().execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_investigations'"
            ).fetchone()
            if exists and row["mode"] == "conversation":
                saved = db_get().execute(
                    "SELECT state_json, revision FROM chat_investigations WHERE user_id=? AND session_id=?",
                    (g.user["id"], session_id),
                ).fetchone()
                if saved:
                    state = json.loads(saved["state_json"])
                    records = state.get("evidence", [])
                    payload["pending_request"] = (
                        state.get("workspace_pending")
                        if state.get("workspace_pending_revision") == saved["revision"] else None
                    )
            payload["evidence"] = records
            return jsonify(payload)
        except InvestigationError as exc:
            return fail(exc)

    @app.post("/api/agent/workspace/sessions/<session_id>/continue")
    @role_required("analyst")
    def workspace_continue(session_id):
        try:
            original = owned(session_id)
            if original["mode"] == "conversation":
                return jsonify({"id": session_id})
            source = session_payload(original)
            identifier = uuid.uuid4().hex
            now = datetime.now(timezone.utc).isoformat()
            history = clean_history(source.get("history", []))
            transcript = source.get("transcript", [])[-50:]
            state = {"history": history, "transcript": transcript, "evidence": []}
            from hawki_chat_agent import investigation_tables
            db = db_get()
            investigation_tables(db)
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("""INSERT INTO chat_sessions
                    (id,user_id,title,mode,context_json,history_json,transcript_json,
                     last_result_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (identifier, g.user["id"], source["title"], "conversation", "{}",
                     json.dumps(history, ensure_ascii=False), json.dumps(transcript, ensure_ascii=False),
                     None, now, now))
                db.execute("""INSERT INTO chat_investigations
                    (user_id,session_id,state_json) VALUES (?,?,?)""",
                    (g.user["id"], identifier, json.dumps(state, ensure_ascii=False)))
                db.commit()
            except Exception:
                db.rollback()
                raise
            audit("workspace_continued", {"session_id": identifier, "source_session_id": session_id})
            return jsonify({"id": identifier}), 201
        except InvestigationError as exc:
            return fail(exc)

    @app.post("/api/agent/workspace/turn")
    @role_required("analyst")
    def workspace_turn():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) - {"message", "session_id", "request_id", "model", "context"}:
            return jsonify({"error": "Invalid conversation request."}), 400
        message, sid, rid = (payload.get(key) for key in ("message", "session_id", "request_id"))
        if (not isinstance(message, str) or not message.strip() or len(message) > 12000
                or not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{8,100}", sid)
                or not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", rid)):
            return jsonify({"error": "Invalid message or conversation identifier."}), 400
        model = payload.get("model") or config["llm_model"]
        if model != config["llm_model"]:
            return jsonify({"error": "The selected model is not configured for this workspace."}), 400
        try:
            scope = selected_scope(payload.get("context"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        message = message.strip()
        identity = json.dumps({"message": message, "context": scope, "model": model}, sort_keys=True)
        db, claim = db_get(), None
        try:
            runtime = hermes_settings()
            if runtime:
                result, status_code = hermes_start(
                    db, g.user["id"], sid, rid, message, scope, model, identity,
                    runtime, str(config.get("llm_output_language", "ko")), audit,
                )
                return jsonify(result), status_code
            claim = investigation_begin(db, g.user["id"], sid, rid, identity)
            if "cached" in claim:
                return jsonify(claim["cached"])
            claim["state"]["workspace_pending"] = {
                "session_id": sid, "request_id": rid, "message": message,
                "context": scope, "model": model,
            }
            claim["state"]["workspace_pending_revision"] = claim["revision"]
            cursor = db.execute("""UPDATE chat_investigations SET state_json=?
                WHERE user_id=? AND session_id=? AND lease_token=?""",
                (json.dumps(claim["state"], ensure_ascii=False), g.user["id"], sid, claim["token"]))
            if cursor.rowcount != 1:
                db.rollback()
                raise InvestigationError("The active conversation changed.")
            db.commit()
            result = run_chat(
                config=dict(config, llm_model=model), message=message,
                history=clean_history(claim["state"].get("history", [])),
                context={"_investigation": investigation_memory(claim["state"]),
                         "_selected_scope": scope},
                service=service, extract_content=extract_content,
            )
            result["request_context"] = scope
            result["request_id"] = rid
            claim["state"].pop("workspace_pending", None)
            claim["state"].pop("workspace_pending_revision", None)
            result = investigation_finish(db, g.user["id"], sid, rid, message, claim, result)
            audit("agent_conversation", {
                "session_id": sid, "request_id": rid,
                "message_sha256": hashlib.sha256(message.encode()).hexdigest(),
                "incomplete": bool(result.get("incomplete")),
                "tools": [{"tool": record.get("tool"), "ref": record.get("ref"),
                           "status": (record.get("result") or {}).get("status")}
                          for record in result.get("tool_trace", [])],
            })
            return jsonify(result)
        except InvestigationError as exc:
            return fail(exc)
        except requests.RequestException:
            return jsonify({"error": "The model connection failed.", "code": "chat_transport_error"}), 502
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "The model returned an unusable response.", "code": "chat_response_error"}), 502
        finally:
            if claim and claim.get("token"):
                investigation_release(db, g.user["id"], sid, claim["token"])
