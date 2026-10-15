"""Owned workspace jobs; the runtime never receives the web authentication database."""
import hashlib
import hmac
import json
from pathlib import Path
import time

import requests
from flask import current_app

from hawki_hermes_common import clean_history, history_window
from hawki_chat_agent import (InvestigationError, investigation_begin, investigation_finish,
                              investigation_release, investigation_memory)

SETTINGS_PATH = Path(__file__).parent / 'data' / 'workspace-hermes.json'


def settings():
    if not SETTINGS_PATH.is_file():
        return None
    value = json.loads(SETTINGS_PATH.read_text())
    if value.get('version') != 1 or value.get('url') != 'http://hawki-hermes-workspace:8767':
        raise ValueError('Invalid workspace runtime configuration.')
    secret = current_app.secret_key
    if isinstance(secret, str):
        secret = secret.encode()
    if not isinstance(secret, bytes) or not secret:
        raise ValueError('The web session secret is unavailable.')
    return dict(value, token=hmac.new(secret, b'HAWKI-Hermes-Workspace-v1', hashlib.sha256).hexdigest())


def remote(config, path, owner, body=None):
    response = requests.request('GET' if body is None else 'POST', config['url'] + path,
        headers={'Authorization': 'Bearer ' + config['token'], 'X-Hawki-Owner': str(owner)},
        json=body, timeout=(2, 5), allow_redirects=False)
    if len(response.content) > 2097152:
        raise ValueError('Runtime response is too large.')
    return response.status_code, response.json()


def readiness(config):
    try:
        status, body = remote(config, '/healthz', '')
        return status == 200 and body.get('worker_alive') is True
    except (requests.RequestException, ValueError, TypeError):
        return False


def row_for(db, owner, session):
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_investigations'").fetchone()
    if not exists:
        return None
    return db.execute('''SELECT i.* FROM chat_investigations i JOIN chat_sessions s
        ON i.session_id=s.id AND i.user_id=s.user_id
        WHERE i.user_id=? AND i.session_id=? AND s.mode='conversation' ''', (owner, session)).fetchone()


def persist_state(db, row, state):
    changed = db.execute('''UPDATE chat_investigations SET state_json=?
        WHERE user_id=? AND session_id=? AND lease_token=? AND revision=?''',
        (json.dumps(state, ensure_ascii=False), row['user_id'], row['session_id'],
         row['lease_token'], row['revision'])).rowcount
    db.commit()
    return changed == 1


def reconcile(db, owner, session, config, audit):
    row = row_for(db, owner, session)
    if row is None:
        return None
    state = json.loads(row['state_json'])
    job = state.get('hermes_job')
    if not job:
        return None
    try:
        status, body = remote(config, '/v1/jobs/' + job['id'], owner)
    except (requests.RequestException, ValueError, TypeError):
        # Preserve the claim when submission or completion is uncertain.
        return {'running': True, 'phase': 'reconnecting'}
    if status == 404:
        if time.time() - job['submitted_at'] < 10:
            return {'running': True, 'phase': 'submitting'}
        state.pop('hermes_job', None)
        if persist_state(db, row, state):
            investigation_release(db, owner, session, row['lease_token'])
        return {'running': False, 'phase': 'retry_required'}
    if status != 200 or body.get('id') != job['id']:
        return {'running': True, 'phase': 'reconnecting'}
    phase = body.get('status')
    if phase in {'queued', 'running'}:
        return {'running': True, 'phase': phase, 'tools_completed': body.get('tools_completed', 0)}
    if phase not in {'done', 'failed', 'interrupted'}:
        return {'running': True, 'phase': 'reconnecting'}
    result = body.get('result')
    if not isinstance(result, dict) or not isinstance(result.get('answer'), str):
        raise InvestigationError('The runtime returned an invalid result.', 502)
    result = dict(result)
    result.pop('_diagnostic', None)
    history = result.pop('_history', None)
    if history is not None:
        state['hermes_messages'] = history_window(clean_history(history), 60000)
    else:
        previous = state.get('hermes_messages', state.get('history', []))
        state['hermes_messages'] = history_window([*previous,
            {'role': 'user', 'content': job['message']},
            {'role': 'assistant', 'content': result['answer']}], 60000)
    from hawki_collection_review_v1 import reconcile_proposals
    reconcile_proposals(owner, session, job['request_id'], result)
    result.update(request_context=job['scope'], request_id=job['request_id'], model=job['model'])
    state.pop('hermes_job', None)
    state.pop('workspace_pending', None)
    state.pop('workspace_pending_revision', None)
    claim = {'state': state, 'token': row['lease_token'], 'digest': job['identity_hash'],
             'revision': row['revision']}
    try:
        investigation_finish(db, owner, session, job['request_id'], job['message'], claim, result)
    except InvestigationError:
        # Another poll may have committed this exact completion first.
        current = row_for(db, owner, session)
        if current is None or current['last_request'] != job['request_id']:
            raise
    else:
        audit('agent_conversation', {'session_id': session, 'request_id': job['request_id'],
            'engine': 'hermes', 'incomplete': bool(result.get('incomplete')),
            'message_sha256': hashlib.sha256(job['message'].encode()).hexdigest(),
            'tools': [{'tool': r.get('tool'), 'ref': r.get('ref'),
                       'status': (r.get('result') or {}).get('status')}
                      for r in result.get('tool_trace', [])]})
    try:
        remote(config, '/v1/jobs/' + job['id'] + '/ack', owner, {})
    except (requests.RequestException, ValueError, TypeError):
        pass
    return {'running': False, 'phase': 'complete'}


def start(db, owner, session, request_id, message, scope, model, identity,
          runtime, language, audit):
    progress = reconcile(db, owner, session, runtime, audit)
    if progress and progress['running']:
        raise InvestigationError('Another request is running in this conversation.')
    claim = investigation_begin(db, owner, session, request_id, identity)
    if 'cached' in claim:
        return claim['cached'], 200
    identifier = hmac.new(runtime['token'].encode(),
        json.dumps([str(owner), session, request_id], separators=(',', ':')).encode(),
        hashlib.sha256).hexdigest()
    state = claim['state']
    job = {'id': identifier, 'owner': str(owner), 'session_id': session,
        'request_id': request_id, 'message': message, 'scope': scope,
        'model': model, 'language': language, 'memory': investigation_memory(state),
        'history': history_window(state.get('hermes_messages', state.get('history', [])), 60000)}
    from hawki_collection_review_v1 import response_context
    job['memory']['collection_proposals_version'] = 1
    response_budget = max(500, 9400 - len(json.dumps([job['scope'], job['memory']], ensure_ascii=False).encode()))
    job['memory']['responses'] = response_context(db, owner, session, budget=response_budget)
    state['workspace_pending'] = {'session_id': session, 'request_id': request_id,
                                  'message': message, 'context': scope, 'model': model}
    state['workspace_pending_revision'] = claim['revision']
    state['hermes_job'] = {'id': identifier, 'request_id': request_id, 'message': message,
        'scope': scope, 'model': model, 'identity_hash': claim['digest'], 'submitted_at': time.time()}
    row = row_for(db, owner, session)
    if not persist_state(db, row, state):
        raise InvestigationError('The active conversation changed.')
    try:
        status, body = remote(runtime, '/v1/jobs', owner, job)
    except (requests.RequestException, ValueError, TypeError):
        return {'status': 'submission_uncertain', 'request_id': request_id, 'engine': 'hermes'}, 202
    if status not in {200, 202}:
        state.pop('hermes_job', None)
        if persist_state(db, row, state):
            investigation_release(db, owner, session, claim['token'])
        raise InvestigationError('The investigation runtime is busy. Retry shortly.' if status == 429
                                 else 'The investigation runtime rejected this request.',
                                 429 if status == 429 else 502)
    return {'status': body.get('status', 'queued'), 'request_id': request_id, 'engine': 'hermes'}, 202
