"""Small transport and persistence helpers shared by the isolated runtime."""
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

TOOLS = {'response_capabilities', 'list_velociraptor_flows', 'read_collection_results', 'get_collection_flow', 'lookup_indicator', 'get_alert', 'summarize_logs', 'search_logs', 'list_assets', 'propose_collection', 'environment', 'list_velociraptor_clients'}
ID = re.compile(r'[A-Za-z0-9_.:-]{8,128}\Z')


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix('.new')
    with temporary.open('wb') as handle:
        os.chmod(temporary, 0o600)
        handle.write(encoded(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def http(url, token='', body=None, timeout=30, limit=2097152):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(url, headers=headers,
        data=encoded(body) if body is not None else None)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    try:
        response = urllib.request.build_opener(NoRedirect).open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('Response exceeds the configured size limit.')
        return response.status, json.loads(raw)


def validate_job(job):
    keys = {'id', 'owner', 'session_id', 'request_id', 'message', 'scope',
            'memory', 'history', 'language', 'model'}
    if not isinstance(job, dict) or set(job) != keys or len(encoded(job)) > 200000:
        raise ValueError('Invalid job envelope.')
    if not isinstance(job['id'], str) or not re.fullmatch('[a-f0-9]{64}', job['id']):
        raise ValueError('Invalid job identifier.')
    if not isinstance(job['owner'], str) or not re.fullmatch('[0-9]{1,20}', job['owner']):
        raise ValueError('Invalid job owner.')
    for key in ('session_id', 'request_id'):
        if not isinstance(job[key], str) or not ID.fullmatch(job[key]):
            raise ValueError('Invalid conversation identifier.')
    if (not isinstance(job['message'], str) or not job['message'].strip()
            or len(job['message']) > 12000 or job['model'] != 'hawki-local'):
        raise ValueError('Invalid message or model.')
    if not isinstance(job['language'], str) or len(job['language']) > 30:
        raise ValueError('Invalid language.')
    if not isinstance(job['scope'], dict) or not isinstance(job['memory'], dict):
        raise ValueError('Invalid context.')
    if len(encoded([job['scope'], job['memory']])) > 10000:
        raise ValueError('Context is too large.')
    clean_history(job['history'])
    return job


def clean_history(messages):
    if not isinstance(messages, list) or len(messages) > 300:
        raise ValueError('Invalid conversation history.')
    result, pending = [], set()
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError('Invalid history message.')
        role = message.get('role')
        if role == 'system':
            continue
        if role not in {'user', 'assistant', 'tool'}:
            raise ValueError('Invalid history role.')
        text = message.get('content')
        if text is not None and not isinstance(text, str):
            raise ValueError('Text-only history is required.')
        item = {'role': role, 'content': text}
        if role == 'assistant' and message.get('tool_calls'):
            if pending:
                raise ValueError('Unfinished tool calls in history.')
            calls = message['tool_calls']
            if not isinstance(calls, list) or len(calls) > 8:
                raise ValueError('Invalid history tool calls.')
            item['tool_calls'] = []
            for call in calls:
                function = call.get('function', {})
                identifier = call.get('id')
                if (not isinstance(identifier, str) or not identifier or identifier in pending
                        or function.get('name') not in TOOLS
                        or not isinstance(function.get('arguments'), str)):
                    raise ValueError('Invalid history tool call.')
                pending.add(identifier)
                item['tool_calls'].append({'id': identifier, 'type': 'function',
                    'function': {'name': function['name'], 'arguments': function['arguments']}})
        elif role == 'tool':
            identifier = message.get('tool_call_id')
            if identifier not in pending:
                raise ValueError('Unpaired tool result in history.')
            pending.remove(identifier)
            item['tool_call_id'] = identifier
        elif pending:
            raise ValueError('Missing tool result in history.')
        result.append(item)
    if pending:
        raise ValueError('Incomplete tool history.')
    return result


def history_window(messages, budget):
    groups = []
    for message in clean_history(messages):
        if message['role'] == 'user':
            groups.append([])
        if groups:
            groups[-1].append(message)
    kept = []
    for group in reversed(groups):
        if len(encoded(group + kept)) > budget:
            break
        kept = group + kept
    return kept
