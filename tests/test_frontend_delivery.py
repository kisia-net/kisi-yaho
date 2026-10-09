"""Offline delivery contract; no production account, Wazuh data or network."""
import functools
from pathlib import Path
import unittest
from unittest.mock import patch

from flask import Flask, jsonify, render_template, request, session
from hawki_redteam_ui import register_redteam_scan_routes


TOKEN = 'T' * 48  # Only a mock assertion value, never a production token.


def scan():
    return {
        'schema': 'hawki.deep-scan/v1', 'scan_id': 'a' * 24,
        'alert_id': 'offline-test-alert', 'status': 'queued',
        'tools': {}, 'probes': [], 'summary': 'offline only',
        'raw_response': 'must-not-forward', 'Authorization': TOKEN,
    }


class Response:
    def __init__(self, value, status=200):
        self.value, self.status_code = value, status

    def json(self):
        if self.value is None:
            raise ValueError('Not JSON')
        return self.value


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.app = Flask(__name__, template_folder=str(root / 'templates'),
                         static_folder=str(root / 'static'))
        self.app.secret_key = 'offline-unit-test-only'
        self.live = True

        def role_required(minimum):
            def decorate(function):
                @functools.wraps(function)
                def wrapper(*args, **kwargs):
                    role = session.get('role')
                    if not role:
                        return jsonify(error='offline unauthenticated'), 401
                    if role not in ('analyst', 'admin'):
                        return jsonify(error='offline forbidden'), 403
                    return function(*args, **kwargs)
                return wrapper
            return decorate

        @self.app.before_request
        def offline_csrf():
            if request.method == 'POST' and request.headers.get('X-CSRF-Token') != 'offline-csrf':
                return jsonify(error='offline CSRF rejected'), 400

        register_redteam_scan_routes(self.app,
            configuration=lambda: ('http://runner.test:8091', TOKEN),
            role_required=role_required, live_enabled=lambda: self.live)
        self.client = self.app.test_client()
        self.login('analyst')

    def login(self, role):
        with self.client.session_transaction() as state:
            state.clear()
            if role:
                state['role'] = role

    def post(self, payload=None, csrf=True):
        return self.client.post('/api/redteam/scans',
            json=payload if payload is not None else {'alert_id': 'offline-test-alert'},
            headers={'X-CSRF-Token': 'offline-csrf'} if csrf else {})

    def test_submit_202_uses_fixed_tools_and_server_token_only(self):
        with patch('hawki_redteam_ui.requests.request', return_value=Response(scan(), 202)) as call:
            response = self.post()
        self.assertEqual(response.status_code, 202)
        self.assertEqual(call.call_args.args, ('POST', 'http://runner.test:8091/v1/scans'))
        self.assertEqual(call.call_args.kwargs['json']['tools'], ['promptfoo', 'garak'])
        self.assertEqual(call.call_args.kwargs['headers']['Authorization'], 'Bearer ' + TOKEN)
        self.assertEqual(call.call_args.kwargs['timeout'], 5)
        self.assertFalse(call.call_args.kwargs['allow_redirects'])
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn(TOKEN, response.get_data(as_text=True))
        self.assertNotIn('must-not-forward', response.get_data(as_text=True))

    def test_get_latest_is_read_only_and_whitelisted(self):
        with patch('hawki_redteam_ui.requests.request', return_value=Response(scan())) as call:
            response = self.client.get('/api/redteam/scans/latest')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(call.call_args.args, ('GET', 'http://runner.test:8091/v1/scans/latest'))
        self.assertIsNone(call.call_args.kwargs['json'])
        self.assertNotIn('raw_response', response.json)

    def test_missing_route_404_is_not_no_results(self):
        with patch('hawki_redteam_ui.requests.request', return_value=Response({'error': 'Not found.'}, 404)):
            self.assertEqual(self.client.get('/api/redteam/scans/latest').status_code, 502)
            self.assertEqual(self.post().status_code, 502)

    def test_known_empty_result_stays_404_only_on_get(self):
        with patch('hawki_redteam_ui.requests.request', return_value=Response({'error': 'No deep scan is available.'}, 404)):
            self.assertEqual(self.client.get('/api/redteam/scans/latest').status_code, 404)
            self.assertEqual(self.post().status_code, 502)

    def test_html_404_is_an_upstream_error(self):
        with patch('hawki_redteam_ui.requests.request', return_value=Response(None, 404)):
            self.assertEqual(self.client.get('/api/redteam/scans/latest').status_code, 502)

    def test_auth_role_and_csrf_stop_before_runner(self):
        with patch('hawki_redteam_ui.requests.request') as call:
            self.login(None)
            self.assertEqual(self.client.get('/api/redteam/scans/latest').status_code, 401)
            self.login('viewer')
            self.assertEqual(self.client.get('/api/redteam/scans/latest').status_code, 403)
            self.login('analyst')
            self.assertEqual(self.post(csrf=False).status_code, 400)
        call.assert_not_called()

    def test_demo_or_non_live_mode_cannot_submit(self):
        self.live = False
        with patch('hawki_redteam_ui.requests.request') as call:
            self.assertEqual(self.post().status_code, 409)
        call.assert_not_called()

    def test_fixture_ids_extra_fields_and_wrong_tools_rejected(self):
        with patch('hawki_redteam_ui.requests.request') as call:
            for payload in ({'alert_id': 'evt-' + 'a' * 16},
                            {'alert_id': 'offline-test-alert', 'callback': 'http://other.test'},
                            {'alert_id': 'offline-test-alert', 'tools': ['garak']}):
                self.assertEqual(self.post(payload).status_code, 400)
        call.assert_not_called()

    def test_scan_id_mismatch_is_rejected(self):
        with patch('hawki_redteam_ui.requests.request', return_value=Response(scan())):
            self.assertEqual(self.client.get('/api/redteam/scans/' + 'b' * 24).status_code, 502)

    def test_card_template_contains_actions_details_and_scoped_assets(self):
        with self.app.test_request_context('/'):
            html = render_template('_redteam_deep_scan.html',
                csrf_token=lambda: 'offline-csrf', asset_version='offline-test')
        for marker in ('data-scan-start', 'data-scan-refresh', 'data-scan-details',
                       'redteam_deep_scan.js', 'redteam_deep_scan.css'):
            self.assertIn(marker, html)
        self.assertNotIn(TOKEN, html)


if __name__ == '__main__':
    unittest.main()
