import base64
import json

import httpx

from usb_functions.graph_diagnostics import diagnose, token_summary, safe_message


def test_token_inspection_only_returns_selected_claims():
    claims = {'tid': 'test-tenant', 'roles': ['User.Read.All'], 'private_claim': 'must-not-leak'}
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    result = token_summary('header.' + encoded + '.signature')
    assert result == {'inspectable': True, 'tid': 'test-tenant', 'roles': ['User.Read.All']}
    assert token_summary('opaque-token') == {'inspectable': False}


def test_probes_are_bounded_and_return_graph_error_without_token_or_records():
    class Tokens:
        def token(self, resource):
            assert resource == 'https://graph.microsoft.com'
            return 'private-access-value'
    cfg = {'user_group': {'id': 'group-id'}, 'users': [{'object_id': 'user-id'}]}
    calls = []
    def handle(request):
        calls.append(request)
        assert request.headers['authorization'] == 'Bearer private-access-value'
        if request.url.path.endswith('/members'):
            return httpx.Response(403, json={'error': {'code': 'Authorization_RequestDenied',
                'message': 'Insufficient privileges', 'innerError': {'request-id': 'correlation-id'}}})
        return httpx.Response(200, json={'value': [{'private_record': 'must-not-leak'}]})
    result = diagnose('test-tenant', tokens=Tokens(), transport=httpx.MockTransport(handle), config=cfg)
    assert len(calls) == 5
    assert all(r.method == 'GET' or (r.method == 'POST' and r.url.path.endswith('/runHuntingQuery')) for r in calls)
    assert result['probes']['group_members']['error_code'] == 'Authorization_RequestDenied'
    assert result['probes']['group_members']['inner_request_id'] == 'correlation-id'
    assert 'private-access-value' not in json.dumps(result)
    assert 'must-not-leak' not in json.dumps(result)
    assert result['policy_or_group_writes'] is False


def test_error_text_redacts_bearer_values():
    assert 'private-access-value' not in safe_message('Bearer private-access-value')


def test_diagnostic_requires_authenticated_operator(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from usb_functions.api import create_business_api
    from usb_functions.bridge import sign_request
    import usb_functions.graph_diagnostics as diagnostics
    key = 'test-diagnostic-bridge-key-at-least-forty-eight-characters'
    tenant = '10000000-0000-0000-0000-000000000099'
    client = TestClient(create_business_api(tmp_path/'diagnostics.sqlite3', key, tenant))
    path = '/api/diagnostics/graph'
    assert client.get(path).status_code in (401, 403)
    monkeypatch.setattr(diagnostics, 'diagnose', lambda tenant_id: {'safe_result': True})
    user = {'source': 'entra', 'tenant_id': tenant, 'username': 'reader@example.invalid',
            'oid': 'test-reader', 'roles': ['USB.Reader']}
    def get():
        return client.get(path, headers={'X-USB-Assertion': sign_request(key, user, 'GET', path, b'')})
    assert get().status_code == 403
    user['roles'] = ['USB.Operator']
    assert get().json() == {'safe_result': True}
