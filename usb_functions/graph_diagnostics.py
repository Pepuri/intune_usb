"""Bounded operator diagnostics. Never returns or logs a bearer token."""
import base64
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx

from app.configuration import deployment_json
from .read_sources import AppTokens, GRAPH


def token_summary(token):
    # Inspection only; this does not validate or authorize an incoming token.
    try:
        part = token.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        return {'inspectable': True, **{k: claims[k] for k in
                ('aud', 'tid', 'oid', 'appid', 'azp', 'idtyp', 'iat', 'nbf', 'exp', 'roles') if k in claims}}
    except (ValueError, IndexError, TypeError, UnicodeError):
        return {'inspectable': False}


def safe_message(value):
    text = str(value)[:1000]
    text = re.sub(r'(?i)Bearer\s+\S+', '[redacted]', text)
    text = re.sub(r'\beyJ[A-Za-z0-9_.-]{30,}', '[redacted]', text)
    return text[:500]


def diagnose(tenant_id, *, tokens=None, transport=None, config=None):
    cfg = config or deployment_json('USB_SAMPLE_DIRECTORY_JSON', 'sample-tenant-resources.json')
    token = (tokens or AppTokens(tenant_id)).token('https://graph.microsoft.com')
    summary = token_summary(token)
    probes = {
        'group': ('GET', '/groups/' + cfg['user_group']['id'], {'$select': 'id,displayName,securityEnabled'}, None),
        'group_members': ('GET', '/groups/' + cfg['user_group']['id'] + '/members', {'$select': 'id', '$top': '1'}, None),
        'user': ('GET', '/users/' + cfg['users'][0]['object_id'], {'$select': 'id,accountEnabled'}, None),
        'intune': ('GET', '/deviceManagement/managedDevices', {'$select': 'id', '$top': '1'}, None),
        'defender': ('POST', '/security/runHuntingQuery', None, {'Query': 'DeviceEvents | where Timestamp > ago(1d) | take 0', 'Timespan': 'P1D'}),
    }

    def probe(item):
        name, (method, path, params, body) = item
        try:
            with httpx.Client(timeout=12, transport=transport, follow_redirects=False) as client:
                r = client.request(method, GRAPH + path, params=params, json=body,
                                   headers={'Authorization': 'Bearer ' + token})
            result = {'http_status': r.status_code, 'request_id': r.headers.get('request-id'), 'date': r.headers.get('date')}
            if not r.is_success:
                try:
                    error = r.json().get('error', {})
                    inner = error.get('innerError', error.get('innererror', {}))
                    result.update(error_code=safe_message(error.get('code', '')),
                                  error_message=safe_message(error.get('message', '')),
                                  inner_code=safe_message(inner.get('code', '')),
                                  inner_request_id=safe_message(inner.get('request-id', '')))
                except (ValueError, AttributeError):
                    result['error_code'] = 'non_json_error'
            else:
                result['status'] = 'ok'
            return name, result
        except httpx.RequestError:
            return name, {'status': 'network_error'}

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = dict(pool.map(probe, probes.items()))
    return {'checked_at': datetime.now(timezone.utc).isoformat(), 'token': summary,
            'tenant_matches_configuration': summary.get('tid') == tenant_id,
            'probes': results, 'policy_or_group_writes': False}
