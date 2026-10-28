"""Tenant-bound, read-only Microsoft data sources. No policy/group write client exists here."""
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from urllib.parse import quote, urlparse
from uuid import UUID
from types import SimpleNamespace

import httpx
import msal
from dotenv import dotenv_values
from app.store import ROOT
from app.runtime import cloud_mode
from app.configuration import deployment_json, ConfigurationError

GRAPH = 'https://graph.microsoft.com/v1.0'
FABRIC = 'https://api.fabric.microsoft.com/v1'


class SourceError(Exception):
    def __init__(self, status, code='', http_status=None):
        self.status, self.code, self.http_status = status, code, http_status
        super().__init__(status)


class AppTokens:
    """Reuse the configured app identity; tokens/secrets stay on the Function server."""
    def __init__(self, tenant_id):
        self.tenant_id = str(UUID(tenant_id))
        self.lock = threading.Lock()
        self.client = None

    def token(self, resource):
        if resource not in ('https://graph.microsoft.com', 'https://api.fabric.microsoft.com', 'https://database.windows.net'):
            raise SourceError('configuration_error', 'audience_not_allowed')
        if cloud_mode() and os.getenv('USB_SOURCE_AUTH','managed_identity') == 'managed_identity':
            from azure.identity import ManagedIdentityCredential
            with self.lock:
                if self.client is None:
                    self.client=ManagedIdentityCredential(client_id=os.getenv('AZURE_CLIENT_ID') or None)
                return self.client.get_token(resource+'/.default').token
        with self.lock:
            if self.client is None:
                cfg = os.environ if cloud_mode() else dotenv_values(ROOT / '.env.local')
                if cfg.get('ENTRA_TENANT_ID') != self.tenant_id:
                    raise SourceError('configuration_error', 'tenant_mismatch')
                if not cfg.get('ENTRA_CLIENT_ID') or not cfg.get('ENTRA_CLIENT_SECRET'):
                    raise SourceError('configuration_error', 'app_credentials_missing')
                self.client = msal.ConfidentialClientApplication(cfg['ENTRA_CLIENT_ID'],
                    authority='https://login.microsoftonline.com/' + self.tenant_id,
                    client_credential=cfg['ENTRA_CLIENT_SECRET'])
            result = self.client.acquire_token_for_client(scopes=[resource + '/.default'])
        if not result.get('access_token'):
            raise SourceError('authentication_error', str(result.get('error', 'token_failed')))
        return result['access_token']


def source_result(call):
    try:
        data = call()
        return {'status': 'ok', 'data': data}
    except SourceError as e:
        return {'status': e.status, 'code': e.code, 'http_status': e.http_status}
    except (httpx.RequestError, TimeoutError):
        return {'status': 'unavailable', 'code': 'network_or_timeout'}
    except Exception:
        # Never return connection strings, SQL diagnostics, bearer tokens or service error messages.
        return {'status': 'unavailable', 'code': 'source_read_failed'}


class ReadSources:
    def __init__(self, tenant_id, config=None, tokens=None, transport=None, sql_reader=None):
        self.config = config if config is not None else deployment_json('USB_READ_SOURCES_JSON', 'read-sources.json')
        if self.config['tenant_id'] != tenant_id:
            raise ConfigurationError('조회 소스의 테넌트 연결 설정을 확인해 주세요.')
        self.tokens = tokens or AppTokens(tenant_id)
        self.transport = transport
        self.sql_reader = sql_reader

    def request(self, method, url, *, params=None, body=None):
        parsed = urlparse(url)
        # Tight allowlist: even a malicious pagination URL cannot send a token elsewhere.
        graph_get = method == 'GET' and parsed.netloc == 'graph.microsoft.com' and (
            parsed.path.startswith('/v1.0/users/') or parsed.path == '/v1.0/deviceManagement/managedDevices')
        hunting = method == 'POST' and url == GRAPH + '/security/runHuntingQuery'
        ws, lh = str(UUID(self.config['fabric_workspace_id'])), str(UUID(self.config['fabric_lakehouse_id']))
        fabric_get = method == 'GET' and url == f'{FABRIC}/workspaces/{ws}/lakehouses/{lh}'
        if parsed.scheme != 'https' or parsed.username or parsed.password or not (graph_get or hunting or fabric_get):
            raise SourceError('configuration_error', 'read_route_not_allowed')
        audience = 'https://api.fabric.microsoft.com' if fabric_get else 'https://graph.microsoft.com'
        headers = {'Authorization': 'Bearer ' + self.tokens.token(audience)}
        if fabric_get:
            headers['x-ms-fabric-skill'] = 'sqldw-cli'
        with httpx.Client(timeout=12, transport=self.transport, follow_redirects=False) as client:
            response = client.request(method, url, params=params, json=body, headers=headers)
        if not response.is_success:
            states = {401: 'authentication_error', 403: 'permission_denied', 404: 'not_found', 429: 'throttled'}
            raise SourceError(states.get(response.status_code, 'service_error'), 'http_' + str(response.status_code), response.status_code)
        return response.json()

    def user(self, upn):
        row = self.request('GET', GRAPH + '/users/' + quote(upn, safe=''), params={
            '$select': 'id,displayName,userPrincipalName,department,accountEnabled,onPremisesSecurityIdentifier'})
        if row.get('userPrincipalName', '').casefold() != upn.casefold():
            raise SourceError('identity_mismatch', 'upn_mismatch')
        return row

    def usb(self, serial):
        # A JSON string literal is also a KQL string literal; input never becomes KQL syntax.
        literal = json.dumps(serial, ensure_ascii=True)
        query = '''let events = DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("PnpDeviceConnected", "RemovableStoragePolicyTriggered", "UsbDriveMounted", "UsbDriveMount")
| extend usb = parse_json(AdditionalFields)
| extend SerialNumber = tostring(usb.SerialNumber), VID=tostring(usb.VendorId), PID=tostring(usb.ProductId), InstancePath=coalesce(tostring(usb.DeviceInstanceId),tostring(usb.DeviceId)), ClassName=tostring(usb.ClassName)
| where ActionType != "PnpDeviceConnected" or ClassName in~ ("USB", "DiskDrive") or InstancePath startswith "USB";
let sightings = events
| where SerialNumber =~ SERIAL_LITERAL
| project Timestamp, DeviceId, DeviceName, ActionType, ClassName, SerialNumber, VID, PID, InstancePath
| join kind=leftouter (DeviceInfo | where Timestamp > ago(30d) | summarize arg_max(Timestamp, AadDeviceId) by DeviceId | project DeviceId, AadDeviceId) on DeviceId
| order by Timestamp desc
| take 201
| extend RecordKind="observation";
let coverage = events | summarize EventCount=count(), SerialFieldEventCount=countif(isnotempty(SerialNumber)) | extend RecordKind="coverage";
union sightings, coverage'''.replace('SERIAL_LITERAL', literal)
        records = self.request('POST', GRAPH + '/security/runHuntingQuery', body={'Query': query, 'Timespan': 'P30D'}).get('results', [])
        rows = [r for r in records if r.get('RecordKind') == 'observation']
        coverage = next(({'event_count': r.get('EventCount'), 'serial_field_event_count': r.get('SerialFieldEventCount')} for r in records if r.get('RecordKind') == 'coverage'), {})
        if len(rows) >= 201:
            raise SourceError('incomplete', 'usb_observations_truncated')
        return {'observations': rows, 'lookback_days': 30, 'usb_encryption': 'unknown', 'coverage': coverage,
                'matching_basis': 'explicit AdditionalFields.SerialNumber; instance path is retained without inventing a serial'}

    def devices(self, user_id, observations=()):
        # serialNumber here would be the PC chassis serial, never the USB serial.
        observed_ids = sorted({str(UUID(r['AadDeviceId'])) for r in observations if r.get('AadDeviceId')})
        if len(observed_ids) > 20:
            raise SourceError('incomplete', 'observed_pcs_limit_exceeded')
        # Any classified normal PC may be used; do not restrict valid PCs to the user's own PC.
        predicate = ' or '.join("azureADDeviceId eq '" + v + "'" for v in observed_ids)
        params = {'$select': 'id,deviceName,azureADDeviceId,userId,lastSyncDateTime,complianceState,operatingSystem', '$top': '100'}
        endpoint = GRAPH + '/deviceManagement/managedDevices'
        if predicate:
            params['$filter'] = predicate
        else:
            # The live Intune service rejects userId filtering on the collection.
            endpoint = GRAPH + '/users/' + str(UUID(user_id)) + '/managedDevices'
        data = self.request('GET', endpoint, params=params)
        data['lookup_basis'] = 'observed_entra_device_ids' if observed_ids else 'user_inventory_only_no_usb_evidence'
        return data

    def fabric(self, upn, serial, user_id=''):
        cfg = self.config
        server = cfg.get('fabric_server')
        if not server:
            meta = self.request('GET', f"{FABRIC}/workspaces/{cfg['fabric_workspace_id']}/lakehouses/{cfg['fabric_lakehouse_id']}")
            server = meta.get('properties', {}).get('sqlEndpointProperties', {}).get('connectionString', '')
        if not re.fullmatch(r'[a-zA-Z0-9.-]+\.(?:datawarehouse\.fabric|fabric)\.microsoft\.com', server or ''):
            raise SourceError('configuration_error', 'fabric_sql_endpoint_missing_or_invalid')
        for name in ('approvals_table', 'pcs_table'):
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*', cfg[name]):
                raise SourceError('configuration_error', 'table_identifier_invalid')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', cfg['fabric_database']):
            raise SourceError('configuration_error', 'database_identifier_invalid')
        if self.sql_reader:
            return self.sql_reader(upn, serial, user_id)
        import mssql_python
        tokens = self.tokens
        class SqlTokenProvider:
            def get_token(self, scope):
                if scope != 'https://database.windows.net/.default':
                    raise SourceError('configuration_error', 'sql_scope_mismatch')
                return SimpleNamespace(token=tokens.token('https://database.windows.net'))
        try:
            conn = mssql_python.connect(f'Server={server},1433;Database={cfg["fabric_database"]};Encrypt=yes;TrustServerCertificate=no;ApplicationIntent=ReadOnly;',
                                        token_provider=SqlTokenProvider(), timeout=10, autocommit=True)
            try:
                conn.timeout = 12
                cursor = conn.cursor()
                def read(sql, parameters=()):
                    cursor.execute(sql, parameters)
                    columns = [v[0] for v in cursor.description]
                    return [dict(zip(columns, (v.isoformat() if hasattr(v, 'isoformat') else v for v in row))) for row in cursor.fetchall()]
                # Fixed statements + bound values. No caller SQL, schema changes, or writes.
                approvals = read(f'SELECT TOP (201) * FROM {cfg["approvals_table"]} WHERE LOWER(user_upn)=? AND UPPER(usb_serial)=? ORDER BY approval_id', (upn.lower(), serial.upper()))
                pcs = read(f'SELECT TOP (1001) * FROM {cfg["pcs_table"]} ORDER BY device_id')
                if len(approvals) >= 201 or len(pcs) >= 1001:
                    raise SourceError('incomplete', 'fabric_rows_truncated')
                return {'approvals': approvals, 'pcs': pcs, 'workspace_id': cfg['fabric_workspace_id'], 'lakehouse_id': cfg['fabric_lakehouse_id']}
            finally:
                conn.close()
        except mssql_python.Error as e:
            diagnostic = str(e).lower()
            if 'authentication' in diagnostic or 'login' in diagnostic or 'authorization' in diagnostic:
                raise SourceError('authentication_error', 'sql_login_failed') from None
            if 'permission' in diagnostic or 'denied' in diagnostic:
                raise SourceError('permission_denied', 'sql_read_denied') from None
            raise SourceError('unavailable', 'sql_connection_or_query_failed') from None

    def evaluate(self, body):
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {name: pool.submit(source_result, call) for name, call in {
                'entra': lambda: self.user(body.user_upn), 'defender': lambda: self.usb(body.usb_serial),
                'fabric': lambda: self.fabric(body.user_upn, body.usb_serial)}.items()}
            sources = {name: future.result() for name, future in futures.items()}
        user = sources['entra'].get('data', {})
        observations = sources['defender'].get('data', {}).get('observations', [])
        sources['intune'] = source_result(lambda: self.devices(user['id'], observations)) if user.get('id') else {'status': 'not_queried', 'code': 'entra_user_unresolved'}
        return decide(body, sources, self.config.get('max_sync_age_hours', 24))


def decide(body, sources, max_sync_age_hours=24, clock=None):
    now = clock or datetime.now(timezone.utc)
    today = now.astimezone(timezone(timedelta(hours=9))).date().isoformat()
    blockers, pending = [], []
    for name, result in sources.items():
        if result['status'] != 'ok':
            pending.append(name + ':' + result['status'])
    user = sources.get('entra', {}).get('data', {})
    if user and user.get('accountEnabled') is False:
        blockers.append('entra_account_disabled')
    elif sources.get('entra', {}).get('status') == 'ok' and user.get('accountEnabled') is not True:
        pending.append('entra_account_state_unknown')
    identity_reference = None
    if user:
        # Defender supports an Entra user/group Object ID in the Sid condition.
        # Endpoint evaluation still depends on noninteractive Graph access / CA.
        try:
            identity_reference = {'kind':'entra_object_id','value':str(UUID(user['id'])), 'endpoint_evaluation_verified':False}
        except (ValueError, KeyError, TypeError):
            pending.append('policy_user_sid_unresolved')
    defender = sources.get('defender', {}).get('data', {})
    observations = defender.get('observations', [])
    identities = {(r.get('VID', '').upper(), r.get('PID', '').upper(), r.get('InstancePath', '').upper()) for r in observations}
    if sources.get('defender', {}).get('status') != 'ok':
        pass
    elif not observations:
        coverage = defender.get('coverage', {})
        pending.append('usb_serial_telemetry_unavailable' if coverage.get('event_count', 0) and coverage.get('serial_field_event_count') == 0 else 'usb_not_observed_in_last_30_days')
    elif len(identities) != 1:
        pending.append('usb_multiple_candidates')
    elif not all(next(iter(identities))):
        pending.append('usb_identity_incomplete')
    if any(r.get('ActionType') == 'PnpDeviceConnected' and r.get('ClassName') != 'DiskDrive' and not r.get('InstancePath', '').upper().startswith('USBSTOR') for r in observations):
        pending.append('usb_storage_class_unconfirmed')
    if body.permission == 'read_write':
        pending.append('usb_bitlocker_evidence_required')
    fabric = sources.get('fabric', {}).get('data', {})
    approvals = fabric.get('approvals', [])
    valid = []
    for row in approvals:
        if row.get('is_sample') not in (False, 0):
            continue
        if str(row.get('user_object_id', '')).lower() != str(user.get('id', '')).lower():
            continue
        if str(row.get('usb_serial', '')).casefold() != body.usb_serial.casefold() or str(row.get('user_upn', '')).casefold() != body.user_upn.casefold():
            continue
        start, end = str(row.get('valid_from_date', ''))[:10], str(row.get('valid_until_date', ''))[:10]
        if row.get('approval_status') not in ('active', 'deployment_pending') or row.get('validation_status') != 'verified':
            continue
        if not start <= today <= end or not start <= body.valid_from_date.isoformat() <= body.valid_until_date.isoformat() <= end:
            continue
        if not row.get('approval_document_no') or row.get('permission') not in ('read_only', 'read_write') or (body.permission == 'read_write' and row.get('permission') != 'read_write'):
            continue
        valid.append(row)
    if not valid and sources.get('fabric', {}).get('status') == 'ok':
        pending.append('fabric_no_matching_real_valid_approval')
    elif len(valid) > 1:
        pending.append('fabric_overlapping_approvals')
    devices = sources.get('intune', {}).get('data', {})
    if devices.get('@odata.nextLink'):
        pending.append('intune_devices_truncated')
    observed_ids = {str(r.get('AadDeviceId', '')).lower() for r in observations if r.get('AadDeviceId')}
    targets = []
    for pc in devices.get('value', []):
        aad = str(pc.get('azureADDeviceId', '')).lower()
        if aad not in observed_ids or pc.get('operatingSystem') != 'Windows':
            continue
        classifications = [r for r in fabric.get('pcs', []) if r.get('is_sample') in (False, 0) and
                           (str(r.get('device_id', '')).lower() == str(pc.get('id', '')).lower() or str(r.get('entra_device_id', '')).lower() == aad)]
        if len(classifications) != 1 or classifications[0].get('exception_assignment') != 'allowed':
            continue
        try:
            synced = datetime.fromisoformat(pc.get('lastSyncDateTime', '').replace('Z', '+00:00'))
            if not now - timedelta(hours=max_sync_age_hours) <= synced <= now + timedelta(minutes=5):
                continue
        except (ValueError, TypeError):
            continue
        targets.append(pc)
    if not targets and all(sources.get(k, {}).get('status') == 'ok' for k in ('fabric', 'defender', 'intune')):
        pending.append('no_recent_managed_and_classified_observed_pc')
    if body.valid_until_date.isoformat() < today:
        blockers.append('requested_period_expired')
    elif body.valid_from_date.isoformat() > today:
        pending.append('requested_period_not_started')
    return {'checked_at_utc': now.isoformat(), 'reference_date_kst': today,
            'policy_identity_reference': identity_reference,
            'decision': 'blocked' if blockers else ('pending' if pending else 'ready_for_review'),
            'blockers': blockers, 'pending_reasons': pending, 'sources': sources,
            'eligible_approval_ids': [r['approval_id'] for r in valid], 'eligible_pc_ids': [r['id'] for r in targets],
            'eligible_approval_count': len(valid) if all(sources.get(k, {}).get('status') == 'ok' for k in ('fabric', 'entra')) else None,
            'eligible_pc_count': len(targets) if all(sources.get(k, {}).get('status') == 'ok' for k in ('fabric', 'defender', 'intune')) else None,
            'policy_changed': False, 'device_application_verified': False, 'publisher': 'mock',
            'note': '조회·판정 결과이며 정책 게시 또는 실제 단말 허용 결과가 아닙니다.'}
