import csv
import io
import json
import os
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.store import ROOT, Store, get_store
from app.runtime import cloud_mode
from app.auth import actor
from .workflow import Workflow
from .bridge import protect_backend
from .sample_directory import LAB_LOCK, LabError

DEMO_DATE = date.fromisoformat(os.getenv('USB_DEMO_DATE', '2026-10-28'))


def reference_day():
    if cloud_mode():
        from .pair_policy import kst_day
        return kst_day()
    return DEMO_DATE


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def fail(message, code=409):
    raise HTTPException(code, message)


class Registration(BaseModel):
    model_config = ConfigDict(extra='forbid')
    user_display_name: str = Field(min_length=1, max_length=60)
    user_upn: str = Field(min_length=5, max_length=150)
    department: str = Field(min_length=1, max_length=60)
    usb_serial: str = Field(min_length=8, max_length=100, pattern=r'^SAMPLE-[A-Za-z0-9-]+$')
    usb_name: str = Field(min_length=1, max_length=100)
    approval_document_no: str = Field(min_length=3, max_length=80)
    request_reason: str = Field(min_length=3, max_length=500)
    permission: Literal['read_only', 'read_write']
    valid_from_date: date
    valid_until_date: date
    bitlocker_state: Literal['encrypted', 'not_encrypted', 'unknown'] = 'encrypted'
    sample_group_key: str | None = Field(default=None, pattern=r'^SAMPLE-APR-\d{3}$')

    @field_validator('user_display_name', 'user_upn', 'department', 'usb_name', 'approval_document_no', 'request_reason', mode='before')
    @classmethod
    def trim(cls, v):
        return v.strip() if isinstance(v, str) else v

    @field_validator('user_upn')
    @classmethod
    def fake_upn(cls, v):
        if not v.lower().endswith('@example.invalid') or ' ' in v or v.count('@') != 1:
            raise ValueError('로컬 데모는 @example.invalid 가상 계정만 사용할 수 있습니다.')
        return v.lower()

    @model_validator(mode='after')
    def dates(self):
        if self.valid_until_date < self.valid_from_date:
            raise ValueError('종료일은 시작일보다 빠를 수 없습니다.')
        if self.valid_until_date < reference_day():
            raise ValueError('종료일은 데모 기준일 이후여야 합니다.')
        return self


class Change(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)
    valid_until_date: date | None = None
    approval_document_no: str | None = Field(default=None, max_length=80)

    @field_validator('reason', mode='before')
    @classmethod
    def trim(cls, value):
        return value.strip()


class LookupInput(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    user_upn: str = Field(min_length=5, max_length=150, pattern=r'^[^\s@/#?]+@[^\s@/#?]+\.[^\s@/#?]+$')
    usb_serial: str = Field(min_length=1, max_length=100, pattern=r'^[^\x00-\x1f\x7f]+$')
    permission: Literal['read_only', 'read_write'] = 'read_only'
    valid_from_date: date
    valid_until_date: date

    @model_validator(mode='after')
    def date_order(self):
        if self.valid_until_date < self.valid_from_date:
            raise ValueError('종료일은 시작일보다 빠를 수 없습니다.')
        return self


def eligible(row):
    return (row['approval_status'] in ('active', 'deployment_pending')
            and row['validation_status'] == 'verified'
            and date.fromisoformat(row['valid_from_date']) <= reference_day() <= date.fromisoformat(row['valid_until_date'])
            and (row['permission'] != 'read_write' or row['bitlocker_state'] == 'encrypted'))


def create_business_api(db_path=None, bridge_key='', tenant_id='', allow_demo=False, workflow=None, read_sources=None, sample_directory=None, pair_policy_service=None, store=None, remote_auth=None, command_queue=None, notebook_worker=False):
    app = FastAPI(title='USB local Functions API', docs_url=None, redoc_url=None, openapi_url=None)
    store = store or get_store(db_path)
    engine = workflow or Workflow(store, reference_date=None if cloud_mode() else DEMO_DATE)
    app.state.store = store
    app.state.workflow = engine
    if cloud_mode():
        if allow_demo:
            raise ValueError('Demo identities are not permitted in Azure mode')
        from .remote_auth import protect_remote, EntraAPI
        if not notebook_worker:
            from .lake_queue import install_queue, LakeQueue
            install_queue(app,command_queue or LakeQueue.from_env())
        protect_remote(app, remote_auth or EntraAPI.from_env())
    else:
        protect_backend(app, store, bridge_key, tenant_id, allow_demo=allow_demo)

    def lab(request):
        if request.state.user.get('source') != 'entra':
            fail('샘플 테넌트 작업에는 Entra SSO 로그인이 필요합니다.', 403)
        if not getattr(app.state, 'sample_directory', None):
            from .sample_directory import SampleDirectory
            app.state.sample_directory = sample_directory or SampleDirectory(store, tenant_id)
        return app.state.sample_directory

    def linked_lab(request):
        from .sample_ledger import SampleLedger
        if not getattr(app.state, 'sample_ledger', None):
            app.state.sample_ledger = SampleLedger(store, tenant_id, directory=lab(request))
        else:
            lab(request)
        return app.state.sample_ledger

    def pair_service(request):
        from .pair_service import PairPolicyService
        directory = lab(request)
        if not getattr(app.state, 'pair_policy_service', None):
            app.state.pair_policy_service = pair_policy_service or PairPolicyService(store, tenant_id, directory)
        return app.state.pair_policy_service

    @app.get('/api/pair-policy')
    def pair_preview(request: Request):
        from .pair_policy import PairPolicyError
        try:
            return pair_service(request).preview()
        except PairPolicyError as error:
            fail(str(error))

    @app.get('/api/pair-policy/package.zip')
    def pair_package(request: Request):
        from .pair_policy import package_bytes, PairPolicyError
        try:
            manifest = pair_service(request).prepare()
            return Response(package_bytes(manifest), media_type='application/zip',
                headers={'Content-Disposition':'attachment; filename="usb-explicit-pairs.zip"'})
        except PairPolicyError as error:
            fail(str(error))

    class PairPublish(BaseModel):
        model_config = ConfigDict(extra='forbid')
        version: str = Field(pattern=r'^[a-f0-9]{64}$')

    @app.post('/api/pair-policy/publish')
    def pair_publish(body: PairPublish, request: Request):
        from .pair_policy import PairPolicyError
        try:
            return pair_service(request).publish(body.version, actor.get())
        except PairPolicyError as error:
            fail(str(error))

    @app.get('/api/sample-directory/mappings')
    def sample_mappings(request: Request):
        return {'users': list(lab(request).users.values())}

    @app.post('/api/sample-directory/sync')
    def sample_sync(request: Request):
        return linked_lab(request).drain(source='manual-api')

    class SampleChange(BaseModel):
        model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
        action: Literal['approve', 'revoke']
        valid_until_date: date | None = None
        reason: str = Field(min_length=3, max_length=500)

    @app.get('/api/sample-directory')
    def sample_status(request: Request):
        return lab(request).status()

    @app.post('/api/sample-directory/expiry')
    def sample_expiry(request: Request):
        return lab(request).expire(source='manual-api')

    @app.post('/api/sample-directory/{key}')
    def sample_change(key: str, body: SampleChange, request: Request):
        from .sample_directory import LabError
        try:
            with store.connect() as db:
                if any(r['sample_key'] == key and r.get('active', True) for r in store.rows(db, 'sample_ledger_links')):
                    fail('이 계정은 승인 원장에서 자동 관리됩니다. 연결된 원장에서 처리해 주세요.')
            return lab(request).change(key, body.action, body.valid_until_date, body.reason, actor.get())
        except LabError as error:
            fail(str(error))

    @app.post('/api/lookups/evaluate')
    def lookup_evaluate(body: LookupInput):
        from .read_sources import ReadSources
        sources = read_sources or ReadSources(tenant_id)
        result = sources.evaluate(body)
        result['tenant_id'] = tenant_id
        result['lookup_id'] = 'READ-' + uuid.uuid4().hex[:12].upper()
        # Separate local receipt: never changes approvals, mock verification or queued policies.
        with store.connect() as db:
            store.save(db, 'read_lookups', result['lookup_id'],
                       dict(result, actor_upn=actor.get(), input=body.model_dump(mode='json')))
        return result
    def event(db, row, action, before, description):
        history = dict(is_sample=True, event_id='LOCAL-EVT-' + uuid.uuid4().hex, approval_id=row.get('approval_id', ''),
                       user_upn=row.get('user_upn', ''), usb_id=row.get('usb_id', ''), event_type=action,
                       old_status=before.get('approval_status', ''), new_status=row.get('approval_status', ''),
                       actor_upn=actor.get(), event_at_utc=now(), description=description,
                       before=before, after=row.copy())
        store.save(db, 'history', history['event_id'], history)

    def get_row(db, key):
        row = store.get(db, 'approvals', key)
        if not row:
            fail('등록 정보를 찾을 수 없습니다.', 404)
        return row

    def check_revision(row, revision):
        if row.get('revision', 1) != revision:
            fail('다른 화면에서 변경되었습니다. 새로 고침 후 다시 처리해 주세요.')

    @app.get('/api/state')
    def state():
        with store.connect() as db:
            return {'mode': 'azure_functions' if cloud_mode() else 'local_functions', 'reference_date': reference_day().isoformat(), 'loaded_at_utc': now(),
                    'approvals': store.rows(db, 'approvals'), 'pcs': sorted(store.rows(db, 'pcs'), key=lambda p:p['device_name']),
                    'sample_group_links': store.rows(db, 'sample_ledger_links'),
                    'history': sorted(store.rows(db, 'history'), key=lambda x: x['event_at_utc'], reverse=True)}

    @app.post('/api/approvals', status_code=201)
    def register(body: Registration, request: Request):
        with LAB_LOCK, store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            data = body.model_dump(mode='json', exclude_none=True)
            operation = request.headers.get('idempotency-key','')
            if len(operation)>128: fail('Idempotency key is too long',422)
            request_key = actor.get()+':register:'+operation if operation else ''
            request_hash = __import__('hashlib').sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
            prior = store.get(db,'requests',request_key) if request_key else None
            if prior:
                if prior['hash']!=request_hash: fail('같은 요청 ID를 다른 내용으로 사용할 수 없습니다.')
                return prior['response']
            for old in store.rows(db, 'approvals'):
                if (old['user_upn'].lower() == body.user_upn and old['usb_serial'].upper() == body.usb_serial.upper()
                    and old['approval_status'] not in ('revoked', 'rejected', 'expired')
                    and old['valid_from_date'] <= data['valid_until_date'] and old['valid_until_date'] >= data['valid_from_date']):
                    fail('동일 사용자–USB 조합에 기간이 겹치는 등록이 있습니다.')
            key = 'LOCAL-APR-' + uuid.uuid4().hex[:10].upper()
            row = dict(data, approval_id=key, is_sample=True, sample_dataset_id='local-demo',
                       user_object_id=str(uuid.uuid4()), usb_id='LOCAL-USB-' + uuid.uuid4().hex[:8],
                       approval_status='verification_pending', validation_status='not_observed',
                       deployment_status='not_published', policy_profile_name='', ledger_version=1,
                       deployment_version=0, updated_at_utc=now(), revision=1, usb_vid='FFFF', usb_pid='0001',
                       last_observed_pc='', last_error='', revocation_reason='', withdrawal_confirmed_at_utc='')
            if body.sample_group_key:
                try:
                    linked_lab(request).link(db, row, body.sample_group_key, actor.get())
                    row['deployment_status'] = 'sample_group_managed'
                except LabError as error:
                    fail(str(error))
            store.save(db, 'approvals', key, row)
            event(db, row, 'registered', {}, '그룹웨어 승인 정보 Function 접수 · 식별 검증 대기')
            if request_key: store.save(db,'requests',request_key,{'hash':request_hash,'response':row.copy()})
            return row

    @app.post('/api/approvals/{key}/{action}')
    def change(key: str, action: Literal['verify', 'extend', 'revoke', 'confirm_device'], body: Change, request: Request):
        with LAB_LOCK, store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = get_row(db, key)
            linked = store.get(db, 'sample_ledger_links', key)
            if linked:
                linked_lab(request)
                if action == 'confirm_device':
                    fail('그룹 연결 테스트에서는 단말 적용을 확인 처리하지 않습니다.')
            check_revision(row, body.revision)
            before = row.copy()
            if action == 'verify':
                if row['approval_status'] != 'verification_pending':
                    fail('식별 검증 대기 건만 처리할 수 있습니다.')
                if row['permission'] == 'read_write' and row['bitlocker_state'] != 'encrypted':
                    fail('읽기·쓰기는 암호화 확인 후 처리할 수 있습니다.')
                if date.fromisoformat(row['valid_until_date']) < reference_day():
                    fail('만료된 승인은 검증 처리할 수 없습니다.')
                row.update(validation_status='verified', approval_status='deployment_pending', deployment_status='publish_pending')
            elif action == 'extend':
                if row['approval_status'] not in ('active', 'deployment_pending'):
                    fail('유효 또는 배포 대기 건만 연장할 수 있습니다.')
                if not body.valid_until_date or body.valid_until_date <= date.fromisoformat(row['valid_until_date']):
                    fail('새 종료일은 기존 종료일 이후여야 합니다.', 422)
                if not body.approval_document_no or not body.approval_document_no.strip():
                    fail('연장 승인 기안번호가 필요합니다.', 422)
                for other in store.rows(db, 'approvals'):
                    if (other['approval_id'] != key and other['user_upn'].lower() == row['user_upn'].lower()
                        and other['usb_serial'].upper() == row['usb_serial'].upper()
                        and other['approval_status'] not in ('revoked', 'rejected', 'expired')
                        and other['valid_from_date'] <= body.valid_until_date.isoformat()
                        and other['valid_until_date'] >= row['valid_from_date']):
                        fail('연장 기간이 같은 사용자–USB 조합의 다른 승인과 겹칩니다.')
                row.update(valid_until_date=body.valid_until_date.isoformat(), approval_document_no=body.approval_document_no.strip(),
                           approval_status='deployment_pending', deployment_status='publish_pending')
            elif action == 'revoke':
                if row['approval_status'] not in ('active', 'deployment_pending', 'verification_pending'):
                    fail('이미 종료된 건은 다시 회수할 수 없습니다.')
                never_published = row['deployment_status'] == 'not_published' and not row.get('deployment_version', 0)
                row.update(approval_status='revoked', revocation_reason=body.reason,
                           deployment_status='not_published' if never_published else 'withdrawal_pending')
            else:
                if row['deployment_status'] not in ('published', 'withdrawal_published'):
                    fail('모의 정책 게시 이후에만 단말 확인을 기록할 수 있습니다.')
                if row['deployment_status'] == 'published':
                    if not eligible(row):
                        fail('현재 유효한 승인만 적용 확인할 수 있습니다.')
                    row.update(deployment_status='device_applied', approval_status='active', device_apply_confirmed_at_utc=now())
                else:
                    row.update(deployment_status='withdrawal_confirmed', withdrawal_confirmed_at_utc=now())
            row.update(revision=row.get('revision', 1)+1,
                       ledger_version=row.get('ledger_version', 1)+(action != 'confirm_device'), updated_at_utc=now())
            if linked:
                row['deployment_status'] = 'sample_group_managed'
            store.save(db, 'approvals', key, row)
            if linked:
                linked_lab(request).queue(db, key, actor.get())
            event(db, row, action, before, '로컬 모의 처리 · ' + body.reason)
            return row

    @app.get('/api/deployment/preview')
    def deployment_preview():
        with store.connect() as db:
            return engine.preview(db)

    class Publish(BaseModel):
        model_config = ConfigDict(extra='forbid')
        fingerprint: str
        simulate_failures: int = Field(default=0,ge=0,le=5)

    @app.post('/api/deployment/simulate', status_code=202)
    def simulate(body: Publish):
        try:
            job, duplicate = engine.enqueue_publish(body.fingerprint,actor.get(),body.simulate_failures)
        except ValueError as error:
            fail(str(error))
        return {'job':job,'duplicate':duplicate,'accepted':bool(job),'mode':'local_functions','publisher':'mock'}

    @app.get('/api/jobs')
    def jobs():
        with store.connect() as db:
            runtime={r:store.get(db,'runtime',r) for r in ('worker','expiry')}
            policy=store.get(db,'policy','current')
        return {'jobs':engine.jobs(),'runtime':runtime,'policy':policy,'publisher':'mock'}

    @app.post('/api/jobs/{key}/retry')
    def retry_job(key: str):
        try:
            return engine.retry(key,actor.get())
        except LookupError as error: fail(str(error),404)
        except ValueError as error: fail(str(error))

    @app.post('/api/worker/drain')
    def drain():
        return engine.drain(source='manual-api')

    @app.post('/api/expiry/scan')
    def expiry():
        with LAB_LOCK:
            return engine.expire(source='manual-api')

    class PCChange(BaseModel):
        revision: int
        assignment: Literal['allowed', 'excluded', 'unclassified']
        reason: str = Field(min_length=3, max_length=500)

        @field_validator('reason', mode='before')
        @classmethod
        def trim(cls, value):
            return value.strip()

    @app.post('/api/pcs/{key}')
    def pc_change(key: str, body: PCChange):
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = store.get(db, 'pcs', key)
            if not row:
                fail('PC를 찾을 수 없습니다.',404)
            check_revision(row, body.revision)
            before = row.copy()
            row.update(exception_assignment=body.assignment, exclusion_reason=body.reason.strip(),
                       device_purpose={'allowed':'일반 업무 PC','excluded':'공용 PC','unclassified':'미분류 PC'}[body.assignment],
                       baseline_block_required=True, bitlocker_policy_required=True,
                       group_sync_status='pending', revision=row.get('revision',1)+1)
            if body.assignment != 'allowed' and before['allow_policy_assignment'] == 'assigned':
                row['withdrawal_status'] = 'pending'
            store.save(db,'pcs',key,row)
            event(db, {'approval_id': row['device_name'], 'approval_status': body.assignment, 'pc':row.copy()}, 'pc_classification',
                  {'approval_status': before['exception_assignment'], 'pc':before}, 'PC 로컬 분류 변경 · 기본 차단 유지 · ' + body.reason)
            return row

    @app.get('/api/export.csv')
    def export(ids: str = ''):
        with store.connect() as db:
            rows = store.rows(db, 'approvals')
        if ids:
            selected = set(ids.split(','))
            rows = [r for r in rows if r['approval_id'] in selected]
        columns = ['approval_id','user_display_name','user_upn','department','usb_serial','permission','valid_from_date',
                   'valid_until_date','approval_status','validation_status','deployment_status','approval_document_no','is_sample']
        buf = io.StringIO(newline='')
        writer = csv.writer(buf)
        writer.writerow(columns+['demo_reference_date','exported_at_utc'])
        exported = now()
        for row in rows:
            # Guard spreadsheet formula interpretation even in operator-entered fields.
            values = [str(row.get(c,'')) for c in columns]
            writer.writerow([("'"+v) if v.lstrip().startswith(('=','+','-','@')) else v for v in values]+[reference_day().isoformat(),exported])
        return Response('\ufeff'+buf.getvalue(), media_type='text/csv; charset=utf-8',
                        headers={'Content-Disposition':'attachment; filename="usb-ledger-demo.csv"'})

    return app
