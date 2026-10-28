"""Opt-in ledger to sample group synchronization; no policy or device writes."""
from datetime import date
import time
import uuid

from .sample_directory import SampleDirectory, LabError, LAB_LOCK, utc_stamp

SERIAL = 'SAMPLE-GROUP-FLOW-ONLY-20261028'


class SampleLedger:
    def __init__(self, store, tenant_id, directory=None):
        self.store = store
        self.directory = directory or SampleDirectory(store, tenant_id)

    def link(self, db, row, sample_key, who):
        target = self.directory.users.get(sample_key)
        if not target or row['user_upn'] != target['source_upn']:
            raise LabError('가상 사용자와 실제 샘플 계정 매핑이 일치하지 않습니다.')
        if row['usb_serial'] != SERIAL or row['permission'] != 'read_only':
            raise LabError('실제 그룹 연결 테스트는 공통 샘플 USB·읽기 전용만 지원합니다.')
        if row['valid_until_date'] < self.directory.today().isoformat():
            raise LabError('실제 그룹 테스트 종료일은 현재 KST 날짜 이후여야 합니다.')
        # One opt-in ledger per account avoids turning distinct USB approvals into a broad group grant.
        old_links = [r for r in self.store.rows(db, 'sample_ledger_links')
                     if r['sample_key'] == sample_key and r.get('active', True)]
        for old in old_links:
            prior = self.store.get(db, 'approvals', old['approval_id'])
            if (not prior or prior['approval_status'] not in ('revoked', 'expired', 'rejected')
                    or old['state'] != 'verified' or old['member'] is not False):
                raise LabError('이미 연결된 샘플 계정입니다. 기존 연결 원장에서 처리해 주세요.')
            old['active'] = False
            self.store.save(db, 'sample_ledger_links', old['approval_id'], old)
        link = {'approval_id': row['approval_id'], 'sample_key': sample_key, 'upn': target['upn'],
                'state': 'queued', 'member': None, 'requested_by': who, 'updated_at': utc_stamp(),
                'processed_revision': None, 'desired_member': False, 'error': '',
                'sid_lookup': 'assumed', 'device_confirmed': False, 'active': True}
        self.store.save(db, 'sample_ledger_links', row['approval_id'], link)
        return link

    def queue(self, db, key, who):
        link = self.store.get(db, 'sample_ledger_links', key)
        if link:
            link.update(state='queued', requested_by=who, updated_at=utc_stamp(), error='')
            link.update(attempts=0, retry_after=0)
            self.store.save(db, 'sample_ledger_links', key, link)

    def drain(self, source='scheduled-timer'):
        outcomes = []
        with LAB_LOCK:
            with self.store.connect() as db:
                links = self.store.rows(db, 'sample_ledger_links')
            for link in links:
                if not link.get('active', True):
                    continue
                if link.get('retry_after', 0) > time.time():
                    continue
                with self.store.connect() as db:
                    row = self.store.get(db, 'approvals', link['approval_id'])
                    if (row and row['approval_status'] in ('active','deployment_pending','verification_pending')
                            and row['valid_until_date'] < self.directory.today().isoformat()):
                        row.update(approval_status='expired', revision=row.get('revision',1)+1,
                                   ledger_version=row.get('ledger_version',1)+1, updated_at_utc=utc_stamp())
                        self.store.save(db, 'approvals', row['approval_id'], row)
                if not row:
                    # Missing ledger must fail closed: withdraw a previously linked sample grant.
                    desired = False
                    revision = None
                    until = None
                else:
                    desired = (row['approval_status'] in ('active', 'deployment_pending')
                               and row['validation_status'] == 'verified'
                               and row['valid_from_date'] <= self.directory.today().isoformat() <= row['valid_until_date']
                               and row['permission'] == 'read_only' and row['usb_serial'] == SERIAL
                               and row['user_upn'] == self.directory.users[link['sample_key']]['source_upn'])
                    revision = row.get('revision', 1)
                    until = date.fromisoformat(row['valid_until_date']) if desired else None
                # Only touch opt-in rows. Date transitions also invalidate a previously verified receipt.
                if (link['state'] == 'verified' and link['processed_revision'] == revision
                        and link['desired_member'] == desired):
                    continue
                link.update(state='processing', desired_member=desired, updated_at=utc_stamp())
                with self.store.connect() as db:
                    self.store.save(db, 'sample_ledger_links', link['approval_id'], link)
                try:
                    receipt = self.directory.change(link['sample_key'], 'approve' if desired else 'revoke', until,
                        '원장 자동 동기화 · ' + link['approval_id'], link['requested_by'], source=source)
                    link.update(state='verified', member=receipt['after_member'], processed_revision=revision,
                                event_id=receipt['event_id'], error='', attempts=0, retry_after=0)
                except LabError as error:
                    attempts=link.get('attempts', 0)+1
                    link.update(state='retry_pending', member=None, error=str(error), attempts=attempts,
                                retry_after=time.time()+min(60, 2**min(attempts, 6)))
                link['updated_at'] = utc_stamp()
                event = {'event_id': 'GROUP-EVT-' + uuid.uuid4().hex, 'is_sample': True,
                         'approval_id': link['approval_id'], 'user_upn': row['user_upn'] if row else '',
                         'usb_id': row.get('usb_id', '') if row else '', 'event_type': 'sample_group_sync',
                         'old_status': '', 'new_status': '', 'actor_upn': link['requested_by'],
                         'event_at_utc': utc_stamp(), 'description': '실제 샘플 그룹 ' +
                         ('가입' if desired else '제거') + (' 확인' if link['state'] == 'verified' else ' 재시도 대기'),
                         'sample_group_result': dict(link), 'execution_source': source}
                with self.store.connect() as db:
                    self.store.save(db, 'sample_ledger_links', link['approval_id'], link)
                    self.store.save(db, 'history', event['event_id'], event)
                outcomes.append(dict(link))
        return {'source': source, 'outcomes': outcomes, 'mode': 'sample_group_only'}
