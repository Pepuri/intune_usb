"""Notebook driver: command + business changes + durable receipt commit in one state file."""
import json
import time
import jwt
import httpx
from .lake_queue import canonical


class NotebookIdentity:
    def __init__(self,key):
        self.key=key

    def validate(self,token):
        claims=jwt.decode(token,self.key,algorithms=['HS256'],audience='usb-notebook-api',issuer='usb-notebook-worker')
        return claims['user']


class LakeWorker:
    def intake_path(self, path):
        from app.runtime import pairing_preview_enabled
        import re
        return pairing_preview_enabled() and (path == '/api/expiry/scan' or bool(re.fullmatch(
            r'/api/approvals/[A-Za-z0-9-]+/(?:verify|extend|revoke)',path)))

    def __init__(self, store, queue, *, read_sources=None):
        self.store,self.queue=store,queue
        from .api import create_business_api
        import os
        self.api=create_business_api(tenant_id=os.environ['ENTRA_TENANT_ID'],store=store,
                                    remote_auth=NotebookIdentity(queue.key),notebook_worker=True,
                                    read_sources=read_sources)

    async def run_lookup(self, request_id, *, source='manual-notebook-read-only', allow_registration=False):
        """Process exactly one signed lookup, without expiry, workers or policy publishing."""
        import os
        import re
        flags = ('USB_CLOUD_SAMPLE_WRITES', 'USB_PAIR_POLICY_WRITES',
                 'USB_PAIR_POLICY_AUTO_PUBLISH', 'USB_SAMPLE_GROUP_WRITES')
        if any(os.getenv(key, '0') != '0' for key in flags):
            raise ValueError('Read-only notebook requires every write flag to be zero')
        if source not in ('manual-notebook-read-only', 'notebook-read-only-batch', 'notebook-intake-no-policy-writes'):
            raise ValueError('Invalid read-only processing source')
        if not re.fullmatch('[a-f0-9]{64}', request_id):
            raise ValueError('Invalid request ID')
        raw = self.queue.files.read('requests/' + request_id + '.json')
        if raw is None:
            raise ValueError('Request not found')
        command = self.queue.verify(raw, request_id)
        allowed = {'/api/lookups/evaluate'} | ({'/api/approvals'} if allow_registration else set())
        pairing_action = allow_registration and self.intake_path(command['path'])
        if command['path'] not in allowed and not pairing_action:
            raise ValueError('Only a lookup request can be processed in read-only mode')
        if pairing_action and command['path'].startswith('/api/approvals/'):
            with self.store.connect() as db:
                row = self.store.get(db,'approvals',command['path'].split('/')[3])
                if not row or row.get('policy_mode') != 'usb_mtp_pairing':
                    raise ValueError('Only the new pairing preview ledger may be changed')
        if command['path'] == '/api/approvals' and command['body'].get('sample_group_key'):
            raise ValueError('Group-linked registration is not enabled in metadata intake mode')
        existing = self.queue.files.read('results/' + request_id + '.json')
        if existing is not None:
            return json.loads(existing)
        with self.store.connect() as db:
            receipt = self.store.get(db, 'command_receipts', request_id)
            if receipt is None:
                token = jwt.encode({'iss': 'usb-notebook-worker', 'aud': 'usb-notebook-api',
                                    'exp': time.time() + 120, 'user': command['user']},
                                   self.queue.key, algorithm='HS256')
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.api),
                                             base_url='http://notebook') as client:
                    response = await client.post(command['path'], json=command['body'],
                        headers={'Authorization': 'Bearer ' + token})
                receipt = {'request_id': request_id,
                           'status': 'completed' if response.is_success else 'rejected',
                           'http_status': response.status_code, 'result': response.json(),
                           'processed_at': time.time(), 'source': source}
                self.store.save(db, 'command_receipts', request_id, receipt)
        self.queue.files.create('results/' + request_id + '.json', canonical(receipt))
        return receipt

    async def run_pending_lookups(self, limit=50, *, include_registrations=False):
        """Read-only batch: leave other workflow requests pending and skip completed files."""
        import os
        import re
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError('Notebook batch limit must be between 1 and 500')
        if any(os.getenv(key, '0') != '0' for key in ('USB_CLOUD_SAMPLE_WRITES',
                'USB_PAIR_POLICY_WRITES', 'USB_PAIR_POLICY_AUTO_PUBLISH', 'USB_SAMPLE_GROUP_WRITES')):
            raise ValueError('Read-only notebook requires every write flag to be zero')
        outcomes = []
        for name in sorted(self.queue.files.names('requests/')):
            if len(outcomes) >= limit:
                break
            request_id = name.rsplit('/', 1)[-1].removesuffix('.json')
            if not name.endswith('.json') or not re.fullmatch('[a-f0-9]{64}', request_id):
                continue
            if self.queue.files.read('results/' + request_id + '.json') is not None:
                continue
            raw = self.queue.files.read(name)
            try:
                candidate = json.loads(raw)
                allowed = {'/api/lookups/evaluate'} | ({'/api/approvals'} if include_registrations else set())
                if not isinstance(candidate, dict) or (candidate.get('path') not in allowed and
                    not (include_registrations and self.intake_path(candidate.get('path','')))):
                    continue
                receipt = await self.run_lookup(request_id,
                    source='notebook-intake-no-policy-writes' if include_registrations else 'notebook-read-only-batch',
                    allow_registration=include_registrations)
            except (ValueError, KeyError, TypeError):
                receipt = {'request_id': request_id, 'status': 'rejected',
                           'detail': '조회 요청 서명·신원·기한·입력을 확인해 주세요.',
                           'source': 'notebook-intake-no-policy-writes' if include_registrations else 'notebook-read-only-batch',
                           'processed_at': time.time()}
                with self.store.connect() as db:
                    self.store.save(db, 'command_receipts', request_id, receipt)
                self.queue.files.create('results/' + request_id + '.json', canonical(receipt))
            outcomes.append(receipt)
        return {'processed': len(outcomes), 'outcomes': outcomes,
                'source': 'notebook-intake-no-policy-writes' if include_registrations else 'notebook-read-only-batch',
                'policy_or_group_writes': False}

    async def run_pending_intake(self, limit=50):
        """Save sample approval metadata and evaluate lookups; never publish or maintain policies."""
        result = await self.run_pending_lookups(limit=limit, include_registrations=True)
        from app.runtime import pairing_preview_enabled
        if pairing_preview_enabled():
            result['pairing_expiry'] = self.api.state.workflow.expire_pairings(source='notebook-pairing-preview')
        return result

    async def run(self, limit=50):
        if not isinstance(limit,int) or not 1 <= limit <= 500:
            raise ValueError('Notebook batch limit must be between 1 and 500')
        names=sorted(self.queue.files.names('requests/'))
        outcomes=[]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.api),base_url='http://notebook') as client:
            for name in names:
                if len(outcomes)>=limit:
                    break
                request_id=name.rsplit('/',1)[-1].removesuffix('.json')
                if not name.endswith('.json'):
                    continue
                # Completed result files are immutable; retries repair a missing file from the durable receipt.
                if self.queue.files.read('results/'+request_id+'.json') is not None:
                    continue
                with self.store.connect() as db:
                    receipt=self.store.get(db,'command_receipts',request_id)
                    if receipt is None:
                        try:
                            command=self.queue.verify(self.queue.files.read(name),request_id)
                        except (ValueError,KeyError,TypeError):
                            receipt={'request_id':request_id,'status':'rejected','detail':'서명·신원·처리 기한 검증 실패'}
                        else:
                            token=jwt.encode({'iss':'usb-notebook-worker','aud':'usb-notebook-api',
                                              'exp':time.time()+60,'user':command['user']},self.queue.key,algorithm='HS256')
                            response=await client.post(command['path'],json=command['body'],headers={
                                'Authorization':'Bearer '+token,'idempotency-key':request_id})
                            receipt={'request_id':request_id,'status':'completed' if response.is_success else 'rejected',
                                     'http_status':response.status_code,'result':response.json()}
                        receipt['processed_at']=time.time()
                        receipt['source']='scheduled-notebook'
                        self.store.save(db,'command_receipts',request_id,receipt)
                # A crash here is safe: next run republishes this already committed receipt, without reapplying.
                self.queue.files.create('results/'+request_id+'.json',canonical(receipt))
                outcomes.append(receipt)
        # Date-based revocation is performed by the scheduled notebook even without new files.
        with self.store.connect():
            self.api.state.workflow.expire(source='scheduled-notebook')
            self.api.state.workflow.drain(source='scheduled-notebook')
        from .pair_service import PairPolicyService
        from .pair_policy import PairPolicyError
        from .sample_directory import LabError
        from .sample_directory import SampleDirectory
        from .sample_ledger import SampleLedger
        import os
        try:
            directory=SampleDirectory(self.store,os.environ['ENTRA_TENANT_ID'])
            SampleLedger(self.store,os.environ['ENTRA_TENANT_ID'],directory=directory).drain(source='scheduled-notebook')
            directory.expire(source='scheduled-notebook')
            PairPolicyService(self.store,os.environ['ENTRA_TENANT_ID']).tick(source='scheduled-notebook')
        except (PairPolicyError,LabError):
            # Surface failure to the scheduler; never claim a successful policy update.
            raise RuntimeError('Sample policy processing requires attention') from None
        return {'processed':len(outcomes),'outcomes':outcomes}
