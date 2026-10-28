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
    def __init__(self, store, queue):
        self.store,self.queue=store,queue
        from .api import create_business_api
        import os
        self.api=create_business_api(tenant_id=os.environ['ENTRA_TENANT_ID'],store=store,
                                    remote_auth=NotebookIdentity(queue.key),notebook_worker=True)

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
