"""Function accepts immutable signed files; a scheduled Fabric notebook applies commands."""
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone

from fastapi.responses import JSONResponse
from fastapi import Request
from app.onelake import LakeFiles


def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()


def allowed(path):
    return path in {'/api/approvals','/api/pair-policy/publish','/api/deployment/simulate',
                    '/api/worker/drain','/api/expiry/scan','/api/sample-directory/sync',
                    '/api/sample-directory/expire','/api/lookups/evaluate'} or bool(re.fullmatch(
        r'/api/(?:approvals/[A-Za-z0-9-]+/(?:verify|extend|revoke|confirm_device)|pcs/[A-Za-z0-9-]+|jobs/[A-Za-z0-9-]+/retry|sample-directory/SAMPLE-APR-\d{3})',path))


class LakeQueue:
    def __init__(self, files, signing_key):
        if len(signing_key)<48 or signing_key.startswith('@Microsoft.KeyVault('):
            raise ValueError('A resolved, dedicated request signing key of at least 48 characters is required')
        self.files, self.key = files, signing_key.encode()

    @classmethod
    def from_env(cls):
        return cls(LakeFiles.from_env(),os.environ.get('USB_REQUEST_SIGNING_KEY',''))

    def signature(self, value):
        return hmac.new(self.key,canonical(value),hashlib.sha256).hexdigest()

    def enqueue(self, path, body, user, idempotency):
        if not allowed(path) or not isinstance(body,dict):
            raise ValueError('지원하는 업무 요청 경로와 JSON 객체가 필요합니다.')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',idempotency or ''):
            raise ValueError('유효한 Idempotency-Key가 필요합니다.')
        request_id = hashlib.sha256((user['oid']+':'+idempotency).encode()).hexdigest()
        content = {'path':path,'body':body,'user':user,'request_id':request_id}
        content_hash = hashlib.sha256(canonical(content)).hexdigest()
        request = dict(content,content_hash=content_hash,issued_at=time.time(),
                       created_at=datetime.now(timezone.utc).isoformat())
        request['signature']=self.signature(request)
        filename='requests/'+request_id+'.json'
        if not self.files.create(filename,canonical(request)):
            existing=json.loads(self.files.read(filename))
            if existing.get('content_hash') != content_hash:
                raise ValueError('같은 접수 키에 다른 요청이 있습니다.')
        return {'accepted':True,'status':'queued','request_id':request_id,
                'status_url':'/api/cloud-requests/'+request_id,
                'message':'레이크하우스 파일로 접수했습니다. 정기 노트북 처리 결과를 확인해 주세요.'}

    def verify(self, raw, request_id):
        value=json.loads(raw)
        if not isinstance(value,dict) or not isinstance(value.get('user'),dict):
            raise ValueError('Invalid command document')
        signature=value.pop('signature','')
        if not hmac.compare_digest(signature,self.signature(value)) or value.get('request_id')!=request_id:
            raise ValueError('Invalid command signature')
        if (not allowed(value.get('path','')) or value['user'].get('source')!='entra'
            or 'USB.Operator' not in value['user'].get('roles',[])
            or value['user'].get('tenant_id')!=os.environ['ENTRA_TENANT_ID']):
            raise ValueError('Invalid command identity or route')
        if value['issued_at']>time.time()+60 or value['issued_at']<time.time()-86400:
            raise ValueError('Command expired; submit a new request')
        return value

    def status(self, request_id, user):
        if not re.fullmatch('[a-f0-9]{64}',request_id):
            return None
        raw=self.files.read('requests/'+request_id+'.json')
        if raw is None:
            return None
        request=json.loads(raw)
        if user['oid']!=request['user']['oid'] and 'USB.Operator' not in user.get('roles',[]):
            return None
        result=self.files.read('results/'+request_id+'.json')
        return dict(json.loads(result) if result else {'request_id':request_id,'status':'queued'},
                    path=request['path'],created_at=request['created_at'])


def install_queue(app, queue):
    app.state.command_queue=queue

    @app.middleware('http')
    async def file_commands(request, call_next):
        if request.method=='POST':
            if not allowed(request.url.path) or request.url.query:
                return JSONResponse({'detail':'지원하지 않는 파일 처리 경로입니다.'},status_code=404)
            raw=await request.body()
            if len(raw)>1024*1024:
                return JSONResponse({'detail':'요청이 너무 큽니다.'},status_code=413)
            try:
                body=json.loads(raw)
                result=queue.enqueue(request.url.path,body,request.state.user,request.headers.get('idempotency-key'))
            except (ValueError,TypeError):
                return JSONResponse({'detail':'요청 형식 또는 접수 키가 유효하지 않습니다.'},status_code=409)
            return JSONResponse(result,status_code=202)
        return await call_next(request)

    @app.get('/api/cloud-requests/{request_id}')
    def request_status(request_id:str, request:Request):
        result=queue.status(request_id,request.state.user)
        return result if result else JSONResponse({'detail':'요청을 찾을 수 없습니다.'},status_code=404)

    @app.get('/api/cloud-requests')
    def requests(request:Request):
        names=sorted(queue.files.names('requests/'))
        if len(names)>2000:
            return JSONResponse({'detail':'요청 파일 보관 분할이 필요합니다.'},status_code=409)
        results=[queue.status(name.rsplit('/',1)[-1][:-5],request.state.user) for name in names if name.endswith('.json')]
        return {'requests':sorted([r for r in results if r],key=lambda r:r['created_at'],reverse=True)[:100]}
