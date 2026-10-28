"""Web UI / Entra BFF. Business requests cross the local Function boundary."""
import os
import secrets
import uuid
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .store import ROOT, get_store
from .auth import AuthSettings, AuthService
from .runtime import require_local_runtime
from urllib.parse import urlparse
from usb_functions.bridge import loopback_url, sign_request


def create_app(db_path=None, auth_settings=None, client_factory=None, function_transport=None, bridge_key=None, shared_store=None):
    require_local_runtime()
    app=FastAPI(title='USB 운영 콘솔 · 로컬',docs_url=None,redoc_url=None,openapi_url=None)
    settings=auth_settings or AuthSettings.from_env()
    sessions=None
    if settings.cloud:
        from .sessions import SharedSessions
        from .onelake import OneLakeStore
        sessions=SharedSessions(shared_store or OneLakeStore.from_env('auth'),os.environ.get('USB_SESSION_ENCRYPTION_KEY',''))
    auth=AuthService(settings,client_factory,sessions)
    app.state.auth=auth
    auth.install(app)
    key=bridge_key or os.getenv('USB_FUNCTION_BRIDGE_KEY','')
    configured_endpoint=os.getenv('USB_FUNCTION_URL','http://127.0.0.1:7071')
    if settings.cloud:
        parsed=urlparse(configured_endpoint)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.hostname in ('localhost','127.0.0.1')
            or parsed.port not in (None,443) or parsed.username or parsed.password
            or parsed.path not in ('','/') or parsed.query or parsed.fragment):
            raise ValueError('Azure Function endpoint must be a fixed HTTPS origin')
        expected_scope='api://'+str(uuid.UUID(os.environ['USB_FUNCTION_AUDIENCE']))+'/USB.Access'
        if settings.api_scope != expected_scope:
            raise ValueError('Function API scope and audience must match')
        endpoint=configured_endpoint.rstrip('/')
    else:
        endpoint=loopback_url(configured_endpoint)
    # Explicit db_path is the isolated test harness. Runtime has no in-process fallback.
    if not settings.cloud and db_path is not None and function_transport is None:
        from usb_functions.api import create_business_api
        key=bridge_key or secrets.token_urlsafe(48)
        backend=create_business_api(db_path,key,settings.tenant_id,allow_demo=settings.mode=='demo')
        function_transport=httpx.ASGITransport(app=backend)
        app.state.backend=backend
        app.state.store=backend.state.store
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=[urlparse(settings.redirect_uri).hostname] if settings.cloud else ['127.0.0.1','localhost','[::1]','testserver'])

    @app.middleware('http')
    async def local_guard(request: Request, call_next):
        transport_error=auth.transport_guard(request)
        if transport_error is not None:
            return transport_error
        if request.method not in ('GET','HEAD','OPTIONS'):
            origin=request.headers.get('origin')
            expected_origin=settings.redirect_uri.removesuffix('/auth/callback') if settings.cloud else str(request.base_url).rstrip('/')
            if request.headers.get('x-local-demo')!='1' or (settings.cloud and origin != expected_origin) or (origin and origin!=expected_origin):
                return Response('로컬 화면에서 요청해 주세요.',status_code=403)
        blocked=auth.guard(request)
        response=blocked if blocked is not None else await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers['Cache-Control']='no-store'
        if settings.cloud:
            response.headers['Strict-Transport-Security']='max-age=31536000'
        return response

    @app.api_route('/api/{rest:path}',methods=['GET','POST'])
    async def function_proxy(rest: str,request: Request):
        body=await request.body()
        if len(body)>1024*1024:return JSONResponse({'detail':'요청 크기가 너무 큽니다.'},status_code=413)
        user=getattr(request.state,'user',None)
        if not user:return JSONResponse({'detail':'로그인이 필요합니다.'},status_code=401)
        if not settings.cloud and len(key)<48:return JSONResponse({'detail':'로컬 Function 연결 설정이 필요합니다. run-stack.ps1로 시작해 주세요.'},status_code=503)
        target=request.url.path+('?' + request.url.query if request.url.query else '')
        headers={'content-type':request.headers.get('content-type','application/json'),
                 'idempotency-key':request.headers.get('idempotency-key',str(uuid.uuid4()))}
        if settings.cloud:
            token=auth.api_token(request)
            if not token:
                return JSONResponse({'detail':'회사 계정으로 다시 로그인해 주세요.'},status_code=401)
            headers['Authorization']='Bearer '+token
        else:
            headers['x-usb-assertion']=sign_request(key,user,request.method,target,body)
        try:
            async with httpx.AsyncClient(base_url=endpoint,transport=function_transport,trust_env=False,timeout=150 if rest.startswith('pair-policy') else 90 if rest.startswith('sample-directory') else 75 if rest=='lookups/evaluate' else 20) as client:
                result=await client.request(request.method,target,content=body,headers=headers)
        except httpx.RequestError:
            return JSONResponse({'detail':'로컬 Function에 연결할 수 없습니다. Function 실행 상태를 확인해 주세요.'},status_code=503)
        forwarded={k:v for k,v in result.headers.items() if k.lower() in ('content-type','content-disposition','x-usb-worker')}
        return Response(result.content,status_code=result.status_code,headers=forwarded)

    @app.get('/')
    def index():return FileResponse(ROOT/'app/static/index.html')
    app.mount('/static',StaticFiles(directory=ROOT/'app/static'),name='static')
    return app


app=create_app()
