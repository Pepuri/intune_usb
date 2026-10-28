"""Tenant-bound local Entra sign-in. Authentication tokens never enter the browser session."""
import os
import logging
import secrets
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse
from uuid import UUID

import msal
from fastapi import Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from .store import ROOT
from .runtime import cloud_mode

actor = ContextVar('usb_actor', default='local.operator@example.invalid')
ROLE_READER = 'USB.Reader'
ROLE_OPERATOR = 'USB.Operator'
SESSION_COOKIE = 'usb_session'
FLOW_COOKIE = 'usb_flow'


@dataclass(frozen=True)
class AuthSettings:
    mode: str = 'demo'
    tenant_id: str = ''
    client_id: str = ''
    client_secret: str = ''
    redirect_uri: str = 'http://localhost:8765/auth/callback'
    cloud: bool = False
    api_scope: str = ''
    trusted_proxy_cidrs: tuple = ()

    @classmethod
    def from_env(cls):
        result = cls(os.getenv('USB_AUTH_MODE','demo'), os.getenv('ENTRA_TENANT_ID',''),
                     os.getenv('ENTRA_CLIENT_ID',''), os.getenv('ENTRA_CLIENT_SECRET',''),
                     os.getenv('ENTRA_REDIRECT_URI','http://localhost:8765/auth/callback'),
                     cloud_mode(), os.getenv('USB_FUNCTION_SCOPE',''),
                     tuple(v.strip() for v in os.getenv('USB_TRUSTED_PROXY_CIDRS','').split(',') if v.strip()))
        if result.mode not in ('demo','entra'):
            raise ValueError('USB_AUTH_MODE must be demo or entra')
        if result.mode == 'entra':
            UUID(result.tenant_id)
            if result.client_id:
                UUID(result.client_id)
            parsed = urlparse(result.redirect_uri)
            if result.cloud:
                import ipaddress
                if (parsed.scheme != 'https' or not parsed.hostname or parsed.hostname in ('localhost','127.0.0.1')
                    or parsed.port not in (None,443) or parsed.username or parsed.password
                    or parsed.path != '/auth/callback' or parsed.query or parsed.fragment):
                    raise ValueError('Azure Entra mode requires a fixed HTTPS callback')
                if not result.configured or not result.api_scope.startswith('api://') or not result.api_scope.endswith('/USB.Access'):
                    raise ValueError('Azure web identity and Function delegated scope are required')
                if result.client_secret.startswith('@Microsoft.KeyVault('):
                    raise ValueError('Entra credential Key Vault reference is unresolved')
                for cidr in result.trusted_proxy_cidrs:
                    network=ipaddress.ip_network(cidr)
                    if network.prefixlen == 0:
                        raise ValueError('Do not trust every proxy address')
            elif parsed.scheme != 'http' or parsed.hostname != 'localhost' or parsed.path != '/auth/callback' or parsed.query or parsed.fragment:
                raise ValueError('Local Entra mode requires http://localhost:<port>/auth/callback')
        if result.cloud and result.mode != 'entra':
            raise ValueError('Demo sign-in is not permitted in Azure mode')
        return result

    @property
    def configured(self):
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def authority(self):
        return f'https://login.microsoftonline.com/{self.tenant_id}'


class AuthService:
    def __init__(self, settings, client_factory=None, shared_sessions=None):
        self.settings = settings
        self.client_factory = client_factory
        self.flows = {}
        self.sessions = {}
        self.lock = threading.Lock()
        self.shared = shared_sessions
        if settings.cloud and self.shared is None:
            raise ValueError('Azure mode requires shared encrypted sessions')

    def put(self, kind, handle, value):
        if self.shared:
            self.shared.put(kind,handle,value)
        else:
            with self.lock:
                self.prune()
                getattr(self,kind)[handle]=value

    def get(self, kind, handle, consume=False):
        if self.shared:
            return self.shared.get(kind,handle,consume)
        with self.lock:
            self.prune()
            return getattr(self,kind).pop(handle,None) if consume else getattr(self,kind).get(handle)

    def delete(self, kind, handle):
        if self.shared:
            self.shared.delete(kind,handle)
        else:
            with self.lock:
                getattr(self,kind).pop(handle,None)

    def api_token(self, request):
        entry=self.get('sessions',request.cookies.get(SESSION_COOKIE,''))
        return entry.get('api_access_token') if entry else None

    def transport_guard(self, request):
        if not self.settings.cloud:
            return None
        import ipaddress
        expected=urlparse(self.settings.redirect_uri)
        if request.headers.get('host','').lower() != expected.netloc.lower():
            return JSONResponse({'detail':'잘못된 서비스 호스트입니다.'},status_code=400)
        if request.url.scheme != 'https':
            peer=request.client.host if request.client else ''
            try:
                trusted=any(ipaddress.ip_address(peer) in ipaddress.ip_network(c) for c in self.settings.trusted_proxy_cidrs)
            except ValueError:
                trusted=False
            # App Service supplies its own protocol marker after TLS termination.
            # Prefer that marker when present; a trusted peer is still mandatory.
            platform_proto = request.headers.get('x-appservice-proto', '').lower()
            forwarded_proto = request.headers.get('x-forwarded-proto', '').lower()
            effective_proto = platform_proto or forwarded_proto
            if not trusted or effective_proto != 'https':
                logging.warning('USB_HTTPS_PROXY_REJECTED peer=%s trusted=%s forwarded=%s platform=%s',
                                peer, trusted,
                                forwarded_proto if forwarded_proto in ('', 'http', 'https') else 'invalid',
                                platform_proto if platform_proto in ('', 'http', 'https') else 'invalid')
                return JSONResponse({'detail':'HTTPS 연결이 필요합니다.'},status_code=400)
            request.scope['scheme']='https'
        return None

    def client(self):
        if self.client_factory:
            return self.client_factory()
        # Only OIDC sign-in is requested; downstream API permissions are not requested.
        return msal.ConfidentialClientApplication(self.settings.client_id,
                    authority=self.settings.authority, client_credential=self.settings.client_secret,
                    exclude_scopes=['offline_access'])

    def prune(self):
        for cache in (self.flows, self.sessions):
            for key, item in list(cache.items()):
                if item['expires'] <= time.time():
                    del cache[key]

    def identity(self, request):
        if self.settings.mode == 'demo':
            return {'name':'로컬 운영자','username':'local.operator@example.invalid',
                    'oid':'local-demo','tenant_id':'','roles':[ROLE_OPERATOR], 'source':'demo'}
        entry = self.get('sessions',request.cookies.get(SESSION_COOKIE,''))
        return entry['user'].copy() if entry else None

    def claims_identity(self, claims):
        if (claims.get('tid') != self.settings.tenant_id or claims.get('aud') != self.settings.client_id
            or claims.get('iss') != self.settings.authority + '/v2.0'
            or not claims.get('oid') or float(claims.get('exp',0)) <= time.time()):
            raise ValueError('Tenant, issuer, audience or expiry mismatch')
        roles = sorted(set(claims.get('roles',[])) & {ROLE_READER, ROLE_OPERATOR})
        if not roles:
            raise PermissionError('No assigned application role')
        return {'name':claims.get('name','회사 계정'), 'username':claims.get('preferred_username',claims['oid']),
                'oid':claims['oid'], 'tenant_id':claims['tid'], 'roles':roles, 'source':'entra'}

    def install(self, app):
        @app.get('/api/me')
        def me(request: Request):
            user = self.identity(request)
            return {'authenticated':bool(user),'mode':self.settings.mode,'configured':self.settings.configured,
                    'tenant_id':self.settings.tenant_id,'user':user,
                    'can_write':bool(user and ROLE_OPERATOR in user['roles'])}

        @app.get('/auth/status')
        def status():
            return {'mode':self.settings.mode,'configured':self.settings.configured,
                    'tenant_id':self.settings.tenant_id,'redirect_uri':self.settings.redirect_uri,
                    'roles':[ROLE_READER,ROLE_OPERATOR]}

        @app.get('/auth/login')
        def login(request: Request):
            if self.settings.mode != 'entra':
                return RedirectResponse('/')
            if not self.settings.configured:
                return RedirectResponse('/?auth_error=configuration_pending',status_code=303)
            if not self.settings.cloud and request.url.hostname != 'localhost':
                return RedirectResponse(self.settings.redirect_uri.replace('/auth/callback','/auth/login'),status_code=303)
            # Query callback is used only on loopback HTTP; access logging is disabled by run-local.ps1.
            try:
                flow = self.client().initiate_auth_code_flow(scopes=[self.settings.api_scope] if self.settings.cloud else [], redirect_uri=self.settings.redirect_uri,
                                                            response_mode='query')
                if 'auth_uri' not in flow:
                    raise ValueError('No auth URI')
            except Exception:
                return RedirectResponse('/?auth_error=login_unavailable',status_code=303)
            handle = secrets.token_urlsafe(40)
            self.put('flows',handle,{'flow':flow,'expires':time.time()+600})
            response = RedirectResponse(flow['auth_uri'],status_code=303)
            response.set_cookie(FLOW_COOKIE,handle,max_age=600,httponly=True,secure=self.settings.cloud,samesite='lax',path='/auth')
            return response

        @app.get('/auth/callback')
        def callback(request: Request):
            saved = self.get('flows',request.cookies.get(FLOW_COOKIE,''),consume=True)
            error = 'invalid_flow'
            response = None
            if saved and self.settings.mode == 'entra' and self.settings.configured:
                try:
                    # MSAL validates state, nonce and authorization response before claims are consumed.
                    result = self.client().acquire_token_by_auth_code_flow(saved['flow'],dict(request.query_params))
                    if 'error' in result:
                        raise ValueError('Authorization response rejected')
                    claims = result.get('id_token_claims',{})
                    user = self.claims_identity(claims)
                    handle = secrets.token_urlsafe(48)
                    expires = min(time.time()+3600,float(claims['exp']))
                    session={'user':user,'expires':expires}
                    if self.settings.cloud:
                        token=result.get('access_token')
                        if not token or int(result.get('expires_in',0)) <= 0:
                            raise ValueError('Function access token required')
                        session.update(api_access_token=token,expires=min(expires,time.time()+int(result['expires_in'])))
                    self.delete('sessions',request.cookies.get(SESSION_COOKIE,''))
                    self.put('sessions',handle,session)
                    response = RedirectResponse('/',status_code=303)
                    response.set_cookie(SESSION_COOKIE,handle,max_age=max(1,int(session['expires']-time.time())),
                                        httponly=True,secure=self.settings.cloud,samesite='lax',path='/')
                except PermissionError:
                    error = 'role_required'
                except Exception:
                    error = 'invalid_identity'
            if response is None:
                response = RedirectResponse('/?'+urlencode({'auth_error':error}),status_code=303)
                response.delete_cookie(SESSION_COOKIE,path='/')
            response.delete_cookie(FLOW_COOKIE,path='/auth')
            return response

        @app.post('/auth/logout')
        def logout(request: Request):
            self.delete('sessions',request.cookies.get(SESSION_COOKIE,''))
            self.delete('flows',request.cookies.get(FLOW_COOKIE,''))
            target = self.settings.authority+'/oauth2/v2.0/logout?'+urlencode({
                'post_logout_redirect_uri':self.settings.redirect_uri.replace('/auth/callback','/')}) if self.settings.mode=='entra' else '/'
            response = JSONResponse({'logout_url':target})
            response.delete_cookie(SESSION_COOKIE,path='/')
            response.delete_cookie(FLOW_COOKIE,path='/auth')
            return response

    def guard(self, request):
        user = self.identity(request)
        request.state.user = user
        if request.url.path == '/' and not user:
            return FileResponse(ROOT/'app'/'static'/'login.html')
        if request.url.path.startswith('/api/') and request.url.path != '/api/me':
            if not user:
                return JSONResponse({'detail':'회사 계정 로그인이 필요합니다.'},status_code=401)
            if request.method not in ('GET','HEAD','OPTIONS') and ROLE_OPERATOR not in user['roles']:
                return JSONResponse({'detail':'USB 운영자 권한이 필요합니다.'},status_code=403)
        return None
