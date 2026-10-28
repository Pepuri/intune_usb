"""Loopback-only UI→Function trust boundary, not an Entra token substitute in Azure."""
import hashlib
import secrets
import time
from urllib.parse import urlparse

import jwt
from fastapi.responses import JSONResponse
from app.auth import actor, ROLE_OPERATOR, ROLE_READER


def sign_request(key, user, method, target, body):
    if len(key) < 48:
        raise ValueError('Local Function bridge key is missing or too short')
    issued = int(time.time())
    return jwt.encode({'iss':'usb-local-ui','aud':'usb-local-functions','iat':issued,'exp':issued+60,
                       'jti':secrets.token_urlsafe(24),'method':method,'target':target,
                       'body_sha256':hashlib.sha256(body).hexdigest(),'user':user},key,algorithm='HS256')


def loopback_url(value):
    url=urlparse(value)
    if url.scheme != 'http' or url.hostname not in ('localhost','127.0.0.1') or url.username or url.password or url.path not in ('','/') or url.query or url.fragment:
        raise ValueError('Function endpoint must be a loopback HTTP origin')
    return value.rstrip('/')


def protect_backend(app, store, key, tenant_id, allow_demo=False):
    if len(key)<48:
        raise ValueError('A dedicated local Function bridge key is required')
    with store.connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS bridge_nonces (nonce TEXT PRIMARY KEY, expires INTEGER)')

    @app.middleware('http')
    async def signed_request(request, call_next):
        if request.url.path == '/health' and request.method=='GET':
            return JSONResponse({'service':'usb-functions','publisher':'mock','mode':'local-only'})
        try:
            token=request.headers.get('x-usb-assertion','')
            claims=jwt.decode(token,key,algorithms=['HS256'],audience='usb-local-functions',issuer='usb-local-ui',
                              options={'require':['exp','iat','jti','method','target','body_sha256','user']})
            body=await request.body()
            target=request.url.path+('?' + request.url.query if request.url.query else '')
            if claims['method']!=request.method or claims['target']!=target or claims['body_sha256']!=hashlib.sha256(body).hexdigest():
                raise ValueError('Request does not match signed assertion')
            user=claims['user']
            if user.get('source')=='entra':
                if user.get('tenant_id')!=tenant_id or not user.get('oid'):
                    raise ValueError('Invalid tenant identity')
            elif not (allow_demo and user.get('source')=='demo'):
                raise ValueError('Demo identities not permitted')
            if not user.get('username') or not ({ROLE_READER,ROLE_OPERATOR}&set(user.get('roles',[]))):
                raise ValueError('Application role required')
        except (jwt.PyJWTError,ValueError,KeyError,TypeError):
            return JSONResponse({'detail':'Function 요청 인증에 실패했습니다.'},status_code=401)
        if request.method not in ('GET','HEAD','OPTIONS'):
            if ROLE_OPERATOR not in user['roles']:
                return JSONResponse({'detail':'USB 운영자 권한이 필요합니다.'},status_code=403)
            with store.connect() as db:
                db.execute('DELETE FROM bridge_nonces WHERE expires < ?', (int(time.time()),))
                try:
                    db.execute('INSERT INTO bridge_nonces VALUES (?,?)',(claims['jti'],claims['exp']))
                except Exception:
                    return JSONResponse({'detail':'이미 사용한 Function 요청입니다.'},status_code=409)
        request.state.user=user
        context=actor.set(user['username'])
        try:
            response=await call_next(request)
        finally:
            actor.reset(context)
        response.headers['X-USB-Worker']='azure-functions-local'
        response.headers['Cache-Control']='no-store'
        return response
