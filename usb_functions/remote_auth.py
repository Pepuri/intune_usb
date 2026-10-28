"""Validate delegated Entra v2 access tokens for this API, never UI-supplied identities."""
import os
from uuid import UUID
import jwt
from fastapi.responses import JSONResponse
from app.auth import actor, ROLE_READER, ROLE_OPERATOR


class EntraAPI:
    def __init__(self, tenant_id, audience, web_client_id, key_client=None):
        self.tenant_id = str(UUID(tenant_id))
        self.audience = str(UUID(audience))
        self.web_client_id = str(UUID(web_client_id))
        if self.audience == self.web_client_id:
            raise ValueError('Use separate web and Function API app registrations')
        self.issuer = f'https://login.microsoftonline.com/{self.tenant_id}/v2.0'
        self.keys = key_client or jwt.PyJWKClient(
            f'https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys',
            cache_jwk_set=True, lifespan=3600, timeout=10)

    @classmethod
    def from_env(cls):
        return cls(os.environ['ENTRA_TENANT_ID'], os.environ['USB_FUNCTION_AUDIENCE'],
                   os.environ['USB_WEB_CLIENT_ID'])

    def validate(self, token):
        key = self.keys.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=['RS256'], audience=self.audience, issuer=self.issuer,
                            options={'require':['exp','iat','nbf','iss','aud','tid','oid','azp','scp','ver']})
        if (claims['tid'] != self.tenant_id or claims['ver'] != '2.0'
            or claims['azp'] != self.web_client_id or claims.get('idtyp') == 'app'
            or 'USB.Access' not in claims['scp'].split()):
            raise ValueError('Invalid delegated API actor or scope')
        UUID(claims['oid'])
        roles = sorted(set(claims.get('roles', [])) & {ROLE_READER, ROLE_OPERATOR})
        if not roles:
            raise PermissionError('API application role required')
        return {'source':'entra','tenant_id':self.tenant_id,'oid':claims['oid'], 'roles':roles,
                'username':claims.get('preferred_username') or claims['oid'],
                'name':claims.get('name','회사 계정')}


def protect_remote(app, validator):
    @app.middleware('http')
    async def authenticate(request, call_next):
        if request.url.path == '/health' and request.method == 'GET':
            return JSONResponse({'service':'usb-functions','mode':'azure','policy_writes':'explicit-opt-in-only'})
        authorization = request.headers.get('authorization','')
        try:
            if not authorization.startswith('Bearer ') or len(authorization) > 20000:
                raise ValueError('Bearer token required')
            user = validator.validate(authorization[7:])
        except PermissionError:
            return JSONResponse({'detail':'Function 앱 역할이 필요합니다.'},status_code=403)
        except (jwt.PyJWTError, ValueError, KeyError, TypeError, AttributeError):
            return JSONResponse({'detail':'Function Entra 인증에 실패했습니다.'},status_code=401)
        if request.method not in ('GET','HEAD','OPTIONS') and ROLE_OPERATOR not in user['roles']:
            return JSONResponse({'detail':'USB 운영자 권한이 필요합니다.'},status_code=403)
        request.state.user = user
        context = actor.set(user['username'])
        try:
            response = await call_next(request)
        finally:
            actor.reset(context)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-USB-Worker'] = 'azure-functions-entra'
        return response
