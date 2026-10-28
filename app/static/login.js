'use strict';
fetch('/auth/status').then(r=>r.json()).then(s=>{
 document.querySelector('#tenant-id').textContent=s.tenant_id;
 const button=document.querySelector('#entra-login');
 const note=document.querySelector('#login-note');
 if(s.configured){button.removeAttribute('aria-disabled');note.textContent='등록된 회사 계정으로 로그인합니다. 조회와 운영 권한은 별도로 확인합니다.';}
 else {button.removeAttribute('href');note.textContent='테넌트 연결 구조 준비 완료 · Entra 앱 등록 및 역할 할당 대기';}
 const errors={configuration_pending:'앱 등록 설정이 아직 완료되지 않았습니다.',login_unavailable:'로그인을 시작하지 못했습니다. 연결 설정을 확인해 주세요.',invalid_flow:'로그인 요청이 만료되었거나 일치하지 않습니다. 다시 로그인해 주세요.',invalid_identity:'이 테넌트에서 발급한 유효한 로그인 정보를 확인하지 못했습니다.',role_required:'앱 사용 권한이 할당되지 않았습니다. 운영자에게 문의해 주세요.'};
 const error=new URLSearchParams(location.search).get('auth_error');
 document.querySelector('#login-error').textContent=errors[error]||'';
 if(error)history.replaceState(null,'','/');
}).catch(()=>{document.querySelector('#login-note').textContent='로컬 서버 연결을 확인해 주세요.';});
