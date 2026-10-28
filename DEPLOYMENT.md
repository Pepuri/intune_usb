# 배포 설정

## 구성

App Service → Entra 위임 토큰 → 별도 Function → Lakehouse Files 요청 → Fabric 노트북 → Intune 정책·결과 Files.
App Service와 Function은 별도 Azure 리소스이며 공통 Python 코드는 두 패키지에 포함합니다.
Function에서 정책을 예약 처리하지 않습니다. Azure 모드의 Function 타이머는 no-op이며 Fabric이 처리합니다.

## 설정 순서

1. `deploy/web.settings.example.json`과 `deploy/function.settings.example.json`을 각 서비스에 별도로 구성합니다.
2. 웹/API Entra 앱 등록을 분리하고 API v2 토큰, USB.Access 위임 scope, Reader/Operator 역할·동의를 설정합니다.
3. 웹 HTTPS callback·Function origin·신뢰 프록시 CIDR을 고정하고 관리 ID에 최소 OneLake/Key Vault 권한을 부여합니다.
4. 비밀값은 Key Vault에 보관합니다. 웹의 세션 암호화 키와 Function/노트북 요청 서명 키는 분리합니다.
5. `config/read-sources.json`, `config/sample-tenant-resources.json` 및 제한된 샘플 정책 상수는 **가상 fixture**입니다.
   실제 배포 환경용 구성은 고객사별 비공개 설정에서 주입하고, 변경된 ID와 쓰기 allowlist 일치 여부를 검증해야 합니다.
   소스에 실값을 넣어 커밋하지 마세요. 현재 자동 환경 구성 주입 도구는 제공하지 않습니다.
6. `python scripts/build-packages.py`로 별도 패키지를 빌드합니다. Windows 가상환경은 배포하지 않습니다.
7. App Service 시작 명령은 `deploy/plan.json`에 있습니다. 웹 패키지의 requirements.txt를 Linux 원격 빌드로 설치합니다.
8. Function 패키지는 host.json·function_app.py·requirements.txt를 루트에 둡니다. Python 3.12 Linux 빌드를 사용합니다.
   Consumption/Premium/Dedicated의 원격 빌드와 Flex Consumption 배포 방식은 다르므로 선택한 호스팅 요금제에 맞게 설정합니다.
9. Fabric 전용 Environment에 requirements-fabric.txt 의존성을 준비하고 기본 Lakehouse를 노트북에 연결합니다.
   fabric-worker.zip을 Files/usb-operations/code/source.zip에 업로드한 뒤 노트북 매개변수·Key Vault를 설정합니다.
10. 쓰기 OFF 상태에서 실제 HTTPS SSO·원격 API·파일 접수·노트북 처리·결과 조회를 검증합니다.
11. 대상 정책과 빈 테스트 PC 그룹을 검증한 뒤 제한된 쓰기를 켜고 반영·회수·만료를 검증합니다.
12. 한국시간 매일 08:00·13:00·18:00 예약, 동시 실행 1개를 설정하고 첫 자연 실행 이력을 확인합니다.

## 저장소와 운영 경계

Files/usb-operations 아래 requests/, state/ledger.json, state/auth.json, results/를 사용합니다.
공유 세션의 토큰은 암호화하며 auth 파일은 분석 테이블에 내보내지 않습니다.
Blob lease·ETag·처리 영수증으로 중복 실행과 결과 복구를 처리합니다.
상태 JSON 32MiB, 요청 조회 2000파일 제한이 있으므로 보관·분할을 설계해야 합니다.
요청 처리 기한은 24시간입니다. 주말 포함 매일 실행하고 실패 시 기한 내 재시도해야 합니다.
정책 반영 완료는 PC에서 USB 동작이 적용됐다는 뜻이 아닙니다.

## 아직 검증이 필요한 항목

고객사별 실제 HTTPS SSO, 배포된 Function 인증, 관리 ID 권한, Linux 빌드, Fabric 자연 예약 실행, 실제 단말 적용.
이 저장소의 테스트는 가상 fixture와 모의 API를 사용합니다. 로컬 Azurite 테스트는 실제 OneLake 테스트와 구분합니다.
별도 개발 환경에서 수행한 수동 Fabric 검증의 리소스 주소·사용자·증적은 이 저장소에 포함하지 않습니다.

공식 배포 문서:
- https://learn.microsoft.com/en-us/azure/azure-functions/python-build-options
- https://learn.microsoft.com/en-us/azure/azure-functions/deployment-zip-push
- https://learn.microsoft.com/en-us/azure/developer/python/python-web-app-github-actions-app-service

## Function 시작 진단

외부 저장소나 인증 설정 때문에 초기화가 실패하면 API는 업무 요청을 모두 503으로 차단합니다.
호스트는 진단을 위해 인덱싱할 수 있도록 유지하며 health의 initialization_failed는 정상 준비 상태가 아닙니다.
시작 로그에는 예외 유형·HTTP 상태·검증된 오류 코드만 기록하고 SDK 예외 본문과 자격증명은 기록하지 않습니다.
Function의 관리 ID에는 앱 Files 폴더에 대한 ReadWrite와 필요한 메타데이터 접근만 부여합니다.
실제 테넌트·앱·OneLake ID와 요청 서명 키는 Azure의 비공개 설정에서 관리하며 저장소에 넣지 않습니다.

## App Service 실제 로그인 검증

2026-10-29: App Service 화면과 별도 웹 전용 Entra 앱을 연결해 실제 운영자 로그인과 위임 토큰 기반 Function 원장 조회를 확인했습니다.
기존 로컬 앱 등록은 유지합니다. 웹 전용 앱에는 Graph 애플리케이션 권한을 추가하지 않고 USB.Access 위임 scope와 운영자 역할을 사용합니다.
공유 세션은 Lakehouse auth.json에 암호문으로 저장하며 재시작 뒤에도 유지됐습니다. 웹 관리 ID는 이 파일의 ReadWrite와 필요한 메타데이터 접근만 가집니다.
App Service의 TLS 종료 뒤 프로토콜은 신뢰 프록시의 x-appservice-proto 또는 X-Forwarded-Proto로 확인합니다. 실제 관측한 내부 프록시 IP만 비공개 설정에 지정합니다.
HTTPS 리다이렉트, Secure·HttpOnly·SameSite=Lax 쿠키, HSTS, 미인증 API의 401을 확인했습니다.
실제 환경 식별자·클라이언트 비밀값·세션 암호화 키는 GitHub에 넣지 않습니다.
현재 Azure 원장은 신규 0건입니다. 기존 샘플 이관과 Graph 조회 소스·샘플 정책 대상의 운영 설정, Fabric 예약 처리는 별도 검증해야 합니다.

TLS 전달 헤더: https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings

## 비공개 업무 대상 설정

Function의 USB_SAMPLE_DIRECTORY_JSON에는 고객사별 샘플 사용자 40명·테넌트·그룹·지정 정책 메타데이터 JSON을 넣고, USB_READ_SOURCES_JSON에는 조회 소스 메타데이터 JSON을 넣습니다. 실제 값은 소스 파일 대신 Azure 비공개 설정에서 관리합니다.
환경 설정이 없으면 config/의 가상 fixture를 사용하므로 실제 로그인 테넌트와 다를 경우 업무 메뉴는 configuration_required(503)를 반환합니다. 설정 JSON의 대상 이외 그룹·정책 경로와 다른 테넌트는 계속 거부합니다.
설정값은 프로세스 시작 시 대상 allowlist에 반영되므로 변경 후 재시작이 필요합니다. 예약 노트북도 같은 비공개 메타데이터를 환경에 전달한 후 업무 모듈을 로드해야 합니다.
이 설정은 Graph 권한을 부여하지 않습니다. 권한 부족·연결 실패는 화면에 별도 상태로 표시하며 성공으로 처리하지 않습니다. 정책 쓰기 기본 OFF와 빈 PC 그룹 보호 조건은 유지합니다.
