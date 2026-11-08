# USB Control

App Service 화면·Entra SSO, 별도 Azure Function API, Fabric Lakehouse Files와 예약 노트북으로 구성한 USB 승인 원장 프로토타입입니다.
하나의 저장소에서 서비스별 패키지를 따로 빌드합니다. main 브랜치의 서비스 코드 변경은 GitHub Actions로 App Service와 Function에 각각 배포합니다.

| 경로 | 역할 |
|---|---|
| app/ | App Service 화면·SSO·공유 세션 |
| usb_functions/ 및 function_app.py | Function API·요청 접수·조회·공통 업무 코드 |
| notebooks/ | Fabric 처리·정책 동기화 템플릿 |
| deploy/ | 서비스별 설정 예시와 처리 일정 |
| config/ 및 sample_data/ | 가상 환경 ID와 가상 데이터만 포함한 테스트 fixture |

## 로컬 실행

Python 3.12 가상환경에 `pip install -r requirements-dev.txt`로 의존성을 설치합니다.
`run-stack.ps1 -Demo`는 Azure Functions Core Tools와 Azurite가 별도로 필요합니다.
`python -m pytest -q`로 모의 테스트를 실행할 수 있습니다. 실제 테넌트에 연결하지 않습니다.

## 게시·배포 준비

`python scripts/check-release.py`로 검사하고 `python scripts/build-packages.py`로 빌드합니다.
App Service는 `dist/web.zip`, Function은 `dist/function.zip`을 각각 사용합니다.
Fabric의 `code/source.zip`에는 `dist/fabric-worker.zip`을 사용합니다.
이 ZIP은 소스 패키지입니다. Python 3.12 Linux에서 의존성 설치·원격 빌드가 추가로 필요합니다.
`validate.yml`은 검사·패키징을 수행하고, `main_intuneusbfunction.yml`은 별도 Function 패키지를 Flex Consumption으로 배포합니다. App Service 배포는 `deploy-web.yml`로 분리합니다.

이 폴더에는 실제 고객사 테넌트·계정·리소스 식별자, 비밀 설정, 실행 증적을 포함하지 않습니다.
fixture의 ID는 실존 리소스를 가리키지 않으며 예제 이름도 모두 가상입니다.
모든 정책 쓰기는 기본 OFF입니다. 기존 정책 게시 경로는 비활성 샘플 사용자 40명·지정 정책 1개·빈 PC 그룹을 전제로 제한됩니다.
일반 고객사 운영 정책으로 확대하려면 대상 설정과 보호 조건을 별도로 검토해야 합니다.
설정 순서와 검증 범위는 [DEPLOYMENT.md](DEPLOYMENT.md), 게시 절차는 [PUBLISHING.md](PUBLISHING.md)를 참고하세요.

## 현재 배포 상태

2026-10-28: Function을 Python 3.12 Flex Consumption에 배포했습니다. 실제 HTTPS health 200과 미인증·사용자 헤더 위조·잘못된 Bearer 요청의 401을 확인했습니다.
2026-10-29: 별도 App Service에 화면을 배포하고 실제 Entra 운영자 로그인 → 원격 Function 원장 조회를 확인했습니다. App Service 재시작 후에도 암호화 공유 세션이 유지됩니다.
새 Azure 원장은 0건이며 기존 샘플 이관과 업무 소스·정책 대상 환경 설정, Fabric 자연 예약 실행은 별도 작업입니다. Intune 정책 쓰기는 비활성 상태입니다.


## USB·MTP 페어링 원장 연결

2026-11-08: 등록 화면과 기존 승인 원장을 USB·MTP XML 미리보기에 연결했습니다.
사용자 Object ID와 USB 시리얼 또는 MTP 전체 InstancePathId를 조합하고,
PC 그룹 1개·정책 1개 안에 승인된 사용자–장치 조합만 생성합니다.
새 모드의 AccessMask는 63이며 BitLocker 조건은 사용하지 않습니다.
기존 읽기 전용 승인은 자동 전환하지 않습니다.

App Service의 기존 SSO와 Function 인증·파일 접수 구조는 유지합니다.
Fabric 노트북은 접수·검증·연장·회수 및 새 페어링의 만료 상태만 처리하고
Intune 정책과 그룹은 변경하지 않습니다. 예약은 08:00·13:00·18:00 KST입니다.
`USB_PAIRING_PREVIEW_ENABLED=1`과 네 개 쓰기 플래그 OFF가 함께 필요합니다.
현재 식별 검증은 수동 가정이며 실제 사용자·USB 확인이나 단말 적용 증거가 아닙니다.
노트북은 `code/lookup-worker.zip`의 검증된 해시를 고정해 사용합니다.

자세한 동작과 로컬 재현은 [USB_MTP_LOCAL_PREVIEW.md](USB_MTP_LOCAL_PREVIEW.md),
Azure 설정은 [DEPLOYMENT.md](DEPLOYMENT.md)를 참고하세요.
