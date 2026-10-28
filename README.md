# USB Control

App Service 화면·Entra SSO, 별도 Azure Function API, Fabric Lakehouse Files와 예약 노트북으로 구성한 USB 승인 원장 프로토타입입니다.
하나의 저장소에서 서비스별 패키지를 따로 빌드합니다. GitHub에 올리는 것만으로 Azure에 배포되지는 않습니다.

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
`validate.yml`은 검사·패키징을 수행하고, `main_intuneusbfunction.yml`은 별도 Function 패키지를 Flex Consumption으로 배포합니다. App Service는 별도 배포 대상입니다.

이 폴더에는 실제 고객사 테넌트·계정·리소스 식별자, 비밀 설정, 실행 증적을 포함하지 않습니다.
fixture의 ID는 실존 리소스를 가리키지 않으며 예제 이름도 모두 가상입니다.
모든 정책 쓰기는 기본 OFF입니다. 현재 정책 작성기는 비활성 샘플 사용자 40명·지정 정책 1개·빈 PC 그룹을 전제로 제한됩니다.
일반 고객사 운영 정책으로 확대하려면 대상 설정과 보호 조건을 별도로 검토해야 합니다.
설정 순서와 검증 범위는 [DEPLOYMENT.md](DEPLOYMENT.md), 게시 절차는 [PUBLISHING.md](PUBLISHING.md)를 참고하세요.

## 현재 배포 상태

2026-10-28: Function을 Python 3.12 Flex Consumption에 배포했습니다. 실제 HTTPS health 200과 미인증·사용자 헤더 위조·잘못된 Bearer 요청의 401을 확인했습니다.
App Service 화면 배포·실제 원격 SSO와 Fabric 자연 예약 실행은 별도 작업입니다. Intune 정책 쓰기는 비활성 상태입니다.
