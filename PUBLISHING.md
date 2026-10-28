# GitHub 게시 준비

이 폴더만 저장소로 사용합니다. 원래 운영 폴더나 상위 디렉터리를 통째로 올리지 않습니다.
GitHub 소스 게시와 Azure 실제 배포는 별개입니다. 이 저장소의 워크플로는 Azure에 배포하지 않습니다.

1. `python scripts/check-release.py`와 `python -m pytest -q`를 실행합니다.
2. `python scripts/build-packages.py`로 별도 ZIP을 확인합니다.
3. 게시할 계정·저장소 이름·공개 범위를 선택한 뒤 이 폴더에서만 Git을 초기화합니다.
4. GitHub Actions는 테스트·패키징만 수행합니다. 자동 배포나 예약 실행은 포함하지 않습니다.

비밀값·실제 환경 구성·DB·증적·로그·ZIP·.venv는 Git 제외 대상입니다.
requirements와 테스트 fixture는 포함됩니다. 가상 sample_data는 고객사 데이터가 아닙니다.
저장소 공개 여부는 코드 사용 범위와 조직 방침에 맞춰 별도로 정합니다.
고객사 설정을 추가한 뒤에는 이전 검사 결과를 재사용하지 말고 다시 검사해야 합니다.
