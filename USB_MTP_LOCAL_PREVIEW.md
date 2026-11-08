# USB·MTP 페어링 — PPT 로직 로컬 구현

PC 할당 그룹 1개와 Intune Custom 정책 1개를 사용하는 후보를 생성합니다.
현재 구현은 로컬 검증 전용이며 그룹·정책을 새로 만들거나 변경하지 않습니다.

## 변경된 설계

| 항목 | 기존 경로 | 새 로컬 경로 |
|---|---|---|
| 장치 | SAMPLE USB 시리얼 | USB 시리얼 / MTP 전체 InstancePathId |
| 권한 | 읽기 9 / 쓰기 18 | 페어링 허용 63: 디스크·파일 읽기/쓰기/실행 비트 전체 |
| 암호화 | 쓰기에 BitLocker 필요 | 암호화 조건 없음 |
| 사용자 | 40명 샘플 매핑 | 사용자 Entra Object ID를 Sid로 명시 |
| 기본 설정 | 별도 기본 차단 전제 | 활성화 1, 기본 차단 2, RemovableMediaDevices\|WpdDevices 포함 |
| 저장 | 기존 approvals | 같은 approvals에 policy_mode=usb_mtp_pairing으로 구분 (기존 승인 자동 승격 없음) |
| 게시 | 환경 설정으로 제어 | 게시 API 항상 403, Graph 클라이언트 없음 |

하나의 정책 내부에 장치별 GroupData와 RuleData를 생성합니다. 장치 그룹은
PrimaryId와 정확한 SerialNumberId 또는 InstancePathId를 MatchAll로 묶습니다.
해당 장치를 승인받은 사용자만 Rule의 Sid로 열거합니다. 각 사용자 Entry에는
Allow/Options=0과 AuditAllowed/Options=2, AccessMask=63을 생성합니다.
두 장치의 사용자 집합을 합쳐 교차 권한을 만들지 않습니다.

전체 대상 PC에는 같은 후보 정책이 전달되는 설계이며, PC에서 사용자와 장치가
일치하는 Entry만 적용됩니다. 대상은 **PC 그룹**입니다. 별도의 사용자 할당 그룹은
만들지 않습니다. Object ID 입력 및 모의 식별 검증은 수동 가정이며 실제 조회 결과가 아닙니다.

## 실행

운영 폴더에서 다음 명령을 실행한 뒤 http://localhost:8877/#register 에 접속합니다.

```powershell
.\.venv\Scripts\python.exe scripts\run-pairing-preview.py
```

기존 SSO 설정 파일을 읽거나 수정하지 않고 별도 데모 인증과
`.data/ppt-pairing-preview.sqlite3`를 사용합니다. 실제 Entra 로그인은 재검증하지 않았습니다.
동일 화면은 기존 로컬 Function 스택에도 통합되어 있으므로 해당 스택을 재시작하면
기존 로그인 상태로 새 메뉴를 사용할 수 있습니다.

등록 → 원장 상세의 모의 식별 검증 → 페어링 정책 메뉴의 XML 후보 확인 → 연장·회수 →
만료 검사까지 기존 화면과 API로 처리합니다. 페어링 정책 화면은 approvals를 직접 읽으며
두 번째 원장에 복사하지 않습니다. 모의 식별 검증 이전에는 XML에서 제외됩니다.
동일 사용자 Object ID·장치 종류·식별값의 기간 중복 등록, 오래된 revision의 변경 요청,
동일 요청 ID의 다른 내용 재사용을 차단합니다. 신규 페어링은 기존 모의 게시 큐와
기존 Intune 게시 컴파일러에서도 제외합니다.

정책 XML은 매번 현재 원장을 기준으로 생성하므로 만료 검사 실행 전이라도 기간이 지난
페어링은 포함되지 않습니다. 로컬 만료 검사는 원장 상태와 변경 이력도 갱신합니다.
신규 페어링의 회수·만료는 미게시 상태로 남으며 실제 단말 적용 확인으로 기록할 수 없습니다.
브라우저 종료 후에도 SQLite 원장과 이력은 보존됩니다.

검증용 서버의 기준일은 시작 시 한국 날짜로 정합니다. 시간 경과 재현은
`--reference-date 2026-11-11`처럼 명시해 재시작할 수 있습니다. 고정된 검증 기준일이며
실제 클라우드 예약 실행 또는 자연적인 날짜 경과를 검증했다는 의미는 아닙니다.
Windows의 실제 식별 경로와 지원 버전 확인은 별도입니다.

이전 독립 실험 화면 `/#pairinglab`과 `ppt_pairings` 데이터는 보존하지만 기본 메뉴에서는
사용하지 않으며, 기존 등록 화면을 통한 데이터와 혼합하지 않습니다.

OMA 설정은 기본 3개 + 서로 다른 장치 수×2개입니다. 최대 1000개 설정을 넘으면 거부하며,
XML별 64KiB는 기존 코드의 보수적 로컬 제한입니다. 이는 레지스트리나 Microsoft의 XML 한도라고
주장하는 값이 아닙니다. 장치 498개는 다른 설정이 없을 때의 설정 개수 기준 상한일 뿐입니다.

## 미수행 범위

Azure/Fabric/GitHub 변경, 실제 정책 PATCH, 레지스트리 변경, 실제 PC USB/MTP 동작 검증은
하지 않습니다. Fabric 정기 작업이나 기존 읽기 전용 승인 행의 전환도 수행하지 않습니다.
이 후보를 실제 정기 처리에 연결하려면 별도 배포 검증이 필요합니다.

공식 스키마: [Defender CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp),
[Device Control policies](https://learn.microsoft.com/defender-endpoint/device-control-policies).


## Azure 연결

같은 등록·원장·XML 미리보기를 Azure에서도 쓰기 OFF 상태로 사용할 수 있도록 연결했습니다.
Azure에서는 등록·변경을 즉시 로컬 SQLite에 저장하지 않고 기존 Function → Lakehouse 파일 →
Fabric 예약 노트북 → 공유 원장 구조로 처리합니다. 신규 페어링 행만 변경·만료 처리하며,
기존 일반 승인 행과 원본 샘플 테이블은 유지합니다. 자세한 설정은 DEPLOYMENT.md를 참조하세요.
