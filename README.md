# AWS CloudTrail Logs for Threat Hunting

## 개요

이 프로젝트는 MITRE ATT&CK for Cloud 프레임워크를 기반으로 AWS CloudTrail 로그를 생성하는 도구입니다. 보안 전문가와 연구원들이 위협 탐지 및 머신러닝 모델 학습에 사용할 수 있는 악의적인 활동 패턴이 포함된 CloudTrail 로그를 생성합니다.

## 주요 기능

- **MITRE ATT&CK 매핑**: 모든 생성된 이벤트는 MITRE ATT&CK for Cloud 기법에 매핑됨
- **다양한 공격 시나리오**: 초기 접근부터 영향까지 전체 공격 체인을 포함
- **현실적인 로그 생성**: 실제 AWS 환경에서 발생하는 것과 유사한 로그 구조
- **ML 학습 데이터**: 머신러닝 기반 위협 탐지 모델 학습에 적합

## 파일 구조

```
aws-cloudtrail-logs-for-threathunting/
├── generate_cloudtrail_logs_for_threathunting.py  # 메인 로그 생성 스크립트
├── logs/
│   └── aws-cloudtrail-logs-based-on-mitre-attack-cloud.log  # 생성된 로그 파일
└── usecase/
    └── usecase-cloudtrail  # 상세 유즈케이스 문서
```

## 지원되는 공격 시나리오

### 1. 초기 접근 (Initial Access)
- **1.1 침해된 IAM 사용자 자격 증명** (T1078.004)
  - 무차별 대입 로그인 시도
  - 의심스러운 IP에서의 성공적인 로그인
  - 비정상적인 시간대의 API 호출
  
- **1.2 비정상적인 지리적 위치에서의 접근** (T1078.004)
  - Tor 출구 노드 및 VPN IP 탐지
  - 고위험 국가에서의 접근
  
- **1.3 노출된 EKS 클러스터 API 엔드포인트** (T1190)
  - 퍼블릭 엔드포인트 활성화
  - 과도하게 허용적인 CIDR 설정

### 2. 권한 유지 (Persistence)
- **2.1 백도어용 새 IAM 사용자 생성** (T1098)
  - 의심스러운 명명 패턴의 사용자
  - 관리자 권한 부여
  
- **2.2 IAM 역할 신뢰 정책 수정** (T1098)
  - 외부 AWS 계정 추가
  
- **2.3 저속 주기적 접근** (T1078)
  - 자동화된 주기적 접근 패턴
  - 정찰 활동

### 3. 권한 상승 (Privilege Escalation)
- **3.1 잘못 구성된 IAM 정책 악용** (T1068)
  - 정책 버전 생성 및 권한 상승
  
- **3.2 STS를 통한 악의적인 역할 가정** (T1556.001)
  - 높은 권한 역할로의 전환
  
- **3.3 크로스 계정 접근** (T1078.004)
  - 신뢰 관계를 통한 외부 계정 접근
  
- **3.4 AssumeRole 체인 공격** (T1556.001)
  - 다단계 역할 가정을 통한 추적 회피

### 4. 방어 회피 (Defense Evasion)
- **4.1 보안 로그 비활성화/삭제** (T1562.001)
  - CloudTrail 중지 및 삭제
  - S3 버킷 리다이렉션
  
- **4.2 보안 서비스 비활성화** (T1562.001)
  - GuardDuty 탐지기 삭제
  - Security Hub 비활성화
  
- **4.3 익명화 서비스 사용** (T1090.003)
  - Tor 및 VPN을 통한 접근

### 5. 자격 증명 접근 (Credential Access)
- **5.1 Secrets Manager 접근** (T1552.005)
  - 대량 시크릿 조회
  
- **5.2 인스턴스 메타데이터 악용** (T1552.005)
  - IMDSv1을 통한 자격 증명 탈취
  - 외부 IP에서의 인스턴스 자격 증명 사용
  
- **5.3 STS 단기 액세스 키 악용** (T1078.004)
  - ASIA 키를 사용한 의심스러운 활동

### 6. 탐지 (Discovery)
- **6.1 AWS 인프라 정찰** (T1580)
  - 대량의 List/Describe API 호출
  - 버스트 정찰 활동

### 7. 수집 (Collection)
- **7.1 데이터 도난을 위한 스냅샷 생성** (T1213)
  - RDS/EBS 스냅샷 생성
  - 외부 계정과 공유
  
- **7.2 RDS 스냅샷 공개 노출** (T1213)
  - 퍼블릭 액세스 권한 부여

### 8. 유출 (Exfiltration)
- **8.1 S3 버킷 공개 설정** (T1537)
  - 버킷 정책/ACL 수정
  
- **8.2 EC2를 통한 데이터 유출** (T1041)
  - 비정상적인 리전에서 인스턴스 시작
  - 허용적인 보안 그룹 규칙
  
- **8.3 대량 S3 다운로드** (T1048)
  - 대규모 GetObject 이벤트
  - 외부 IP로의 전송

### 9. 영향 (Impact)
- **9.1 크립토재킹** (T1496)
  - GPU 인스턴스 대량 실행
  - 마이닝 풀 포트 개방
  
- **9.2 파괴적 활동** (T1485)
  - 리소스 대량 삭제
  - 업무 시간 외 활동

## 사용법

```bash
# CloudTrail 로그 생성
python generate_cloudtrail_logs_for_threathunting.py
```

생성된 로그는 `aws-cloudtrail-logs-based-on-mitre-attack-cloud.log` 파일에 저장됩니다.

## 로그 구조

각 로그 이벤트는 다음과 같은 구조를 가집니다:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {...},
  "eventTime": "2024-01-15T10:30:45Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "192.168.1.100",
  "tags": {
    "usecase": "Create New IAM User for Backdoor Access",
    "description": "Creating backdoor user",
    "technique_id": "T1098"
  }
}
```

## 활용 방법

1. **위협 탐지 규칙 개발**: 각 유즈케이스의 패턴을 기반으로 SIEM 규칙 작성
2. **머신러닝 모델 학습**: 정상/악의적 활동 분류 모델 학습
3. **보안 교육**: 실제 공격 시나리오 이해 및 대응 훈련
4. **보안 테스트**: 기존 보안 도구의 탐지 능력 평가

## 주의사항

- 이 도구는 교육 및 연구 목적으로만 사용해야 합니다
- 생성된 로그는 모의 데이터이며 실제 AWS 환경에서 발생한 것이 아닙니다
- 실제 운영 환경에서는 사용하지 마십시오

## 기여

이 프로젝트에 기여하고 싶으시다면:
1. 새로운 공격 시나리오 제안
2. 기존 시나리오 개선
3. 버그 리포트 및 수정

## 라이선스

이 프로젝트는 교육 및 연구 목적으로 제공됩니다. 상업적 사용 시 별도 문의가 필요합니다.

## 참고 자료

- [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)