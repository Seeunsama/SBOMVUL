# SBOMVUL
SBOM 기반 오픈소스 취약점 분석 파이프라인 + 웹 대시보드 (OSV.dev + NVD)
<img width="1884" height="865" alt="image" src="https://github.com/user-attachments/assets/b4e24cba-b6e5-439a-ac8c-a2befed1707a" />


---

## [1] About the Project

### Why SBOMVUL?
SBOM(Software Bill of Materials)은 프로젝트에 포함된 오픈소스 구성요소를 **패키지 단위(PURL)** 로 표현합니다.  
하지만 취약점 데이터 소스는 **패키지 중심(OSV)**, **CVE/벤더 중심(NVD)** 등 구조가 달라서,
실무에서는 “SBOM → 취약점” 매핑이 한 번에 잘 되지 않는 문제가 있습니다.

SBOMVUL은 다음 흐름을 하나로 묶어 **자동화 + 시각화**합니다.

- 컨테이너 안에서 SBOM 자동 생성(cdxgen)
- OSV.dev로 패키지 기반 취약점 조회
- NVD JSON Feed로 CVE/CVSS 점수 보강(enrichment)
- 결과를 정적 웹 대시보드로 확인(localhost)

---

### Features
- **Automatic SBOM generation**
  - `cdxgen`으로 CycloneDX SBOM(JSON) 생성
- **OSV.dev + NVD integration**
  - OSV: 패키지 기반 취약점 탐지
  - NVD: CVE/CVSS 점수/메타데이터 보강
- **Interactive vulnerability dashboard**
  - Severity 통계(critical/high/medium/low)
  - Score 기준 정렬
  - 텍스트/심각도 필터링
- **Fully containerized pipeline**
  - 실행 환경 고정(재현 가능)
  - 로컬에서 바로 실행 가능

---

### Technologies
- **SBOM**
  - CycloneDX
  - cdxgen
- **Data Sources**
  - OSV.dev API
  - NVD official JSON feed
- **Pipeline**
  - Python 3
  - pandas / requests
- **Web Dashboard**
  - Static HTML/CSS/JS (Tooplate “Nexus Brew” 기반 커스텀)

---

## [2] Getting Started

SBOMVUL은 **Docker 컨테이너 내부에서 파이프라인 스크립트 3개 실행 → 로컬호스트에서 대시보드 확인** 방식입니다.

### Prerequisites
- Docker (Desktop) 설치

---

### Run with Docker Image

#### 1) Pull image

~~~bash
docker pull seeuni/sbomvul:latest
~~~

#### 2) Run container (port 8080 exposed)
~~~bash
docker run -it --rm -p 8080:8080 --name sbomvul seeuni/sbomvul:latest /bin/bash
~~~

**(자주 나는 문제) 포트 8080 충돌**
- 이미 8080을 다른 컨테이너/프로세스가 쓰는 경우, 호스트 포트를 바꿔서 실행합니다.

~~~bash
docker run -it --rm -p 8090:8080 --name sbomvul seeuni/sbomvul:latest /bin/bash
~~~

**(자주 나는 문제) 컨테이너 이름 충돌**
- `--name sbomvul`이 이미 존재하면 아래로 정리 후 재실행합니다.

~~~bash
docker ps -a | grep sbomvul
docker stop sbomvul
docker rm sbomvul
~~~

#### 3) Run pipeline scripts (inside container)
컨테이너 쉘에서 아래 3개를 순서대로 실행합니다.

~~~bash
cd /scable

python3 generate_sbom.py
python3 cve_data_update.py
python3 osv_nvd_enrich_sbom.py
~~~

- `generate_sbom.py`
  - 대상 GitHub 리포지토리를 기반으로 SBOM 생성
  - 결과 예시: `/scable/generated_sbom/*.json`
- `cve_data_update.py`
  - NVD JSON feed 로컬 캐시 업데이트
- `osv_nvd_enrich_sbom.py`
  - SBOM을 OSV + NVD로 enrichment
  - 실제 실행 로그 예시:
    - SBOM input: `/scable/generated_sbom/text-generation-webui-sbom.json`
    - Enriched output: `/scable/generated_sbom/sbom_data/*-with-vulns.json`
    - Web index update: `/scable/generated_sbom/sbomvul_web/sbom_index.json`

#### 4) Serve dashboard (inside container)
대시보드가 정적 웹이므로 파이썬 서버로 띄웁니다.

~~~bash
cd /scable/generated_sbom
python3 -m http.server 8080
~~~

#### 5) Open dashboard (host browser)
- 8080으로 실행한 경우:
  - `http://localhost:8080/sbomvul_web/index.html`
- 8090으로 실행한 경우:
  - `http://localhost:8090/sbomvul_web/index.html`

---

## [3] API Reference
SBOMVUL은 별도 서버 API가 아니라, **로컬 파이프라인 스크립트 + 정적 웹**으로 동작합니다.

### Scripts
- `generate_sbom.py`
  - 역할: SBOM 생성(cdxgen 실행 자동화)
  - 출력: `generated_sbom/` 하위에 SBOM JSON 생성
- `cve_data_update.py`
  - 역할: NVD 공식 JSON feed 다운로드/갱신
  - 출력: `nvd_data/` 등 로컬 캐시
- `osv_nvd_enrich_sbom.py`
  - 역할: OSV 조회 + NVD 데이터로 CVE/CVSS 보강 후 결과 JSON 생성 + 웹 인덱스 업데이트
  - 출력:
    - `generated_sbom/sbom_data/*-with-vulns.json`
    - `generated_sbom/sbomvul_web/sbom_index.json`

> 각 스크립트의 입력 파라미터(예: GitHub URL 입력 방식)는 현재 구현 기준으로 동작합니다.  
> (추가 옵션화/CLI 인자 지원은 향후 VISION에 포함)

---

## [4] Usage Screenshots


### Home
<img width="1875" height="861" alt="image" src="https://github.com/user-attachments/assets/54e952d6-9a98-4571-b0fa-5827590381dd" />

### Dashboard
<img width="1874" height="859" alt="image" src="https://github.com/user-attachments/assets/f48a796c-80de-4fb5-90ce-81a490ea791e" />


### Filtering / Sorting
- critical
<img width="1876" height="856" alt="image" src="https://github.com/user-attachments/assets/249a91d8-abba-44fc-be2c-6c473e7f3c27" />

- Sorting CVE-id
<img width="1873" height="856" alt="image" src="https://github.com/user-attachments/assets/2fa50928-e4cc-4fdd-b0a9-3df23e3f7046" />

### ABOUT
<img width="1875" height="859" alt="image" src="https://github.com/user-attachments/assets/6c2fb28b-7c5a-43e5-939b-40482b3dcad4" />
<img width="1877" height="856" alt="image" src="https://github.com/user-attachments/assets/9a0b5e15-daf1-46be-976c-1a26b4f61eea" />
<img width="1876" height="856" alt="image" src="https://github.com/user-attachments/assets/384d6534-3c0a-4929-8a18-a5acf1a75f6a" />



---

## [5] SBOMVUL's VISION
- **Shift-left security**
  - 빌드/배포 이전에 개발자가 SBOM 기반 취약점을 빠르게 확인하도록 지원
- **More accurate mapping**
  - 패키지 중심(OSV) + CVE/점수 중심(NVD)을 함께 사용해 매핑 품질 향상
- **Automation-friendly**
  - 컨테이너 기반 실행으로 재현성을 확보하고, CI 파이프라인 연결을 쉽게
- **Dashboard as a report**
  - “누가 봐도 이해 가능한” 형태로 취약점 현황을 시각화하여 공유/보고에 활용

---

## Credits
- 

## License
- 
