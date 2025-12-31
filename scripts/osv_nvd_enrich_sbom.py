import json
import requests
from packageurl import PackageURL
import concurrent.futures
import threading
import pandas as pd
import os
import shutil
import glob
import re
from datetime import datetime
from pathlib import Path

# === 경로 설정 ===
BASE_DIR = Path(__file__).resolve().parent
CSV_PATH = BASE_DIR / "cve_cvss3_data.csv"

SBOM_DIR = BASE_DIR / "generated_sbom"         # generate_sbom.py 결과 위치
DATA_DIR = SBOM_DIR / "sbom_data"              # enriched SBOM JSON 모아두는 폴더
WEB_DIR = SBOM_DIR / "sbomvul_web"            # 웹 대시보드(index.html) 폴더
INDEX_PATH = WEB_DIR / "sbom_index.json"       # SBOM 목록/인덱스 파일


def load_cve_csv():
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"CVE CSV not found: {CSV_PATH}")

    # pandas.read_csv 는 errors 인자를 받지 않으므로, open 쪽에서 처리
    with open(CSV_PATH, "r", encoding="utf-8", errors="replace") as f:
        df = pd.read_csv(f)

    if "CVE_ID" not in df.columns:
        raise ValueError("CVE CSV must contain 'CVE_ID' column.")
    return df.set_index("CVE_ID")


def clean_text(input_text: str) -> str:
    if not isinstance(input_text, str):
        return ""
    cleaned = re.sub(r"[^\x00-\x7F]+", " ", input_text)
    cleaned = re.sub(
        r"(?<!\()https?://[^\s]+",
        lambda m: f"({m.group()})",
        cleaned,
    )
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def query_osv(ecosystem: str, name: str, version: str | None, retries: int = 3):
    if not ecosystem or not name:
        return []

    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": name,
            "ecosystem": ecosystem,
        }
    }
    if version:
        payload["version"] = version

    for attempt in range(retries):
        try:
            resp = requests.post(url, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulns", [])
        except requests.exceptions.RequestException:
            if attempt == retries - 1:
                return []


def add_vulnerabilities_to_sbom(sbom_path: Path, cve_data: pd.DataFrame):
    """
    SBOM을 읽어서 OSV + NVD 기반 취약점만 추출해 리스트로 반환
    """
    with sbom_path.open("r", encoding="utf-8") as f:
        sbom = json.load(f)

    components = sbom.get("components", [])
    vulnerabilities_dict: dict[str, dict] = {}
    lock = threading.Lock()

    def process_component(component: dict):
        purl = component.get("purl")
        if not purl:
            return
        try:
            purl_obj = PackageURL.from_string(purl)
        except Exception:
            return

        eco = purl_obj.type
        name = f"{purl_obj.namespace}/{purl_obj.name}" if purl_obj.namespace else purl_obj.name
        version = purl_obj.version

        ecosystem_mapping = {
            "pypi": "PyPI",
            "maven": "Maven",
            "npm": "npm",
        }
        eco = ecosystem_mapping.get(eco, eco.capitalize())

        vulns = query_osv(eco, name, version)
        if not vulns:
            return

        for vuln in vulns:
            cve_id = next(
                (alias for alias in vuln.get("aliases", []) if alias.startswith("CVE")),
                None,
            )
            if not cve_id:
                continue

            with lock:
                if cve_id not in vulnerabilities_dict:
                    # NVD CSV 기반 CVSS 매핑
                    try:
                        cve_info = cve_data.loc[cve_id]
                    except KeyError:
                        ratings = []
                    else:
                        bs = cve_info.get("Base_Score")
                        sev = cve_info.get("Base_Severity")
                        ver = cve_info.get("CVSS_Version")
                        vec = cve_info.get("Vector_String")

                        if (
                            (sev == "N/A" or pd.isna(sev))
                            or (bs == "N/A" or pd.isna(bs))
                            or (ver == "N/A" or pd.isna(ver))
                            or (vec == "N/A" or pd.isna(vec))
                        ):
                            ratings = []
                        else:
                            cvss_version = str(ver).replace(".", "")
                            ratings = [
                                {
                                    "severity": str(sev).lower(),
                                    "score": float(bs),
                                    "method": f"CVSSv{cvss_version}",
                                    "vector": vec,
                                }
                            ]

                    published = vuln.get("published")
                    modified = vuln.get("modified")
                    cleaned_details = clean_text(vuln.get("details", ""))

                    vulnerabilities_dict[cve_id] = {
                        "id": cve_id,
                        "source": {
                            "name": "OSV-DEV",
                            "url": f"https://osv.dev/vulnerability/{vuln.get('id')}",
                        },
                        "description": cleaned_details,
                        "ratings": ratings,
                        "published": published,
                        "updated": modified,
                        "affects": [],
                    }

                vulnerabilities_dict[cve_id]["affects"].append(
                    {"ref": component.get("bom-ref")}
                )

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(process_component, components)

    # 🔥 SBOM 전체가 아니라 "취약점 리스트"만 반환
    return list(vulnerabilities_dict.values())


def main():
    cve_data = load_cve_csv()

    if not SBOM_DIR.exists():
        raise FileNotFoundError(f"SBOM directory not found: {SBOM_DIR}")

    # generated_sbom 안의 "*-sbom.json" 중에서 가장 최근 파일 사용
    sbom_candidates = sorted(
        SBOM_DIR.glob("*-sbom.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not sbom_candidates:
        raise FileNotFoundError(f"No *-sbom.json found in {SBOM_DIR}")

    sbom_path = sbom_candidates[0]
    print(f"[SBOM] using: {sbom_path}")

    # 취약점 리스트 생성
    vulns = add_vulnerabilities_to_sbom(sbom_path, cve_data)

    # 디렉터리 준비
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    WEB_DIR.mkdir(parents=True, exist_ok=True)

    # 프로젝트 이름 추출 (예: text-generation-webui-sbom -> text-generation-webui)
    project_name = sbom_path.stem
    if project_name.endswith("-sbom"):
        project_name = project_name[:-5]

    # 날짜 기반 파일명
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_filename = f"{project_name}-{date_str}-with-vulns.json"
    output_path = DATA_DIR / output_filename

    # enriched SBOM 저장 (취약점 리스트)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(vulns, f, indent=2, ensure_ascii=False)

    print(f"[SBOM] enriched SBOM saved: {output_path}")

    # === sbom_index.json 갱신 ===
    index_data = {"latest": output_filename, "items": []}
    if INDEX_PATH.exists():
        try:
            with INDEX_PATH.open("r", encoding="utf-8") as f:
                index_data = json.load(f)
        except json.JSONDecodeError:
            pass

    items = index_data.get("items", [])

    item_id = f"{project_name}-{date_str}"
    label = project_name  


    # 같은 id 있으면 교체
    items = [it for it in items if it.get("id") != item_id]
    items.append(
        {
            "id": item_id,
            "label": label,
            "file": output_filename,
        }
    )

    index_data["items"] = items
    index_data["latest"] = output_filename

    with INDEX_PATH.open("w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2, ensure_ascii=False)

    print(f"[SBOM] index updated: {INDEX_PATH}")


if __name__ == "__main__":
    main()
