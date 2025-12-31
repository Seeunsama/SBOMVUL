import os
import requests
import json
import pandas as pd
from zipfile import ZipFile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "nvd_data")

NVD_URLS = [
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2023.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2022.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2021.json.zip",
]


def download_nvd_data():
    os.makedirs(DATA_DIR, exist_ok=True)

    for url in NVD_URLS:
        file_name = url.split("/")[-1]  # nvdcve-2.0-2024.json.zip
        zip_path = os.path.join(DATA_DIR, file_name)

        print(f"[NVD] downloading {file_name} ...")
        resp = requests.get(url, timeout=60)
        if resp.status_code != 200:
            print(f"[NVD] failed: {url} (status={resp.status_code})")
            continue

        with open(zip_path, "wb") as f:
            f.write(resp.content)

        with ZipFile(zip_path, "r") as zf:
            zf.extractall(DATA_DIR)

        os.remove(zip_path)
        print(f"[NVD] downloaded and extracted: {file_name}")


def convert_json_to_csv():
    records = []

    json_files = [
        f for f in os.listdir(DATA_DIR)
        if f.endswith(".json") and f.startswith("nvdcve-2.0-")
    ]
    json_files.sort()

    for file_name in json_files:
        path = os.path.join(DATA_DIR, file_name)
        print(f"[NVD] parsing {file_name} ...")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            cve = v.get("cve", {})

            cve_id = cve.get("id")
            if not cve_id:
                continue

            # CWE
            cwe_value = "N/A"
            weaknesses = cve.get("weaknesses", [])
            for w in weaknesses:
                desc_list = w.get("description", [])
                for d in desc_list:
                    if d.get("lang") == "en":
                        cwe_value = d.get("value", "N/A")
                        break
                if cwe_value != "N/A":
                    break

            # CVSS v3.x
            metrics = cve.get("metrics", {})
            cvss_data = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    break

            if cvss_data:
                cvss_version = cvss_data.get("version", "N/A")
                vector_string = cvss_data.get("vectorString", "N/A")
                base_score = cvss_data.get("baseScore", "N/A")
                base_severity = cvss_data.get("baseSeverity", "N/A")
            else:
                cvss_version = "N/A"
                vector_string = "N/A"
                base_score = "N/A"
                base_severity = "N/A"

            # description
            description = "N/A"
            desc_list = cve.get("descriptions", [])
            for d in desc_list:
                if d.get("lang") == "en":
                    description = d.get("value", "N/A").replace("\u00a0", " ").strip()
                    break

            records.append(
                {
                    "CVE_ID": cve_id,
                    "CWE_Value": cwe_value,
                    "CVSS_Version": cvss_version,
                    "Vector_String": vector_string,
                    "Base_Score": base_score,
                    "Base_Severity": base_severity,
                    "Description": description,
                    "Source_File": file_name,
                }
            )

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.drop_duplicates(subset=["CVE_ID"], keep="first")

    csv_path = os.path.join(BASE_DIR, "cve_cvss3_data.csv")
    df.to_csv(csv_path, index=False, encoding="utf-8")
    print(f"[NVD] CSV saved: {csv_path}")


if __name__ == "__main__":
    download_nvd_data()
    convert_json_to_csv()
