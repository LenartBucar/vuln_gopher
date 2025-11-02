import requests
import json

INTERNETDB = "https://internetdb.shodan.io/{ip_address}"
NIST_VULN_ID = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
NIST_VULN_NAME = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"


def get_ip_data(ip: str) -> dict | None:
    data = requests.get(INTERNETDB.format(ip_address=ip)).json()
    if "detail" in data:
        print(data["detail"][0]["msg"])
        return None
    return data


def get_vuln_by_name(vuln_name: str) -> dict | None:
    vuln_name = vuln_name.replace("/", "2.3:")
    data = requests.get(NIST_VULN_NAME.format(cpe_name=vuln_name)).json()
    return data


def get_vuln_by_id(vuln_id: str) -> dict | None:
    data = requests.get(NIST_VULN_ID.format(cve_id=vuln_id)).json()
    return data