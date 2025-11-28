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


def parse_vuln(data: dict, pos = 0) -> dict | None:
    result = {}

    if data["totalResults"] == 0:
        return None

    if pos >= data["totalResults"]:
        raise ValueError(f"{data['totalResults']} returned results is less than requested {pos}")

    cve = data["vulnerabilities"][pos]["cve"]

    result["id"] = cve["id"]

    for description in cve["descriptions"]:
        if description["lang"] == "en":
            result["description"] = description["value"]
            break
    else:
        result["description"] = None

    result["comment"] = cve.get("evaluatorComment", None)
    result["impact"] = cve.get("evaluatorImpact", None)
    result["solution"] = cve.get("evaluatorSolution", None)

    return result


def print_vuln(filtered_data: dict) -> None:
    output(f"ID: {filtered_data['id']}")
    output(f"Description: {filtered_data['description']}")
    output(f"Comment: {filtered_data['comment']}")
    output(f"Impact: {filtered_data['impact']}")
    output(f"Solution: {filtered_data['solution']}")


def output(text, *args, display = True, out_file=None, **kwargs):
    if display:
        print(text, *args, **kwargs)
    if out_file is not None:
        with open(out_file, "a", encoding="UTF-8") as f:
            print(text, *args, file=f, **kwargs)


def main():
    vuln_id_test = "CVE-2019-1010218"
    print_vuln(parse_vuln(get_vuln_by_id(vuln_id_test)))


if __name__ == '__main__':
    main()