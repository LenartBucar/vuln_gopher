import requests
import json
from time import sleep
import dotenv
from socket import getservbyport

INTERNETDB = "https://internetdb.shodan.io/{ip_address}"
NIST_VULN_ID = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
NIST_VULN_NAME = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"

NIST_APIKEY = dotenv.dotenv_values(".env").get("NIST_APIKEY")
HEADERS = {"apikey": NIST_APIKEY} if NIST_APIKEY is not None else {}

OUTPUT_CONFIG = {"display": True, "out_file": None, "buffer": "-"*10}

DELAY = 0.65

if NIST_APIKEY is None:
    DELAY *= 10


def get_ip_data(ip: str) -> dict | None:
    sleep(DELAY)
    data = requests.get(INTERNETDB.format(ip_address=ip)).json()
    output(data)
    if "detail" in data:
        if type(data["detail"]) is str:
            output(data["detail"])
        else:
            output(data["detail"][0]["msg"])
        return None
    return data


def get_vuln_by_name(vuln_name: str) -> dict | None:
    vuln_name = vuln_name.replace("/", "2.3:")
    try:
        sleep(DELAY)
        data = requests.get(NIST_VULN_NAME.format(cpe_name=vuln_name), headers=HEADERS).json()
    except requests.exceptions.JSONDecodeError:
        return {"ERROR": f"{vuln_name} returned no results"}
    return data


def get_vuln_by_id(vuln_id: str) -> dict | None:
    try:
        sleep(DELAY)
        data = requests.get(NIST_VULN_ID.format(cve_id=vuln_id), headers=HEADERS).json()
    except requests.exceptions.JSONDecodeError:
        return {"ERROR": f"{vuln_id} returned no results"}
    return data


def parse_vuln(data: dict, pos = 0, display_all = False) -> list[dict] | None:
    result = []

    total_n = min(data["totalResults"], data["resultsPerPage"])

    if total_n == 0:
        return None

    if pos >= total_n:
        raise ValueError(f"{total_n} returned results is less than requested {pos}")


    if display_all:
        low = pos
        high = total_n
    else:
        low = pos
        high = pos + 1

    for pos in range(low, high):
        result.append({})
        current = result[-1]
        cve = data["vulnerabilities"][pos]["cve"]

        current["id"] = cve["id"]

        for description in cve["descriptions"]:
            if description["lang"] == "en":
                current["description"] = description["value"]
                break
        else:
            current["description"] = None

        current["comment"] = cve.get("evaluatorComment", None)
        current["impact"] = cve.get("evaluatorImpact", None)
        current["solution"] = cve.get("evaluatorSolution", None)

    return result


def print_vuln(filtered_data: list[dict]) -> None:
    if filtered_data is None:
        raise ValueError("No data returned")
    for vuln in filtered_data:
        output(f"ID: {vuln['id']}")
        output(f"Description: {vuln['description']}")
        output(f"Comment: {vuln['comment']}")
        output(f"Impact: {vuln['impact']}")
        output(f"Solution: {vuln['solution']}")
        buffer()


def output(text: str, *args, **kwargs) -> None:
    if OUTPUT_CONFIG["display"]:
        print(text, *args, **kwargs)
    out_file: str | None = OUTPUT_CONFIG["out_file"]
    if out_file is not None:
        out_file: str
        with open(out_file, "a", encoding="UTF-8") as f:
            print(text, *args, file=f, **kwargs)

def buffer():
    output(OUTPUT_CONFIG["buffer"])

def handle_ip(ip: str, display_all: bool = False) -> None:
    data = get_ip_data(ip)
    if data is None:
        return

    for name in data["cpes"]:
        vuln = get_vuln_by_name(name)
        if "ERROR" in vuln:
            output(vuln["ERROR"])
            buffer()
            continue
        try:
            print_vuln(parse_vuln(vuln, display_all=display_all))
        except ValueError as e:
            output(f"{name}: {e}")
            buffer()

    for vuln_id in data["vulns"]:
        vuln = get_vuln_by_id(vuln_id)
        if "ERROR" in vuln:
            output(vuln["ERROR"])
            buffer()
            continue
        try:
            print_vuln(parse_vuln(vuln, display_all=display_all))
        except ValueError as e:
            output(f"{vuln_id}: {e}")
            buffer()

    for port_num in data["ports"]:
        try:
            output(f"Port: {port_num} - {getservbyport(port_num)}")
        except OSError as e:
            output(f"Port: {port_num} - no known service found")


def main():
    # vuln_id_test = "CVE-2019-1010218"
    # vuln_id_test = "CVE-2022-4900"
    # print_vuln(parse_vuln(get_vuln_by_id(vuln_id_test)))

    # vuln_name_test = "cpe:2.3:o:microsoft:windows_10:1607"
    # vuln = get_vuln_by_name(vuln_name_test)
    # output(vuln, out_file="vuln.json")
    # print_vuln(parse_vuln(vuln, display_all=True))

    # ip = "91.216.172.11"
    ip = "84.255.196.242"
    handle_ip(ip)


if __name__ == '__main__':
    main()