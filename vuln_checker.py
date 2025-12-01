import requests
from time import sleep
from socket import getservbyport
import argparse
import shelve

try:
    from dotenv import dotenv_values
except ImportError:
    dotenv_values = lambda x: {}


class Config:
    # API links
    INTERNETDB = "https://internetdb.shodan.io/{ip_address}"
    NIST_VULN_ID = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    NIST_VULN_NAME = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"

    # Load API key for NIST, if it is available
    NIST_APIKEY = dotenv_values(".env").get("NIST_APIKEY")
    HEADERS = {"apikey": NIST_APIKEY} if NIST_APIKEY is not None else {}

    DELAY = 0.65

    # Increase delay between API calls if the key is not available, to comply with lower rate limits
    if NIST_APIKEY is None:
        DELAY *= 10

    # Configuration of the program output
    OUTPUT_CONFIG = {"display": True, "out_file": None, "separator": "-"*10, "template": "output_{ip}.out"}

    # starting strings to distinguish between a CPE and CVE
    CPE_IDENT = "cpe"
    CVE_IDENT = "CVE"

    CACHE_FILE = "cache"
    SKIP_CACHE = False

    DISPLAY_ALL = False


def get_ip_data(ip: str) -> dict | None:
    """
    Queries InternetDB for the information on the given IP address
    :param ip: IP address
    :return: data about the given IP address or None if an error occurs (Invalid IP address or no information about it)
    """
    data = requests.get(Config.INTERNETDB.format(ip_address=ip)).json()
    if "detail" in data:
        if type(data["detail"]) is str:
            output(data["detail"])
        else:
            output(data["detail"][0]["msg"])
        return None
    return data


def get_vuln_by_name(vuln_name: str) -> dict:
    """
    Queries NIST Vulnerabilities API using a CPE name
    :param vuln_name: CPE name
    :return: Information about the given CPE
    """
    vuln_name = vuln_name.replace("/", "2.3:")
    try:
        sleep(Config.DELAY)
        data = requests.get(Config.NIST_VULN_NAME.format(cpe_name=vuln_name), headers=Config.HEADERS).json()
    except requests.exceptions.JSONDecodeError:  # Empty response
        return {"ERROR": f"{vuln_name} returned no results"}
    return data


def get_vuln_by_id(vuln_id: str) -> dict:
    """
    Queries NIST Vulnerabilities API using a CVE ID
    :param vuln_id: CVE ID
    :return: Information about the given CVE ID
    """
    try:
        sleep(Config.DELAY)
        data = requests.get(Config.NIST_VULN_ID.format(cve_id=vuln_id), headers=Config.HEADERS).json()
    except requests.exceptions.JSONDecodeError:  # Empty response
        return {"ERROR": f"{vuln_id} returned no results"}
    return data


def get_vuln(vuln_str: str) -> dict:
    """
    Decide whether the given string represents a CPE or CVE and queries an appropriate API
    :param vuln_str: string representing either a CPE or CVE
    :raises ValueError: if the given string does not represent either a CPE or CVE
    :return: data about the given CPE or CVE
    """
    if vuln_str.lower().startswith(Config.CPE_IDENT.lower()):
        return get_vuln_by_name(vuln_str)

    if vuln_str.lower().startswith(Config.CVE_IDENT.lower()):
        return get_vuln_by_id(vuln_str)

    raise ValueError(f"Invalid format: {vuln_str}")


def parse_vuln(data: dict, pos = 0) -> list[dict] | None:
    """
    Parse the data about a vulnerability
    :param data: response from NIST Vulnerabilities API
    :param pos: Which entry to parse if multiple responses are returned
    :raises ValueError: If the requested position is greater than the number of entries in the response
    :return: Parsed data about the given vulnerability or None if no data was found
    """
    result = []

    total_n = min(data["totalResults"], data["resultsPerPage"])

    if total_n == 0:
        return None

    if pos >= total_n:
        raise ValueError(f"{total_n} returned results is less than requested {pos}")


    if Config.DISPLAY_ALL:
        high = total_n
    else:
        high = pos + 1

    for pos in range(pos, high):
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


def handle_vuln(vuln_str: str) -> None:
    """
    Outputs the parsed data about a vulnerability
    :param vuln_str: CPE or CVE ID
    :return: None
    """
    with shelve.open(Config.CACHE_FILE) as cache:
        if not Config.SKIP_CACHE:
            vuln_data = cache.get(vuln_str)
        else:
            vuln_data = None

        if vuln_data is None:
            vuln_data = get_vuln(vuln_str)

            if "ERROR" in vuln_data:
                output(vuln_data["ERROR"])
                output_separator()
                return None

            try:
                vuln_data = parse_vuln(vuln_data)
            except ValueError as e:
                output(f"{vuln_str}: {e}")
                output_separator()
                return None

            cache[vuln_str] = vuln_data

    try:
        print_vuln(vuln_data)
    except ValueError as e:
        output(f"{vuln_str}: {e}")
        output_separator()


def print_vuln(filtered_data: list[dict] | None) -> None:
    """
    Outputs nicely formatted data about a vulnerability
    :param filtered_data: List of vulnerabilities and the corresponding data
    :raises ValueError: If no data was found
    :return: None
    """
    if filtered_data is None:
        raise ValueError("No data returned")
    for vuln in filtered_data:
        output(f"ID: {vuln['id']}")
        output(f"Description: {vuln['description']}")
        output(f"Comment: {vuln['comment']}")
        output(f"Impact: {vuln['impact']}")
        output(f"Solution: {vuln['solution']}")
        output_separator()


def output(text: str, *args, **kwargs) -> None:
    """
    Outputs the given text based on the state of Config.OUTPUT_CONFIG.
    If "display" value is True, output will be written to console.
    If "out_file" is set (not None), output will be written to that file.
    If "display" is False and "out_file" is None, the program will not produce any output!
    :param text: Text to output
    :param args: Additional arguments for the `print` function
    :param kwargs: Additional keyword arguments for the `print` function
    :return: None
    """
    if Config.OUTPUT_CONFIG["display"]:
        print(text, *args, **kwargs)
    out_file: str | None = Config.OUTPUT_CONFIG["out_file"]
    if out_file is not None:
        out_file: str
        with open(out_file, "a", encoding="UTF-8") as f:
            print(text, *args, file=f, **kwargs)


def output_separator() -> None:
    """
    Outputs a separator string between sections, as defined in Config.OUTPUT_CONFIG["separator"]
    :return: None
    """
    output(Config.OUTPUT_CONFIG["separator"])


def process_ip(ip: str) -> None:
    """
    Fetches, parses, and outputs all of the information about a given IP address.
    :param ip: IP address
    :return: None
    """
    data = get_ip_data(ip)
    if data is None:
        output(f"No information found for IP address {ip}")
        return

    output(f"Information about IP: {ip}")

    if data["ports"]:
        output("Open ports:")

    for port_num in data["ports"]:
        try:
            output(f"Port: {port_num} - {getservbyport(port_num)}")
        except OSError:
            output(f"Port: {port_num} - no known service found")
    output_separator()

    if data["cpes"] or data["vulns"]:
        output("Detected vulnerabilities:")

    for vuln_str in data["cpes"] + data["vulns"]:
        handle_vuln(vuln_str)


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
    process_ip(ip)


def run_with_args():
    parser = argparse.ArgumentParser(description="Open vulnerability checker")
    parser.add_argument("ip", help="IP address to check. Leave blank to use your public IP address.", default=None)
    parser.add_argument("-q", "--quiet-output", action="store_true",
                        help="Hides console output. The program will not output anything if --out-file is not set.")
    parser.add_argument("-o", "--out-file", help="File to which the output will be appended.",
                        default=Config.OUTPUT_CONFIG["out_file"], nargs="?", const=Config.OUTPUT_CONFIG["template"])
    parser.add_argument("-s", "--separator", help="Define custom string to separate entries with.",
                        default=Config.OUTPUT_CONFIG["separator"])
    parser.add_argument("-f", "--force", action="store_true", help="Force fetch the data from the API (even if it already exists in cache).")
    parser.add_argument("-v", "--verbose", action="store_true", help="When multiple entries are returned for a single vulnerability, display all of them instead of just the first one.")
    args = parser.parse_args()

    ip = args.ip
    if ip is None:  # Get the machine's public IP address
        ip = requests.get('https://api.ipify.org').content.decode('utf8')

    Config.OUTPUT_CONFIG["out_file"] = args.out_file.format(ip=ip) if args.out_file is not None else args.out_file
    Config.OUTPUT_CONFIG["display"] = not args.quiet_output
    Config.OUTPUT_CONFIG["separator"] = args.separator
    Config.SKIP_CACHE = args.force
    Config.DISPLAY_ALL = args.verbose

    process_ip(ip)


if __name__ == '__main__':

    main()