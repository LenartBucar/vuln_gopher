# Vuln checker

Vuln checker is a CLI tool intended for quick surface level analysis of open ports and vulnerabilities on any machine connected into the internet. The tool itself does absolutely no offensive analysis and it does not interact with the target machine in any way. It instead relies on InternetDB Public API (by Shodan.io) which periodically checks all of the devices. That means that the information provided by the tool may be up to a week out of date, and it does not guarantee to provide every single vulnerability on the target machine. 

## Setup

The tool was developed using Python 3.14, but it might work on some earlier versions as well. The tool works out of the box using only packages in standard library, however if one wants to use a NIST API key with it to increase rate limits (and reduce delays between API calls) the package `dotenv` needs to be installed. 

### Obtaining a NIST API key

The tool relies on the availability of the [NIST Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities). The API has a rate limit of 5 calls per 30 seconds. To increase the limit to 50 calls per 30 seconds, a free API key is needed. The key can be obtained from [their website](https://nvd.nist.gov/developers/request-an-api-key) for free, using an email address.

To use the key with the tool, create a `.env` file in the directory with the `vuln_checker.py` script, and add a key `NIST_APIKEY={your key}` into the file where `{your key}` is replaced with the obtained API key. 

## Usage

The simplest way to run the tool is to simply call `python vuln_checker.py`. That will automatically select the public IP of the current machine and display the result onto stdout. By adding the IP after the call, any IP can be checked (e.g. `python vuln_checker.py 1.1.1.1`). Besides that, the tool offers the following options / flags:

- `-q` or `--quiet` suppresses the console output of the program.
- `-o` or `--out-file` writes output to the provided log file. If the filename is not provided but the flag is set, the file will be named automatically. In the file name, template `{ip}` will be automatically replaced with the target IP address.
- `-s` or `--separator` sets the separator string to be placed between groups of data. A string of 10 `-` characters is used by default. 
- `-f` or `--force` fetches the data from the API regardless of whether it already exists in cache or not. Useful when cache is suspected to be outdated. 
- `-v` or `--verbose` shows the results for ALL vulnerabilities returned, instead of just the first one for each name / ID. 
- `-h` or `--help` displays a help message with all options listed and described.

### Note on `--quiet`

If `-q` (or `--quiet`) flag is set, the tool will provide no output to stdout. That means that if `--out-file` is not set, the program will provide no output whatsoever. This could occasionally be useful, for example in order to fill / update the cache. 

## Description

The following description follows the approximate flow of the code throughout the execution. 

At the beginning, `argparse` is used to parse the command line arguments. Most of them are used to update the `Config` object, while the IP is passed onto `process_ip` function. From there the data about the IP is obtained using `get_ip_data` which queries the InternetDB API. The returned result contains open ports, which are immediately printed, as well as a list of detected vulnerabilities. Those are passed into `handle_vuln`. That function first checks if that vulnerability already exists in the cache, and if it does, uses the cached value to prevent overloading the API. If it doesn't, `get_vuln` queries the API for the information. The returned result is then parsed by `parse_vuln` and stored into cache for later retrieval. Resulting data is then printed to the screen or an output file, depending on the Config. `get_vuln` analyses the input to determine whether the string represents a CPE or a CVE ID and queries the corresponding API. 