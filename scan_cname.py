import argparse
import sys
import requests
import dns.resolver
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from pyfiglet import Figlet
import csv
from colorama import init, Fore, Style


# Initialize colorama
init(autoreset=True)

f = Figlet(font="small")  # 'small', 'mini', 'slant', etc.
banner_text = f.renderText("Subdomain Finder")

# header

HEADER = rf"""
{Fore.BLUE}      
 ██████╗███╗   ██╗ █████╗ ███╗   ███╗███████╗    ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗      █████╗    ███████╗███████╗ █████╗ 
██╔════╝████╗  ██║██╔══██╗████╗ ████║██╔════╝    ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗    ██╔══██╗   ██╔════╝██╔════╝██╔══██╗
██║     ██╔██╗ ██║███████║██╔████╔██║█████╗      █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝    ███████║   █████╗  ███████╗╚██████║
██║     ██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══╝      ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗    ██╔══██║   ██╔══╝  ╚════██║ ╚═══██║
╚██████╗██║ ╚████║██║  ██║██║ ╚═╝ ██║███████╗    ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║    ██║  ██║██╗██║     ███████║ █████╔╝
 ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝ ╚════╝ 
                                                                                                                               
{Style.RESET_ALL}

       {Fore.CYAN}CNAME Finder v1.0{Style.RESET_ALL}
               
"""
# Print header immediately on start
print(HEADER)


# Argument Parser
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        # Print header and error message
        print(f"\n{Fore.YELLOW}[ERROR]{Style.RESET_ALL} {message}\n")
        self.print_help()
        sys.exit(2)


parser = MyParser(
    description=f"{Fore.CYAN}CNAME Finder v1.0 - Modernized{Style.RESET_ALL}"
)
parser.add_argument("-f", "--file", required=True, help="Input file with subdomains")
parser.add_argument(
    "--threads", type=int, default=10, help="Number of threads (default 10)"
)
parser.add_argument(
    "--delay", type=float, default=0.0, help="Delay per request (default 0s)"
)
parser.add_argument(
    "--timeout", type=int, default=5, help="HTTP/DNS timeout (default 5s)"
)
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
parser.add_argument(
    "--takeover-keywords",
    default="amazonaws,elb,herokuapp,github.io,netlify.app,cloudfront.net,azurewebsites.net",
    help="eg. python scan_cname.py --file subdomains.txt ",
)

args = parser.parse_args()

INPUT_FILE = Path(args.file)
THREADS = args.threads
DELAY = args.delay
TIMEOUT = args.timeout
VERBOSE = args.verbose
TAKEOVER_KEYWORDS = [kw.strip().lower() for kw in args.takeover_keywords.split(",")]


# Vulnerable service fingerprints

vul_services_fingerprints = {
    "AWS S3": ".s3.amazonaws.com",
    "AWS Elastic Beanstalk": ".elasticbeanstalk.com",
    "AWS CloudFront": ".cloudfront.net",
    "Microsoft Azure App Services": ".azurewebsites.net",
    "Microsoft Azure Blob Storage": ".blob.core.windows.net",
    "GitHub Pages": ".github.io",
    "Heroku": ".herokuapp.com",
    "Shopify": ".myshopify.com",
    "Zendesk": ".zendesk.com",
    "Freshdesk": ".freshdesk.com",
    "Help Scout": ".helpscoutdocs.com",
    "Intercom": ".intercom.help",
    "UserVoice": ".uservoice.com",
    "Unbounce": ".unbouncepages.com",
    "ActiveCampaign": ".activehosted.com",
    "Kajabi": ".kajabi.com",
    "LeadPages": ".lp.com",
    "Tilda": ".tilda.ws",
    "Canny.io": ".canny.io",
    "ReadTheDocs": ".readthedocs.io",
    "ReadMe.io": ".readme.io",
    "Surge.sh": ".surge.sh",
}


# Ensure results folder exists and handle file versioning

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


def get_versioned_file_path(base_name, ext):
    i = 0
    while True:
        if i == 0:
            file_path = RESULTS_DIR / f"{base_name}.{ext}"
        else:
            file_path = RESULTS_DIR / f"{base_name}{i}.{ext}"
        if not file_path.exists():
            return file_path
        i += 1


OUTPUT_FILE = get_versioned_file_path("danger_only", "txt")
CSV_FILE = get_versioned_file_path("all_results", "csv")


# Load subdomains

if not INPUT_FILE.is_file():
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File '{INPUT_FILE}' not found.")
    sys.exit(1)

with INPUT_FILE.open("r") as f:
    subdomains = [line.strip() for line in f if line.strip()]

print(f"[INFO] Loaded {len(subdomains)} subdomains from: {INPUT_FILE}")
print(f"[INFO] Starting scan with {THREADS} threads...\n")


# Helper functions


def status_color(code):
    if code is None:
        return Fore.CYAN
    return (
        Fore.GREEN
        if 200 <= code < 300
        else Fore.YELLOW if 300 <= code < 400 else Fore.RED
    )


results = []
results_lock = Lock()


# Scan function


def scan_subdomain(subdomain):
    cname_val = None
    ip_val = None
    status_code = None
    takeover = False
    final_url = None

    # DNS CNAME check
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=TIMEOUT)
        for rdata in answers:
            cname_val = rdata.target.to_text().rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        cname_val = None
    except Exception as e:
        if VERBOSE:
            print(f"[WARN] DNS error (CNAME) for {subdomain}: {e}")

    # Takeover detection from CNAME
    if cname_val:
        cname_lower = cname_val.lower()
        if any(keyword in cname_lower for keyword in TAKEOVER_KEYWORDS):
            takeover = True
        for service, fingerprint in vul_services_fingerprints.items():
            if fingerprint.lower() in cname_lower:
                takeover = True
                if VERBOSE:
                    print(
                        f"[INFO] Potential takeover detected for {subdomain} ({service})"
                    )
                break

        if takeover:
            if DELAY > 0:
                time.sleep(DELAY)
            return subdomain, cname_val, ip_val, status_code, final_url, takeover

    # Only query A records if takeover not detected
    try:
        answers = dns.resolver.resolve(subdomain, "A", lifetime=TIMEOUT)
        ip_val = [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        ip_val = None
    except Exception as e:
        if VERBOSE:
            print(f"[WARN] DNS error (A) for {subdomain}: {e}")

    # HTTP/HTTPS check only if no takeover detected yet
    for protocol in ["https://", "http://"]:
        try:
            r = requests.get(
                f"{protocol}{subdomain}", timeout=TIMEOUT, allow_redirects=True
            )
            status_code = r.status_code
            final_url = r.url
            break
        except requests.RequestException as e:
            if VERBOSE:
                print(f"[WARN] HTTP error for {subdomain} ({protocol}): {e}")
            status_code = None

    if DELAY > 0:
        time.sleep(DELAY)

    # Check for takeover again after HTTP (optional)
    if cname_val:
        cname_lower = cname_val.lower()
        if any(keyword in cname_lower for keyword in TAKEOVER_KEYWORDS):
            takeover = True
        for service, fingerprint in vul_services_fingerprints.items():
            if fingerprint.lower() in cname_lower:
                takeover = True
                break

    return subdomain, cname_val, ip_val, status_code, final_url, takeover


# Process results


def process_result(result):
    sub, cname, ip, status, final_url, takeover = result
    with results_lock:
        results.append(result)

    cname_text = f"CNAME: {Fore.GREEN}{cname}{Style.RESET_ALL}" if cname else "No CNAME"
    ip_text = f"IPs: {', '.join(ip)}" if ip else ""
    status_val = (
        f"{status_color(status)}{status if status else 'None'}{Style.RESET_ALL}"
    )
    final_url_text = f" | Final URL: {final_url}" if final_url else ""

    if takeover:
        print(
            f"{Fore.RED}[TAKEOVER]{Style.RESET_ALL} {sub} → {cname_text} {ip_text} | Status: {status_val}{final_url_text}"
        )
    else:
        print(f"{sub} → {cname_text} {ip_text} | Status: {status_val}{final_url_text}")


# Run threaded scanning

with ThreadPoolExecutor(max_workers=THREADS) as executor:
    futures = {executor.submit(scan_subdomain, sd): sd for sd in subdomains}
    for future in as_completed(futures):
        process_result(future.result())


# Save dangerous/takeover results (HTTP 200)

with OUTPUT_FILE.open("w") as f:
    for r in results:
        sub, cname, ip, status, final_url, takeover = r
        if takeover and status == 200:
            f.write(f"{sub} → {cname} | Status: {status} | Final URL: {final_url}\n")


# Save full CSV

with CSV_FILE.open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(
        ["Subdomain", "CNAME", "IPs", "HTTP Status", "Final URL", "Takeover"]
    )
    for r in results:
        writer.writerow(r)


# Summary

total_subdomains = len(results)
total_cname = sum(1 for r in results if r[1])
total_no_cname = total_subdomains - total_cname
total_takeover_risk = sum(1 for r in results if r[5])
total_takeover_200 = sum(1 for r in results if r[5] and r[3] == 200)

summary = f"""
{Fore.CYAN}────────────── SUMMARY ──────────────{Style.RESET_ALL}
Total subdomains scanned: {total_subdomains}
CNAME found: {Fore.GREEN}{total_cname}{Style.RESET_ALL}
No CNAME: {Fore.YELLOW}{total_no_cname}{Style.RESET_ALL}
Takeover risk (any status): {Fore.RED}{total_takeover_risk}{Style.RESET_ALL}
Takeover risk (200 HTTP): {Fore.RED}{total_takeover_200}{Style.RESET_ALL}
Dangerous output saved: {OUTPUT_FILE}
Full CSV saved: {CSV_FILE}
"""
print(summary)
