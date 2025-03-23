"""
mwhsrecon_tool
Made by HuyDom

Description:
    This tool performs comprehensive web reconnaissance including:
      - Nmap scanning
      - WHOIS lookup
      - HTTP headers retrieval
      - SSL/TLS certificate details
      - Directory enumeration (asynchronous with rate limiting)
      - URL parameter discovery via crawling
      - Integration with external tools: Gobuster and Dirb
    It also allows adding custom cookies header and gracefully handles interruption (Ctrl+C).
"""

import nmap
import whois
import requests
import socket
import ssl
import json
import time
import aiohttp
import asyncio
import subprocess
import os
import shutil
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

def print_banner():
    """In banner ASCII ở đầu chương trình."""
    banner = r"""
  
███████████████████████████████████████████████████████████████████████████████
█░░░░░░██████████░░░░░░█░░░░░░██████████░░░░░░█░░░░░░██░░░░░░░░█░░░░░░░░░░░░░░█
█░░▄▀░░░░░░░░░░░░░░▄▀░░█░░▄▀░░██████████░░▄▀░░█░░▄▀░░██░░▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█
█░░▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██████████░░▄▀░░█░░▄▀░░██░░▄▀░░░░█░░▄▀░░░░░░░░░░█
█░░▄▀░░░░░░▄▀░░░░░░▄▀░░█░░▄▀░░██████████░░▄▀░░█░░▄▀░░██░░▄▀░░███░░▄▀░░█████████
█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░██░░░░░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░███░░▄▀░░░░░░░░░░█
█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░███░░▄▀▄▀▄▀▄▀▄▀░░█
█░░▄▀░░██░░░░░░██░░▄▀░░█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░███░░░░░░░░░░▄▀░░█
█░░▄▀░░██████████░░▄▀░░█░░▄▀░░░░░░▄▀░░░░░░▄▀░░█░░▄▀░░██░░▄▀░░███████████░░▄▀░░█
█░░▄▀░░██████████░░▄▀░░█░░▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██░░▄▀░░░░█░░░░░░░░░░▄▀░░█
█░░▄▀░░██████████░░▄▀░░█░░▄▀░░░░░░▄▀░░░░░░▄▀░░█░░▄▀░░██░░▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█
█░░░░░░██████████░░░░░░█░░░░░░██░░░░░░██░░░░░░█░░░░░░██░░░░░░░░█░░░░░░░░░░░░░░█
███████████████████████████████████████████████████████████████████████████████
        mwhsrecon_tool
   github.com/DOMBNC/mwhsrecon_tool/
"""
    print(banner)

class WebRecon:
    def __init__(self, target, wordlist_path=None, crawl_depth=1, rate_limit=0.5, cookies=None):
        # Xử lý chuỗi đầu vào cho target
        if target.startswith("http://"):
            target = target[len("http://"):]
        elif target.startswith("https://"):
            target = target[len("https://"):]
        target = target.rstrip("/")  # Xóa dấu '/' ở cuối nếu có
        self.target = target
        self.base_url = f"https://{self.target}"
        self.wordlist_path = wordlist_path if wordlist_path else "wordlist.txt"
        self.crawl_depth = crawl_depth
        self.rate_limit = rate_limit
        self.cookies = cookies  # Cookies header được truyền vào dưới dạng chuỗi, ví dụ: "key1=value1; key2=value2"
        self.results = {
            "target": self.target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "nmap_scan": {},
            "whois_info": {},
            "http_headers": {},
            "ssl_info": {},
            "directories": [],
            "parameters": {},
            "external_tools": {"gobuster": [], "dirb": []}
        }
        self.visited_urls = set()

    def get_custom_headers(self):
        """Trả về header tùy chỉnh, bao gồm Cookie nếu có."""
        headers = {}
        if self.cookies:
            headers["Cookie"] = self.cookies
        return headers

    def validate_wordlist(self):
        """Kiểm tra file wordlist có tồn tại hay không"""
        if not os.path.exists(self.wordlist_path):
            print(f"[!] Error: Wordlist file '{self.wordlist_path}' not found.")
            return False
        return True

    def sanitize_filename(self, filename):
        """Làm sạch tên file để tránh lỗi khi lưu báo cáo"""
        sanitized = filename.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        return sanitized

    def nmap_scan(self):
        """Perform an Nmap scan on the target."""
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, "22,80,443", arguments="-sV")
            if self.target in nm.all_hosts():
                self.results["nmap_scan"] = {
                    "host": self.target,
                    "state": nm[self.target].state(),
                    "ports": {}
                }
                for proto in nm[self.target].all_protocols():
                    for port in nm[self.target][proto].keys():
                        self.results["nmap_scan"]["ports"][port] = {
                            "state": nm[self.target][proto][port]["state"],
                            "service": nm[self.target][proto][port]["name"],
                            "version": nm[self.target][proto][port].get("version", "N/A")
                        }
            else:
                self.results["nmap_scan"] = {"error": "Host not found or scan failed"}
        except Exception as e:
            self.results["nmap_scan"] = {"error": str(e)}

    def whois_lookup(self):
        """Retrieve WHOIS information for the target domain."""
        try:
            w = whois.whois(self.target)
            self.results["whois_info"] = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except Exception as e:
            self.results["whois_info"] = {"error": str(e)}

    def http_headers(self):
        """Fetch HTTP headers from the target website."""
        headers = self.get_custom_headers()
        try:
            response = requests.get(self.base_url, headers=headers, timeout=10)
            self.results["http_headers"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers)
            }
        except requests.RequestException as e:
            # Thử với http:// nếu https:// không thành công
            try:
                url = f"http://{self.target}"
                response = requests.get(url, headers=headers, timeout=10)
                self.results["http_headers"] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers)
                }
            except requests.RequestException as e:
                self.results["http_headers"] = {"error": str(e)}

    def ssl_info(self):
        """Retrieve SSL/TLS certificate details."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    self.results["ssl_info"] = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "valid_from": cert["notBefore"],
                        "valid_until": cert["notAfter"],
                        "serial_number": cert["serialNumber"]
                    }
        except Exception as e:
            self.results["ssl_info"] = {"error": str(e)}

    async def fetch_url(self, session, url):
        """Async helper to fetch a URL."""
        headers = self.get_custom_headers()
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                return response.status, url
        except Exception:
            return None, url

    async def directory_enum_async(self, limit=100):
        """Enumerate directories asynchronously with rate limiting."""
        if not os.path.exists(self.wordlist_path):
            self.results["directories"].append(f"Error: Wordlist file '{self.wordlist_path}' not found")
            return
        try:
            with open(self.wordlist_path, "r") as f:
                directories = [line.strip() for line in f.readlines()][:limit]
            print(f"Enumerating directories (limited to {limit}) with rate limit {self.rate_limit}s...")
            headers = self.get_custom_headers()
            async with aiohttp.ClientSession(headers=headers) as session:
                tasks = []
                for dir_name in directories:
                    url = f"{self.base_url}/{dir_name}"
                    tasks.append(self.fetch_url(session, url))
                    await asyncio.sleep(self.rate_limit)
                responses = await asyncio.gather(*tasks)
                for status, url in responses:
                    if status == 200:
                        self.results["directories"].append(url)
                        print(f"  Found: {url}")
                    elif status == 403:
                        self.results["directories"].append(f"{url} (Forbidden)")
        except Exception as e:
            self.results["directories"].append(f"Error: {str(e)}")

    def directory_enum(self, limit=100):
        """Wrapper to run async directory enumeration."""
        asyncio.run(self.directory_enum_async(limit))

    def crawl_page(self, url, depth):
        """Recursively crawl pages to discover parameters."""
        if depth > self.crawl_depth or url in self.visited_urls:
            return
        self.visited_urls.add(url)
        headers = self.get_custom_headers()
        try:
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            parsed_base = urlparse(self.base_url)
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("http"):
                    parsed_url = urlparse(href)
                else:
                    parsed_url = urlparse(f"{self.base_url}/{href.lstrip('/')}")
                if parsed_url.netloc == parsed_base.netloc:
                    params = parse_qs(parsed_url.query)
                    if params:
                        self.results["parameters"][parsed_url.path] = params
                    if depth < self.crawl_depth:
                        self.crawl_page(parsed_url.geturl(), depth + 1)
        except requests.RequestException:
            pass

    def parameter_discovery(self):
        """Crawl the website to discover URL parameters with specified depth."""
        try:
            print(f"Crawling with depth {self.crawl_depth}...")
            self.crawl_page(self.base_url, 0)
        except Exception as e:
            self.results["parameters"] = {"error": str(e)}

    def integrate_gobuster(self):
        """Integrate gobuster for directory enumeration."""
        if not shutil.which("gobuster"):
            self.results["external_tools"]["gobuster"].append("Error: gobuster not installed")
            return
        if not os.path.exists(self.wordlist_path):
            self.results["external_tools"]["gobuster"].append(f"Error: Wordlist file '{self.wordlist_path}' not found")
            return
        try:
            print("Running gobuster for directory enumeration...")
            result = subprocess.run(
                ["gobuster", "dir", "-u", self.base_url, "-w", self.wordlist_path, "-q", "-t", "10"],
                capture_output=True, text=True, timeout=300
            )
            for line in result.stdout.splitlines():
                if "Status: 200" in line or "Status: 403" in line:
                    parts = line.split()
                    if parts:
                        dir_path = parts[0]
                        self.results["external_tools"]["gobuster"].append(f"{self.base_url}{dir_path} ({parts[1]})")
            if result.stderr:
                self.results["external_tools"]["gobuster"].append(f"Error: {result.stderr}")
        except subprocess.TimeoutExpired:
            self.results["external_tools"]["gobuster"].append("Error: gobuster timed out")
        except Exception as e:
            self.results["external_tools"]["gobuster"].append(f"Error: {str(e)}")

    def integrate_dirb(self):
        """Integrate dirb for directory enumeration."""
        if not shutil.which("dirb"):
            self.results["external_tools"]["dirb"].append("Error: dirb not installed")
            return
        if not os.path.exists(self.wordlist_path):
            self.results["external_tools"]["dirb"].append(f"Error: Wordlist file '{self.wordlist_path}' not found")
            return
        try:
            print("Running dirb for directory enumeration...")
            result = subprocess.run(
                ["dirb", self.base_url, self.wordlist_path, "-S", "-r"],
                capture_output=True, text=True, timeout=300
            )
            for line in result.stdout.splitlines():
                if "+ " in line and "(CODE:" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        dir_url = parts[1]
                        code_part = line.split("(CODE:")[1].split("|")[0]
                        self.results["external_tools"]["dirb"].append(f"{dir_url} (Status: {code_part})")
            if result.stderr:
                self.results["external_tools"]["dirb"].append(f"Error: {result.stderr}")
        except subprocess.TimeoutExpired:
            self.results["external_tools"]["dirb"].append("Error: dirb timed out")
        except Exception as e:
            self.results["external_tools"]["dirb"].append(f"Error: {str(e)}")

    def run(self):
        """Execute all recon tasks."""
        print(f"Starting reconnaissance on {self.target}...")
        print("Note: Ensure you have permission to scan this target. Unauthorized scanning may be illegal.")
        self.nmap_scan()
        self.whois_lookup()
        self.http_headers()
        self.ssl_info()
        self.directory_enum()
        self.parameter_discovery()
        self.integrate_gobuster()
        self.integrate_dirb()
        print("Reconnaissance completed.")

    def save_report(self, filename="recon_report.json"):
        """Save the results to a JSON file."""
        filename = self.sanitize_filename(filename)
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"Report saved to {filename}")

    def display_report(self):
        """Display the aggregated results."""
        print("\n=== Reconnaissance Report ===")
        print(f"Target: {self.results['target']}")
        print(f"Timestamp: {self.results['timestamp']}")
        
        print("\nNmap Scan Results:")
        if "error" in self.results["nmap_scan"]:
            print(f"  Error: {self.results['nmap_scan']['error']}")
        else:
            print(f"  Host: {self.results['nmap_scan']['host']} ({self.results['nmap_scan']['state']})")
            for port, info in self.results["nmap_scan"]["ports"].items():
                print(f"    Port {port}: {info['state']} - {info['service']} (v{info['version']})")
        
        print("\nWHOIS Information:")
        if "error" in self.results["whois_info"]:
            print(f"  Error: {self.results['whois_info']['error']}")
        else:
            for key, value in self.results["whois_info"].items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
        
        print("\nHTTP Headers:")
        if "error" in self.results["http_headers"]:
            print(f"  Error: {self.results['http_headers']['error']}")
        else:
            print(f"  Status Code: {self.results['http_headers']['status_code']}")
            for key, value in self.results["http_headers"]["headers"].items():
                print(f"    {key}: {value}")
        
        print("\nSSL/TLS Information:")
        if "error" in self.results["ssl_info"]:
            print(f"  Error: {self.results['ssl_info']['error']}")
        else:
            for key, value in self.results["ssl_info"].items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
        
        print("\nDiscovered Directories (Internal):")
        if not self.results["directories"]:
            print("  None found")
        else:
            for directory in self.results["directories"]:
                print(f"  {directory}")
        
        print("\nDiscovered Parameters:")
        if "error" in self.results["parameters"]:
            print(f"  Error: {self.results['parameters']['error']}")
        elif not self.results["parameters"]:
            print("  None found")
        else:
            for path, params in self.results["parameters"].items():
                print(f"  Path: {path}")
                for param, value in params.items():
                    print(f"    {param}: {value}")
        
        print("\nExternal Tool Results - Gobuster:")
        if not self.results["external_tools"]["gobuster"]:
            print("  None found or not run")
        else:
            for result in self.results["external_tools"]["gobuster"]:
                print(f"  {result}")
        
        print("\nExternal Tool Results - Dirb:")
        if not self.results["external_tools"]["dirb"]:
            print("  None found or not run")
        else:
            for result in self.results["external_tools"]["dirb"]:
                print(f"  {result}")

def main():
    try:
        # In banner ASCII
        print_banner()

        target = input("Enter the target website (e.g., example.com): ").strip()
        wordlist_path = input("Enter path to wordlist (default: wordlist.txt): ").strip() or "wordlist.txt"
        try:
            crawl_depth = int(input("Enter crawl depth (default: 1): ").strip() or 1)
        except ValueError:
            crawl_depth = 1
        try:
            rate_limit = float(input("Enter rate limit in seconds (default: 0.5): ").strip() or 0.5)
        except ValueError:
            rate_limit = 0.5
        # Cho phép nhập cookie header nếu có
        cookies = input("Enter cookies header (optional): ").strip() or None

        recon = WebRecon(target, wordlist_path=wordlist_path, crawl_depth=crawl_depth, rate_limit=rate_limit, cookies=cookies)
        recon.run()
        recon.display_report()
        recon.save_report(f"recon_report_{target}.json")
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user. Exiting gracefully...")

if __name__ == "__main__":
    main()
