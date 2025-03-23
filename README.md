# nwksrecon_tool
![Logo](https://github.com/user-attachments/assets/bb878bd2-415a-4bdc-9036-996fd9c70c73)


## Authors
[@HuyDom](https://github.com/DOMBNC)
**Made by HuyDom**

## Giới thiệu

The **mwhsrecon_tool** allows for a comprehensive website reconnaissance, including:

- Port and service scanning with **Nmap**
- Domain **WHOIS** query
- Get **HTTP headers** (with the ability to customize cookies)
- Get **SSL/TLS certificate information**
- Asynchronous **Directory Enumeration** with `aiohttp`
- **URL parameter discovery** by crawling
- Integrate external tools such as **Gobuster** and **Dirb**
- Save results as JSON files
- Handle sudden stops with `Ctrl+C` (graceful interrupt)

## Installation
# 1. Clone repository:
```bash
 git clone https://github.com/DOMBNC/mwhsrecon_tool.git
 cd nwhsrecon_tool
```
# 2. Environment setup (should use venv or similar):
```bash
 python3 -m venv venv
 source venv/bin/activate
 pip install -r requirements.txt
```
# 3. Run the tool:
```bash
 python nwhsrecon.py
```
## How to use

Target: The domain or IP you want to scan (e.g. example.com).

Wordlist: The path to the file containing the wordlist/directories to brute-force (default wordlist.txt).

Crawl Depth: The depth of the link to find URL parameters.

Rate Limit: The time to wait (seconds) between each request when listing directories (Directory enum).

Cookies: Optional cookie header, e.g. "sessionid=abc123; token=xyz456".

After the scan is complete, the tool will:

Print a detailed report to the screen

Save the report file as JSON (e.g. recon_report_example.com.json)

## 🛠 Skills

python

## Feedback

If you have any feedback, please reach out to me at huytrinh870@gmail.com
