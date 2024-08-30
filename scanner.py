import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Disable warnings about unverified HTTPS requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to check for SQL Injection vulnerabilities
def check_sql_injection(url):
    sql_payloads = ["'", "\"", "`", "''", "\"\"", "``"]
    for payload in sql_payloads:
        response = requests.get(url + payload, verify=False)
        if "error" in response.text.lower():
            print(f"[!] SQL Injection vulnerability detected with payload: {payload}")
            return True
    return False

# Function to check for XSS vulnerabilities
def check_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.get(url + xss_payload, verify=False)
    if xss_payload in response.text:
        print(f"[!] XSS vulnerability detected with payload: {xss_payload}")
        return True
    return False

# Function to check for insecure HTTP headers
def check_headers(url):
    response = requests.get(url, verify=False)
    headers = response.headers
    if "X-Content-Type-Options" not in headers:
        print("[!] Missing X-Content-Type-Options header")
    if "X-Frame-Options" not in headers:
        print("[!] Missing X-Frame-Options header")
    if "Content-Security-Policy" not in headers:
        print("[!] Missing Content-Security-Policy header")

# Main function to run the vulnerability scanner
def scan_website(url):
    print(f"Scanning website: {url}")
    if not url.startswith("http"):
        url = "http://" + url

    check_sql_injection(url)
    check_xss(url)
    check_headers(url)
    print("Scan complete.")

# Test the vulnerability scanner
if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    scan_website(target_url)
