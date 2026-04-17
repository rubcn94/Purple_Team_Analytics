#!/bin/bash

################################################################################
# KALI LINUX PURPLE TEAM - WEB APPLICATION AUDIT SCRIPT
# Focused web application security assessment
# Version: 1.0
################################################################################

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMEOUT_PER_TOOL=1800
MASTER_LOG_DIR="/var/log/purple_team"

################################################################################
# UTILITY FUNCTIONS
################################################################################

init_logging() {
    mkdir -p "$MASTER_LOG_DIR"
    MASTER_LOG="${MASTER_LOG_DIR}/web_audit_$(date +%Y%m%d_%H%M%S).log"
    touch "$MASTER_LOG"
}

log_message() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$MASTER_LOG"
}

print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS") echo -e "${GREEN}[✓]${NC} ${message}" ;;
        "FAIL") echo -e "${RED}[✗]${NC} ${message}" ;;
        "INFO") echo -e "${CYAN}[ℹ]${NC} ${message}" ;;
        "WARN") echo -e "${YELLOW}[⚠]${NC} ${message}" ;;
        "PHASE") echo -e "${PURPLE}[◆]${NC} ${message}" ;;
    esac
    log_message "$status" "$message"
}

display_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║    KALI LINUX PURPLE TEAM - WEB AUDIT SUITE                  ║"
    echo "║    Focused Web Application Security Assessment                ║"
    echo "║    Version 1.0                                                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

ethical_disclaimer() {
    echo -e "${RED}"
    echo "════════════════════════════════════════════════════════════════"
    echo "                    ETHICAL USE DISCLAIMER"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "This tool is designed for authorized security testing ONLY."
    echo "Unauthorized access to computer systems is illegal."
    echo ""
    echo -e "${RED}Misuse of this tool may result in criminal prosecution.${NC}"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
}

display_help() {
    cat << EOF
${PURPLE}USAGE:${NC}
    ./kali_web_audit.sh [OPTIONS]

${PURPLE}OPTIONS:${NC}
    -u, --url URL                Target URL (REQUIRED)
    -c, --client "NAME"          Client name for reporting (optional)
    -o, --output /path/to/dir    Output directory (default: /results/)
    -t, --timeout SECONDS        Timeout per tool (default: 1800)
    -s, --skip TOOLS             Comma-separated tools to skip
    -h, --help                   Display this help message

${PURPLE}EXAMPLES:${NC}
    ./kali_web_audit.sh -u http://example.com -c "Acme Corp"
    ./kali_web_audit.sh -u https://secure.example.com -o ./audit_results
    ./kali_web_audit.sh -u http://10.0.0.5:8080 -s "wpscan,xsser"

${PURPLE}TOOLS INCLUDED:${NC}
    • Nikto          - Web server scanning and vulnerability detection
    • Whatweb        - Web application identification
    • WAF detection  - Web Application Firewall detection
    • Dirb/Gobuster  - Directory and file enumeration
    • WPScan         - WordPress vulnerability scanning
    • SQLMap         - SQL injection detection
    • SSL Labs Scan  - SSL/TLS configuration analysis
    • XSSer          - XSS vulnerability detection

${RED}DISCLAIMER:${NC} Unauthorized access is illegal. Obtain written permission before testing.

EOF
}

command_exists() {
    command -v "$1" &> /dev/null
    return $?
}

check_tool() {
    local tool=$1
    if ! command_exists "$tool"; then
        print_status "WARN" "Tool not found: $tool"
        return 1
    fi
    return 0
}

validate_url() {
    local url=$1
    if [[ $url =~ ^https?:// ]]; then
        return 0
    fi
    return 1
}

confirm_target() {
    local url=$1
    echo -e "${YELLOW}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    CONFIRM TARGET DETAILS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "Target URL: $url"
    echo "Client: $CLIENT_NAME"
    echo "Output Directory: $OUTPUT_DIR"
    echo ""
    read -p "Proceed with web audit? (yes/no): " -r confirmation
    if [[ ! $confirmation =~ ^[Yy][Ee][Ss]$ ]]; then
        print_status "WARN" "Web audit cancelled"
        exit 0
    fi
}

create_result_dirs() {
    local base_dir=$1
    mkdir -p "${base_dir}"
    print_status "SUCCESS" "Result directory created: $base_dir"
}

extract_domain() {
    local url=$1
    # Extract domain from URL
    echo "$url" | sed -E 's#https?://([^:/]+).*#\1#'
}

################################################################################
# WEB AUDIT FUNCTIONS
################################################################################

run_nikto() {
    local url=$1
    local output_dir=$2
    local log_file="${output_dir}/nikto_scan.log"

    print_status "INFO" "Running Nikto web server scan..."
    if check_tool "nikto"; then
        timeout $TIMEOUT_PER_TOOL nikto -h "$url" \
            -o "${output_dir}/nikto_report.html" \
            >> "$log_file" 2>&1 && \
        print_status "SUCCESS" "Nikto scan completed" || \
        print_status "FAIL" "Nikto scan failed"
    fi
}

run_whatweb() {
    local url=$1
    local output_dir=$2
    local log_file="${output_dir}/whatweb_scan.log"

    print_status "INFO" "Running Whatweb fingerprinting..."
    if check_tool "whatweb"; then
        timeout $TIMEOUT_PER_TOOL whatweb -a 3 --log-json "${output_dir}/whatweb_results.json" \
            "$url" >> "$log_file" 2>&1 && \
        print_status "SUCCESS" "Whatweb scan completed" || \
        print_status "FAIL" "Whatweb scan failed"
    fi
}

run_wafw00f() {
    local url=$1
    local output_dir=$2
    local log_file="${output_dir}/wafw00f_scan.log"

    print_status "INFO" "Running WAF detection..."
    if check_tool "wafw00f"; then
        timeout $TIMEOUT_PER_TOOL wafw00f -i "$url" -o "${output_dir}/wafw00f_report.json" \
            >> "$log_file" 2>&1 && \
        print_status "SUCCESS" "WAF detection completed" || \
        print_status "WARN" "WAF detection skipped"
    fi
}

run_directory_scan() {
    local url=$1
    local output_dir=$2

    print_status "INFO" "Running directory enumeration..."
    if check_tool "gobuster"; then
        timeout $TIMEOUT_PER_TOOL gobuster dir -u "$url" \
            -w /usr/share/wordlists/dirb/common.txt \
            -o "${output_dir}/gobuster_results.txt" \
            >> "${output_dir}/gobuster_scan.log" 2>&1 && \
        print_status "SUCCESS" "Gobuster scan completed" || \
        print_status "WARN" "Gobuster scan failed"
    elif check_tool "dirb"; then
        timeout $TIMEOUT_PER_TOOL dirb "$url" /usr/share/wordlists/dirb/common.txt \
            -o "${output_dir}/dirb_results.txt" \
            >> "${output_dir}/dirb_scan.log" 2>&1 && \
        print_status "SUCCESS" "Dirb scan completed" || \
        print_status "WARN" "Dirb scan failed"
    fi
}

run_wpscan() {
    local url=$1
    local output_dir=$2
    local log_file="${output_dir}/wpscan_scan.log"

    print_status "INFO" "Detecting WordPress installation..."
    if check_tool "wpscan"; then
        # Quick check for WordPress
        if curl -s "$url" | grep -q "wp-content\|wp-includes\|wordpress" 2>/dev/null; then
            print_status "INFO" "WordPress detected, running WPScan..."
            timeout $TIMEOUT_PER_TOOL wpscan --url "$url" \
                --output "${output_dir}/wpscan_report.json" \
                --format json >> "$log_file" 2>&1 && \
            print_status "SUCCESS" "WPScan completed" || \
            print_status "WARN" "WPScan failed"
        else
            print_status "INFO" "WordPress not detected, skipping WPScan"
        fi
    fi
}

run_sqlmap() {
    local url=$1
    local output_dir=$2
    local log_file="${output_dir}/sqlmap_scan.log"

    print_status "INFO" "Running SQLMap for SQL injection testing..."
    if check_tool "sqlmap"; then
        timeout $TIMEOUT_PER_TOOL sqlmap -u "$url" --crawl=2 --forms --batch \
            --output-dir="${output_dir}/sqlmap_output" \
            >> "$log_file" 2>&1 && \
        print_status "SUCCESS" "SQLMap scan completed" || \
        print_status "WARN" "SQLMap scan failed or no vulnerabilities found"
    fi
}

run_xsser() {
    local url=$1
    local output_dir=$2
    local log_file="${output_dir}/xsser_scan.log"

    print_status "INFO" "Running XSSer for XSS detection..."
    if check_tool "xsser"; then
        timeout $TIMEOUT_PER_TOOL xsser --url "$url" --crawl=1 --auto \
            > "${output_dir}/xsser_results.txt" 2>&1 && \
        print_status "SUCCESS" "XSSer scan completed" || \
        print_status "WARN" "XSSer scan failed"
    fi
}

run_ssl_scan() {
    local url=$1
    local output_dir=$2
    local domain=$(extract_domain "$url")
    local log_file="${output_dir}/ssl_scan.log"

    print_status "INFO" "Running SSL/TLS configuration analysis..."

    # Use testssl.sh if available
    if check_tool "testssl.sh"; then
        timeout $TIMEOUT_PER_TOOL testssl.sh --json > "${output_dir}/testssl_report.json" \
            "$domain" >> "$log_file" 2>&1 && \
        print_status "SUCCESS" "testssl.sh completed" || \
        print_status "WARN" "testssl.sh failed"
    # Fallback to OpenSSL checks
    elif check_tool "openssl"; then
        {
            echo "=== SSL Certificate Information ===" >> "$log_file"
            echo | openssl s_client -connect "$domain:443" -showcerts
            echo ""
            echo "=== Supported Ciphers ===" >> "$log_file"
            openssl s_client -connect "$domain:443" -cipher 'ALL' < /dev/null
        } > "${output_dir}/openssl_results.txt" 2>&1 && \
        print_status "SUCCESS" "OpenSSL analysis completed" || \
        print_status "WARN" "SSL analysis failed"
    fi
}

################################################################################
# REPORT GENERATION
################################################################################

generate_report() {
    local output_dir=$1
    local url=$2
    local report_file="${output_dir}/WEB_AUDIT_REPORT.txt"

    cat > "$report_file" << EOF
╔═══════════════════════════════════════════════════════════════╗
║              WEB AUDIT EXECUTION REPORT                       ║
╚═══════════════════════════════════════════════════════════════╝

Execution Date: $(date)
Target URL: $url
Client: $CLIENT_NAME
Domain: $(extract_domain "$url")

Output Directory: $output_dir
Master Log: $MASTER_LOG

═══════════════════════════════════════════════════════════════

Scans Performed:
  ✓ Nikto Web Server Scan
  ✓ Whatweb Fingerprinting
  ✓ WAF Detection
  ✓ Directory/File Enumeration
  ✓ WordPress Vulnerability Scan (if applicable)
  ✓ SQL Injection Detection
  ✓ XSS Vulnerability Detection
  ✓ SSL/TLS Configuration Analysis

Output Files:
  Nikto Report:        ${output_dir}/nikto_report.html
  Whatweb Results:     ${output_dir}/whatweb_results.json
  WAF Detection:       ${output_dir}/wafw00f_report.json
  Directory Enum:      ${output_dir}/gobuster_results.txt or dirb_results.txt
  WordPress Scan:      ${output_dir}/wpscan_report.json (if applicable)
  SQLMap Results:      ${output_dir}/sqlmap_output/
  XSSer Results:       ${output_dir}/xsser_results.txt
  SSL Analysis:        ${output_dir}/testssl_report.json or openssl_results.txt

═══════════════════════════════════════════════════════════════

Recommended Next Steps:
  1. Review Nikto findings for known vulnerabilities
  2. Check WAF detection results for protection levels
  3. Analyze directory enumeration for sensitive files
  4. Investigate any SQL injection findings
  5. Review SSL/TLS configuration for weak ciphers
  6. If WordPress: review WPScan vulnerabilities and plugins
  7. Test application functionality against findings
  8. Prioritize remediation by severity and impact

═══════════════════════════════════════════════════════════════
Generated by Kali Linux Purple Team Web Audit Suite
EOF

    cat "$report_file"
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Default values
    TARGET_URL=""
    CLIENT_NAME="Web Audit Assessment"
    OUTPUT_DIR="/results"
    SKIP_TOOLS=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                TARGET_URL="$2"
                shift 2
                ;;
            -c|--client)
                CLIENT_NAME="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT_PER_TOOL="$2"
                shift 2
                ;;
            -s|--skip)
                IFS=',' read -ra SKIP_TOOLS <<< "$2"
                shift 2
                ;;
            -h|--help)
                display_help
                exit 0
                ;;
            *)
                print_status "FAIL" "Unknown option: $1"
                display_help
                exit 1
                ;;
        esac
    done

    # Validation
    if [[ -z "$TARGET_URL" ]]; then
        print_status "FAIL" "Target URL is required (-u option)"
        display_help
        exit 1
    fi

    if ! validate_url "$TARGET_URL"; then
        print_status "FAIL" "Invalid URL format: $TARGET_URL (must start with http:// or https://)"
        exit 1
    fi

    # Initialize
    display_banner
    ethical_disclaimer
    init_logging

    # Setup results directory
    RESULT_DIR="${OUTPUT_DIR}/web_audit_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESULT_DIR"
    create_result_dirs "$RESULT_DIR"

    # Confirm target
    confirm_target "$TARGET_URL"

    print_status "INFO" "Web audit initiated for $TARGET_URL"
    print_status "INFO" "Results will be saved to: $RESULT_DIR"
    echo ""

    # Run scans
    run_nikto "$TARGET_URL" "$RESULT_DIR"
    run_whatweb "$TARGET_URL" "$RESULT_DIR"
    run_wafw00f "$TARGET_URL" "$RESULT_DIR"
    run_directory_scan "$TARGET_URL" "$RESULT_DIR"
    run_wpscan "$TARGET_URL" "$RESULT_DIR"
    run_sqlmap "$TARGET_URL" "$RESULT_DIR"
    run_xsser "$TARGET_URL" "$RESULT_DIR"
    run_ssl_scan "$TARGET_URL" "$RESULT_DIR"

    # Generate report
    echo ""
    generate_report "$RESULT_DIR" "$TARGET_URL"

    print_status "SUCCESS" "Web audit completed successfully"
    print_status "INFO" "Master log: $MASTER_LOG"
}

# Run main
main "$@"
