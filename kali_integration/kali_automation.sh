#!/bin/bash

################################################################################
# KALI LINUX PURPLE TEAM AUTOMATION SUITE
# Main Orchestration Script for Automated Pentest Workflow
# Version: 1.0
################################################################################

# Color definitions for purple team branding
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MASTER_LOG_DIR="/var/log/purple_team"
TIMEOUT_PER_TOOL=1800  # 30 minutes per tool
TOOL_CHECK_TIMEOUT=5

################################################################################
# UTILITY FUNCTIONS
################################################################################

# Initialize logging
init_logging() {
    mkdir -p "$MASTER_LOG_DIR"
    MASTER_LOG="${MASTER_LOG_DIR}/pentest_$(date +%Y%m%d_%H%M%S).log"
    touch "$MASTER_LOG"
}

# Log function with timestamp
log_message() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$MASTER_LOG"
}

# Color print function
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

# Display banner
display_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║    KALI LINUX PURPLE TEAM AUTOMATION SUITE                    ║"
    echo "║    Automated Pentest Workflow Orchestration                   ║"
    echo "║    Version 1.0                                                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Display ethical use disclaimer
ethical_disclaimer() {
    echo -e "${RED}"
    echo "════════════════════════════════════════════════════════════════"
    echo "                    ETHICAL USE DISCLAIMER"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "This tool is designed for authorized security testing ONLY."
    echo "Unauthorized access to computer systems is illegal."
    echo ""
    echo "You are responsible for:"
    echo "  • Obtaining written authorization before testing"
    echo "  • Complying with all applicable laws and regulations"
    echo "  • Protecting the confidentiality of findings"
    echo "  • Following your organization's security policies"
    echo ""
    echo -e "${RED}Misuse of this tool may result in criminal prosecution.${NC}"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
}

# Display help
display_help() {
    cat << EOF
${PURPLE}USAGE:${NC}
    ./kali_automation.sh [OPTIONS]

${PURPLE}OPTIONS:${NC}
    -t, --target IP/CIDR         Target IP address or CIDR range (REQUIRED)
    -d, --domain DOMAIN          Target domain name (optional)
    -c, --client "CLIENT NAME"   Client name for reporting (optional)
    -o, --output /path/to/dir    Output directory for results (default: /results/)
    -p, --phase PHASE            Run specific phase only: 1-4 (default: all)
    -s, --skip TOOLS             Comma-separated tools to skip (e.g., nmap,nikto)
    -h, --help                   Display this help message

${PURPLE}PHASES:${NC}
    Phase 1: RECON       - Service discovery and enumeration
    Phase 2: ENUM        - Deeper enumeration and fingerprinting
    Phase 3: VULN SCAN   - Vulnerability detection
    Phase 4: WEB         - Web application auditing

${PURPLE}EXAMPLES:${NC}
    # Full pentest of IP range
    ./kali_automation.sh -t 192.168.1.0/24 -d example.com -c "Acme Corp"

    # Single host with all phases
    ./kali_automation.sh -t 192.168.1.10 -c "Server Audit"

    # Web-only scanning
    ./kali_automation.sh -t 192.168.1.20 -d example.com -p 4

    # Skip slow tools
    ./kali_automation.sh -t 10.0.0.0/8 -c "Large Scope" -s "masscan,nikto"

${PURPLE}OUTPUT:${NC}
    Results saved to: /results/CLIENT_DATE/
    Structure:
        ├── recon/       - Network reconnaissance results
        ├── enum/        - Enumeration results
        ├── vuln/        - Vulnerability scan results
        ├── web/         - Web application audit results
        └── logs/        - Detailed phase logs

${RED}DISCLAIMER:${NC} Unauthorized access is illegal. Obtain written permission before testing.

EOF
}

# Check if command exists
command_exists() {
    command -v "$1" &> /dev/null
    return $?
}

# Tool availability check
check_tool() {
    local tool=$1
    if ! command_exists "$tool"; then
        print_status "WARN" "Tool not found: $tool"
        return 1
    fi
    return 0
}

# Validate IP/CIDR
validate_target() {
    local target=$1
    # Simple validation for IP or CIDR
    if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    fi
    return 1
}

# Confirm target before starting
confirm_target() {
    local target=$1
    local domain=$2
    echo -e "${YELLOW}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    CONFIRM TARGET DETAILS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "Target IP/Range: $target"
    [[ -n $domain ]] && echo "Domain: $domain"
    echo "Client: $CLIENT_NAME"
    echo "Output Directory: $OUTPUT_DIR"
    echo ""
    read -p "Proceed with pentest? (yes/no): " -r confirmation
    if [[ ! $confirmation =~ ^[Yy][Ee][Ss]$ ]]; then
        print_status "WARN" "Pentest cancelled by user"
        exit 0
    fi
}

# Create result directories
create_result_dirs() {
    local base_dir=$1
    mkdir -p "${base_dir}/recon"
    mkdir -p "${base_dir}/enum"
    mkdir -p "${base_dir}/vuln"
    mkdir -p "${base_dir}/web"
    mkdir -p "${base_dir}/logs"
    print_status "SUCCESS" "Result directories created: $base_dir"
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local message=$3
    local percent=$((current * 100 / total))
    printf "\r${CYAN}[Progress]${NC} %3d%% | %s" "$percent" "$message"
}

################################################################################
# PHASE 1: RECONNAISSANCE
################################################################################

phase_1_recon() {
    print_status "PHASE" "PHASE 1 - RECONNAISSANCE"
    local recon_dir="${RESULT_DIR}/recon"
    local phase_log="${RESULT_DIR}/logs/phase_1_recon.log"

    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"
    echo "PHASE 1: RECONNAISSANCE - $(date)" | tee -a "$phase_log"
    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"

    # NMAP - TCP Full Scan
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " nmap " ]]; then
        print_status "INFO" "Running Nmap TCP full scan..."
        show_progress 1 5 "Nmap TCP Full Scan"
        if check_tool "nmap"; then
            timeout $TIMEOUT_PER_TOOL nmap -sS -p- --open -sV --script discovery \
                -oX "${recon_dir}/nmap_tcp_full.xml" \
                -oN "${recon_dir}/nmap_tcp_full.txt" \
                "$TARGET_IP" >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "Nmap TCP scan completed" || \
            print_status "FAIL" "Nmap TCP scan failed"
        fi
    fi

    # NMAP - UDP Top 100
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " nmap " ]]; then
        print_status "INFO" "Running Nmap UDP scan..."
        show_progress 2 5 "Nmap UDP Top 100"
        if check_tool "nmap"; then
            timeout $TIMEOUT_PER_TOOL nmap -sU --top-ports 100 \
                -oX "${recon_dir}/nmap_udp_top100.xml" \
                -oN "${recon_dir}/nmap_udp_top100.txt" \
                "$TARGET_IP" >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "Nmap UDP scan completed" || \
            print_status "FAIL" "Nmap UDP scan failed"
        fi
    fi

    # Masscan (faster alternative for large ranges)
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " masscan " ]]; then
        if check_tool "masscan"; then
            print_status "INFO" "Running Masscan..."
            show_progress 3 5 "Masscan Fast Scan"
            timeout $TIMEOUT_PER_TOOL masscan "$TARGET_IP" -p1-65535 --max-rate 1000 \
                -oX "${recon_dir}/masscan_results.xml" >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "Masscan completed" || \
            print_status "WARN" "Masscan skipped or failed"
        fi
    fi

    # WhatWeb
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " whatweb " ]]; then
        if check_tool "whatweb"; then
            print_status "INFO" "Running Whatweb fingerprinting..."
            show_progress 4 5 "Whatweb Fingerprinting"
            timeout $TIMEOUT_PER_TOOL whatweb -a 3 "$TARGET_IP" \
                > "${recon_dir}/whatweb_results.txt" 2>&1 && \
            print_status "SUCCESS" "Whatweb completed" || \
            print_status "WARN" "Whatweb skipped or failed"
        fi
    fi

    # WAF Detection
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " wafw00f " ]]; then
        if check_tool "wafw00f"; then
            print_status "INFO" "Running WAF detection..."
            show_progress 5 5 "WAF Detection"
            timeout $TIMEOUT_PER_TOOL wafw00f "$TARGET_IP" \
                > "${recon_dir}/wafw00f_results.txt" 2>&1 && \
            print_status "SUCCESS" "WAF detection completed" || \
            print_status "WARN" "WAF detection skipped or failed"
        fi
    fi

    echo "" | tee -a "$phase_log"
    print_status "SUCCESS" "Phase 1 reconnaissance completed"
}

################################################################################
# PHASE 2: ENUMERATION
################################################################################

phase_2_enum() {
    print_status "PHASE" "PHASE 2 - ENUMERATION"
    local enum_dir="${RESULT_DIR}/enum"
    local phase_log="${RESULT_DIR}/logs/phase_2_enum.log"

    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"
    echo "PHASE 2: ENUMERATION - $(date)" | tee -a "$phase_log"
    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"

    # Enum4Linux (SMB enumeration)
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " enum4linux " ]]; then
        if check_tool "enum4linux"; then
            print_status "INFO" "Running Enum4Linux..."
            show_progress 1 4 "Enum4Linux SMB Enumeration"
            timeout $TIMEOUT_PER_TOOL enum4linux -a "$TARGET_IP" \
                > "${enum_dir}/enum4linux_results.txt" 2>&1 && \
            print_status "SUCCESS" "Enum4Linux completed" || \
            print_status "WARN" "Enum4Linux skipped or failed"
        fi
    fi

    # SMBClient enumeration
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " smbclient " ]]; then
        if check_tool "smbclient"; then
            print_status "INFO" "Running SMBClient enumeration..."
            show_progress 2 4 "SMBClient Share Enumeration"
            timeout $TIMEOUT_PER_TOOL smbclient -L "//$TARGET_IP" -N \
                > "${enum_dir}/smbclient_shares.txt" 2>&1 && \
            print_status "SUCCESS" "SMBClient enumeration completed" || \
            print_status "WARN" "SMBClient skipped or failed"
        fi
    fi

    # Nikto Web Server Scan
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " nikto " ]]; then
        if check_tool "nikto"; then
            print_status "INFO" "Running Nikto web server scan..."
            show_progress 3 4 "Nikto Web Scan"
            timeout $TIMEOUT_PER_TOOL nikto -h "http://$TARGET_IP" -o "${enum_dir}/nikto_results.html" \
                >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "Nikto completed" || \
            print_status "WARN" "Nikto skipped or failed"
        fi
    fi

    # Gobuster/Dirb for directory enumeration
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " gobuster " ]]; then
        if check_tool "gobuster"; then
            print_status "INFO" "Running Gobuster directory scan..."
            show_progress 4 4 "Gobuster Directory Enumeration"
            timeout $TIMEOUT_PER_TOOL gobuster dir -u "http://$TARGET_IP" -w /usr/share/wordlists/dirb/common.txt \
                -o "${enum_dir}/gobuster_dirs.txt" >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "Gobuster completed" || \
            print_status "WARN" "Gobuster skipped or failed"
        elif check_tool "dirb"; then
            print_status "INFO" "Running Dirb (Gobuster not found)..."
            timeout $TIMEOUT_PER_TOOL dirb "http://$TARGET_IP" /usr/share/wordlists/dirb/common.txt \
                -o "${enum_dir}/dirb_results.txt" >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "Dirb completed" || \
            print_status "WARN" "Dirb skipped or failed"
        fi
    fi

    echo "" | tee -a "$phase_log"
    print_status "SUCCESS" "Phase 2 enumeration completed"
}

################################################################################
# PHASE 3: VULNERABILITY SCANNING
################################################################################

phase_3_vuln_scan() {
    print_status "PHASE" "PHASE 3 - VULNERABILITY SCANNING"
    local vuln_dir="${RESULT_DIR}/vuln"
    local phase_log="${RESULT_DIR}/logs/phase_3_vuln_scan.log"

    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"
    echo "PHASE 3: VULNERABILITY SCANNING - $(date)" | tee -a "$phase_log"
    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"

    # Nmap Vulnerability Scripts
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " nmap " ]]; then
        if check_tool "nmap"; then
            print_status "INFO" "Running Nmap vulnerability scripts..."
            show_progress 1 2 "Nmap Vulnerability Detection"
            timeout $TIMEOUT_PER_TOOL nmap -sV --script vuln "$TARGET_IP" \
                -oX "${vuln_dir}/nmap_vuln.xml" \
                -oN "${vuln_dir}/nmap_vuln.txt" >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "Nmap vuln scan completed" || \
            print_status "FAIL" "Nmap vuln scan failed"
        fi
    fi

    # Searchsploit against found services
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " searchsploit " ]]; then
        if check_tool "searchsploit"; then
            print_status "INFO" "Running Searchsploit against discovered services..."
            show_progress 2 2 "Searchsploit Exploit Research"
            # Extract service names from nmap results and search
            if [[ -f "${vuln_dir}/nmap_vuln.txt" ]]; then
                timeout $TIMEOUT_PER_TOOL searchsploit -u >> "$phase_log" 2>&1
                timeout $TIMEOUT_PER_TOOL bash -c "grep -oP 'Service: \K[^/]+' '${vuln_dir}/nmap_vuln.txt' | sort -u | while read service; do searchsploit \"\$service\"; done" \
                    > "${vuln_dir}/searchsploit_results.txt" 2>&1 && \
                print_status "SUCCESS" "Searchsploit completed" || \
                print_status "WARN" "Searchsploit skipped or failed"
            fi
        fi
    fi

    echo "" | tee -a "$phase_log"
    print_status "SUCCESS" "Phase 3 vulnerability scanning completed"
}

################################################################################
# PHASE 4: WEB APPLICATION AUDITING
################################################################################

phase_4_web_audit() {
    print_status "PHASE" "PHASE 4 - WEB APPLICATION AUDITING"
    local web_dir="${RESULT_DIR}/web"
    local phase_log="${RESULT_DIR}/logs/phase_4_web_audit.log"

    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"
    echo "PHASE 4: WEB APPLICATION AUDITING - $(date)" | tee -a "$phase_log"
    echo "═══════════════════════════════════════════════════════════════" | tee -a "$phase_log"

    # SQLMap
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " sqlmap " ]]; then
        if check_tool "sqlmap"; then
            print_status "INFO" "Running SQLMap database testing..."
            show_progress 1 3 "SQLMap Database Vulnerability"
            # Crawl and test for SQL injection
            timeout $TIMEOUT_PER_TOOL sqlmap -u "http://$TARGET_IP" --crawl=2 --forms --batch \
                -o "${web_dir}/sqlmap_results.txt" >> "$phase_log" 2>&1 && \
            print_status "SUCCESS" "SQLMap completed" || \
            print_status "WARN" "SQLMap skipped or failed"
        fi
    fi

    # WPScan (if WordPress detected)
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " wpscan " ]]; then
        if check_tool "wpscan"; then
            print_status "INFO" "Checking for WordPress installation..."
            show_progress 2 3 "WPScan WordPress Security"
            if curl -s "http://$TARGET_IP/wp-admin/" | grep -q "WordPress" 2>/dev/null; then
                print_status "INFO" "WordPress detected, running WPScan..."
                timeout $TIMEOUT_PER_TOOL wpscan --url "http://$TARGET_IP/" --output "${web_dir}/wpscan_results.json" \
                    --format json >> "$phase_log" 2>&1 && \
                print_status "SUCCESS" "WPScan completed" || \
                print_status "WARN" "WPScan failed"
            else
                print_status "INFO" "WordPress not detected, skipping WPScan"
            fi
        fi
    fi

    # XSSer
    if [[ ! " ${SKIP_TOOLS[@]} " =~ " xsser " ]]; then
        if check_tool "xsser"; then
            print_status "INFO" "Running XSSer for XSS detection..."
            show_progress 3 3 "XSSer XSS Detection"
            timeout $TIMEOUT_PER_TOOL xsser --url "http://$TARGET_IP/" --crawl=1 --auto \
                > "${web_dir}/xsser_results.txt" 2>&1 && \
            print_status "SUCCESS" "XSSer completed" || \
            print_status "WARN" "XSSer skipped or failed"
        fi
    fi

    echo "" | tee -a "$phase_log"
    print_status "SUCCESS" "Phase 4 web auditing completed"
}

################################################################################
# RESULTS IMPORT
################################################################################

import_results() {
    print_status "INFO" "Importing results into unified database..."

    # Check if kali_importer.py exists
    if [[ -f "${SCRIPT_DIR}/kali_importer.py" ]]; then
        python3 "${SCRIPT_DIR}/kali_importer.py" --results-dir "$RESULT_DIR" \
            --client "$CLIENT_NAME" --target "$TARGET_IP" >> "$MASTER_LOG" 2>&1 && \
        print_status "SUCCESS" "Results imported successfully" || \
        print_status "WARN" "Results import failed (kali_importer.py issue)"
    else
        print_status "WARN" "kali_importer.py not found, skipping result import"
    fi
}

################################################################################
# FINAL REPORT
################################################################################

generate_summary() {
    local summary_file="${RESULT_DIR}/PENTEST_SUMMARY.txt"

    cat > "$summary_file" << EOF
╔═══════════════════════════════════════════════════════════════╗
║              PENTEST EXECUTION SUMMARY                        ║
╚═══════════════════════════════════════════════════════════════╝

Execution Date: $(date)
Client: $CLIENT_NAME
Target: $TARGET_IP
Domain: $TARGET_DOMAIN

Results Location: $RESULT_DIR

Phase Completion Status:
  Phase 1 - Reconnaissance: COMPLETED
  Phase 2 - Enumeration: COMPLETED
  Phase 3 - Vulnerability Scanning: COMPLETED
  Phase 4 - Web Auditing: COMPLETED

Output Files:
  Reconnaissance:   $RESULT_DIR/recon/
  Enumeration:      $RESULT_DIR/enum/
  Vulnerabilities:  $RESULT_DIR/vuln/
  Web Audit:        $RESULT_DIR/web/
  Logs:             $RESULT_DIR/logs/

Master Log: $MASTER_LOG

═══════════════════════════════════════════════════════════════

For detailed findings, review individual phase logs in logs/ directory.

Next Steps:
  1. Review vulnerability findings
  2. Analyze impact and severity
  3. Prioritize remediation efforts
  4. Schedule follow-up testing

═══════════════════════════════════════════════════════════════
EOF

    cat "$summary_file"
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Default values
    TARGET_IP=""
    TARGET_DOMAIN=""
    CLIENT_NAME="Security Assessment"
    OUTPUT_DIR="/results"
    PHASE_START=1
    PHASE_END=4
    SKIP_TOOLS=()

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET_IP="$2"
                shift 2
                ;;
            -d|--domain)
                TARGET_DOMAIN="$2"
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
            -p|--phase)
                PHASE_START="$2"
                PHASE_END="$2"
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
    if [[ -z "$TARGET_IP" ]]; then
        print_status "FAIL" "Target IP/range is required (-t option)"
        display_help
        exit 1
    fi

    if ! validate_target "$TARGET_IP"; then
        print_status "FAIL" "Invalid target format: $TARGET_IP"
        exit 1
    fi

    # Initialize
    display_banner
    ethical_disclaimer
    init_logging

    # Create results directory
    RESULT_DIR="${OUTPUT_DIR}/pentest_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESULT_DIR"
    create_result_dirs "$RESULT_DIR"

    # Confirm before proceeding
    confirm_target "$TARGET_IP" "$TARGET_DOMAIN"

    print_status "INFO" "Pentest initiated against $TARGET_IP"
    print_status "INFO" "Results will be saved to: $RESULT_DIR"

    # Run phases
    [[ $PHASE_START -le 1 && $PHASE_END -ge 1 ]] && phase_1_recon
    [[ $PHASE_START -le 2 && $PHASE_END -ge 2 ]] && phase_2_enum
    [[ $PHASE_START -le 3 && $PHASE_END -ge 3 ]] && phase_3_vuln_scan
    [[ $PHASE_START -le 4 && $PHASE_END -ge 4 ]] && phase_4_web_audit

    # Import and summarize
    import_results
    echo ""
    generate_summary

    print_status "SUCCESS" "Pentest workflow completed successfully"
    print_status "INFO" "Master log: $MASTER_LOG"
}

# Run main function
main "$@"
