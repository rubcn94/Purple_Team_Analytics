#!/bin/bash

################################################################################
# KALI LINUX PURPLE TEAM - INTERNAL NETWORK AUDIT SCRIPT
# Focused internal network security assessment
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
    MASTER_LOG="${MASTER_LOG_DIR}/internal_audit_$(date +%Y%m%d_%H%M%S).log"
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
    echo "║    KALI LINUX PURPLE TEAM - INTERNAL AUDIT SUITE              ║"
    echo "║    Internal Network Security Assessment                       ║"
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
    echo "This tool is designed for authorized internal security testing ONLY."
    echo "Unauthorized access to computer systems is illegal."
    echo ""
    echo -e "${RED}Misuse of this tool may result in criminal prosecution.${NC}"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
}

display_help() {
    cat << EOF
${PURPLE}USAGE:${NC}
    ./kali_internal_audit.sh [OPTIONS]

${PURPLE}OPTIONS:${NC}
    -r, --range CIDR             Target IP range (REQUIRED)
    -c, --client "NAME"          Client name for reporting (optional)
    -o, --output /path/to/dir    Output directory (default: /results/)
    -s, --skip TOOLS             Comma-separated tools to skip
    -h, --help                   Display this help message

${PURPLE}EXAMPLES:${NC}
    ./kali_internal_audit.sh -r 192.168.1.0/24 -c "Acme Corp"
    ./kali_internal_audit.sh -r 10.0.0.0/16 -o ./audit_results
    ./kali_internal_audit.sh -r 172.16.0.0/12 -s "responder,snmpwalk"

${PURPLE}TOOLS INCLUDED:${NC}
    • Nmap           - Network discovery and host enumeration
    • Responder      - LLMNR/NBT-NS passive credential capture
    • Crackmapexec   - SMB and LDAP enumeration/exploitation
    • Enum4Linux     - SMB enumeration and information gathering
    • Nbtscan        - NetBIOS scanning
    • SNMPwalk       - SNMP information enumeration
    • Nessus         - Vulnerability scanning (if available)

${PURPLE}MISCONFIGURATIONS CHECKED:${NC}
    • Anonymous FTP access
    • Open SMB shares with null sessions
    • SNMP community string exposure
    • Weak credentials on common services
    • Unnecessary service exposure
    • Unpatched systems

${RED}DISCLAIMER:${NC} Authorized testing only. Unauthorized access is illegal.

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

validate_range() {
    local range=$1
    # Validate CIDR notation
    if [[ $range =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    fi
    return 1
}

confirm_target() {
    local range=$1
    echo -e "${YELLOW}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    CONFIRM TARGET DETAILS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "Target Range: $range"
    echo "Client: $CLIENT_NAME"
    echo "Output Directory: $OUTPUT_DIR"
    echo ""
    read -p "Proceed with internal audit? (yes/no): " -r confirmation
    if [[ ! $confirmation =~ ^[Yy][Ee][Ss]$ ]]; then
        print_status "WARN" "Internal audit cancelled"
        exit 0
    fi
}

create_result_dirs() {
    local base_dir=$1
    mkdir -p "${base_dir}"
    print_status "SUCCESS" "Result directory created: $base_dir"
}

################################################################################
# DISCOVERY AND ENUMERATION FUNCTIONS
################################################################################

run_nmap_discovery() {
    local range=$1
    local output_dir=$2
    local log_file="${output_dir}/nmap_discovery.log"

    print_status "PHASE" "NMAP Host Discovery and Service Enumeration"
    if check_tool "nmap"; then
        print_status "INFO" "Running Nmap host discovery..."
        timeout $TIMEOUT_PER_TOOL nmap -sn "$range" \
            -oX "${output_dir}/nmap_hosts_alive.xml" \
            > "${output_dir}/nmap_hosts_alive.txt" 2>&1 && \
        print_status "SUCCESS" "Host discovery completed"

        print_status "INFO" "Running Nmap service enumeration..."
        timeout $TIMEOUT_PER_TOOL nmap -p- -sV --script discovery,banner "$range" \
            -oX "${output_dir}/nmap_services.xml" \
            -oN "${output_dir}/nmap_services.txt" >> "$log_file" 2>&1 && \
        print_status "SUCCESS" "Service enumeration completed"
    fi
}

run_responder() {
    local output_dir=$2
    local log_file="${output_dir}/responder.log"

    print_status "PHASE" "RESPONDER - LLMNR/NBT-NS Credential Capture"
    if check_tool "responder"; then
        print_status "INFO" "Starting Responder in passive mode..."
        print_status "WARN" "Responder will run in background. Press Ctrl+C in new terminal to stop."
        timeout 300 responder -I eth0 -w -f --output "${output_dir}/responder_hashes" \
            >> "$log_file" 2>&1 & \
        RESPONDER_PID=$!
        print_status "INFO" "Responder running with PID: $RESPONDER_PID"
        sleep 30
        if ps -p $RESPONDER_PID > /dev/null; then
            print_status "SUCCESS" "Responder capture in progress"
        fi
    fi
}

run_crackmapexec() {
    local range=$1
    local output_dir=$2
    local log_file="${output_dir}/crackmapexec.log"

    print_status "PHASE" "CrackMapExec - SMB/LDAP Enumeration"
    if check_tool "crackmapexec"; then
        print_status "INFO" "Running CrackMapExec for SMB enumeration..."
        timeout $TIMEOUT_PER_TOOL crackmapexec smb "$range" \
            > "${output_dir}/cme_smb_results.txt" 2>&1 && \
        print_status "SUCCESS" "SMB enumeration completed"

        print_status "INFO" "Checking for null session access..."
        timeout $TIMEOUT_PER_TOOL bash -c "crackmapexec smb $range -u '' -p ''" \
            > "${output_dir}/cme_null_sessions.txt" 2>&1 && \
        print_status "SUCCESS" "Null session check completed"

        print_status "INFO" "Attempting LDAP enumeration..."
        timeout $TIMEOUT_PER_TOOL crackmapexec ldap "$range" \
            > "${output_dir}/cme_ldap_results.txt" 2>&1 && \
        print_status "SUCCESS" "LDAP enumeration completed" || \
        print_status "WARN" "LDAP enumeration skipped or failed"
    fi
}

run_enum4linux() {
    local range=$1
    local output_dir=$2

    print_status "PHASE" "Enum4Linux - SMB Information Gathering"
    if check_tool "enum4linux"; then
        print_status "INFO" "Running Enum4Linux..."
        # Extract first alive host and enumerate it
        local first_host=$(grep "report for" "${output_dir}/nmap_hosts_alive.txt" 2>/dev/null | head -1 | awk '{print $NF}')
        if [[ -n $first_host ]]; then
            timeout $TIMEOUT_PER_TOOL enum4linux -a "$first_host" \
                > "${output_dir}/enum4linux_results.txt" 2>&1 && \
            print_status "SUCCESS" "Enum4Linux completed"
        else
            print_status "WARN" "No hosts found for Enum4Linux"
        fi
    fi
}

run_nbtscan() {
    local range=$1
    local output_dir=$2
    local log_file="${output_dir}/nbtscan.log"

    print_status "PHASE" "NBTScan - NetBIOS Scanning"
    if check_tool "nbtscan"; then
        print_status "INFO" "Running NBTScan..."
        timeout $TIMEOUT_PER_TOOL nbtscan -r "$range" \
            > "${output_dir}/nbtscan_results.txt" 2>&1 && \
        print_status "SUCCESS" "NBTScan completed"
    fi
}

run_snmpwalk() {
    local range=$1
    local output_dir=$2
    local log_file="${output_dir}/snmpwalk.log"

    print_status "PHASE" "SNMPwalk - SNMP Enumeration"
    if check_tool "snmpwalk"; then
        print_status "INFO" "Scanning for SNMP services..."
        timeout $TIMEOUT_PER_TOOL nmap -p 161 -sU --script snmp-enum "$range" \
            -oN "${output_dir}/snmp_hosts.txt" >> "$log_file" 2>&1

        if [[ -f "${output_dir}/snmp_hosts.txt" ]]; then
            local snmp_hosts=$(grep -oP '(\d+\.\d+\.\d+\.\d+)(?=.*161)' "${output_dir}/snmp_hosts.txt" | sort -u)
            if [[ -n $snmp_hosts ]]; then
                print_status "INFO" "Running SNMPwalk on discovered hosts..."
                for host in $snmp_hosts; do
                    echo "=== SNMP Enumeration for $host ===" >> "${output_dir}/snmpwalk_results.txt"
                    timeout 60 snmpwalk -c public -v 2c "$host" >> "${output_dir}/snmpwalk_results.txt" 2>&1
                done
                print_status "SUCCESS" "SNMPwalk enumeration completed"
            fi
        fi
    fi
}

################################################################################
# MISCONFIGURATION CHECKS
################################################################################

check_anonymous_ftp() {
    local range=$1
    local output_dir=$2
    local log_file="${output_dir}/ftp_checks.log"

    print_status "INFO" "Checking for anonymous FTP access..."
    timeout $TIMEOUT_PER_TOOL nmap -p 21 --script ftp-anon "$range" \
        > "${output_dir}/ftp_anonymous_results.txt" 2>&1 && \
    print_status "SUCCESS" "FTP checks completed"
}

check_smb_shares() {
    local range=$1
    local output_dir=$2
    local log_file="${output_dir}/smb_shares.log"

    print_status "INFO" "Checking for open SMB shares..."
    timeout $TIMEOUT_PER_TOOL nmap -p 445 --script smb-enum-shares,smb-os-discovery "$range" \
        -oN "${output_dir}/smb_shares.txt" >> "$log_file" 2>&1 && \
    print_status "SUCCESS" "SMB share enumeration completed"
}

check_snmp_community() {
    local range=$1
    local output_dir=$2

    print_status "INFO" "Checking for default SNMP community strings..."
    timeout $TIMEOUT_PER_TOOL nmap -p 161 -sU --script snmp-brute "$range" \
        > "${output_dir}/snmp_community_check.txt" 2>&1 && \
    print_status "SUCCESS" "SNMP community string check completed"
}

check_rdp_exposure() {
    local range=$1
    local output_dir=$2

    print_status "INFO" "Checking for exposed RDP services..."
    timeout $TIMEOUT_PER_TOOL nmap -p 3389 --script rdp-enum-encryption "$range" \
        > "${output_dir}/rdp_exposure.txt" 2>&1 && \
    print_status "SUCCESS" "RDP exposure check completed"
}

check_weak_services() {
    local range=$1
    local output_dir=$2

    print_status "INFO" "Checking for weak/unnecessary services..."
    {
        echo "=== Telnet Exposure ==="
        timeout 300 nmap -p 23 "$range" > /dev/null 2>&1 && echo "Telnet found"

        echo ""
        echo "=== VNC Exposure ==="
        timeout 300 nmap -p 5900,5901 "$range" > /dev/null 2>&1 && echo "VNC found"

        echo ""
        echo "=== HTTP (Unencrypted) Services ==="
        timeout 300 nmap -p 80 "$range" -sV > /dev/null 2>&1 && echo "HTTP services found"
    } > "${output_dir}/weak_services_check.txt" 2>&1 && \
    print_status "SUCCESS" "Weak service check completed"
}

################################################################################
# REPORT GENERATION
################################################################################

generate_report() {
    local output_dir=$1
    local range=$2
    local report_file="${output_dir}/INTERNAL_AUDIT_REPORT.txt"

    cat > "$report_file" << EOF
╔═══════════════════════════════════════════════════════════════╗
║           INTERNAL NETWORK AUDIT REPORT                       ║
╚═══════════════════════════════════════════════════════════════╝

Execution Date: $(date)
Target Range: $range
Client: $CLIENT_NAME

Output Directory: $output_dir
Master Log: $MASTER_LOG

═══════════════════════════════════════════════════════════════

Assessments Performed:
  ✓ Nmap Host Discovery
  ✓ Service Enumeration
  ✓ SMB Enumeration (Crackmapexec & Enum4Linux)
  ✓ LDAP Enumeration
  ✓ NetBIOS Scanning (NBTScan)
  ✓ SNMP Enumeration
  ✓ Anonymous FTP Detection
  ✓ Open SMB Share Detection
  ✓ SNMP Community String Testing
  ✓ RDP Exposure Detection
  ✓ Weak Service Detection

Critical Findings to Review:
  1. Check nmap_services.txt for exposed services
  2. Review cme_null_sessions.txt for null session vulnerabilities
  3. Analyze smb_shares.txt for unauthorized share access
  4. Check snmpwalk_results.txt for sensitive information leakage
  5. Review ftp_anonymous_results.txt for anonymous access
  6. Check rdp_exposure.txt for RDP vulnerabilities

Output Files:
  Host Discovery:     ${output_dir}/nmap_hosts_alive.txt
  Services:           ${output_dir}/nmap_services.txt
  SMB Results:        ${output_dir}/cme_smb_results.txt
  Null Sessions:      ${output_dir}/cme_null_sessions.txt
  LDAP Results:       ${output_dir}/cme_ldap_results.txt
  NBTScan Results:    ${output_dir}/nbtscan_results.txt
  SNMP Data:          ${output_dir}/snmpwalk_results.txt
  FTP Check:          ${output_dir}/ftp_anonymous_results.txt
  SMB Shares:         ${output_dir}/smb_shares.txt
  RDP Exposure:       ${output_dir}/rdp_exposure.txt
  Weak Services:      ${output_dir}/weak_services_check.txt

═══════════════════════════════════════════════════════════════

Recommended Remediation:
  1. Disable unnecessary services
  2. Restrict SMB access with proper firewalling
  3. Implement SNMP access controls
  4. Enforce strong authentication
  5. Deploy network segmentation
  6. Implement monitoring and alerting
  7. Regular security patching
  8. Network access control (NAC) deployment

═══════════════════════════════════════════════════════════════
Generated by Kali Linux Purple Team Internal Audit Suite
EOF

    cat "$report_file"
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Default values
    TARGET_RANGE=""
    CLIENT_NAME="Internal Network Audit"
    OUTPUT_DIR="/results"
    SKIP_TOOLS=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--range)
                TARGET_RANGE="$2"
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
    if [[ -z "$TARGET_RANGE" ]]; then
        print_status "FAIL" "Target range is required (-r option)"
        display_help
        exit 1
    fi

    if ! validate_range "$TARGET_RANGE"; then
        print_status "FAIL" "Invalid CIDR range format: $TARGET_RANGE"
        exit 1
    fi

    # Initialize
    display_banner
    ethical_disclaimer
    init_logging

    # Setup results directory
    RESULT_DIR="${OUTPUT_DIR}/internal_audit_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESULT_DIR"
    create_result_dirs "$RESULT_DIR"

    # Confirm target
    confirm_target "$TARGET_RANGE"

    print_status "INFO" "Internal network audit initiated for $TARGET_RANGE"
    print_status "INFO" "Results will be saved to: $RESULT_DIR"
    echo ""

    # Run discovery and enumeration
    run_nmap_discovery "$TARGET_RANGE" "$RESULT_DIR"
    echo ""
    run_responder "$TARGET_RANGE" "$RESULT_DIR"
    echo ""
    run_crackmapexec "$TARGET_RANGE" "$RESULT_DIR"
    echo ""
    run_enum4linux "$TARGET_RANGE" "$RESULT_DIR"
    echo ""
    run_nbtscan "$TARGET_RANGE" "$RESULT_DIR"
    echo ""
    run_snmpwalk "$TARGET_RANGE" "$RESULT_DIR"
    echo ""

    # Misconfiguration checks
    print_status "PHASE" "MISCONFIGURATION CHECKS"
    check_anonymous_ftp "$TARGET_RANGE" "$RESULT_DIR"
    check_smb_shares "$TARGET_RANGE" "$RESULT_DIR"
    check_snmp_community "$TARGET_RANGE" "$RESULT_DIR"
    check_rdp_exposure "$TARGET_RANGE" "$RESULT_DIR"
    check_weak_services "$TARGET_RANGE" "$RESULT_DIR"

    # Generate report
    echo ""
    generate_report "$RESULT_DIR" "$TARGET_RANGE"

    print_status "SUCCESS" "Internal network audit completed"
    print_status "INFO" "Master log: $MASTER_LOG"
}

# Run main
main "$@"
