#!/bin/bash

################################################################################
# KALI LINUX PURPLE TEAM - WIRELESS AUDIT SCRIPT
# WiFi security assessment and penetration testing
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
    MASTER_LOG="${MASTER_LOG_DIR}/wireless_audit_$(date +%Y%m%d_%H%M%S).log"
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
    echo "║    KALI LINUX PURPLE TEAM - WIRELESS AUDIT SUITE              ║"
    echo "║    WiFi Security Assessment & Penetration Testing             ║"
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
    echo "This tool is designed for authorized wireless security testing ONLY."
    echo "Unauthorized access to wireless networks is ILLEGAL."
    echo ""
    echo "You MUST:"
    echo "  • Obtain written authorization from network owner"
    echo "  • Test only networks you own or have explicit permission to test"
    echo "  • Respect privacy laws and regulations"
    echo ""
    echo -e "${RED}Unauthorized access to wireless networks may result in:${NC}"
    echo "  • Criminal prosecution"
    echo "  • Civil liability"
    echo "  • Substantial fines and imprisonment"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo ""
}

display_help() {
    cat << EOF
${PURPLE}USAGE:${NC}
    ./kali_wireless_audit.sh [OPTIONS]

${PURPLE}OPTIONS:${NC}
    -i, --interface IFACE        Wireless interface (auto-detect if not specified)
    -c, --client "NAME"          Client name for reporting (optional)
    -o, --output /path/to/dir    Output directory (default: /results/)
    -t, --time SECONDS           Capture time in seconds (default: 60)
    -h, --help                   Display this help message

${PURPLE}EXAMPLES:${NC}
    # Auto-detect wireless interface
    ./kali_wireless_audit.sh -c "Acme WiFi Audit"

    # Specify interface explicitly
    ./kali_wireless_audit.sh -i wlan0 -c "Network Security"

    # Custom output and capture time
    ./kali_wireless_audit.sh -i wlan1 -o ./results -t 120

${PURPLE}FEATURES:${NC}
    • Automatic wireless interface detection
    • Monitor mode configuration
    • Network discovery with airodump-ng
    • WEP/WPS network detection
    • Handshake capture for WPA/WPA2
    • Signal strength monitoring
    • Detailed reporting

${PURPLE}REQUIREMENTS:${NC}
    • Root/sudo privileges
    • Wireless adapter supporting monitor mode
    • aircrack-ng suite installed
    • iw or iwconfig utility

${RED}DISCLAIMER:${NC} Only test networks you own or have explicit written authorization.

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "FAIL" "This script requires root/sudo privileges"
        exit 1
    fi
}

create_result_dirs() {
    local base_dir=$1
    mkdir -p "${base_dir}"
    print_status "SUCCESS" "Result directory created: $base_dir"
}

################################################################################
# WIRELESS INTERFACE MANAGEMENT
################################################################################

detect_wireless_interface() {
    print_status "INFO" "Detecting wireless interfaces..."

    # Try to find wireless interface
    local wireless_ifaces=()

    # Method 1: Using iw
    if command_exists iw; then
        while read -r line; do
            if [[ $line =~ ^phy[0-9]+ ]]; then
                local phy=$line
                local dev=$(iw "$phy" info | grep "Interface" | awk '{print $2}' | head -1)
                if [[ -n $dev ]]; then
                    wireless_ifaces+=("$dev")
                fi
            fi
        done < <(iw list 2>/dev/null | grep "^phy")
    fi

    # Method 2: Using iwconfig
    if [[ ${#wireless_ifaces[@]} -eq 0 ]] && command_exists iwconfig; then
        while read -r line; do
            if [[ $line =~ ^([a-zA-Z0-9]+)\ \ IEEE ]]; then
                wireless_ifaces+=("${BASH_REMATCH[1]}")
            fi
        done < <(iwconfig 2>/dev/null)
    fi

    # Method 3: Check /sys/class/net
    if [[ ${#wireless_ifaces[@]} -eq 0 ]]; then
        for dev in /sys/class/net/*/; do
            local dev_name=$(basename "$dev")
            if [[ -d "${dev}/wireless" ]] || [[ -d "${dev}/phy80211" ]]; then
                wireless_ifaces+=("$dev_name")
            fi
        done
    fi

    if [[ ${#wireless_ifaces[@]} -eq 0 ]]; then
        print_status "FAIL" "No wireless interfaces found"
        print_status "INFO" "Supported interfaces:"
        ls /sys/class/net/ 2>/dev/null
        exit 1
    fi

    # Display found interfaces
    echo -e "${CYAN}Found wireless interfaces:${NC}"
    for i in "${!wireless_ifaces[@]}"; do
        echo "$((i+1)). ${wireless_ifaces[$i]}"
    done

    return 0
}

enable_monitor_mode() {
    local iface=$1

    print_status "INFO" "Enabling monitor mode on $iface..."

    # First, bring interface down
    ip link set "$iface" down 2>/dev/null

    # Set to monitor mode
    if command_exists iw; then
        iw dev "$iface" set type monitor 2>/dev/null && \
        ip link set "$iface" up 2>/dev/null && \
        print_status "SUCCESS" "Monitor mode enabled using iw" && \
        return 0
    fi

    # Fallback to iwconfig
    if command_exists iwconfig; then
        iwconfig "$iface" mode monitor 2>/dev/null && \
        ip link set "$iface" up 2>/dev/null && \
        print_status "SUCCESS" "Monitor mode enabled using iwconfig" && \
        return 0
    fi

    # Fallback to airmon-ng
    if command_exists airmon-ng; then
        airmon-ng start "$iface" 2>/dev/null && \
        print_status "SUCCESS" "Monitor mode enabled using airmon-ng" && \
        return 0
    fi

    print_status "FAIL" "Could not enable monitor mode on $iface"
    return 1
}

disable_monitor_mode() {
    local iface=$1

    print_status "INFO" "Disabling monitor mode on $iface..."

    ip link set "$iface" down 2>/dev/null

    if command_exists iw; then
        iw dev "$iface" set type managed 2>/dev/null && \
        ip link set "$iface" up 2>/dev/null && \
        print_status "SUCCESS" "Monitor mode disabled"
        return 0
    fi

    if command_exists iwconfig; then
        iwconfig "$iface" mode managed 2>/dev/null && \
        ip link set "$iface" up 2>/dev/null && \
        print_status "SUCCESS" "Monitor mode disabled"
        return 0
    fi
}

################################################################################
# WIRELESS NETWORK DISCOVERY
################################################################################

scan_networks() {
    local iface=$1
    local output_dir=$2
    local capture_time=$3

    print_status "PHASE" "WIRELESS NETWORK DISCOVERY"

    if ! check_tool "airodump-ng"; then
        print_status "FAIL" "airodump-ng not found"
        return 1
    fi

    print_status "INFO" "Scanning for wireless networks (${capture_time}s)..."
    print_status "INFO" "Press Ctrl+C to stop early"

    timeout "$capture_time" airodump-ng "$iface" \
        -w "${output_dir}/airodump_capture" \
        --output-format csv > /dev/null 2>&1

    if [[ -f "${output_dir}/airodump_capture-01.csv" ]]; then
        print_status "SUCCESS" "Network scan completed"
        parse_airodump_results "${output_dir}/airodump_capture-01.csv" "$output_dir"
        return 0
    else
        print_status "FAIL" "Airodump capture failed"
        return 1
    fi
}

parse_airodump_results() {
    local csv_file=$1
    local output_dir=$2
    local report_file="${output_dir}/network_analysis.txt"

    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "WIRELESS NETWORK ANALYSIS"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Extract and format network information
        awk -F',' 'NR>2 && NF>2 && !/^[[:space:]]*$/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if (NF >= 15) {
                bssid=$1
                power=$4
                beacons=$5
                data=$6
                speed=$7
                cipher=$9
                auth=$10
                essid=$15

                if (bssid != "" && essid != "") {
                    print "BSSID: " bssid
                    print "SSID: " essid
                    print "Power: " power " dBm"
                    print "Security: " cipher " " auth
                    print "Beacons: " beacons ", Data: " data
                    print "Max Speed: " speed " Mbps"
                    print "---"
                }
            }
        }' "$csv_file" >> "$report_file" 2>/dev/null

        echo ""
        echo "═══════════════════════════════════════════════════════════════"
    } > "$report_file"

    cat "$report_file"
}

detect_vulnerabilities() {
    local csv_file=$1
    local output_dir=$2
    local vuln_file="${output_dir}/vulnerability_summary.txt"

    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "WIRELESS VULNERABILITY DETECTION"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Check for WEP networks
        echo "Checking for WEP networks..."
        local wep_count=0
        while IFS=',' read -r _ _ _ _ _ _ _ cipher _; do
            if [[ $cipher == *"WEP"* ]]; then
                print_status "WARN" "WEP network detected: $cipher"
                ((wep_count++))
            fi
        done < "$csv_file"

        if [[ $wep_count -gt 0 ]]; then
            echo "$wep_count WEP networks detected - HIGHLY VULNERABLE" >> "$vuln_file"
        fi

        # Check for open networks
        echo "Checking for open networks..."
        while IFS=',' read -r bssid _ _ _ _ _ _ cipher auth essid; do
            if [[ $cipher == "OPN" ]]; then
                print_status "WARN" "Open network detected: $essid"
                echo "Open network found: $essid ($bssid)" >> "$vuln_file"
            fi
        done < "$csv_file"

        # Check for WPS-enabled networks
        echo "Checking for WPS-enabled networks..."
        while IFS=',' read -r bssid _ _ _ _ _ _ _ _ _ _ _ _ wps essid; do
            if [[ $wps == "Yes" ]]; then
                print_status "WARN" "WPS-enabled network detected: $essid"
                echo "WPS enabled on: $essid ($bssid)" >> "$vuln_file"
            fi
        done < "$csv_file"

        echo ""
        echo "═══════════════════════════════════════════════════════════════"
    } | tee -a "$vuln_file"
}

guide_handshake_capture() {
    local iface=$1
    local output_dir=$2

    if ! check_tool "aireplay-ng"; then
        print_status "WARN" "aireplay-ng not found, handshake capture not available"
        return 1
    fi

    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "          HANDSHAKE CAPTURE GUIDE (WPA/WPA2)"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    echo "To capture a WPA handshake for offline cracking:"
    echo ""
    echo "1. Select a target network from the scan results above"
    echo "2. Note the BSSID (MAC address) and ESSID (network name)"
    echo "3. In another terminal, run airodump-ng in channel-specific mode:"
    echo ""
    echo "   sudo airodump-ng $iface -c [CHANNEL] --bssid [BSSID] -w handshake"
    echo ""
    echo "4. In a third terminal, send a deauthentication packet to force reconnection:"
    echo ""
    echo "   sudo aireplay-ng --deauth 10 -a [BSSID] -c [CLIENT_MAC] $iface"
    echo ""
    echo "5. Observe the airodump-ng window for 'WPA handshake: [BSSID]'"
    echo ""
    echo "6. Once handshake is captured, use hashcat or aircrack-ng to crack:"
    echo ""
    echo "   sudo aircrack-ng -w wordlist.txt handshake-01.cap"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    read -p "Continue? (yes/no): " -r response
    if [[ ! $response =~ ^[Yy][Ee][Ss]$ ]]; then
        return 0
    fi
}

################################################################################
# ADVANCED SCANNING
################################################################################

analyze_signal_strength() {
    local iface=$1
    local output_dir=$2
    local duration=$3

    print_status "PHASE" "SIGNAL STRENGTH ANALYSIS"

    if ! check_tool "airodump-ng"; then
        print_status "WARN" "Cannot perform signal analysis without airodump-ng"
        return 1
    fi

    print_status "INFO" "Analyzing signal strength over ${duration} seconds..."

    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "SIGNAL STRENGTH ANALYSIS"
        echo "═══════════════════════════════════════════════════════════════"
        echo "Timestamp: $(date)"
        echo ""

        timeout "$duration" airodump-ng "$iface" --output-format csv -w "${output_dir}/signal_analysis" 2>/dev/null

        if [[ -f "${output_dir}/signal_analysis-01.csv" ]]; then
            echo "Signal Strength Statistics:"
            echo ""
            awk -F',' 'NR>2 && NF>3 {
                power=$4
                if (power != "") {
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", power)
                    print "Power Level: " power " dBm"
                }
            }' "${output_dir}/signal_analysis-01.csv" | sort | uniq -c | sort -rn
        fi

        echo ""
        echo "═══════════════════════════════════════════════════════════════"
    } | tee -a "${output_dir}/signal_analysis_report.txt"
}

################################################################################
# REPORT GENERATION
################################################################################

generate_wireless_report() {
    local output_dir=$1
    local iface=$2
    local report_file="${output_dir}/WIRELESS_AUDIT_REPORT.txt"

    cat > "$report_file" << EOF
╔═══════════════════════════════════════════════════════════════╗
║           WIRELESS NETWORK AUDIT REPORT                       ║
╚═══════════════════════════════════════════════════════════════╝

Execution Date: $(date)
Interface Used: $iface
Client: $CLIENT_NAME

Output Directory: $output_dir
Master Log: $MASTER_LOG

═══════════════════════════════════════════════════════════════

ASSESSMENT SUMMARY:

This wireless audit captured and analyzed WiFi networks visible from
the testing location. Results include network discovery, security
assessment, and vulnerability detection.

═══════════════════════════════════════════════════════════════

KEY FINDINGS TO REVIEW:

1. Network Analysis
   - Review: ${output_dir}/network_analysis.txt
   - Lists all discovered networks with security details

2. Vulnerability Assessment
   - Review: ${output_dir}/vulnerability_summary.txt
   - Highlights WEP, open, and WPS-enabled networks

3. Signal Strength Data
   - Review: ${output_dir}/signal_analysis_report.txt (if performed)
   - Signal levels across time

═══════════════════════════════════════════════════════════════

SECURITY RECOMMENDATIONS:

1. WEP Networks (CRITICAL)
   - WEP is completely broken, migrate immediately to WPA2/WPA3
   - Can be cracked in minutes

2. Open Networks (CRITICAL)
   - No encryption at all
   - Implement WPA2/WPA3 immediately

3. WPS-Enabled Networks (HIGH)
   - WPS can be attacked via brute force
   - Disable WPS if not required
   - Use strong WiFi passwords

4. General Recommendations
   - Use WPA3 or WPA2 with AES encryption
   - Avoid WPA with TKIP
   - Use strong, unique passwords (20+ characters)
   - Hide SSID broadcast (optional additional security)
   - Implement MAC filtering (optional)
   - Use strong admin credentials
   - Keep firmware updated
   - Disable WPS entirely
   - Implement 802.1X authentication where possible

═══════════════════════════════════════════════════════════════

NEXT STEPS:

1. For WPA/WPA2 Networks
   - Handshake capture guide provided above
   - Crack password offline using:
     * aircrack-ng -w wordlist.txt capture.cap
     * hashcat -m 2500 hash.txt wordlist.txt
   - Review password strength

2. For Identified Issues
   - Implement recommended security controls
   - Test post-remediation with repeat scan

3. Documentation
   - Document all findings
   - Track remediation progress
   - Schedule follow-up testing

═══════════════════════════════════════════════════════════════
Generated by Kali Linux Purple Team Wireless Audit Suite
EOF

    cat "$report_file"
}

################################################################################
# CLEANUP
################################################################################

cleanup() {
    local iface=$1
    print_status "INFO" "Cleaning up..."
    disable_monitor_mode "$iface"
    print_status "SUCCESS" "Cleanup completed"
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Default values
    WIRELESS_IFACE=""
    CLIENT_NAME="Wireless Security Audit"
    OUTPUT_DIR="/results"
    CAPTURE_TIME=60

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                WIRELESS_IFACE="$2"
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
            -t|--time)
                CAPTURE_TIME="$2"
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

    # Check root
    check_root

    # Initialize
    display_banner
    ethical_disclaimer
    init_logging

    # Detect or validate wireless interface
    if [[ -z "$WIRELESS_IFACE" ]]; then
        detect_wireless_interface
        read -p "Select interface number: " -r interface_num
        # Parse selection (simplified)
        print_status "WARN" "Please specify interface with -i flag for automation"
        exit 1
    fi

    # Setup results directory
    RESULT_DIR="${OUTPUT_DIR}/wireless_audit_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESULT_DIR"
    create_result_dirs "$RESULT_DIR"

    print_status "INFO" "Using interface: $WIRELESS_IFACE"
    print_status "INFO" "Results will be saved to: $RESULT_DIR"
    echo ""

    # Enable monitor mode
    if ! enable_monitor_mode "$WIRELESS_IFACE"; then
        print_status "FAIL" "Could not enable monitor mode"
        exit 1
    fi

    # Trap to cleanup on exit
    trap "cleanup $WIRELESS_IFACE" EXIT

    # Perform network scan
    scan_networks "$WIRELESS_IFACE" "$RESULT_DIR" "$CAPTURE_TIME"

    # Analyze for vulnerabilities
    if [[ -f "${RESULT_DIR}/airodump_capture-01.csv" ]]; then
        detect_vulnerabilities "${RESULT_DIR}/airodump_capture-01.csv" "$RESULT_DIR"
        guide_handshake_capture "$WIRELESS_IFACE" "$RESULT_DIR"
    fi

    # Generate report
    echo ""
    generate_wireless_report "$RESULT_DIR" "$WIRELESS_IFACE"

    print_status "SUCCESS" "Wireless audit completed"
    print_status "INFO" "Master log: $MASTER_LOG"
}

# Run main
main "$@"
