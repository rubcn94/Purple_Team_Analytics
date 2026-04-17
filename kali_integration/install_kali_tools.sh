#!/bin/bash

################################################################################
# KALI LINUX PURPLE TEAM - TOOL INSTALLATION SCRIPT
# Installs and verifies all required tools for Purple Team suite
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

# Statistics
TOTAL_TOOLS=0
INSTALLED_TOOLS=0
FAILED_TOOLS=0
SKIPPED_TOOLS=0

################################################################################
# UTILITY FUNCTIONS
################################################################################

print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS") echo -e "${GREEN}[✓]${NC} ${message}" ;;
        "FAIL") echo -e "${RED}[✗]${NC} ${message}" ;;
        "INFO") echo -e "${CYAN}[ℹ]${NC} ${message}" ;;
        "WARN") echo -e "${YELLOW}[⚠]${NC} ${message}" ;;
        "INSTALL") echo -e "${PURPLE}[⟳]${NC} ${message}" ;;
    esac
}

display_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║    KALI LINUX PURPLE TEAM - TOOL INSTALLER                   ║"
    echo "║    Automated Security Tool Installation & Verification        ║"
    echo "║    Version 1.0                                                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

display_help() {
    cat << EOF
${PURPLE}USAGE:${NC}
    ./install_kali_tools.sh [OPTIONS]

${PURPLE}OPTIONS:${NC}
    -u, --update              Update package lists before installation
    -f, --full                Install all optional tools (default: required only)
    -v, --verify              Only verify tool installation (no install)
    -h, --help                Display this help message

${PURPLE}EXAMPLES:${NC}
    # Standard installation with updates
    ./install_kali_tools.sh -u

    # Full installation with all tools
    ./install_kali_tools.sh -u -f

    # Verify existing installation only
    ./install_kali_tools.sh -v

${PURPLE}TOOLS INSTALLED:${NC}

CORE NETWORK TOOLS:
    • nmap              - Network discovery and port scanning
    • masscan           - Faster network scanning (large ranges)
    • nikto             - Web server vulnerability scanner
    • gobuster          - Directory and file enumeration
    • dirb              - Web directory brute-force scanner

ENUMERATION TOOLS:
    • enum4linux        - SMB enumeration and information gathering
    • smbclient         - SMB share access and testing
    • crackmapexec      - SMB/LDAP post-exploitation framework
    • nbtscan           - NetBIOS network scanner
    • snmpwalk          - SNMP information enumeration

WEB APPLICATION TOOLS:
    • whatweb           - Web application identification
    • wafw00f           - Web Application Firewall detection
    • sqlmap            - SQL injection detection and exploitation
    • wpscan            - WordPress vulnerability scanner
    • xsser             - XSS vulnerability detection

WIRELESS TOOLS:
    • aircrack-ng       - WiFi cracking and analysis suite
    • iw                - Wireless configuration tool

SUPPORT TOOLS:
    • searchsploit      - Exploit database search (Metasploit)
    • responder         - LLMNR/NBT-NS credential capture
    • curl              - URL data transfer tool
    • wget              - File download utility
    • git               - Version control

PYTHON TOOLS & DEPENDENCIES:
    • python3           - Python 3 interpreter
    • python3-pip       - Python package manager
    • requests          - HTTP library for Python
    • paramiko          - SSH library for Python

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "FAIL" "This script requires root privileges"
        echo "Run with: sudo $0"
        exit 1
    fi
}

command_exists() {
    command -v "$1" &> /dev/null
    return $?
}

check_distro() {
    if ! command_exists apt-get; then
        print_status "FAIL" "This script requires a Debian-based distribution (Kali Linux)"
        exit 1
    fi
}

update_package_lists() {
    print_status "INFO" "Updating package lists..."
    if apt-get update > /dev/null 2>&1; then
        print_status "SUCCESS" "Package lists updated"
        return 0
    else
        print_status "WARN" "Failed to update package lists"
        return 1
    fi
}

################################################################################
# TOOL INSTALLATION FUNCTIONS
################################################################################

install_tool() {
    local tool_name=$1
    local package_name=$2
    local description=$3

    ((TOTAL_TOOLS++))

    # Check if already installed
    if command_exists "$tool_name"; then
        print_status "SUCCESS" "$description (already installed)"
        ((INSTALLED_TOOLS++))
        return 0
    fi

    print_status "INSTALL" "Installing $description..."

    if apt-get install -y "$package_name" > /dev/null 2>&1; then
        # Verify installation
        if command_exists "$tool_name"; then
            print_status "SUCCESS" "$description installed successfully"
            ((INSTALLED_TOOLS++))
            return 0
        else
            print_status "WARN" "$description installed but command not found in PATH"
            ((SKIPPED_TOOLS++))
            return 1
        fi
    else
        print_status "FAIL" "Failed to install $description"
        ((FAILED_TOOLS++))
        return 1
    fi
}

install_tool_from_git() {
    local tool_name=$1
    local git_repo=$2
    local description=$3
    local install_cmd=$4

    ((TOTAL_TOOLS++))

    if command_exists "$tool_name"; then
        print_status "SUCCESS" "$description (already installed)"
        ((INSTALLED_TOOLS++))
        return 0
    fi

    print_status "INSTALL" "Cloning $description from GitHub..."

    local temp_dir="/tmp/${tool_name}_install"
    rm -rf "$temp_dir"

    if git clone "$git_repo" "$temp_dir" > /dev/null 2>&1; then
        cd "$temp_dir" || return 1

        if eval "$install_cmd" > /dev/null 2>&1; then
            print_status "SUCCESS" "$description installed successfully"
            ((INSTALLED_TOOLS++))
            cd - > /dev/null || return 1
            return 0
        else
            print_status "FAIL" "Installation command failed for $description"
            ((FAILED_TOOLS++))
            cd - > /dev/null || return 1
            return 1
        fi
    else
        print_status "FAIL" "Failed to clone $description from GitHub"
        ((FAILED_TOOLS++))
        return 1
    fi
}

verify_tool() {
    local tool_name=$1
    local description=$2

    if command_exists "$tool_name"; then
        print_status "SUCCESS" "$description is installed"
        return 0
    else
        print_status "FAIL" "$description is NOT installed"
        return 1
    fi
}

install_python_package() {
    local package_name=$1
    local description=$2

    ((TOTAL_TOOLS++))

    print_status "INSTALL" "Installing Python package: $description..."

    if pip3 install "$package_name" > /dev/null 2>&1; then
        print_status "SUCCESS" "Python package '$description' installed"
        ((INSTALLED_TOOLS++))
        return 0
    else
        print_status "FAIL" "Failed to install Python package: $description"
        ((FAILED_TOOLS++))
        return 1
    fi
}

################################################################################
# INSTALLATION PHASES
################################################################################

install_core_network_tools() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "PHASE 1: CORE NETWORK TOOLS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    install_tool "nmap" "nmap" "Nmap - Network mapper"
    install_tool "masscan" "masscan" "Masscan - Fast network scanner"
    install_tool "nikto" "nikto" "Nikto - Web server scanner"
    install_tool "gobuster" "gobuster" "Gobuster - Directory/file enumeration"
    install_tool "dirb" "dirb" "Dirb - Web directory brute-force"
}

install_enumeration_tools() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "PHASE 2: ENUMERATION TOOLS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    install_tool "enum4linux" "enum4linux" "Enum4Linux - SMB enumeration"
    install_tool "smbclient" "smbclient" "SMBClient - SMB client tool"
    install_tool "crackmapexec" "crackmapexec" "CrackMapExec - SMB/LDAP framework"
    install_tool "nbtscan" "nbtscan" "NBTScan - NetBIOS scanner"
    install_tool "snmpwalk" "snmp" "SNMPwalk - SNMP enumeration"
}

install_web_tools() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "PHASE 3: WEB APPLICATION TOOLS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    install_tool "whatweb" "whatweb" "Whatweb - Web application fingerprinting"
    install_tool "wafw00f" "wafw00f" "WAFw00f - WAF detection"
    install_tool "sqlmap" "sqlmap" "SQLMap - SQL injection tool"
    install_tool "wpscan" "wpscan" "WPScan - WordPress vulnerability scanner"
    install_tool "xsser" "xsser" "XSSer - XSS vulnerability detection"
}

install_wireless_tools() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "PHASE 4: WIRELESS TOOLS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    install_tool "aircrack-ng" "aircrack-ng" "Aircrack-ng - WiFi security suite"
    install_tool "iw" "iw" "iw - Wireless configuration tool"
}

install_support_tools() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "PHASE 5: SUPPORT TOOLS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    install_tool "searchsploit" "exploitdb" "Searchsploit - Exploit database"
    install_tool "responder" "responder" "Responder - LLMNR/NBT-NS capture"
    install_tool "curl" "curl" "Curl - URL data transfer"
    install_tool "wget" "wget" "Wget - File download utility"
    install_tool "git" "git" "Git - Version control system"
}

install_python_requirements() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "PHASE 6: PYTHON & DEPENDENCIES"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    # Ensure Python 3 and pip are installed
    install_tool "python3" "python3" "Python 3 interpreter"
    install_tool "pip3" "python3-pip" "Python package manager (pip3)"

    # Python packages
    print_status "INFO" "Installing Python packages..."
    install_python_package "requests" "Requests HTTP library"
    install_python_package "paramiko" "Paramiko SSH library"
    install_python_package "beautifulsoup4" "BeautifulSoup4 HTML parsing"
    install_python_package "lxml" "lxml XML processing"
}

install_optional_tools() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "PHASE 7: OPTIONAL ADVANCED TOOLS"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    print_status "INFO" "Installing optional tools (may take longer)..."

    # testssl.sh for SSL analysis
    if ! command_exists "testssl.sh"; then
        print_status "INSTALL" "Installing testssl.sh..."
        if git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh > /dev/null 2>&1; then
            chmod +x /opt/testssl.sh/testssl.sh
            ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
            print_status "SUCCESS" "testssl.sh installed"
            ((INSTALLED_TOOLS++))
        else
            print_status "WARN" "testssl.sh installation skipped"
            ((SKIPPED_TOOLS++))
        fi
    else
        print_status "SUCCESS" "testssl.sh already installed"
        ((INSTALLED_TOOLS++))
    fi
    ((TOTAL_TOOLS++))

    # Optional: Nessus (if deb/rpm available)
    if ! command_exists "nessus"; then
        print_status "WARN" "Nessus requires manual installation (commercial/free version available)"
        ((SKIPPED_TOOLS++))
    else
        print_status "SUCCESS" "Nessus is installed"
        ((INSTALLED_TOOLS++))
    fi
    ((TOTAL_TOOLS++))
}

################################################################################
# VERIFICATION FUNCTIONS
################################################################################

verify_installation() {
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "VERIFICATION PHASE"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    # Core tools
    echo "Core Network Tools:"
    verify_tool "nmap" "Nmap"
    verify_tool "masscan" "Masscan"
    verify_tool "nikto" "Nikto"
    verify_tool "gobuster" "Gobuster"

    echo ""
    echo "Enumeration Tools:"
    verify_tool "enum4linux" "Enum4Linux"
    verify_tool "smbclient" "SMBClient"
    verify_tool "nbtscan" "NBTScan"

    echo ""
    echo "Web Tools:"
    verify_tool "whatweb" "Whatweb"
    verify_tool "wafw00f" "WAFw00f"
    verify_tool "sqlmap" "SQLMap"
    verify_tool "wpscan" "WPScan"

    echo ""
    echo "Wireless Tools:"
    verify_tool "aircrack-ng" "Aircrack-ng"

    echo ""
    echo "Support Tools:"
    verify_tool "searchsploit" "Searchsploit"
    verify_tool "git" "Git"
    verify_tool "curl" "Curl"

    echo ""
    echo "Python:"
    verify_tool "python3" "Python3"
    verify_tool "pip3" "Pip3"
}

display_summary() {
    echo ""
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "INSTALLATION SUMMARY"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    echo "Total Tools:       $TOTAL_TOOLS"
    echo -e "${GREEN}Successfully Installed: $INSTALLED_TOOLS${NC}"
    echo -e "${YELLOW}Skipped/Already Installed: $SKIPPED_TOOLS${NC}"
    echo -e "${RED}Failed: $FAILED_TOOLS${NC}"

    if [[ $FAILED_TOOLS -eq 0 ]]; then
        echo ""
        print_status "SUCCESS" "All tools installed successfully!"
        echo ""
        echo "Next steps:"
        echo "  1. Run verification: $0 --verify"
        echo "  2. Start using tools from kali_automation.sh"
        echo "  3. Review tool documentation for advanced usage"
    else
        echo ""
        print_status "WARN" "Some tools failed to install"
        echo "You can install them manually or try running the script again with sudo"
    fi

    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    local update_pkgs=0
    local full_install=0
    local verify_only=0

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--update)
                update_pkgs=1
                shift
                ;;
            -f|--full)
                full_install=1
                shift
                ;;
            -v|--verify)
                verify_only=1
                shift
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

    # Check requirements
    check_root
    check_distro

    display_banner

    # Verify only mode
    if [[ $verify_only -eq 1 ]]; then
        verify_installation
        exit 0
    fi

    # Update package lists
    if [[ $update_pkgs -eq 1 ]]; then
        update_package_lists
    fi

    # Installation phases
    install_core_network_tools
    echo ""
    install_enumeration_tools
    echo ""
    install_web_tools
    echo ""
    install_wireless_tools
    echo ""
    install_support_tools
    echo ""
    install_python_requirements

    # Optional tools
    if [[ $full_install -eq 1 ]]; then
        echo ""
        install_optional_tools
    fi

    # Verification
    echo ""
    verify_installation

    # Summary
    display_summary
}

# Run main function
main "$@"
