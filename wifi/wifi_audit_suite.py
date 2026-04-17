#!/usr/bin/env python3
"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    🛡️  PURPLE TEAM WiFi AUDIT SUITE 🛡️
          Comprehensive Security Assessment for SMB/Restaurant WiFi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This tool orchestrates all WiFi security testing modules and generates
a comprehensive report with door-opener narratives for business owners.

TESTED PLATFORMS:
  ✓ Termux (Android tablet/phone)
  ✓ Kali Linux / standard Linux distributions

COMPONENTS:
  1. Rogue AP Detector      - Evil Twin & malicious WiFi detection
  2. Client Isolation Tester - Network segmentation & exposed devices
  3. Router Default Checker  - Default credentials & exposed admin panels
  4. Network Exposure Scanner - PCI DSS violations & internal system exposure

⚠️  ETHICAL DISCLAIMER:
This tool is designed ONLY for authorized security testing. Unauthorized
network testing is illegal. Use only with explicit written permission
from the network owner.

AUTHOR: Purple Team Security Suite
MITRE ATT&CK: T1046, T1078.001, T1135, T1557.002, T1040, T1133
"""

import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path
import time

# ────────────────────────────────────────────────────────────
# ENVIRONMENT DETECTION
# ────────────────────────────────────────────────────────────

def is_termux():
    """Detect Termux environment."""
    return os.path.exists('/data/data/com.termux') or 'TERMUX_VERSION' in os.environ

def get_tool_path(tool_name):
    """Get absolute path to a tool."""
    script_dir = Path(__file__).parent.absolute()
    tool_path = script_dir / tool_name
    return str(tool_path)

# ────────────────────────────────────────────────────────────
# TOOL EXECUTION
# ────────────────────────────────────────────────────────────

def run_tool(tool_name, demo=False, timeout=60):
    """Run a WiFi security tool and capture results."""
    tool_path = get_tool_path(tool_name)

    if not os.path.exists(tool_path):
        return {
            'success': False,
            'error': f'Tool not found: {tool_path}',
            'tool': tool_name,
        }

    try:
        cmd = ['python3', tool_path, '--json']
        if demo:
            cmd.append('--demo')

        print(f"\n  ⏳ Running {tool_name}...", file=sys.stderr, flush=True)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            return {
                'success': False,
                'error': result.stderr,
                'tool': tool_name,
            }

        # Try to parse JSON from output
        try:
            data = json.loads(result.stdout)
            return {
                'success': True,
                'data': data,
                'tool': tool_name,
            }
        except json.JSONDecodeError as e:
            return {
                'success': False,
                'error': f'JSON parse error: {e}',
                'tool': tool_name,
                'raw_output': result.stdout[:500]
            }

    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': f'Tool timeout ({timeout}s)',
            'tool': tool_name,
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'tool': tool_name,
        }

# ────────────────────────────────────────────────────────────
# REPORT AGGREGATION
# ────────────────────────────────────────────────────────────

def aggregate_findings(results):
    """Aggregate findings from all tools."""
    aggregated = {
        'total_critical_risks': 0,
        'total_high_risks': 0,
        'evil_twins': [],
        'exposed_devices': [],
        'default_credentials': [],
        'pci_dss_violations': [],
        'client_isolation_enabled': True,
        'router_vulnerable': False,
    }

    for result in results:
        if not result['success']:
            continue

        data = result['data']
        findings = data.get('findings', {})

        # Aggregate evil twins
        if 'evil_twins' in findings and isinstance(findings['evil_twins'], list):
            aggregated['evil_twins'].extend(findings['evil_twins'])
            aggregated['total_critical_risks'] += len(findings['evil_twins'])

        # Aggregate exposed devices
        if 'critical_devices' in findings and isinstance(findings['critical_devices'], list):
            aggregated['exposed_devices'].extend(findings['critical_devices'])

        if 'devices_found' in data and isinstance(data['devices_found'], list):
            aggregated['exposed_devices'].extend(data['devices_found'])

        if 'high_risk_services' in findings and isinstance(findings['high_risk_services'], list):
            aggregated['total_high_risks'] += len(findings['high_risk_services'])

        # Client isolation
        if 'client_isolation_enabled' in findings:
            aggregated['client_isolation_enabled'] = findings['client_isolation_enabled']

        # Router credentials
        if 'default_credentials_found' in findings and isinstance(findings['default_credentials_found'], list):
            aggregated['default_credentials'].extend(findings['default_credentials_found'])
            if findings['default_credentials_found']:
                aggregated['router_vulnerable'] = True
                aggregated['total_critical_risks'] += len(findings['default_credentials_found'])

        # PCI DSS
        if 'pci_dss_violations' in findings and isinstance(findings['pci_dss_violations'], list):
            aggregated['pci_dss_violations'].extend(findings['pci_dss_violations'])
            aggregated['total_critical_risks'] += len(findings['pci_dss_violations'])

    return aggregated

# ────────────────────────────────────────────────────────────
# REPORT GENERATION
# ────────────────────────────────────────────────────────────

def generate_door_opener_narrative(aggregated):
    """Generate executive summary for business owner."""
    critical_count = aggregated['total_critical_risks']
    high_count = aggregated['total_high_risks']

    if critical_count == 0 and high_count == 0:
        return {
            'overall_risk': 'LOW',
            'headline': '✓ WiFi Network Appears Secure',
            'summary': 'Initial WiFi security assessment shows no critical vulnerabilities.',
            'recommendations': 'Continue regular security monitoring and updates.'
        }

    findings_list = []

    if aggregated['evil_twins']:
        findings_list.append(f"✗ CRITICAL: {len(aggregated['evil_twins'])} Evil Twin networks detected - customers may be intercepted")

    if not aggregated['client_isolation_enabled'] and aggregated['exposed_devices']:
        findings_list.append(f"✗ CRITICAL: {len(aggregated['exposed_devices'])} internal systems visible from customer WiFi")

    if aggregated['default_credentials']:
        findings_list.append(f"✗ CRITICAL: Router admin accessible with default credentials")

    if aggregated['pci_dss_violations']:
        findings_list.append(f"✗ CRITICAL: {len(aggregated['pci_dss_violations'])} PCI DSS compliance violations detected")

    overall_risk = 'CRITICAL' if critical_count >= 3 else 'HIGH' if critical_count >= 1 else 'MEDIUM'

    return {
        'overall_risk': overall_risk,
        'critical_count': critical_count,
        'high_count': high_count,
        'headline': f'⚠️  [{overall_risk}] WiFi Network Has {critical_count} Critical Vulnerability{"ies" if critical_count != 1 else ""}',
        'summary': f'Your WiFi network has {critical_count} critical security issues that could directly impact your customers and business.',
        'key_findings': findings_list,
        'message_for_owner': f'''
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    ⚠️  EXECUTIVE SUMMARY FOR {overall_risk}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

During our WiFi security assessment, we discovered {critical_count} critical
vulnerabilities that put your business and customers at direct risk.

WHAT WE FOUND:
{chr(10).join('  ' + f for f in findings_list)}

WHY THIS MATTERS:
  • Your customers' payment card data could be intercepted
  • Sensitive business data is accessible from public WiFi
  • Your network is vulnerable to takeover attacks
  • You may be violating PCI DSS compliance requirements

IMMEDIATE ACTIONS NEEDED:
  1. Isolate internal networks from guest WiFi (AP Isolation)
  2. Change your router admin password immediately
  3. Disable unnecessary services on all devices
  4. Set up proper network segmentation

The good news: Most of these issues can be fixed quickly and for free
using your existing equipment.

We recommend scheduling a full network security audit within the next week.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'''
    }

def generate_full_report(results, aggregated, demo=False):
    """Generate comprehensive audit report."""
    report = []

    report.append("┏" + "━" * 70 + "┓")
    report.append("┃" + " " * 15 + "🛡️  PURPLE TEAM WiFi AUDIT SUITE 🛡️" + " " * 19 + "┃")
    report.append("┃" + " " * 12 + "Comprehensive WiFi Security Assessment Report" + " " * 14 + "┃")
    report.append("┗" + "━" * 70 + "┛")

    if demo:
        report.append("")
        report.append("⚠️  DEMO MODE - SAMPLE DATA FOR PRESENTATION PURPOSES")

    report.append("")
    report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Platform: {'Termux' if is_termux() else 'Linux'}")
    report.append("")

    # Tool execution summary
    report.append("AUDIT COMPONENTS EXECUTED:")
    tools_run = len([r for r in results if r['success']])
    tools_total = len(results)
    report.append(f"  {tools_run}/{tools_total} tools completed successfully")
    report.append("")

    for result in results:
        status = "✓ COMPLETE" if result['success'] else "✗ FAILED"
        report.append(f"  {status:12} - {result['tool']}")
        if not result['success'] and 'error' in result:
            report.append(f"                 Error: {result['error'][:80]}")

    report.append("")
    report.append("━" * 72)
    report.append("")

    # Overall risk assessment
    report.append("OVERALL SECURITY ASSESSMENT:")
    risk_level = 'CRITICAL' if aggregated['total_critical_risks'] >= 3 else \
                 'HIGH' if aggregated['total_critical_risks'] >= 1 else 'MEDIUM'
    report.append(f"  Overall Risk Level: [{risk_level}]")
    report.append(f"  Critical Issues: {aggregated['total_critical_risks']}")
    report.append(f"  High Risk Issues: {aggregated['total_high_risks']}")
    report.append("")

    # Detailed findings
    if aggregated['evil_twins']:
        report.append(f"EVIL TWIN NETWORKS ({len(aggregated['evil_twins'])}):")
        for et in aggregated['evil_twins']:
            report.append(f"  • {et.get('ssid', 'Unknown')}")
            report.append(f"    BSSIDs: {', '.join(et.get('bssids', []))}")
        report.append("")

    if not aggregated['client_isolation_enabled']:
        report.append("CLIENT ISOLATION: DISABLED (CRITICAL)")
        report.append("  Customers can reach internal business systems")
        report.append("")

    if aggregated['exposed_devices']:
        report.append(f"EXPOSED INTERNAL DEVICES ({len(aggregated['exposed_devices'])}):")
        for device in aggregated['exposed_devices'][:5]:  # Show top 5
            report.append(f"  • {device.get('ip', 'Unknown IP')}")
        if len(aggregated['exposed_devices']) > 5:
            report.append(f"  ... and {len(aggregated['exposed_devices']) - 5} more")
        report.append("")

    if aggregated['default_credentials']:
        report.append("DEFAULT CREDENTIALS DISCOVERED:")
        for cred in aggregated['default_credentials']:
            report.append(f"  • {cred.get('router', 'Unknown')}")
            report.append(f"    Username: {cred.get('username', '?')}")
        report.append("")

    if aggregated['pci_dss_violations']:
        report.append(f"PCI DSS COMPLIANCE VIOLATIONS ({len(aggregated['pci_dss_violations'])}):")
        for v in aggregated['pci_dss_violations'][:3]:
            report.append(f"  • {v.get('violation', 'Unknown')}")
        if len(aggregated['pci_dss_violations']) > 3:
            report.append(f"  ... and {len(aggregated['pci_dss_violations']) - 3} more")
        report.append("")

    # Door opener narrative
    door_opener = generate_door_opener_narrative(aggregated)
    report.append("━" * 72)
    report.append("")
    report.append("DOOR OPENER NARRATIVE FOR BUSINESS OWNER:")
    report.append("")
    report.append(door_opener['headline'])
    report.append("")
    report.append(door_opener['summary'])
    report.append("")

    if 'message_for_owner' in door_opener:
        report.append(door_opener['message_for_owner'])

    return '\n'.join(report)

# ────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ────────────────────────────────────────────────────────────

def main():
    """Main suite execution."""
    import argparse

    parser = argparse.ArgumentParser(
        description='🛡️  Purple Team WiFi Audit Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Run full audit (requires WiFi connection)
  python3 wifi_audit_suite.py

  # Demo mode for presentations
  python3 wifi_audit_suite.py --demo

  # Save results to specific directory
  python3 wifi_audit_suite.py --output ./audit_results/

  # JSON output only
  python3 wifi_audit_suite.py --json

USAGE:
  1. Connect to the target WiFi network
  2. Run this script
  3. Results saved to ~/purple_team_reports/
  4. Use generated report as "door opener" with business owner
        """
    )
    parser.add_argument('--demo', action='store_true', help='Run with demo data for presentations')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--output', help='Custom output directory')
    parser.add_argument('--no-save', action='store_true', help='Do not save results')
    args = parser.parse_args()

    print("\n" + "━" * 72)
    print("    🛡️  PURPLE TEAM WiFi AUDIT SUITE - Starting Comprehensive Assessment")
    print("━" * 72 + "\n")

    if args.demo:
        print("  [!] DEMO MODE - Using sample data for presentation\n")

    # Define tools to run
    tools = [
        'rogue_ap_detector.py',
        'client_isolation_tester.py',
        'router_default_checker.py',
        'network_exposure_scanner.py',
    ]

    print(f"  [*] Will execute {len(tools)} security assessment tools\n")

    # Run tools
    results = []
    for tool in tools:
        result = run_tool(tool, demo=args.demo, timeout=90)
        results.append(result)
        time.sleep(1)  # Stagger requests

    print("\n  [+] All tools completed\n")

    # Aggregate findings
    aggregated = aggregate_findings(results)

    # Generate reports
    full_report = generate_full_report(results, aggregated, demo=args.demo)

    # Compile comprehensive JSON
    comprehensive_json = {
        'audit_timestamp': datetime.now().isoformat(),
        'platform': 'Termux' if is_termux() else 'Linux',
        'demo_mode': args.demo,
        'tool_results': results,
        'aggregated_findings': aggregated,
        'door_opener': generate_door_opener_narrative(aggregated),
    }

    # Output
    if args.json:
        print(json.dumps(comprehensive_json, indent=2))
    else:
        print(full_report)
        print("\n")

    # Save results
    if not args.no_save:
        if args.output:
            reports_dir = Path(args.output)
        else:
            reports_dir = Path.home() / 'purple_team_reports'

        reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save JSON
        json_path = reports_dir / f'wifi_audit_suite_{timestamp}.json'
        with open(json_path, 'w') as f:
            json.dump(comprehensive_json, f, indent=2)
        print(f"\n  [+] JSON report: {json_path}")

        # Save text report
        report_path = reports_dir / f'wifi_audit_suite_{timestamp}.txt'
        with open(report_path, 'w') as f:
            f.write(full_report)
        print(f"  [+] Text report: {report_path}")

        print(f"\n  Reports saved to: {reports_dir}")

    print("\n" + "━" * 72)
    print("  ✓ WiFi Security Audit Complete")
    print("━" * 72 + "\n")

if __name__ == '__main__':
    main()
