#!/usr/bin/env python3
"""
JSHunter CLI — Advanced JavaScript Security Analyzer
Desenvolvido por HuntBox — Empresa 100% ofensiva
Pentest | Red Team | Bug Bounty

Usage:
  python js_analyzer.py https://target.com/app.js
  python js_analyzer.py https://target.com/app.js https://target.com/lib.js
  python js_analyzer.py -f urls.txt
  python js_analyzer.py https://target.com/app.js -o report.json
"""

import sys
import json
import argparse
from typing import List
from dataclasses import asdict
import colorama
from colorama import Fore, Style

from jshunter.services.analyzer_service import AnalyzerService
from jshunter.models.results import AnalysisResult

colorama.init(autoreset=True)

BANNER = f"""
{Fore.RED}     ╦╔═╗╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
     ║╚═╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ╚╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═{Style.RESET_ALL}
    {Fore.WHITE}Advanced JavaScript Security Analyzer{Style.RESET_ALL}
    {Fore.RED}Developed by HuntBox{Style.RESET_ALL} — 100% Offensive
    Pentest {Fore.RED}•{Style.RESET_ALL} Red Team {Fore.RED}•{Style.RESET_ALL} Bug Bounty
"""


class OutputFormatter:
    """Format analysis results for CLI display"""

    @staticmethod
    def format_json(results: List[AnalysisResult]) -> str:
        return json.dumps([asdict(r) for r in results], indent=2, default=str)

    @staticmethod
    def format_text(results: List[AnalysisResult]) -> str:
        output = []

        for result in results:
            output.append(f"\n{'='*70}")
            output.append(f"{Fore.CYAN}TARGET: {result.url}{Style.RESET_ALL}")
            output.append(f"Size: {result.file_size:,} bytes | Engine: {result.analysis_engine}")
            output.append(f"Risk Score: {OutputFormatter._risk_color(result.risk_score)}{result.risk_score}/100{Style.RESET_ALL}")
            output.append(f"Timestamp: {result.analysis_timestamp}")
            output.append(f"{'='*70}\n")

            if result.errors:
                output.append(f"{Fore.RED}[ERRORS]{Style.RESET_ALL}")
                for error in result.errors:
                    output.append(f"  {Fore.RED}x{Style.RESET_ALL} {error}")
                output.append("")

            # Severity Summary
            sc = result.severity_counts
            output.append(f"{Fore.WHITE}[SEVERITY SUMMARY]{Style.RESET_ALL}")
            output.append(f"  {Fore.RED}CRITICAL: {sc.get('critical', 0)}{Style.RESET_ALL}  |  "
                         f"{Fore.YELLOW}HIGH: {sc.get('high', 0)}{Style.RESET_ALL}  |  "
                         f"{Fore.LIGHTYELLOW_EX}MEDIUM: {sc.get('medium', 0)}{Style.RESET_ALL}  |  "
                         f"{Fore.GREEN}LOW: {sc.get('low', 0)}{Style.RESET_ALL}  |  "
                         f"INFO: {sc.get('info', 0)}")
            output.append("")

            if result.api_keys:
                output.append(f"{Fore.RED}[API KEYS] {len(result.api_keys)} found{Style.RESET_ALL}")
                for key in result.api_keys[:15]:
                    output.append(f"  {OutputFormatter._sev_icon(key.get('severity', 'info'))} {key['type']} (L{key['line']})")
                    output.append(f"    {Fore.WHITE}{key['match'][:80]}{Style.RESET_ALL}")
                if len(result.api_keys) > 15:
                    output.append(f"  ... +{len(result.api_keys) - 15} more")
                output.append("")

            if result.credentials:
                output.append(f"{Fore.RED}[CREDENTIALS] {len(result.credentials)} found{Style.RESET_ALL}")
                for cred in result.credentials[:10]:
                    output.append(f"  {Fore.RED}!{Style.RESET_ALL} {cred['type']} (L{cred['line']})")
                    output.append(f"    {cred['match'][:80]}")
                if len(result.credentials) > 10:
                    output.append(f"  ... +{len(result.credentials) - 10} more")
                output.append("")

            if result.high_entropy_strings:
                output.append(f"{Fore.YELLOW}[HIGH ENTROPY] {len(result.high_entropy_strings)} found{Style.RESET_ALL}")
                for ent in result.high_entropy_strings[:10]:
                    output.append(f"  {Fore.YELLOW}~{Style.RESET_ALL} Entropy: {ent.get('entropy', '?')} (L{ent['line']})")
                    output.append(f"    {ent['match'][:60]}")
                if len(result.high_entropy_strings) > 10:
                    output.append(f"  ... +{len(result.high_entropy_strings) - 10} more")
                output.append("")

            if result.xss_vulnerabilities:
                output.append(f"{Fore.RED}[VULNERABILITIES] {len(result.xss_vulnerabilities)} found{Style.RESET_ALL}")
                for xss in result.xss_vulnerabilities:
                    sev = xss.get('severity', 'unknown')
                    output.append(f"  {OutputFormatter._sev_icon(sev)} [{sev.upper()}] {xss['type']} (L{xss['line']})")
                    output.append(f"    {xss['match'][:80]}")
                output.append("")

            if result.interesting_comments:
                output.append(f"{Fore.MAGENTA}[COMMENTS] {len(result.interesting_comments)} found{Style.RESET_ALL}")
                for comment in result.interesting_comments[:10]:
                    output.append(f"  {Fore.MAGENTA}#{Style.RESET_ALL} {comment['type']} (L{comment['line']})")
                    output.append(f"    {comment['match'][:80]}")
                if len(result.interesting_comments) > 10:
                    output.append(f"  ... +{len(result.interesting_comments) - 10} more")
                output.append("")

            if result.api_endpoints:
                output.append(f"{Fore.GREEN}[ENDPOINTS] {len(result.api_endpoints)} found{Style.RESET_ALL}")
                for ep in result.api_endpoints[:20]:
                    output.append(f"  {Fore.GREEN}>{Style.RESET_ALL} [{ep.get('type', '?')}] {ep.get('match', '')[:100]} (L{ep['line']})")
                if len(result.api_endpoints) > 20:
                    output.append(f"  ... +{len(result.api_endpoints) - 20} more")
                output.append("")

            if result.source_map_detected:
                output.append(f"{Fore.YELLOW}[SOURCE MAP DETECTED]{Style.RESET_ALL}")
                output.append(f"  {Fore.YELLOW}!{Style.RESET_ALL} {result.source_map_url}")
                output.append("")

            if result.emails:
                output.append(f"{Fore.CYAN}[EMAILS] {len(result.emails)} found{Style.RESET_ALL}")
                for email in result.emails[:10]:
                    output.append(f"  {Fore.CYAN}@{Style.RESET_ALL} {email['match']} (L{email['line']})")
                output.append("")

            total = result.total_findings
            if total == 0 and not result.api_endpoints:
                output.append(f"{Fore.GREEN}[OK] No security issues detected{Style.RESET_ALL}\n")
            else:
                output.append(f"{Fore.WHITE}[TOTAL] {total} security findings | {len(result.api_endpoints)} endpoints{Style.RESET_ALL}\n")

        return "\n".join(output)

    @staticmethod
    def _risk_color(score):
        if score >= 75: return Fore.RED
        if score >= 50: return Fore.YELLOW
        if score >= 25: return Fore.LIGHTYELLOW_EX
        return Fore.GREEN

    @staticmethod
    def _sev_icon(sev):
        icons = {
            'critical': f'{Fore.RED}!!{Style.RESET_ALL}',
            'high': f'{Fore.YELLOW}!{Style.RESET_ALL}',
            'medium': f'{Fore.LIGHTYELLOW_EX}~{Style.RESET_ALL}',
            'low': f'{Fore.GREEN}-{Style.RESET_ALL}',
            'info': f'{Fore.CYAN}.{Style.RESET_ALL}',
        }
        return icons.get(str(sev).lower(), '?')


def main():
    parser = argparse.ArgumentParser(
        description='JSHunter — Advanced JavaScript Security Analyzer by HuntBox',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://target.com/app.js
  %(prog)s https://target.com/app.js https://target.com/vendor.js
  %(prog)s -f urls.txt
  %(prog)s https://target.com/app.js -o report.json
        """
    )

    parser.add_argument('urls', nargs='*', help='Target URL(s) of JavaScript file(s)')
    parser.add_argument('-f', '--file', help='File containing target URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file path (JSON format)')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    args = parser.parse_args()

    urls = list(args.urls) if args.urls else []

    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls.extend([line.strip() for line in f
                             if line.strip() and not line.strip().startswith('#')])
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found", file=sys.stderr)
            sys.exit(1)

    if not urls:
        print(BANNER)
        parser.print_help()
        sys.exit(1)

    if args.no_color:
        colorama.init(strip=True)

    print(BANNER)

    service = AnalyzerService()
    results = []

    print(f"{Fore.RED}[*]{Style.RESET_ALL} Hunting {len(urls)} target(s)...\n")

    for i, url in enumerate(urls, 1):
        print(f"{Fore.RED}[{i}/{len(urls)}]{Style.RESET_ALL} {url}")
        result = service.analyze_url(url)
        results.append(result)

    if args.json or args.output:
        output = OutputFormatter.format_json(results)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"\n{Fore.GREEN}[+] Report saved to {args.output}{Style.RESET_ALL}")
        else:
            print(output)
    else:
        print(OutputFormatter.format_text(results))


if __name__ == '__main__':
    main()
