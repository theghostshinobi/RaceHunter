#!/usr/bin/env python3

"""
RaceHunter - Command Line Interface
Main entry point for race condition testing
© GHOSTSHINOBI 2025
"""

import sys
import asyncio
import argparse
from pathlib import Path
from core import RaceConfig, RaceStrategy, validate_config, get_version
from scenarios import ScenarioLoader, get_scenario
from engine import TestEngine
from reposys import generate_report
from utils import parse_burp_request, parse_curl_command

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser with all options and help"""
    parser = argparse.ArgumentParser(
        prog='racehunter',
        description='RaceHunter - Advanced Race Condition Detection Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
# Import from Burp Suite
racehunter --from-burp request.txt --parallel 20
# Manual specification
racehunter https://example.com/api/checkout \\
  --method POST \\
  --cookie "session=abc123" \\
  --body '{"product_id":123}' \\
  --parallel 15
# With scenario
racehunter --from-burp request.txt \\
  --scenario ecommerce_coupon \\
  --attempts 10
# List scenarios
racehunter --list-scenarios
        """
    )
    parser.add_argument('--version', action='version', version=get_version())
    parser.add_argument('--list-scenarios', action='store_true', help='List all available scenarios')

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('--from-burp', type=str, metavar='FILE', help='Import request from Burp Suite file')
    input_group.add_argument('--from-curl', type=str, metavar='CMD', help='Parse curl command')
    input_group.add_argument('url', nargs='?', help='Target URL')

    parser.add_argument('--method', type=str, default='POST', help='HTTP method (default: POST)')
    parser.add_argument('--header', action='append', dest='headers', help='Custom header (repeatable)')
    parser.add_argument('--cookie', type=str, help='Cookie string or file')
    parser.add_argument('--body', type=str, help='Request body')
    parser.add_argument('--body-file', type=str, help='Request body from file')

    parser.add_argument('--parallel', type=int, default=10, help='Parallel requests per attempt (default: 10)')
    parser.add_argument('--attempts', type=int, default=5, help='Number of race attempts (default: 5)')
    parser.add_argument('--strategy', type=str, choices=['async_burst', 'http2_single', 'threading'], default='async_burst', help='Race strategy (default: async_burst)')

    parser.add_argument('--scenario', type=str, help='Load pre-configured scenario')

    parser.add_argument('--timeout', type=float, default=10.0, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-verify', action='store_true', help='Disable TLS certificate verification')
    parser.add_argument('--proxy', type=str, help='Proxy URL (socks5://... or http://...)')

    parser.add_argument('--output', type=str, default='./results', help='Output directory (default: ./results)')
    parser.add_argument('--format', type=str, nargs='+', choices=['json', 'md', 'html', 'all'], default=['all'], help='Report formats (default: all)')
    return parser

def parse_headers(header_list) -> dict:
    """Parse header list into dictionary"""
    headers = {}
    if header_list:
        for header in header_list:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers

def parse_cookies(cookie_str) -> dict:
    """Parse cookie string into dictionary"""
    cookies = {}
    if cookie_str:
        for cookie in cookie_str.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    return cookies

async def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # List scenarios and exit
    if args.list_scenarios:
        ScenarioLoader.display_scenarios()
        sys.exit(0)

    # Validate presence of input method
    if not args.from_burp and not args.from_curl and not args.url:
        parser.print_help()
        sys.exit(1)

    # Load scenario if requested
    scenario = None
    if args.scenario:
        scenario = get_scenario(args.scenario)
        if not scenario:
            print(f"[!] Scenario '{args.scenario}' not found")
            print(f"[*] Available scenarios: {', '.join(ScenarioLoader.list_scenarios())}")
            sys.exit(1)
        print(f"[*] Loaded scenario: {scenario.name}")

        # Apply scenario recommended values if defaults detected in CLI
        if args.parallel == 10:
            args.parallel = scenario.recommended_parallel
        if args.attempts == 5:
            args.attempts = scenario.recommended_attempts

    # Build configuration object with robust error handling
    try:
        if args.from_burp:
            print(f"[*] Importing request from: {args.from_burp}")
            config, _ = parse_burp_request(args.from_burp)
            if args.parallel != 10:
                config.parallel_requests = args.parallel
            if args.attempts != 5:
                config.attempts = args.attempts
            config.strategy = RaceStrategy[args.strategy.upper()]
            config.timeout = args.timeout
            config.verify_tls = not args.no_verify
            if args.proxy:
                config.proxy = args.proxy

        elif args.from_curl:
            print(f"[*] Parsing curl command")
            config = parse_curl_command(args.from_curl)
            config.parallel_requests = args.parallel
            config.attempts = args.attempts
            config.strategy = RaceStrategy[args.strategy.upper()]
            config.timeout = args.timeout
            config.verify_tls = not args.no_verify
            if args.proxy:
                config.proxy = args.proxy

        else:
            if not args.url:
                print("[!] URL required")
                sys.exit(1)
            headers = parse_headers(args.headers)
            cookies = parse_cookies(args.cookie) if args.cookie else {}
            body = args.body
            if args.body_file:
                with open(args.body_file, 'r') as f:
                    body = f.read()

            config = RaceConfig(
                target_url=args.url,
                method=args.method,
                headers=headers,
                body=body,
                cookies=cookies,
                parallel_requests=args.parallel,
                attempts=args.attempts,
                strategy=RaceStrategy[args.strategy.upper()],
                timeout=args.timeout,
                verify_tls=not args.no_verify,
                proxy=args.proxy
            )
    except Exception as e:
        print(f"[!] Error creating config: {e}")
        sys.exit(1)

    # Validate config and exit on error
    errors = validate_config(config)
    if errors:
        print("[!] Configuration errors:")
        for error in errors:
            print(f" - {error}")
        sys.exit(1)

    # Run the test engine and output reports
    try:
        engine = TestEngine(config, scenario)
        result = await engine.run()

        print("\n[*] Generating reports...")

        # Handle format "all"
        formats = []
        for fmt in args.format:
            if fmt.lower() == "all":
                formats.extend(["json", "md", "html"])
            else:
                formats.append(fmt.lower())
        formats = list(set(formats))  # Remove duplicates

        from reposys import generate_report
        generate_report(result, args.output, formats)

        print("\n[✓] Test complete!")
        print(f"[*] Reports saved to: {args.output}/")

        sys.exit(1 if result.detection.vulnerable else 0)

    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
        sys.exit(130)

    except Exception as e:
        print(f"\n[!] Error during test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    if sys.platform == 'win32':
        import asyncio.windows_events
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
