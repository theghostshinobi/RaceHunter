# RaceHunter
RaceHunter Beta is an advanced race condition detection tool for pentesters and bug hunters. It performs high-precision concurrent HTTP request bursts to expose hidden concurrency bugs. Includes modular scenarios, robust error handling, and multi-format reports. Use in controlled environments; feedback welcome!



# RaceHunter Beta

RaceHunter Beta is an advanced race condition detection tool designed for penetration testers and bug bounty hunters. It performs high-precision concurrent HTTP request bursts to discover hidden concurrency vulnerabilities. Includes modular scenarios, robust error handling, and generates reports in HTML, Markdown, and JSON formats.

## Ethical Use

Please use RaceHunter responsibly. Only test systems you have explicit permission to evaluate. Unauthorized testing is illegal and unethical. Respect privacy and data laws.

## Installation

Clone the repository:

```bash
git clone https://github.com/theghostshinobi/RaceHunter.git
cd RaceHunter
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the tool with:

```bash
python3 run.py [URL] [OPTIONS]
```

### Common Flags

- `--list-scenarios`  
  List available pre-configured test scenarios.

- `--from-burp FILE`  
  Load HTTP request from a Burp Suite request file.

- `--from-curl CMD`  
  Parse and use a curl command string directly.

- `--method METHOD`  
  HTTP method (default: POST).

- `--header HEADERS`  
  Custom headers (repeatable).

- `--cookie COOKIE`  
  Cookie string or file.

- `--body BODY`  
  Request body data.

- `--body-file FILE`  
  Read request body from file.

- `--parallel PARALLEL`  
  Number of parallel requests per attempt (default: 10).

- `--attempts ATTEMPTS`  
  Number of race attempts (default: 5).

- `--strategy {async_burst,http2_single,threading}`  
  Race strategy - concurrency model to use.

- `--scenario SCENARIO`  
  Loads a pre-configured vulnerability scenario.

- `--timeout TIMEOUT`  
  Request timeout in seconds (default: 10).

- `--no-verify`  
  Disable TLS certificate verification.

- `--proxy PROXY`  
  Proxy URL (e.g., socks5:// or http://).

- `--output OUTPUT`  
  Output directory or file prefix (default: ./results).

- `--format {json,md,html,all}`  
  Format(s) for report generation.

## Example

Basic test with generic scenario:

```bash
python3 run.py https://httpbin.org/get --method GET --parallel 5 --attempts 3 --scenario generic --output ./output --no-verify --format all
```

This command sends 5 parallel GET requests over 3 attempts, testing for race conditions using the generic scenario. Reports will be saved in various formats in `./output`.


This is a beta release; please use responsibly and provide feedback to help improve RaceHunter
