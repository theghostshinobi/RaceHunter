#!/usr/bin/env python3

"""
RaceHunter - Utility Functions
Helper functions for parsing, hashing, and data manipulation
© GHOSTSHINOBI 2025
"""

import re
import hashlib
import json
from typing import Dict, Tuple, List, Optional
from urllib.parse import urlparse
from core import RaceConfig

def parse_burp_request(filepath: str) -> Tuple[RaceConfig, Dict[str, str]]:
    """
    Parse HTTP request saved from Burp Suite
    Returns (RaceConfig, session_data)
    Expected format:
    POST /api/endpoint HTTP/1.1
    Host: example.com
    Cookie: session=abc123
    Content-Type: application/json
    {"key": "value"}
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Request file not found: {filepath}")
    except Exception as e:
        raise Exception(f"Error reading file: {e}")

    parts = content.split('\r\n\r\n', 1)
    if len(parts) == 2:
        headers_section, body = parts
    else:
        headers_section = parts[0]
        body = ""

    lines = headers_section.split('\r\n')
    if not lines:
        raise ValueError("Empty request file")

    first_line = lines[0]
    match = re.match(r'^(\w+)\s+([^\s]+)\s+HTTP/[\d.]+', first_line)
    if not match:
        raise ValueError(f"Invalid request line: {first_line}")

    method = match.group(1)
    path = match.group(2)

    headers = {}
    cookies = {}
    host = ""

    for line in lines[1:]:
        if not line.strip():
            continue
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        value = value.strip()
        if key.lower() == 'host':
            host = value
        elif key.lower() == 'cookie':
            for cookie in value.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    c_name, c_value = cookie.split('=', 1)
                    cookies[c_name.strip()] = c_value.strip()
        else:
            headers[key] = value

    if not host:
        raise ValueError("Host header not found in request")

    scheme = "https" if not host.startswith('http') else ""
    if scheme:
        url = f"{scheme}://{host}{path}"
    else:
        url = f"{host}{path}"

    config = RaceConfig(
        target_url=url,
        method=method,
        headers=headers,
        body=body.strip() if body else None,
        cookies=cookies
    )

    session_data = {
        'url': url,
        'cookies': cookies,
        'headers': headers
    }

    return config, session_data

def parse_curl_command(curl_cmd: str) -> RaceConfig:
    """
    Parse curl command to RaceConfig
    Example:
    curl -X POST https://example.com/api \
    -H "Authorization: Bearer token" \
    -d '{"key":"value"}'
    """
    url_match = re.search(r'https?://[^\s\'"]+', curl_cmd)
    if not url_match:
        raise ValueError("URL not found in curl command")
    url = url_match.group(0)

    method_match = re.search(r'-X\s+(\w+)', curl_cmd)
    method = method_match.group(1) if method_match else "GET"

    headers = {}
    header_matches = re.findall(r"-H\s+['\"]([^:]+):\s*([^'\"]+)['\"]", curl_cmd)
    for key, value in header_matches:
        headers[key.strip()] = value.strip()

    body = None
    data_match = re.search(r"-d\s+['\"](.+?)['\"]", curl_cmd, re.DOTALL)
    if data_match:
        body = data_match.group(1)

    cookies = {}
    cookie_match = re.search(r"-b\s+['\"](.+?)['\"]", curl_cmd)
    if cookie_match:
        cookie_str = cookie_match.group(1)
        for cookie in cookie_str.split(';'):
            if '=' in cookie:
                k, v = cookie.split('=', 1)
                cookies[k.strip()] = v.strip()

    return RaceConfig(
        target_url=url,
        method=method,
        headers=headers,
        body=body,
        cookies=cookies
    )

def calculate_response_hash(body: str, normalize: bool = True) -> str:
    """
    Calculate hash of response body
    If normalize=True, removes timestamps, IDs, nonces before hashing
    """
    if normalize:
        normalized = re.sub(r'"timestamp":\s*"[^"]*"', '"timestamp":"NORMALIZED"', body)
        normalized = re.sub(r'"id":\s*"[^"]*"', '"id":"NORMALIZED"', normalized)
        normalized = re.sub(r'"request_id":\s*"[^"]*"', '"request_id":"NORMALIZED"', normalized)
        normalized = re.sub(r'"nonce":\s*"[^"]*"', '"nonce":"NORMALIZED"', normalized)
        normalized = re.sub(r'"token":\s*"[^"]*"', '"token":"NORMALIZED"', normalized)
    else:
        normalized = body
    return hashlib.sha256(normalized.encode()).hexdigest()

def calculate_semantic_hash(response_dict: Dict) -> str:
    """
    Calculate semantic hash focusing on meaningful fields
    Ignores timestamps, IDs, and other ephemeral data
    """
    semantic_keys = {}
    for key, value in response_dict.items():
        key_lower = key.lower()
        if any(skip in key_lower for skip in ['timestamp', 'time', 'id', 'nonce', 'token', 'csrf']):
            continue
        if any(keep in key_lower for keep in ['status', 'message', 'error', 'success', 'amount', 'balance', 'quantity']):
            semantic_keys[key] = value
    semantic_json = json.dumps(semantic_keys, sort_keys=True)
    return hashlib.sha256(semantic_json.encode()).hexdigest()

def extract_numbers_from_text(text: str) -> List[float]:
    """
    Extract all numeric values from text
    Handles integers, floats, negative numbers, scientific notation
    """
    patterns = [
        r'-?\d+\.\d+',  # Floats
        r'-?\d+',       # Integers
        r'-?\d+e[+-]?\d+',  # Scientific notation
    ]
    numbers = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        numbers.extend([float(m) for m in matches])
    return numbers

def classify_response_status(status_code: int) -> str:
    """
    Classify HTTP status code into category
    """
    if 200 <= status_code < 300:
        return "success"
    elif 300 <= status_code < 400:
        return "redirect"
    elif 400 <= status_code < 500:
        return "client_error"
    elif 500 <= status_code < 600:
        return "server_error"
    else:
        return "unknown"

def format_timing(seconds: float) -> str:
    """
    Format timing in human-readable format
    """
    if seconds < 0.001:
        return f"{seconds * 1000000:.0f}μs"
    elif seconds < 1.0:
        return f"{seconds * 1000:.1f}ms"
    else:
        return f"{seconds:.2f}s"

def format_url(url: str, max_length: int = 80) -> str:
    """
    Format URL for display, truncating if too long
    """
    if len(url) <= max_length:
        return url
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    if len(path) > max_length - len(domain) - 10:
        path = path[:max_length - len(domain) - 13] + "..."
    return f"{parsed.scheme}://{domain}{path}"

def sanitize_filename(name: str) -> str:
    """
    Sanitize string for use as filename
    """
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', name)
    sanitized = re.sub(r'\s+', '_', sanitized)
    return sanitized[:200]

def parse_json_safe(text: str) -> Optional[Dict]:
    """
    Safely parse JSON, returns None if invalid
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

def calculate_similarity(str1: str, str2: str) -> float:
    """
    Calculate similarity ratio between two strings
    Returns value between 0.0 (completely different) and 1.0 (identical)
    """
    from difflib import SequenceMatcher
    return SequenceMatcher(None, str1, str2).ratio()

def find_common_substrings(strings: List[str], min_length: int = 10) -> List[str]:
    """
    Find common substrings across multiple strings
    Useful for identifying patterns in responses
    """
    if not strings:
        return []
    if len(strings) == 1:
        return [strings[0]]

    common = set()
    first = strings[0]

    for i in range(len(first) - min_length + 1):
        substring = first[i:i + min_length]
        if all(substring in s for s in strings[1:]):
            common.add(substring)

    return list(common)

def detect_response_type(body: str) -> str:
    """
    Detect response content type
    """
    body_lower = body.strip().lower()
    if body_lower.startswith('{') or body_lower.startswith('['):
        return "json"
    elif body_lower.startswith('<html') or '<html' in body_lower:
        return "html"
    elif all(c in 'abcdefghijklmnopqrstuvwxyz0123456789 \n\r\t.,:;-_?=!@#$%^&*()[]{}' for c in body_lower):
        return "text"
    else:
        return "binary"

def extract_values_from_json(json_obj: Dict, key_pattern: str) -> List:
    """
    Extract all values matching key pattern from nested JSON
    Supports dot notation: "data.balance"
    """
    results = []

    def recurse(obj, pattern_parts):
        if not pattern_parts:
            return [obj]
        current_key = pattern_parts[0]
        remaining = pattern_parts[1:]
        if isinstance(obj, dict):
            if current_key in obj:
                results.extend(recurse(obj[current_key], remaining))
            # Also check case-insensitive
            for key, value in obj.items():
                if key.lower() == current_key.lower():
                    results.extend(recurse(value, remaining))
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    results.extend(recurse(item, pattern_parts))

    pattern_parts = key_pattern.split('.')
    recurse(json_obj, pattern_parts)
    return results

def truncate_body(body: str, max_length: int = 500) -> str:
    """
    Truncate response body for display
    """
    if len(body) <= max_length:
        return body
    return body[:max_length] + f"... ({len(body) - max_length} more chars)"
