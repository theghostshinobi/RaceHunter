#!/usr/bin/env python3

"""
RaceHunter - Core Data Structures
Production-ready race condition testing framework
© GHOSTSHINOBI 2025
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum
import time
import hashlib
import json
import re

# ====================================================================
# ENUMERATIONS
# ====================================================================

class RaceStrategy(Enum):
    """Race condition attack strategies"""
    ASYNC_BURST = "async_burst"          # asyncio.Barrier sync (default)
    HTTP2_SINGLE_PACKET = "http2_single" # HTTP/2 multiplexing (best precision)
    THREADING = "threading"              # threading.Barrier fallback

class VulnerabilityType(Enum):
    """Race condition vulnerability classifications"""
    BALANCE_OVERDRAW = "balance_overdraw"
    COUPON_REUSE = "coupon_reuse"
    STOCK_EXHAUSTION = "stock_exhaustion"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DUPLICATE_TRANSACTION = "duplicate_transaction"
    CSRF_TOKEN_REUSE = "csrf_token_reuse"
    GENERIC_RACE = "generic_race"

class SeverityLevel(Enum):
    """Vulnerability severity levels (CVSS-aligned)"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # 0.0

class HTTPMethod(Enum):
    """Supported HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

# ====================================================================
# CONFIGURATION DATACLASSES
# ====================================================================

@dataclass
class RaceConfig:
    """Complete configuration for race condition testing"""

    # Target
    target_url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)

    # Race settings
    strategy: RaceStrategy = RaceStrategy.ASYNC_BURST
    parallel_requests: int = 10
    attempts: int = 5

    # HTTP settings
    http2_enabled: bool = True
    timeout: float = 10.0
    verify_tls: bool = False

    # Analysis thresholds
    success_threshold: float = 0.3

    # Network
    proxy: Optional[str] = None
    user_agent: str = "RaceHunter/1.0"
    follow_redirects: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize config to dictionary"""
        return {
            'target_url': self.target_url,
            'method': self.method,
            'headers': self.headers,
            'body': self.body,
            'cookies': self.cookies,
            'strategy': self.strategy.value,
            'parallel_requests': self.parallel_requests,
            'attempts': self.attempts,
            'http2_enabled': self.http2_enabled,
            'timeout': self.timeout,
            'verify_tls': self.verify_tls,
            'success_threshold': self.success_threshold,
            'proxy': self.proxy,
            'user_agent': self.user_agent,
            'follow_redirects': self.follow_redirects
        }

# ====================================================================
# RESPONSE & RESULT DATACLASSES
# ====================================================================

@dataclass
class RaceResponse:
    """Single HTTP response from race batch"""
    request_id: int
    status_code: int
    body: str
    headers: Dict[str, str]
    timing: float  # seconds
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        """Check if response is 2xx success"""
        return 200 <= self.status_code < 300

    @property
    def is_error(self) -> bool:
        """Check if request failed completely"""
        return self.error is not None or self.status_code == 0

    @property
    def body_hash(self) -> str:
        """SHA256 hash of response body"""
        return hashlib.sha256(self.body.encode()).hexdigest()

    def extract_numbers(self) -> List[float]:
        """Extract all numeric values from response body"""
        pattern = r'-?\d+\.?\d*'
        matches = re.findall(pattern, self.body)
        return [float(m) for m in matches if m]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize response to dictionary"""
        return {
            'request_id': self.request_id,
            'status_code': self.status_code,
            'body': self.body[:500] if len(self.body) > 500 else self.body,  # Truncate large bodies
            'body_full_hash': self.body_hash,
            'headers': self.headers,
            'timing': self.timing,
            'error': self.error,
            'is_success': self.is_success
        }

@dataclass
class RaceAttempt:
    """Single race attempt (batch of parallel requests)"""
    attempt_number: int
    requests_sent: int
    responses: List[RaceResponse]
    total_time: float
    anomaly_detected: bool = False
    anomaly_score: float = 0.0

    @property
    def success_count(self) -> int:
        """Count successful responses (2xx)"""
        return sum(1 for r in self.responses if r.is_success)

    @property
    def error_count(self) -> int:
        """Count failed requests"""
        return sum(1 for r in self.responses if r.is_error)

    @property
    def success_rate(self) -> float:
        """Percentage of successful responses"""
        if not self.responses:
            return 0.0
        return self.success_count / len(self.responses)

    @property
    def status_code_distribution(self) -> Dict[int, int]:
        """Count of each status code"""
        distribution = {}
        for resp in self.responses:
            code = resp.status_code
            distribution[code] = distribution.get(code, 0) + 1
        return distribution

    @property
    def average_timing(self) -> float:
        """Average response timing"""
        timings = [r.timing for r in self.responses if not r.is_error]
        return sum(timings) / len(timings) if timings else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize attempt to dictionary"""
        return {
            'attempt_number': self.attempt_number,
            'requests_sent': self.requests_sent,
            'success_count': self.success_count,
            'error_count': self.error_count,
            'success_rate': self.success_rate,
            'status_code_distribution': self.status_code_distribution,
            'total_time': self.total_time,
            'average_timing': self.average_timing,
            'anomaly_detected': self.anomaly_detected,
            'anomaly_score': self.anomaly_score,
            'responses': [r.to_dict() for r in self.responses]
        }

@dataclass
class Detection:
    """Vulnerability detection result"""
    vulnerable: bool
    vulnerability_type: Optional[VulnerabilityType]
    severity: SeverityLevel
    confidence: float  # 0.0-1.0
    anomaly_reasons: List[str] = field(default_factory=list)
    affected_responses: List[RaceResponse] = field(default_factory=list)

    # Metrics
    baseline_success_rate: float = 0.0
    race_success_rate: float = 0.0
    deviation: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize detection to dictionary"""
        return {
            'vulnerable': self.vulnerable,
            'vulnerability_type': self.vulnerability_type.value if self.vulnerability_type else None,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'anomaly_reasons': self.anomaly_reasons,
            'baseline_success_rate': self.baseline_success_rate,
            'race_success_rate': self.race_success_rate,
            'deviation': self.deviation,
            'affected_response_count': len(self.affected_responses)
        }

@dataclass
class RaceResult:
    """Complete race condition test result"""
    config: RaceConfig
    baseline: RaceAttempt
    attempts: List[RaceAttempt]
    detection: Detection

    # Metadata
    timestamp: float = field(default_factory=time.time)
    duration: float = 0.0

    # Additional data
    proof_of_concept: str = ""
    remediation_advice: str = ""

    @property
    def total_requests(self) -> int:
        """Total requests sent across all attempts"""
        return sum(a.requests_sent for a in self.attempts) + self.baseline.requests_sent

    @property
    def total_successes(self) -> int:
        """Total successful responses"""
        return sum(a.success_count for a in self.attempts)

    @property
    def anomaly_count(self) -> int:
        """Number of attempts with anomaly detected"""
        return sum(1 for a in self.attempts if a.anomaly_detected)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete result to dictionary"""
        return {
            'config': self.config.to_dict(),
            'baseline': self.baseline.to_dict(),
            'attempts': [a.to_dict() for a in self.attempts],
            'detection': self.detection.to_dict(),
            'timestamp': self.timestamp,
            'duration': self.duration,
            'total_requests': self.total_requests,
            'total_successes': self.total_successes,
            'anomaly_count': self.anomaly_count,
            'proof_of_concept': self.proof_of_concept,
            'remediation_advice': self.remediation_advice
        }

    def to_json(self) -> str:
        """Serialize to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

# ====================================================================
# SCENARIO TEMPLATE DATACLASS
# ====================================================================

@dataclass
class RaceScenario:
    """Pre-configured scenario template"""
    name: str
    description: str
    category: str  # ecommerce, fintech, saas, gaming, generic
    vulnerability_type: VulnerabilityType
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)

    # Recommended config
    recommended_parallel: int = 10
    recommended_attempts: int = 5
    recommended_strategy: RaceStrategy = RaceStrategy.ASYNC_BURST

    # Documentation
    false_positive_notes: str = ""
    remediation_template: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize scenario to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'vulnerability_type': self.vulnerability_type.value,
            'success_indicators': self.success_indicators,
            'failure_indicators': self.failure_indicators,
            'recommended_parallel': self.recommended_parallel,
            'recommended_attempts': self.recommended_attempts,
            'recommended_strategy': self.recommended_strategy.value,
            'false_positive_notes': self.false_positive_notes,
            'remediation_template': self.remediation_template
        }

# ====================================================================
# VERSION & METADATA
# ====================================================================

__version__ = "1.0.0"
__author__ = "GHOSTSHINOBI"
__license__ = "MIT"

# ====================================================================
# UTILITY FUNCTIONS
# ====================================================================

def get_version() -> str:
    """Get RaceHunter version string"""
    return f"RaceHunter v{__version__}"

def validate_url(url: str) -> bool:
    """Validate URL format"""
    pattern = r'^https?://[^\s<>"{}|\\^`\[\]]+$'
    return bool(re.match(pattern, url))

def validate_config(config: RaceConfig) -> List[str]:
    """Validate RaceConfig, return list of errors"""
    errors = []

    if not config.target_url:
        errors.append("target_url is required")
    elif not validate_url(config.target_url):
        errors.append(f"Invalid URL format: {config.target_url}")

    if config.parallel_requests < 1:
        errors.append("parallel_requests must be >= 1")
    elif config.parallel_requests > 100:
        errors.append("parallel_requests must be <= 100 (too many may crash)")

    if config.attempts < 1:
        errors.append("attempts must be >= 1")
    elif config.attempts > 50:
        errors.append("attempts must be <= 50 (too many is excessive)")

    if config.timeout < 1.0:
        errors.append("timeout must be >= 1.0 seconds")

    if not 0.0 <= config.success_threshold <= 1.0:
        errors.append("success_threshold must be between 0.0 and 1.0")

    return errors
