#!/usr/bin/env python3

"""
RaceHunter - Anomaly Detection & Analysis
Production-ready detection logic for race condition vulnerabilities
© GHOSTSHINOBI 2025
"""

import re
import statistics
from typing import List, Dict, Optional
from collections import defaultdict

from core import (
    RaceAttempt,
    RaceResponse,
    RaceScenario,
    Detection,
    VulnerabilityType,
    SeverityLevel
)

from utils import (
    calculate_response_hash,
    calculate_semantic_hash,
    parse_json_safe,
    extract_numbers_from_text
)


class AnomalyDetector:
    """
    Production-grade anomaly detector for race conditions
    Multi-signal analysis with confidence scoring
    """

    def __init__(
        self,
        baseline: RaceAttempt,
        attempts: List[RaceAttempt],
        scenario: Optional[RaceScenario] = None
    ):
        self.baseline = baseline
        self.attempts = attempts
        self.scenario = scenario

    def detect_vulnerability(self) -> Detection:
        """
        Main entry point for vulnerability detection
        Returns Detection object with verdict and evidence
        """
        status_analysis = self._analyze_status_codes()
        similarity_analysis = self._analyze_response_similarity()
        numeric_analysis = self._analyze_numeric_patterns()
        keyword_analysis = self._analyze_keywords()
        timing_analysis = self._analyze_timing()

        vulnerability_signals = []
        confidence_scores = []

        if status_analysis['anomaly']:
            vulnerability_signals.append(status_analysis['reason'])
            confidence_scores.append(status_analysis['confidence'])

        if similarity_analysis['anomaly']:
            vulnerability_signals.append(similarity_analysis['reason'])
            confidence_scores.append(similarity_analysis['confidence'])

        if numeric_analysis['anomaly']:
            vulnerability_signals.append(numeric_analysis['reason'])
            confidence_scores.append(numeric_analysis['confidence'] * 1.5)  # Higher weight

        if keyword_analysis['anomaly']:
            vulnerability_signals.append(keyword_analysis['reason'])
            confidence_scores.append(keyword_analysis['confidence'])

        if timing_analysis['anomaly']:
            vulnerability_signals.append(timing_analysis['reason'])
            confidence_scores.append(timing_analysis['confidence'] * 0.5)  # Lower weight

        vulnerable = len(vulnerability_signals) >= 2  # At least 2 signals

        confidence = min(sum(confidence_scores) / len(confidence_scores), 1.0) if confidence_scores else 0.0

        vuln_type = self._classify_vulnerability_type(numeric_analysis, keyword_analysis, status_analysis)

        severity = self._determine_severity(vuln_type, confidence, numeric_analysis)

        baseline_success_rate = self.baseline.success_rate
        race_success_rates = [a.success_rate for a in self.attempts]
        avg_race_success_rate = statistics.mean(race_success_rates) if race_success_rates else 0.0
        deviation = abs(avg_race_success_rate - baseline_success_rate)

        affected_responses = self._collect_affected_responses()

        return Detection(
            vulnerable=vulnerable,
            vulnerability_type=vuln_type if vulnerable else None,
            severity=severity,
            confidence=confidence,
            anomaly_reasons=vulnerability_signals,
            affected_responses=affected_responses,
            baseline_success_rate=baseline_success_rate,
            race_success_rate=avg_race_success_rate,
            deviation=deviation
        )

    def _analyze_status_codes(self) -> Dict:
        baseline_success_rate = self.baseline.success_rate
        race_success_rates = [a.success_rate for a in self.attempts]
        avg_race_success_rate = statistics.mean(race_success_rates) if race_success_rates else 0.0
        deviation = abs(avg_race_success_rate - baseline_success_rate)

        if deviation > 0.2:  # 20% deviation threshold
            anomalous_attempts = sum(
                1 for a in self.attempts if abs(a.success_rate - baseline_success_rate) > 0.2
            )
            consistency = anomalous_attempts / len(self.attempts) if self.attempts else 0
            return {
                'anomaly': True,
                'reason': f"Status code anomaly: {avg_race_success_rate * 100:.0f}% success rate vs baseline {baseline_success_rate * 100:.0f}%",
                'confidence': consistency,
                'deviation': deviation
            }
        return {'anomaly': False, 'confidence': 0.0}

    def _analyze_response_similarity(self) -> Dict:
        all_responses = []
        for attempt in self.attempts:
            all_responses.extend(attempt.responses)

        if not all_responses:
            return {'anomaly': False, 'confidence': 0.0}

        semantic_hashes = []
        for resp in all_responses:
            if resp.is_error:
                continue
            json_data = parse_json_safe(resp.body)
            if json_data:
                hash_val = calculate_semantic_hash(json_data)
            else:
                hash_val = calculate_response_hash(resp.body, normalize=True)
            semantic_hashes.append(hash_val)

        if not semantic_hashes:
            return {'anomaly': False, 'confidence': 0.0}

        unique_hashes = len(set(semantic_hashes))
        total_hashes = len(semantic_hashes)
        uniqueness = unique_hashes / total_hashes

        if uniqueness < 0.3:  # High similarity (low uniqueness)
            success_count = sum(1 for r in all_responses if r.is_success)
            success_ratio = success_count / len(all_responses) if all_responses else 0
            if success_ratio > 0.7:
                return {
                    'anomaly': True,
                    'reason': f"High response similarity: {success_ratio * 100:.0f}% identical successful responses",
                    'confidence': success_ratio
                }
        return {'anomaly': False, 'confidence': 0.0}

    def _analyze_numeric_patterns(self) -> Dict:
        anomalies = []
        negative_found = False

        for attempt in self.attempts:
            for resp in attempt.responses:
                if resp.is_error:
                    continue

                numbers = extract_numbers_from_text(resp.body)
                negative_values = [n for n in numbers if n < 0]
                if negative_values:
                    anomalies.append(f"Negative values detected: {negative_values[:3]}")
                    negative_found = True

                json_data = parse_json_safe(resp.body)
                if json_data:
                    financial_fields = ['balance', 'amount', 'quantity', 'stock', 'credits', 'points']
                    for key in financial_fields:
                        value = self._extract_nested_field(json_data, key)
                        if value is not None and isinstance(value, (int, float)) and value < 0:
                            anomalies.append(f"Negative {key}: {value}")
                            negative_found = True

        if anomalies:
            confidence = min(len(anomalies) / (len(self.attempts) * 2), 1.0)
            return {
                'anomaly': True,
                'reason': f"Numeric anomalies: {', '.join(list(set(anomalies))[:3])}",
                'confidence': confidence,
                'negative_values': negative_found
            }
        return {'anomaly': False, 'confidence': 0.0, 'negative_values': False}

    def _analyze_keywords(self) -> Dict:
        success_keywords = [
            r'(?i)success', r'(?i)applied', r'(?i)approved',
            r'(?i)complete', r'(?i)accepted', r'(?i)confirmed'
        ]
        failure_keywords = [
            r'(?i)error', r'(?i)failed', r'(?i)invalid',
            r'(?i)denied', r'(?i)rejected', r'(?i)exhausted',
            r'(?i)already.*used', r'(?i)insufficient'
        ]

        if self.scenario:
            if self.scenario.success_indicators:
                success_keywords = self.scenario.success_indicators
            if self.scenario.failure_indicators:
                failure_keywords = self.scenario.failure_indicators

        baseline_success = 0
        baseline_failure = 0
        for resp in self.baseline.responses:
            body_lower = resp.body.lower()
            if any(re.search(kw, body_lower) for kw in success_keywords):
                baseline_success += 1
            if any(re.search(kw, body_lower) for kw in failure_keywords):
                baseline_failure += 1

        baseline_total = len(self.baseline.responses)
        baseline_success_ratio = baseline_success / baseline_total if baseline_total > 0 else 0

        race_success = 0
        race_failure = 0
        race_total = 0
        for attempt in self.attempts:
            for resp in attempt.responses:
                if resp.is_error:
                    continue
                race_total += 1
                body_lower = resp.body.lower()
                if any(re.search(kw, body_lower) for kw in success_keywords):
                    race_success += 1
                if any(re.search(kw, body_lower) for kw in failure_keywords):
                    race_failure += 1

        race_success_ratio = race_success / race_total if race_total > 0 else 0
        deviation = abs(race_success_ratio - baseline_success_ratio)

        if deviation > 0.3:
            return {
                'anomaly': True,
                'reason': f"Keyword pattern deviation: {race_success_ratio * 100:.0f}% vs baseline {baseline_success_ratio * 100:.0f}%",
                'confidence': min(deviation, 1.0)
            }
        return {'anomaly': False, 'confidence': 0.0}

    def _analyze_timing(self) -> Dict:
        baseline_timings = [r.timing for r in self.baseline.responses if not r.is_error]
        race_timings = []
        for attempt in self.attempts:
            race_timings.extend([r.timing for r in attempt.responses if not r.is_error])

        if not baseline_timings or not race_timings or len(race_timings) < 2:
            return {'anomaly': False, 'confidence': 0.0}

        baseline_avg = statistics.mean(baseline_timings)
        race_avg = statistics.mean(race_timings)

        try:
            race_stdev = statistics.stdev(race_timings)
            race_variance_coef = race_stdev / race_avg if race_avg > 0 else 0
            if race_variance_coef > 1.0:
                return {
                    'anomaly': True,
                    'reason': f"High timing variance (CV={race_variance_coef:.2f}), suggests lock contention",
                    'confidence': min(race_variance_coef / 2.0, 0.5)
                }
        except statistics.StatisticsError:
            pass

        return {'anomaly': False, 'confidence': 0.0}

    def _classify_vulnerability_type(
        self,
        numeric_analysis: Dict,
        keyword_analysis: Dict,
        status_analysis: Dict
    ) -> Optional[VulnerabilityType]:
        if numeric_analysis.get('negative_values'):
            return VulnerabilityType.BALANCE_OVERDRAW

        if self.scenario and self.scenario.vulnerability_type:
            return self.scenario.vulnerability_type

        if status_analysis.get('anomaly') or keyword_analysis.get('anomaly'):
            return VulnerabilityType.GENERIC_RACE

        return VulnerabilityType.GENERIC_RACE

    def _determine_severity(
        self,
        vuln_type: Optional[VulnerabilityType],
        confidence: float,
        numeric_analysis: Dict
    ) -> SeverityLevel:
        if not vuln_type:
            return SeverityLevel.INFO

        critical_types = {
            VulnerabilityType.BALANCE_OVERDRAW,
            VulnerabilityType.PRIVILEGE_ESCALATION
        }
        high_types = {
            VulnerabilityType.COUPON_REUSE,
            VulnerabilityType.STOCK_EXHAUSTION,
            VulnerabilityType.DUPLICATE_TRANSACTION
        }
        medium_types = {
            VulnerabilityType.RATE_LIMIT_BYPASS,
            VulnerabilityType.CSRF_TOKEN_REUSE
        }

        if vuln_type in critical_types:
            return SeverityLevel.CRITICAL
        if vuln_type in high_types:
            return SeverityLevel.HIGH
        if vuln_type in medium_types:
            return SeverityLevel.MEDIUM

        if confidence >= 0.8:
            return SeverityLevel.HIGH
        if confidence >= 0.5:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def _collect_affected_responses(self) -> List[RaceResponse]:
        affected = []
        for attempt in self.attempts:
            if attempt.anomaly_detected:
                for resp in attempt.responses:
                    if resp.is_success and len(affected) < 5:
                        affected.append(resp)

        if not affected:
            for attempt in self.attempts:
                for resp in attempt.responses:
                    if resp.is_success and len(affected) < 5:
                        affected.append(resp)
        return affected

    def _extract_nested_field(self, data: dict, field_name: str) -> Optional[any]:
        if not isinstance(data, dict):
            return None
        if field_name in data:
            return data[field_name]
        for key, value in data.items():
            if isinstance(value, dict):
                result = self._extract_nested_field(value, field_name)
                if result is not None:
                    return result
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        result = self._extract_nested_field(item, field_name)
                        if result is not None:
                            return result
        return None
