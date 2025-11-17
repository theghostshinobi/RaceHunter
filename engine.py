#!/usr/bin/env python3

"""
RaceHunter - Test Execution Engine
Orchestrates complete race condition testing workflow
© GHOSTSHINOBI 2025
"""

import asyncio
import time
from typing import Optional, List
from core import RaceConfig, RaceResult, RaceAttempt, RaceScenario, Detection, SeverityLevel
from raceclient import RaceHTTPClient

class TestEngine:
    """
    Complete test execution engine
    Orchestrates: preflight → baseline → race attempts → analysis → report
    """

    def __init__(self, config: RaceConfig, scenario: Optional[RaceScenario] = None):
        self.config = config
        self.scenario = scenario
        self.client = RaceHTTPClient(config)
        self.baseline: Optional[RaceAttempt] = None
        self.attempts: List[RaceAttempt] = []

    async def run(self) -> RaceResult:
        """Execute complete race condition test, return RaceResult"""
        start_time = time.time()
        print(f"\n{'='*60}")
        print("RaceHunter - Race Condition Testing")
        print(f"{'='*60}")
        print(f"Target: {self.config.target_url}")
        print(f"Method: {self.config.method}")
        print(f"Strategy: {self.config.strategy.value}")
        print(f"Parallel Requests: {self.config.parallel_requests}")
        print(f"Attempts: {self.config.attempts}")
        if self.scenario:
            print(f"Scenario: {self.scenario.name}")
        print(f"{'='*60}\n")

        # Phase 1: Pre-flight check
        print("[*] Phase 1: Pre-flight check...")
        if not await self._preflight_check():
            raise RuntimeError("Pre-flight check failed. Endpoint not reachable.")
        print("[✓] Pre-flight check passed\n")

        # Phase 2: Establish baseline
        print("[*] Phase 2: Establishing baseline (5 sequential requests)...")
        self.baseline = await self._establish_baseline()
        print(f"[✓] Baseline established: {self.baseline.success_count}/{self.baseline.requests_sent} successful")
        print(f" Success rate: {self.baseline.success_rate * 100:.1f}%")
        print(f" Average timing: {self.baseline.average_timing * 1000:.1f}ms\n")

        # Phase 3: Execute race attempts
        print(f"[*] Phase 3: Executing {self.config.attempts} race attempts...")
        self.attempts = await self._execute_race_attempts()
        print(f"[✓] Completed {len(self.attempts)} race attempts\n")

        # Phase 4: Analysis
        print("[*] Phase 4: Analyzing results...")
        from analysis import AnomalyDetector
        detector = AnomalyDetector(
            baseline=self.baseline,
            attempts=self.attempts,
            scenario=self.scenario
        )
        detection = detector.detect_vulnerability()
        print("[✓] Analysis complete\n")

        # Phase 5: Generate result including PoC and remediation
        duration = time.time() - start_time
        result = RaceResult(
            config=self.config,
            baseline=self.baseline,
            attempts=self.attempts,
            detection=detection,
            duration=duration
        )

        if detection.vulnerable:
            result.proof_of_concept = self._generate_poc()
            result.remediation_advice = self._generate_remediation(detection)

        self._display_summary(result)

        return result

    async def _preflight_check(self) -> bool:
        """Send single test request to verify endpoint is reachable"""
        try:
            return await self.client.preflight_check()
        except Exception as e:
            print(f"[!] Pre-flight error: {e}")
            return False

    async def _establish_baseline(self) -> RaceAttempt:
        """Execute baseline measurement with sequential requests"""
        return await self.client.execute_baseline(num_requests=5)

    async def _execute_race_attempts(self) -> List[RaceAttempt]:
        """Execute N race attempts with progress tracking"""
        attempts = []
        for i in range(self.config.attempts):
            attempt_num = i + 1
            print(f" └─ Attempt {attempt_num}/{self.config.attempts}... ", end="", flush=True)

            attempt = await self.client.execute_race()
            attempt.attempt_number = attempt_num

            # Quick anomaly check against baseline
            if self.baseline:
                deviation = abs(attempt.success_rate - self.baseline.success_rate)
                if deviation > self.config.success_threshold:
                    attempt.anomaly_detected = True
                    attempt.anomaly_score = deviation
                    print(f"[⚠️ ANOMALY] {attempt.success_count}/{attempt.requests_sent} successful ({attempt.success_rate * 100:.0f}%)")
                else:
                    print(f"[OK] {attempt.success_count}/{attempt.requests_sent} successful ({attempt.success_rate * 100:.0f}%)")
            else:
                print(f"{attempt.success_count}/{attempt.requests_sent} successful")

            attempts.append(attempt)

            if i < self.config.attempts - 1:
                await asyncio.sleep(1.0)  # Avoid overwhelming target

        return attempts

    def _generate_poc(self) -> str:
        """Generate proof-of-concept script"""
        poc = f"""# Race Condition Proof-of-Concept
# Target: {self.config.target_url}

import asyncio
import httpx

async def race_attack():
    n = {self.config.parallel_requests}
    barrier = asyncio.Barrier(n)

    async def send_request(req_id):
        await barrier.wait()  # Synchronization point
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method="{self.config.method}",
                url="{self.config.target_url}",
                headers={repr(self.config.headers)},
                content={repr(self.config.body)},
                cookies={repr(self.config.cookies)}
            )
            print(f"Request {{req_id}}: {{response.status_code}}")
            return response

    tasks = [send_request(i) for i in range(n)]
    responses = await asyncio.gather(*tasks)
    return responses

asyncio.run(race_attack())
"""
        return poc

    def _generate_remediation(self, detection: Detection) -> str:
        """Generate remediation advice based on vulnerability type"""
        if self.scenario and self.scenario.remediation_template:
            return self.scenario.remediation_template

        remediations = {
            "balance_overdraw": """
Remediation:
1. Use database transactions with proper isolation level (SERIALIZABLE)
2. Implement row-level locking (SELECT FOR UPDATE)
3. Add idempotency keys to prevent duplicate processing
4. Consider using optimistic locking with version numbers
""",
            "coupon_reuse": """
Remediation:
1. Add unique constraint on (coupon_code, user_id, order_id)
2. Use INSERT ... ON CONFLICT DO NOTHING for atomic redemption
3. Implement idempotency keys
4. Add rate limiting per user
""",
            "stock_exhaustion": """
Remediation:
1. Use atomic decrement operations (UPDATE ... WHERE stock > 0)
2. Implement database-level constraints (CHECK stock >= 0)
3. Use optimistic locking with version field
4. Consider queue-based inventory management
""",
            "rate_limit_bypass": """
Remediation:
1. Use atomic counter operations (Redis INCR)
2. Implement distributed rate limiting (Redis + Lua scripts)
3. Add request deduplication window
4. Consider using token bucket algorithm
"""
        }

        vuln_key = detection.vulnerability_type.value if detection.vulnerability_type else "generic_race"
        return remediations.get(vuln_key, """
Remediation:
1. Review concurrent access to shared resources
2. Implement proper locking mechanisms
3. Use database transactions with appropriate isolation
4. Add idempotency to API endpoints
""")

    def _display_summary(self, result: RaceResult):
        """Display test summary to console"""
        print(f"\n{'=' * 60}")
        print("TEST SUMMARY")
        print(f"{'=' * 60}")

        if result.detection.vulnerable:
            print("Verdict: ✗ VULNERABLE")
            print(f"Type: {result.detection.vulnerability_type.value if result.detection.vulnerability_type else 'Unknown'}")
            print(f"Severity: {result.detection.severity.value.upper()}")
            print(f"Confidence: {result.detection.confidence * 100:.0f}%")
        else:
            print("Verdict: ✓ NO RACE CONDITION DETECTED")
            print(f"Confidence: {result.detection.confidence * 100:.0f}%")

        print("\nStatistics:")
        print(f" Total Requests: {result.total_requests}")
        print(f" Total Successes: {result.total_successes}")
        print(f" Anomalies Detected: {result.anomaly_count}/{len(result.attempts)} attempts")
        print(f" Duration: {result.duration:.1f}s")

        if result.detection.vulnerable:
            print("\nBaseline vs Race:")
            print(f" Baseline Success Rate: {result.detection.baseline_success_rate * 100:.1f}%")
            print(f" Race Success Rate: {result.detection.race_success_rate * 100:.1f}%")
            print(f" Deviation: {result.detection.deviation * 100:.1f} percentage points")

            if result.detection.anomaly_reasons:
                print("\nAnomaly Indicators:")
                for reason in result.detection.anomaly_reasons:
                    print(f" • {reason}")
        print(f"{'=' * 60}\n")


# Async helper for quick testing
async def run_quick_test(config: RaceConfig) -> RaceResult:
    engine = TestEngine(config)
    return await engine.run()
