#!/usr/bin/env python3

"""
RaceHunter - Scenario Templates
Pre-configured scenarios for common race condition use cases
© GHOSTSHINOBI 2025
"""

from typing import Optional, List
from core import RaceScenario, VulnerabilityType, RaceStrategy

# ====================================================================
# SCENARIO DEFINITIONS
# ====================================================================

SCENARIOS = {

    "ecommerce_coupon": RaceScenario(
        name="E-commerce Coupon Application",
        description="Tests single-use coupon enforcement during concurrent applications",
        category="ecommerce",
        vulnerability_type=VulnerabilityType.COUPON_REUSE,
        success_indicators=[
            r"(?i)(coupon|discount).*applied",
            r"(?i)discount[:\s]+[\$€£]?\d+",
            r"(?i)success"
        ],
        failure_indicators=[
            r"(?i)(already|previously).*used",
            r"(?i)invalid.*coupon",
            r"(?i)(expired|exhausted)",
            r"(?i)error"
        ],
        recommended_parallel=20,
        recommended_attempts=10,
        recommended_strategy=RaceStrategy.ASYNC_BURST,
        false_positive_notes="Some systems may accept duplicate coupons if different sessions. Verify session isolation.",
        remediation_template="""
Remediation for Coupon Reuse:
1. Add unique constraint: UNIQUE(coupon_code, user_id, order_id)
2. Use atomic insertion: INSERT ... ON CONFLICT DO NOTHING
3. Implement idempotency keys for each redemption attempt
4. Add rate limiting per user (max 5 attempts/minute)
5. Use database-level locking: SELECT FOR UPDATE in transaction
"""
    ),

    "ecommerce_checkout": RaceScenario(
        name="E-commerce Checkout",
        description="Tests race conditions in order placement and payment processing",
        category="ecommerce",
        vulnerability_type=VulnerabilityType.DUPLICATE_TRANSACTION,
        success_indicators=[
            r"(?i)order.*placed",
            r"(?i)payment.*success",
            r"(?i)order\s*(id|number)[:\s]+\w+"
        ],
        failure_indicators=[
            r"(?i)payment.*failed",
            r"(?i)insufficient.*funds",
            r"(?i)error"
        ],
        recommended_parallel=15,
        recommended_attempts=10,
        recommended_strategy=RaceStrategy.ASYNC_BURST,
        remediation_template="""
Remediation for Duplicate Transactions:
1. Implement idempotency keys in payment gateway
2. Use optimistic locking with version field
3. Add unique constraint on (user_id, cart_hash, timestamp_window)
4. Implement request deduplication window (5 seconds)
"""
    ),

    "stock_purchase": RaceScenario(
        name="Stock/Inventory Purchase",
        description="Tests stock exhaustion and overselling vulnerabilities",
        category="ecommerce",
        vulnerability_type=VulnerabilityType.STOCK_EXHAUSTION,
        success_indicators=[
            r"(?i)purchase.*success",
            r"(?i)order.*confirmed",
            r"(?i)stock.*available"
        ],
        failure_indicators=[
            r"(?i)out.*of.*stock",
            r"(?i)insufficient.*inventory",
            r"(?i)sold.*out"
        ],
        recommended_parallel=25,
        recommended_attempts=15,
        recommended_strategy=RaceStrategy.ASYNC_BURST,
        remediation_template="""
Remediation for Stock Exhaustion:
1. Use atomic decrement: UPDATE products SET stock = stock - 1 WHERE id = ? AND stock > 0
2. Add CHECK constraint: CHECK (stock >= 0)
3. Implement optimistic locking with version field
4. Use queue-based inventory management for high-demand items
"""
    ),

    "fintech_withdrawal": RaceScenario(
        name="Financial Withdrawal/Transfer",
        description="Tests balance overdraw during concurrent withdrawals",
        category="fintech",
        vulnerability_type=VulnerabilityType.BALANCE_OVERDRAW,
        success_indicators=[
            r"(?i)withdraw.*success",
            r"(?i)transfer.*complete",
            r"(?i)balance[:\s]+[\$€£]?\d+"
        ],
        failure_indicators=[
            r"(?i)insufficient.*funds",
            r"(?i)balance.*too.*low",
            r"(?i)overdraft"
        ],
        recommended_parallel=10,
        recommended_attempts=20,
        recommended_strategy=RaceStrategy.HTTP2_SINGLE_PACKET,
        remediation_template="""
Remediation for Balance Overdraw:
1. Use database transaction with SERIALIZABLE isolation level
2. Implement row-level locking: SELECT balance FROM accounts WHERE id = ? FOR UPDATE
3. Add CHECK constraint: CHECK (balance >= 0)
4. Use optimistic locking with version numbers
5. Implement two-phase commit for distributed systems
"""
    ),

    "fintech_payment": RaceScenario(
        name="Payment Processing",
        description="Tests payment race conditions and double charging",
        category="fintech",
        vulnerability_type=VulnerabilityType.DUPLICATE_TRANSACTION,
        success_indicators=[
            r"(?i)payment.*processed",
            r"(?i)transaction.*complete",
            r"(?i)charged[:\s]+[\$€£]?\d+"
        ],
        failure_indicators=[
            r"(?i)payment.*declined",
            r"(?i)transaction.*failed"
        ],
        recommended_parallel=10,
        recommended_attempts=15,
        recommended_strategy=RaceStrategy.ASYNC_BURST,
        remediation_template="""
Remediation for Duplicate Payment:
1. Implement idempotency keys (UUID per payment intent)
2. Use payment gateway's deduplication features
3. Add unique constraint on (user_id, amount, merchant_ref, timestamp_window)
4. Implement state machine with atomic transitions
"""
    ),

    "rate_limit_bypass": RaceScenario(
        name="Rate Limiting Bypass",
        description="Tests rate limiter effectiveness under concurrent load",
        category="generic",
        vulnerability_type=VulnerabilityType.RATE_LIMIT_BYPASS,
        success_indicators=[
            r"(?i)success",
            r"(?i)200.*ok",
            r"(?i)request.*processed"
        ],
        failure_indicators=[
            r"(?i)429",
            r"(?i)too.*many.*requests",
            r"(?i)rate.*limit.*exceeded"
        ],
        recommended_parallel=50,
        recommended_attempts=5,
        recommended_strategy=RaceStrategy.ASYNC_BURST,
        remediation_template="""
Remediation for Rate Limit Bypass:
1. Use atomic counter operations (Redis INCR)
2. Implement distributed rate limiting with Redis + Lua scripts
3. Use token bucket or leaky bucket algorithm
4. Add request fingerprinting and deduplication
5. Consider using Cloudflare or AWS WAF rate limiting
"""
    ),

    "csrf_token_reuse": RaceScenario(
        name="CSRF Token Reuse",
        description="Tests CSRF token validation under concurrent requests",
        category="generic",
        vulnerability_type=VulnerabilityType.CSRF_TOKEN_REUSE,
        success_indicators=[
            r"(?i)success",
            r"(?i)action.*performed"
        ],
        failure_indicators=[
            r"(?i)csrf.*token.*invalid",
            r"(?i)token.*expired",
            r"(?i)forbidden"
        ],
        recommended_parallel=15,
        recommended_attempts=10,
        recommended_strategy=RaceStrategy.ASYNC_BURST,
        remediation_template="""
Remediation for CSRF Token Reuse:
1. Implement one-time CSRF tokens (invalidate after use)
2. Use atomic token validation and invalidation in same transaction
3. Add per-request nonce in addition to session token
4. Consider using encrypted tokens with short expiry
"""
    ),

    "generic": RaceScenario(
        name="Generic Race Condition",
        description="Generic scenario for custom race condition testing",
        category="generic",
        vulnerability_type=VulnerabilityType.GENERIC_RACE,
        success_indicators=[
            r"(?i)success",
            r"(?i)ok",
            r"(?i)complete"
        ],
        failure_indicators=[
            r"(?i)error",
            r"(?i)failed",
            r"(?i)invalid"
        ],
        recommended_parallel=10,
        recommended_attempts=5,
        recommended_strategy=RaceStrategy.ASYNC_BURST,
        remediation_template="""
General Race Condition Remediation:
1. Review all concurrent access to shared resources
2. Implement proper locking mechanisms (pessimistic or optimistic)
3. Use database transactions with appropriate isolation level
4. Add idempotency to all state-changing operations
5. Consider using message queues for serialization
"""
    ),
}

# ====================================================================
# SCENARIO LOADER
# ====================================================================

class ScenarioLoader:
    """
    Utility class for loading and managing scenarios
    """

    @staticmethod
    def load_scenario(name: str) -> Optional[RaceScenario]:
        """
        Load scenario by name
        Returns None if not found
        """
        return SCENARIOS.get(name)

    @staticmethod
    def list_scenarios() -> List[str]:
        """
        List all available scenario names
        """
        return list(SCENARIOS.keys())

    @staticmethod
    def get_scenarios_by_category(category: str) -> List[RaceScenario]:
        """
        Get all scenarios in a category
        """
        return [s for s in SCENARIOS.values() if s.category == category]

    @staticmethod
    def search_scenarios(keyword: str) -> List[RaceScenario]:
        """
        Search scenarios by keyword in name or description
        """
        keyword_lower = keyword.lower()
        results = []
        for scenario in SCENARIOS.values():
            if (keyword_lower in scenario.name.lower() or
                keyword_lower in scenario.description.lower() or
                keyword_lower in scenario.category.lower()):
                results.append(scenario)
        return results

    @staticmethod
    def display_scenarios():
        """
        Display all scenarios in formatted output
        """
        print("\n" + "=" * 70)
        print("Available Scenarios")
        print("=" * 70)
        categories = {}
        for name, scenario in SCENARIOS.items():
            categories.setdefault(scenario.category, []).append((name, scenario))
        for category, scenarios in sorted(categories.items()):
            print(f"\n{category.upper()}")
            print("-" * 70)
            for name, scenario in scenarios:
                print(f" {name:<25} - {scenario.name}")
                print(f" {'': <25} {scenario.description}")
        print("\n" + "=" * 70)

def get_scenario(name: str) -> Optional[RaceScenario]:
    """
    Convenience function to load scenario
    """
    return ScenarioLoader.load_scenario(name)
