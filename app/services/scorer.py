"""Scoring algorithm for endpoint health (0-100, higher = safer)."""

from typing import List

from app.models.scan import EndpointResult


def build_flags(result: EndpointResult) -> List[str]:
    """Generate flag list based on check results."""
    flags: List[str] = []

    if result.ssl_expires_days is not None:
        if result.ssl_expires_days <= 0:
            flags.append("SSL_EXPIRED")
        elif result.ssl_expires_days < 30:
            flags.append("SSL_EXPIRING")

    if result.domain_age_days is not None and result.domain_age_days < 90:
        flags.append("NEW_DOMAIN")

    if result.latency_ms is not None and result.latency_ms > 2000:
        flags.append("HIGH_LATENCY")

    if result.abuse_score > 25:
        flags.append("ABUSE_REPORTED")

    if result.in_blacklist:
        flags.append("IN_BLACKLIST")

    if result.domain_owner_changed:
        flags.append("OWNER_CHANGED")

    return flags


def calculate_endpoint_score(result: EndpointResult) -> int:
    """Calculate security score for a single endpoint."""
    score = 100

    # Status penalties
    if result.status == "DOWN":
        score -= 60
    elif result.status == "TIMEOUT":
        score -= 40
    elif result.status == "SSL_ERROR":
        score -= 50
    elif result.status == "UNKNOWN":
        score -= 20

    # SSL penalties
    if result.ssl_expires_days is not None:
        if result.ssl_expires_days <= 0:
            score -= 40
        elif result.ssl_expires_days < 14:
            score -= 25
        elif result.ssl_expires_days < 30:
            score -= 10

    # Domain age penalties (Fase 1: populated via WHOIS)
    if result.domain_age_days is not None:
        if result.domain_age_days < 30:
            score -= 35
        elif result.domain_age_days < 90:
            score -= 15

    if result.domain_owner_changed:
        score -= 30

    # Abuse penalties (Fase 1: populated via AbuseIPDB)
    if result.abuse_score > 75:
        score -= 40
    elif result.abuse_score > 50:
        score -= 25
    elif result.abuse_score > 25:
        score -= 10

    if result.in_blacklist:
        score -= 45

    if "NO_HTTPS" in result.flags:
        score -= 15

    if "REDIRECT_CHAIN" in result.flags:
        score -= 10

    return max(0, min(100, score))


def calculate_overall_score(endpoint_scores: List[int]) -> int:
    """Overall score: average, but worst endpoint pulls it down more."""
    if not endpoint_scores:
        return 50
    if len(endpoint_scores) == 1:
        return endpoint_scores[0]
    avg = sum(endpoint_scores) / len(endpoint_scores)
    worst = min(endpoint_scores)
    # Weighted: 70% average, 30% worst-case
    return max(0, min(100, int(avg * 0.7 + worst * 0.3)))


def overall_status(score: int) -> str:
    if score >= 80:
        return "SAFE"
    if score >= 60:
        return "CAUTION"
    if score >= 40:
        return "RISK"
    return "CRITICAL"


def recommendation(score: int) -> str:
    if score >= 80:
        return "SAFE_TO_INSTALL"
    if score >= 50:
        return "REVIEW_BEFORE_INSTALL"
    return "DO_NOT_INSTALL"
