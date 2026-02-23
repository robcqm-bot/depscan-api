"""Unit tests for the scoring algorithm — no DB or network required."""

import pytest

from app.models.scan import EndpointResult
from app.services.scorer import (
    build_flags,
    calculate_endpoint_score,
    calculate_overall_score,
    overall_status,
    recommendation,
)


def make_result(**kwargs) -> EndpointResult:
    defaults = dict(
        url="https://example.com",
        status="UP",
        latency_ms=200,
        ssl_expires_days=90,
        ssl_valid=True,
        domain_age_days=None,
        domain_owner_changed=None,
        abuse_score=0,
        in_blacklist=False,
        flags=[],
        score=50,
    )
    defaults.update(kwargs)
    return EndpointResult(**defaults)


def test_perfect_endpoint():
    result = make_result()
    assert calculate_endpoint_score(result) == 100


def test_down_penalty():
    result = make_result(status="DOWN")
    assert calculate_endpoint_score(result) == 40


def test_timeout_penalty():
    result = make_result(status="TIMEOUT")
    assert calculate_endpoint_score(result) == 60


def test_ssl_error_penalty():
    result = make_result(status="SSL_ERROR")
    assert calculate_endpoint_score(result) == 50


def test_ssl_expired_penalty():
    result = make_result(ssl_expires_days=-1)
    assert calculate_endpoint_score(result) == 60


def test_ssl_expiring_soon_penalty():
    result = make_result(ssl_expires_days=10)
    assert calculate_endpoint_score(result) == 75


def test_blacklist_penalty():
    result = make_result(in_blacklist=True)
    assert calculate_endpoint_score(result) == 55


def test_no_https_flag():
    result = make_result(url="http://example.com", flags=["NO_HTTPS"])
    assert calculate_endpoint_score(result) == 85


def test_new_domain_young_penalty():
    result = make_result(domain_age_days=20)
    assert calculate_endpoint_score(result) == 65


def test_new_domain_medium_penalty():
    result = make_result(domain_age_days=60)
    assert calculate_endpoint_score(result) == 85


def test_score_clamp_at_zero():
    result = make_result(
        status="DOWN",
        in_blacklist=True,
        abuse_score=80,
        flags=["NO_HTTPS"],
    )
    assert calculate_endpoint_score(result) == 0


def test_score_clamp_at_hundred():
    result = make_result()
    assert calculate_endpoint_score(result) <= 100


def test_overall_score_weighted():
    scores = [100, 100, 0]
    overall = calculate_overall_score(scores)
    # Should be pulled down by worst: 70%*(200/3) + 30%*0 ≈ 46
    assert 40 <= overall <= 50


def test_overall_score_single():
    assert calculate_overall_score([75]) == 75


def test_overall_score_empty():
    assert calculate_overall_score([]) == 50


def test_overall_status_bands():
    assert overall_status(90) == "SAFE"
    assert overall_status(80) == "SAFE"
    assert overall_status(70) == "CAUTION"
    assert overall_status(60) == "CAUTION"
    assert overall_status(50) == "RISK"
    assert overall_status(40) == "RISK"
    assert overall_status(39) == "CRITICAL"
    assert overall_status(0) == "CRITICAL"


def test_recommendation_bands():
    assert recommendation(90) == "SAFE_TO_INSTALL"
    assert recommendation(80) == "SAFE_TO_INSTALL"
    assert recommendation(60) == "REVIEW_BEFORE_INSTALL"
    assert recommendation(50) == "REVIEW_BEFORE_INSTALL"
    assert recommendation(49) == "DO_NOT_INSTALL"
    assert recommendation(0) == "DO_NOT_INSTALL"


def test_build_flags_ssl_expiring():
    result = make_result(ssl_expires_days=15)
    assert "SSL_EXPIRING" in build_flags(result)


def test_build_flags_ssl_expired():
    result = make_result(ssl_expires_days=-5)
    assert "SSL_EXPIRED" in build_flags(result)


def test_build_flags_high_latency():
    result = make_result(latency_ms=2500)
    assert "HIGH_LATENCY" in build_flags(result)


def test_build_flags_in_blacklist():
    result = make_result(in_blacklist=True)
    assert "IN_BLACKLIST" in build_flags(result)


def test_build_flags_new_domain():
    result = make_result(domain_age_days=30)
    assert "NEW_DOMAIN" in build_flags(result)


def test_build_flags_clean():
    result = make_result()
    assert build_flags(result) == []
