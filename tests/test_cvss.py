import pytest
from app.utils.cvss import calculate_cvss_v31, cvss_round_up


def test_cvss_round_up():
    assert cvss_round_up(4.0) == 4.0
    assert cvss_round_up(4.01) == 4.1
    assert cvss_round_up(4.0000) == 4.0
    assert cvss_round_up(9.81) == 9.9


def test_cvss_critical_calculation():
    # Canonical critical vector: Network, Low complexity, No privileges, No UI, Scope unchanged, High impacts
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H => 9.8
    cvss = calculate_cvss_v31(
        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
    )
    assert cvss.base_score == 9.8
    assert cvss.severity_rating == "CRITICAL"
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in cvss.vector_string


def test_cvss_high_calculation():
    # AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:N => 8.1 HIGH
    cvss = calculate_cvss_v31(
        av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N"
    )
    assert cvss.base_score >= 7.0
    assert cvss.severity_rating == "HIGH"


def test_cvss_zero_impact():
    cvss = calculate_cvss_v31(
        av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N"
    )
    assert cvss.base_score == 0.0
    assert cvss.severity_rating == "NONE"


def test_cvss_scope_changed():
    # Scope changed calculation
    cvss = calculate_cvss_v31(
        av="N", ac="L", pr="L", ui="N", s="C", c="H", i="H", a="H"
    )
    assert cvss.metrics["S"] == "C"
    assert cvss.severity_rating == "CRITICAL"

