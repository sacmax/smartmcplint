"""Unit tests for Scanner scoring helpers.

scan() requires a live transport and is tested in integration tests.
_compute_score() and _score_to_grade() are pure functions — tested directly.
"""

import pytest

from smartmcplint.models.config import EngineWeights, ScanConfig
from smartmcplint.models.enums import EngineType, Grade
from smartmcplint.models.findings import Finding
from smartmcplint.models.results import EngineResult
from smartmcplint.scanner import Scanner


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def make_scanner(
    conformance: float = 0.25,
    security: float = 0.30,
    quality: float = 0.25,
    behavior: float = 0.15,
) -> Scanner:
    config = ScanConfig(
        transport="stdio",
        weights=EngineWeights(
            conformance=conformance,
            security=security,
            quality=quality,
            behavior=behavior,
        ),
    )
    return Scanner(config)


def make_result(engine: EngineType, score: float, skipped: bool = False) -> EngineResult:
    return EngineResult(engine=engine, score=score, skipped=skipped)


def all_results(scores: dict[EngineType, float]) -> dict[EngineType, EngineResult]:
    return {et: make_result(et, score) for et, score in scores.items()}


# ---------------------------------------------------------------------------
# _compute_score
# ---------------------------------------------------------------------------

class TestComputeScore:

    def test_all_engines_perfect_score_returns_100(self) -> None:
        scanner = make_scanner()
        results = all_results({
            EngineType.CONFORMANCE: 100.0,
            EngineType.SECURITY:    100.0,
            EngineType.QUALITY:     100.0,
            EngineType.BEHAVIOR:    100.0,
        })
        assert scanner._compute_score(results) == pytest.approx(100.0)

    def test_all_engines_zero_score_returns_0(self) -> None:
        scanner = make_scanner()
        results = all_results({
            EngineType.CONFORMANCE: 0.0,
            EngineType.SECURITY:    0.0,
            EngineType.QUALITY:     0.0,
            EngineType.BEHAVIOR:    0.0,
        })
        assert scanner._compute_score(results) == pytest.approx(0.0)

    def test_skipped_engine_counts_as_100(self) -> None:
        # Quality NOT skipped at score 0 vs skipped at score 0 — skip should lift the score
        scanner = make_scanner()
        not_skipped: dict[EngineType, EngineResult] = {
            EngineType.CONFORMANCE: make_result(EngineType.CONFORMANCE, 0.0),
            EngineType.SECURITY:    make_result(EngineType.SECURITY,    0.0),
            EngineType.QUALITY:     make_result(EngineType.QUALITY,     0.0, skipped=False),
            EngineType.BEHAVIOR:    make_result(EngineType.BEHAVIOR,    0.0),
        }
        skipped: dict[EngineType, EngineResult] = {
            EngineType.CONFORMANCE: make_result(EngineType.CONFORMANCE, 0.0),
            EngineType.SECURITY:    make_result(EngineType.SECURITY,    0.0),
            EngineType.QUALITY:     make_result(EngineType.QUALITY,     0.0, skipped=True),
            EngineType.BEHAVIOR:    make_result(EngineType.BEHAVIOR,    0.0),
        }
        assert scanner._compute_score(skipped) > scanner._compute_score(not_skipped)

    def test_missing_engine_treated_as_100(self) -> None:
        # If an engine didn't run at all (not in dict), it defaults to 100
        scanner = make_scanner()
        results = all_results({
            EngineType.CONFORMANCE: 0.0,
            EngineType.SECURITY:    0.0,
            # QUALITY and BEHAVIOR missing
        })
        score = scanner._compute_score(results)
        # Missing engines count as 100 — score lifted above all-zero case
        assert score > 0.0

    def test_two_skipped_engines_normalize_remaining_to_100(self) -> None:
        # Conformance=100, Security=100, Quality+Behavior skipped → should still be 100
        scanner = make_scanner()
        results: dict[EngineType, EngineResult] = {
            EngineType.CONFORMANCE: make_result(EngineType.CONFORMANCE, 100.0),
            EngineType.SECURITY:    make_result(EngineType.SECURITY,    100.0),
            EngineType.QUALITY:     make_result(EngineType.QUALITY,     0.0, skipped=True),
            EngineType.BEHAVIOR:    make_result(EngineType.BEHAVIOR,    0.0, skipped=True),
        }
        assert scanner._compute_score(results) == pytest.approx(100.0)

    def test_weighted_average_computed_correctly(self) -> None:
        # conformance=50, rest=100 with default weights
        # weighted = 50×0.25 + 100×0.30 + 100×0.25 + 100×0.15 = 82.5
        # total_weight = 0.95
        # score = 82.5 / 0.95 ≈ 86.84
        scanner = make_scanner()
        results = all_results({
            EngineType.CONFORMANCE: 50.0,
            EngineType.SECURITY:    100.0,
            EngineType.QUALITY:     100.0,
            EngineType.BEHAVIOR:    100.0,
        })
        assert scanner._compute_score(results) == pytest.approx(82.5 / 0.95, rel=1e-4)

    def test_custom_weights_not_summing_to_1_normalize_correctly(self) -> None:
        # Equal weights of 0.5 each for only conformance + security — others 0
        scanner = make_scanner(conformance=0.5, security=0.5, quality=0.0, behavior=0.0)
        results = all_results({
            EngineType.CONFORMANCE: 80.0,
            EngineType.SECURITY:    60.0,
            EngineType.QUALITY:     0.0,
            EngineType.BEHAVIOR:    0.0,
        })
        # Only conformance and security have weight — missing quality+behavior default to 100
        # weighted = 80×0.5 + 60×0.5 + 100×0 + 100×0 = 70
        # total_weight = 1.0 → score = 70
        assert scanner._compute_score(results) == pytest.approx(70.0)

    def test_zero_total_weight_returns_100(self) -> None:
        scanner = make_scanner(conformance=0.0, security=0.0, quality=0.0, behavior=0.0)
        results = all_results({
            EngineType.CONFORMANCE: 0.0,
            EngineType.SECURITY:    0.0,
            EngineType.QUALITY:     0.0,
            EngineType.BEHAVIOR:    0.0,
        })
        assert scanner._compute_score(results) == pytest.approx(100.0)

    def test_score_clamped_to_100_maximum(self) -> None:
        # Verify max() guard — all 100s should not exceed 100
        scanner = make_scanner()
        results = all_results({
            EngineType.CONFORMANCE: 100.0,
            EngineType.SECURITY:    100.0,
            EngineType.QUALITY:     100.0,
            EngineType.BEHAVIOR:    100.0,
        })
        assert scanner._compute_score(results) <= 100.0

    def test_score_clamped_to_0_minimum(self) -> None:
        scanner = make_scanner()
        results = all_results({
            EngineType.CONFORMANCE: 0.0,
            EngineType.SECURITY:    0.0,
            EngineType.QUALITY:     0.0,
            EngineType.BEHAVIOR:    0.0,
        })
        assert scanner._compute_score(results) >= 0.0


# ---------------------------------------------------------------------------
# _score_to_grade
# ---------------------------------------------------------------------------

class TestScoreToGrade:

    @pytest.fixture
    def scanner(self) -> Scanner:
        return make_scanner()

    def test_100_is_a_plus(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(100.0) == Grade.A_PLUS

    def test_95_boundary_is_a_plus(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(95.0) == Grade.A_PLUS

    def test_below_95_is_a(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(94.9) == Grade.A

    def test_85_boundary_is_a(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(85.0) == Grade.A

    def test_below_85_is_b(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(84.9) == Grade.B

    def test_70_boundary_is_b(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(70.0) == Grade.B

    def test_below_70_is_c(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(69.9) == Grade.C

    def test_55_boundary_is_c(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(55.0) == Grade.C

    def test_below_55_is_d(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(54.9) == Grade.D

    def test_40_boundary_is_d(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(40.0) == Grade.D

    def test_below_40_is_f(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(39.9) == Grade.F

    def test_0_is_f(self, scanner: Scanner) -> None:
        assert scanner._score_to_grade(0.0) == Grade.F
