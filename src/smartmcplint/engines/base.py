"""Base engine class — shared contract for all scanning engines.

- Not premature abstraction: we know all 5 engines exist and share this pattern.
- Every engine takes a client, runs checks, returns EngineResult.
- BaseEngine handles timing and the try/except wrapper so individual engines
  don't repeat that boilerplate.
- Each engine implements _run_checks() with its specific logic.
"""

import logging
import time
from abc import ABC, abstractmethod

from smartmcplint.client import MCPClient
from smartmcplint.models.enums import EngineType
from smartmcplint.models.findings import Finding
from smartmcplint.models.results import EngineResult

logger = logging.getLogger(__name__)


class BaseEngine(ABC):
    """Abstract base for all scanning engines.

    Subclasses implement:
    - engine_type: which engine this is
    - _run_checks(): the actual scanning logic, returns list of findings
    """

    @property
    @abstractmethod
    def engine_type(self) -> EngineType:
        """Which engine this is — used for tagging findings and results."""

    @abstractmethod
    async def _run_checks(self, client: MCPClient) -> list[Finding]:
        """Run all checks for this engine. Subclasses implement this."""

    async def run(self, client: MCPClient) -> EngineResult:
        """Execute the engine and return a wrapped result.

        - Times the execution (engines report how long they took).
        - Catches unexpected exceptions so one broken engine doesn't crash the scan.
        - Calculates score from findings (engines can override _calculate_score).
        """
        start = time.perf_counter()

        try:
            findings = await self._run_checks(client)
        except Exception as e:
            # Engine crashed — report it as a single critical finding rather than
            # killing the entire scan. Other engines can still produce results.
            logger.error(f"Engine {self.engine_type.value} crashed: {e}")
            findings = [
                Finding(
                    rule_id=f"{self.engine_type.value.upper()}-ERR",
                    engine=self.engine_type,
                    severity="critical",
                    title=f"{self.engine_type.value.title()} engine encountered an internal error",
                    message=f"Engine crashed during execution: {e}",
                )
            ]

        duration_ms = (time.perf_counter() - start) * 1000
        score = self._calculate_score(findings)

        logger.debug(
            f"Engine {self.engine_type.value} completed: "
            f"{len(findings)} findings, score={score:.1f}, duration={duration_ms:.0f}ms"
        )

        return EngineResult(
            engine=self.engine_type,
            score=score,
            findings=findings,
            duration_ms=duration_ms,
        )

    def _calculate_score(self, findings: list[Finding]) -> float:
        """Calculate engine score from findings. Default: deduct points per finding.

        - Critical finding: -20 points
        - Warning: -5 points
        - Info: -0 points (informational, no penalty)
        - Score floors at 0 (no negative scores)

        Engines can override this if they need different scoring logic.
        """
        score = 100.0
        for finding in findings:
            if finding.severity == "critical":
                score -= 20
            elif finding.severity == "warning":
                score -= 5
        return max(0.0, score)
