"""ScanOrchestrator — wires transport, client, engines, and scoring into one scan.

Execution model:
  Phase 1 (parallel): Conformance, Security, Quality, Behavior
  Phase 2 (sequential): Auto-Fix (consumes Phase 1 findings)

The scanner owns the transport lifecycle — it connects, runs all engines,
then disconnects. Engines never manage transport directly.
"""

import asyncio
import logging
import time

from smartmcplint.client import MCPClient
from smartmcplint.engines.autofix import AutoFixEngine
from smartmcplint.engines.base import BaseEngine
from smartmcplint.engines.behavior import BehaviorEngine
from smartmcplint.engines.conformance import ConformanceEngine
from smartmcplint.engines.quality import QualityEngine
from smartmcplint.engines.security import SecurityEngine
from smartmcplint.models.config import ScanConfig
from smartmcplint.models.enums import EngineType, Grade
from smartmcplint.models.findings import FixSuggestion
from smartmcplint.models.results import EngineResult, ScanResult
from smartmcplint.transport import create_transport

logger = logging.getLogger(__name__)

# Grade thresholds — ordered highest to lowest so the first match wins.
_GRADE_THRESHOLDS: list[tuple[float, Grade]] = [
    (95.0, Grade.A_PLUS),
    (85.0, Grade.A),
    (70.0, Grade.B),
    (55.0, Grade.C),
    (40.0, Grade.D),
    (0.0,  Grade.F),
]


class Scanner:
    """Orchestrates a full SmartMCPLint scan against one MCP server.

    Usage:
        scanner = Scanner(config)
        result = await scanner.scan()
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    # -------------------------------------------------------------------------
    # Scoring helpers
    # -------------------------------------------------------------------------

    def _compute_score(self, engine_results: dict[EngineType, EngineResult]) -> float:
        """Compute the weighted average score across all engines.

        Normalizes by the sum of active weights so custom weight configurations
        that don't sum to exactly 1.0 still produce a valid 0-100 score.
        Skipped engines are treated as 100 — no evidence of problems found.
        """
        weights = self._config.weights
        engine_weight_pairs: list[tuple[EngineType, float]] = [
            (EngineType.CONFORMANCE, weights.conformance),
            (EngineType.SECURITY,    weights.security),
            (EngineType.QUALITY,     weights.quality),
            (EngineType.BEHAVIOR,    weights.behavior),
        ]

        total_weight = 0.0
        weighted_score = 0.0

        for engine_type, weight in engine_weight_pairs:
            result = engine_results.get(engine_type)
            engine_score = (result.score if result and not result.skipped else 100.0)
            weighted_score += engine_score * weight
            total_weight += weight

        if total_weight == 0:
            return 100.0

        return min(100.0, max(0.0, weighted_score / total_weight))

    def _score_to_grade(self, score: float) -> Grade:
        """Convert a numeric score to a letter grade."""
        for threshold, grade in _GRADE_THRESHOLDS:
            if score >= threshold:
                return grade
        return Grade.F

    # -------------------------------------------------------------------------
    # Main scan entry point (implemented in subsequent steps)
    # -------------------------------------------------------------------------

    async def scan(self) -> ScanResult:
        """Connect to the server, run all engines, and return a ScanResult."""
        scan_start = time.perf_counter()

        transport = create_transport(
            transport_type=self._config.transport,
            server_cmd=self._config.server_cmd or None,
            server_url=self._config.server_url,
            timeout=self._config.timeout,
        )

        async with transport:
            client = MCPClient(transport)

            logger.info("Initializing MCP session...")
            await client.initialize()
            assert client.server_info is not None

            await client.list_tools()
            logger.info(f"Discovered {len(client.tools)} tool(s)")

            if client.server_info.capabilities.resources:
                await client.list_resources()
                logger.info(f"Discovered {len(client.resources)} resource(s)")

            # Phase 1: run engines in parallel
            engine_results: dict[EngineType, EngineResult] = {}

            all_engines: list[tuple[EngineType, BaseEngine]] = [
                (EngineType.CONFORMANCE, ConformanceEngine()),
                (EngineType.SECURITY,    SecurityEngine(self._config)),
                (EngineType.QUALITY,     QualityEngine(self._config)),
                (EngineType.BEHAVIOR,    BehaviorEngine(self._config)),
            ]

            # Separate engines to run from engines the user explicitly skipped
            active: list[tuple[EngineType, BaseEngine]] = []
            for engine_type, engine in all_engines:
                if engine_type.value in self._config.skip_engines:
                    engine_results[engine_type] = EngineResult(
                        engine=engine_type,
                        score=100.0,
                        skipped=True,
                        skip_reason="Skipped via configuration",
                    )
                else:
                    active.append((engine_type, engine))

            logger.info(
                f"Running {len(active)} engine(s) in parallel "
                f"({len(all_engines) - len(active)} skipped)"
            )

            raw_results = await asyncio.gather(
                *[engine.run(client) for _, engine in active],
                return_exceptions=True,
            )

            for (engine_type, _), raw in zip(active, raw_results):
                if isinstance(raw, BaseException):
                    # BaseEngine.run() should never raise — but if it does,
                    # record it as skipped rather than crashing the whole scan.
                    logger.error(f"Engine {engine_type.value} raised unexpectedly: {raw}")
                    engine_results[engine_type] = EngineResult(
                        engine=engine_type,
                        score=100.0,
                        skipped=True,
                        skip_reason=f"Engine crashed unexpectedly: {raw}",
                    )
                else:
                    engine_results[engine_type] = raw

            # Phase 2: Auto-Fix (sequential — consumes Phase 1 findings)
            all_findings = [
                f
                for er in engine_results.values()
                for f in er.findings
            ]
            fix_suggestions: list[FixSuggestion] = await AutoFixEngine(
                self._config
            ).generate(all_findings)

            if fix_suggestions:
                logger.info(f"Auto-Fix generated {len(fix_suggestions)} suggestion(s)")

            scan_duration_ms = (time.perf_counter() - scan_start) * 1000
            overall_score = self._compute_score(engine_results)

            return ScanResult(
                server_info=client.server_info,
                engine_results=engine_results,
                fix_suggestions=fix_suggestions,
                overall_score=overall_score,
                grade=self._score_to_grade(overall_score),
                scan_duration_ms=scan_duration_ms,
            )
