"""Enumerations used across SmartMCPLint."""

from enum import StrEnum


class FindingSeverity(StrEnum):
    """How serious a finding is."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class EngineType(StrEnum):
    """The five scanning engines."""

    CONFORMANCE = "conformance"
    SECURITY = "security"
    QUALITY = "quality"
    BEHAVIOR = "behavior"
    AUTOFIX = "autofix"


class Grade(StrEnum):
    """Letter grades for scan results."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
