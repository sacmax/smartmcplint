"""Enumerations used across SmartMCPLint."""

from enum import Enum


class FindingSeverity(str, Enum):
    """How serious a finding is."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class EngineType(str, Enum):
    """The five scanning engines."""

    CONFORMANCE = "conformance"
    SECURITY = "security"
    QUALITY = "quality"
    BEHAVIOR = "behavior"
    AUTOFIX = "autofix"


class Grade(str, Enum):
    """Letter grades for scan results."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
