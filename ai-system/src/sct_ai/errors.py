"""Domain-specific exceptions used across the SCT comparison application."""


class SCTComparisonError(Exception):
    """Base class for user-actionable comparison failures."""


class PackageValidationError(SCTComparisonError):
    """Raised when an SCT ZIP is unsafe or invalid."""


class PolicyValidationError(SCTComparisonError):
    """Raised when a ranking policy is missing or invalid."""


class AIConfigurationError(SCTComparisonError):
    """Raised when an AI provider cannot be configured safely."""


class AIOutputError(SCTComparisonError):
    """Raised when a model response fails the evidence contract."""
