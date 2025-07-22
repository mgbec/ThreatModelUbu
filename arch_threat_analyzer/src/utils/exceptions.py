"""
Exceptions Module

This module defines custom exceptions used throughout the application.
"""


class ArchThreatAnalyzerError(Exception):
    """Base exception for all application errors."""
    pass


class ConfigurationError(ArchThreatAnalyzerError):
    """Raised when there is an error in the configuration."""
    pass


class DiagramParsingError(ArchThreatAnalyzerError):
    """Raised when there is an error parsing a diagram."""
    pass


class ThreatAnalysisError(ArchThreatAnalyzerError):
    """Raised when there is an error analyzing threats."""
    pass


class ReportGenerationError(ArchThreatAnalyzerError):
    """Raised when there is an error generating a report."""
    pass
