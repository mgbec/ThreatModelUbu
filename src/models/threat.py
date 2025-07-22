"""
Threat Model

This module defines the data models for representing security threats
and associated risks.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class Risk:
    """
    Represents the risk associated with a security threat.
    """
    level: str  # high, medium, low
    impact: str  # high, medium, low
    likelihood: str  # likely, possible, unlikely
    score: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "level": self.level,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "score": self.score,
            "details": self.details
        }


@dataclass
class Threat:
    """
    Represents a security threat identified in an architectural diagram.
    """
    id: str
    name: str
    description: str
    category: str  # STRIDE category
    affected_component: str  # ID of the affected component or connection
    risk: Risk
    mitigation: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "affected_component": self.affected_component,
            "risk": self.risk.to_dict(),
            "mitigation": self.mitigation,
            "details": self.details
        }


@dataclass
class Mitigation:
    """
    Represents a mitigation strategy for a security threat.
    """
    id: str
    name: str
    description: str
    effectiveness: str  # high, medium, low
    implementation_complexity: str  # high, medium, low
    cost: str  # high, medium, low
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "effectiveness": self.effectiveness,
            "implementation_complexity": self.implementation_complexity,
            "cost": self.cost,
            "details": self.details
        }
