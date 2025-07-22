"""
Architecture Model

This module defines the data models for representing architectural components
and their relationships.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class Component:
    """
    Represents a component in an architectural diagram.
    """
    id: str
    name: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "properties": self.properties,
            "metadata": self.metadata
        }


@dataclass
class Connection:
    """
    Represents a connection between components in an architectural diagram.
    """
    id: str
    source: str  # ID of the source component
    target: str  # ID of the target component
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "properties": self.properties,
            "metadata": self.metadata
        }


@dataclass
class Architecture:
    """
    Represents an architectural diagram with components and connections.
    """
    name: str
    components: List[Component]
    connections: List[Connection]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "components": [component.to_dict() for component in self.components],
            "connections": [connection.to_dict() for connection in self.connections],
            "metadata": self.metadata
        }
    
    def get_component_by_id(self, component_id: str) -> Optional[Component]:
        """
        Get a component by its ID.
        
        Args:
            component_id: ID of the component to find
            
        Returns:
            Component if found, None otherwise
        """
        for component in self.components:
            if component.id == component_id:
                return component
        return None
    
    def get_connections_for_component(self, component_id: str) -> List[Connection]:
        """
        Get all connections for a component.
        
        Args:
            component_id: ID of the component
            
        Returns:
            List of connections where the component is either source or target
        """
        return [
            connection for connection in self.connections
            if connection.source == component_id or connection.target == component_id
        ]
