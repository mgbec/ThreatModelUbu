"""
Threat Analyzer Module

This module analyzes architectural components and their relationships
to identify potential security threats and vulnerabilities.
"""

import logging
from typing import Dict, Any, List

from arch_threat_analyzer.src.models.architecture import Architecture
from arch_threat_analyzer.src.models.threat import Threat, Risk
from arch_threat_analyzer.src.utils.exceptions import ThreatAnalysisError

logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """
    Analyzes architectural diagrams to identify potential security threats and risks.
    
    Uses the STRIDE threat modeling methodology:
    - Spoofing
    - Tampering
    - Repudiation
    - Information Disclosure
    - Denial of Service
    - Elevation of Privilege
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the threat analyzer with configuration.
        
        Args:
            config: Configuration dictionary containing analyzer settings
        """
        self.config = config
        self.threat_rules = self._load_threat_rules()
        logger.debug(f"ThreatAnalyzer initialized with {len(self.threat_rules)} threat rules")
        
    def analyze(self, architecture: Architecture) -> List[Threat]:
        """
        Analyze the architecture for potential security threats.
        
        Args:
            architecture: Structured representation of the architecture
            
        Returns:
            List of identified threats
            
        Raises:
            ThreatAnalysisError: If the analysis fails
        """
        try:
            logger.info(f"Analyzing architecture: {architecture.name}")
            
            threats = []
            
            # Analyze individual components
            for component in architecture.components:
                component_threats = self._analyze_component(component, architecture)
                threats.extend(component_threats)
                
            # Analyze connections between components
            for connection in architecture.connections:
                connection_threats = self._analyze_connection(connection, architecture)
                threats.extend(connection_threats)
                
            # Analyze the overall architecture
            architecture_threats = self._analyze_architecture(architecture)
            threats.extend(architecture_threats)
            
            logger.info(f"Analysis complete. Identified {len(threats)} potential threats")
            return threats
            
        except Exception as e:
            error_msg = f"Failed to analyze architecture: {str(e)}"
            logger.exception(error_msg)
            raise ThreatAnalysisError(error_msg) from e
    
    def _load_threat_rules(self) -> List[Dict[str, Any]]:
        """
        Load threat rules from configuration.
        
        Returns:
            List of threat rules
        """
        # In a real implementation, this would load rules from a database or file
        # For now, return some sample rules
        
        return [
            {
                "id": "T001",
                "name": "Unauthenticated API Access",
                "category": "Spoofing",
                "description": "API endpoints without proper authentication can be accessed by unauthorized users",
                "applies_to": ["api", "gateway", "service"],
                "risk_level": "high",
                "mitigation": "Implement proper authentication mechanisms such as API keys, OAuth, or JWT"
            },
            {
                "id": "T002",
                "name": "Unencrypted Data Transfer",
                "category": "Information Disclosure",
                "description": "Data transferred over unencrypted connections can be intercepted",
                "applies_to_connection": True,
                "risk_level": "high",
                "mitigation": "Use TLS/SSL for all data transfers"
            },
            {
                "id": "T003",
                "name": "Insecure Data Storage",
                "category": "Tampering",
                "description": "Data stored without encryption can be accessed or modified by unauthorized users",
                "applies_to": ["database", "storage"],
                "risk_level": "high",
                "mitigation": "Implement data encryption at rest"
            },
            {
                "id": "T004",
                "name": "Denial of Service Vulnerability",
                "category": "Denial of Service",
                "description": "Services without rate limiting or load balancing are vulnerable to DoS attacks",
                "applies_to": ["service", "api", "server"],
                "risk_level": "medium",
                "mitigation": "Implement rate limiting, load balancing, and DoS protection"
            },
            {
                "id": "T005",
                "name": "Insufficient Logging",
                "category": "Repudiation",
                "description": "Lack of proper logging makes it difficult to track security incidents",
                "applies_to_all": True,
                "risk_level": "medium",
                "mitigation": "Implement comprehensive logging and monitoring"
            },
            {
                "id": "T006",
                "name": "Single Point of Failure",
                "category": "Denial of Service",
                "description": "Architecture has components that represent single points of failure",
                "applies_to_architecture": True,
                "risk_level": "high",
                "mitigation": "Implement redundancy and high availability patterns"
            }
        ]
    
    def _analyze_component(self, component, architecture: Architecture) -> List[Threat]:
        """
        Analyze a single component for potential threats.
        
        Args:
            component: Component to analyze
            architecture: The complete architecture for context
            
        Returns:
            List of identified threats for this component
        """
        logger.debug(f"Analyzing component: {component.name} (Type: {component.type})")
        
        threats = []
        
        # Apply threat rules that are applicable to this component
        for rule in self.threat_rules:
            # Skip rules that don't apply to components
            if "applies_to" not in rule and not rule.get("applies_to_all", False):
                continue
                
            # Check if rule applies to this component type
            if "applies_to" in rule and component.type not in rule["applies_to"] and not rule.get("applies_to_all", False):
                continue
                
            # Create a threat based on this rule
            threat = Threat(
                id=f"{rule['id']}-{component.id}",
                name=rule["name"],
                description=rule["description"],
                category=rule["category"],
                affected_component=component.id,
                risk=Risk(
                    level=rule["risk_level"],
                    impact="high" if rule["risk_level"] == "high" else "medium",
                    likelihood="likely" if rule["risk_level"] == "high" else "possible"
                ),
                mitigation=rule["mitigation"]
            )
            
            threats.append(threat)
            logger.debug(f"Identified threat: {threat.name} for component {component.name}")
            
        return threats
    
    def _analyze_connection(self, connection, architecture: Architecture) -> List[Threat]:
        """
        Analyze a connection between components for potential threats.
        
        Args:
            connection: Connection to analyze
            architecture: The complete architecture for context
            
        Returns:
            List of identified threats for this connection
        """
        logger.debug(f"Analyzing connection from {connection.source} to {connection.target}")
        
        threats = []
        
        # Get the source and target components
        source_component = next((c for c in architecture.components if c.id == connection.source), None)
        target_component = next((c for c in architecture.components if c.id == connection.target), None)
        
        if not source_component or not target_component:
            logger.warning(f"Could not find components for connection: {connection.id}")
            return threats
            
        # Apply threat rules that are applicable to connections
        for rule in self.threat_rules:
            if not rule.get("applies_to_connection", False) and not rule.get("applies_to_all", False):
                continue
                
            # Create a threat based on this rule
            threat = Threat(
                id=f"{rule['id']}-{connection.id}",
                name=rule["name"],
                description=rule["description"],
                category=rule["category"],
                affected_component=f"{source_component.id}-{target_component.id}",
                risk=Risk(
                    level=rule["risk_level"],
                    impact="high" if rule["risk_level"] == "high" else "medium",
                    likelihood="likely" if rule["risk_level"] == "high" else "possible"
                ),
                mitigation=rule["mitigation"]
            )
            
            threats.append(threat)
            logger.debug(f"Identified threat: {threat.name} for connection {connection.id}")
            
        return threats
    
    def _analyze_architecture(self, architecture: Architecture) -> List[Threat]:
        """
        Analyze the overall architecture for potential threats.
        
        Args:
            architecture: The complete architecture
            
        Returns:
            List of identified threats for the overall architecture
        """
        logger.debug(f"Analyzing overall architecture: {architecture.name}")
        
        threats = []
        
        # Apply threat rules that are applicable to the overall architecture
        for rule in self.threat_rules:
            if not rule.get("applies_to_architecture", False) and not rule.get("applies_to_all", False):
                continue
                
            # Create a threat based on this rule
            threat = Threat(
                id=f"{rule['id']}-arch",
                name=rule["name"],
                description=rule["description"],
                category=rule["category"],
                affected_component="overall_architecture",
                risk=Risk(
                    level=rule["risk_level"],
                    impact="high" if rule["risk_level"] == "high" else "medium",
                    likelihood="likely" if rule["risk_level"] == "high" else "possible"
                ),
                mitigation=rule["mitigation"]
            )
            
            threats.append(threat)
            logger.debug(f"Identified threat: {threat.name} for overall architecture")
            
        return threats
