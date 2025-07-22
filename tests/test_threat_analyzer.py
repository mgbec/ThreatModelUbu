"""
Tests for the ThreatAnalyzer module.
"""

import pytest
from unittest.mock import patch, MagicMock

from arch_threat_analyzer.src.threat_analyzer import ThreatAnalyzer
from arch_threat_analyzer.src.models.architecture import Architecture, Component, Connection
from arch_threat_analyzer.src.models.threat import Threat
from arch_threat_analyzer.src.utils.exceptions import ThreatAnalysisError


class TestThreatAnalyzer:
    """Test cases for the ThreatAnalyzer class."""
    
    @pytest.fixture
    def config(self):
        """Sample configuration for testing."""
        return {
            "threat_analyzer": {
                "threat_rules_path": "rules/threats.yaml",
                "risk_assessment": {
                    "impact_weights": {
                        "confidentiality": 0.3,
                        "integrity": 0.3,
                        "availability": 0.4
                    },
                    "likelihood_weights": {
                        "attack_complexity": 0.4,
                        "attack_vector": 0.3,
                        "privileges_required": 0.3
                    }
                }
            }
        }
    
    @pytest.fixture
    def analyzer(self, config):
        """Create a ThreatAnalyzer instance for testing."""
        return ThreatAnalyzer(config)
    
    @pytest.fixture
    def sample_architecture(self):
        """Create a sample architecture for testing."""
        components = [
            Component(id="comp1", name="API Gateway", type="gateway", properties={}),
            Component(id="comp2", name="Database", type="database", properties={})
        ]
        
        connections = [
            Connection(id="conn1", source="comp1", target="comp2", type="data_flow")
        ]
        
        return Architecture(
            name="Test Architecture",
            components=components,
            connections=connections,
            metadata={}
        )
    
    def test_init(self, analyzer):
        """Test initialization of ThreatAnalyzer."""
        assert analyzer is not None
        assert hasattr(analyzer, "threat_rules")
        assert len(analyzer.threat_rules) > 0
    
    def test_analyze(self, analyzer, sample_architecture):
        """Test analyzing an architecture."""
        # Mock the analysis methods
        analyzer._analyze_component = MagicMock(return_value=[MagicMock()])
        analyzer._analyze_connection = MagicMock(return_value=[MagicMock()])
        analyzer._analyze_architecture = MagicMock(return_value=[MagicMock()])
        
        # Analyze the architecture
        threats = analyzer.analyze(sample_architecture)
        
        # Verify the result
        assert len(threats) == 4  # 2 components + 1 connection + 1 architecture
        
        # Verify that the analysis methods were called
        assert analyzer._analyze_component.call_count == 2
        assert analyzer._analyze_connection.call_count == 1
        assert analyzer._analyze_architecture.call_count == 1
    
    def test_analyze_component(self, analyzer, sample_architecture):
        """Test analyzing a component."""
        # Get a component from the sample architecture
        component = sample_architecture.components[0]
        
        # Analyze the component
        threats = analyzer._analyze_component(component, sample_architecture)
        
        # Verify the result
        assert isinstance(threats, list)
        # The number of threats depends on the threat rules that apply to this component
        
    def test_analyze_connection(self, analyzer, sample_architecture):
        """Test analyzing a connection."""
        # Get a connection from the sample architecture
        connection = sample_architecture.connections[0]
        
        # Analyze the connection
        threats = analyzer._analyze_connection(connection, sample_architecture)
        
        # Verify the result
        assert isinstance(threats, list)
        # The number of threats depends on the threat rules that apply to this connection
    
    def test_analyze_architecture(self, analyzer, sample_architecture):
        """Test analyzing the overall architecture."""
        # Analyze the architecture
        threats = analyzer._analyze_architecture(sample_architecture)
        
        # Verify the result
        assert isinstance(threats, list)
        # The number of threats depends on the threat rules that apply to the architecture
