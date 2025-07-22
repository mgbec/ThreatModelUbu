"""
Tests for the DiagramParser module.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from arch_threat_analyzer.src.diagram_parser import DiagramParser
from arch_threat_analyzer.src.models.architecture import Architecture
from arch_threat_analyzer.src.utils.exceptions import DiagramParsingError


class TestDiagramParser:
    """Test cases for the DiagramParser class."""
    
    @pytest.fixture
    def config(self):
        """Sample configuration for testing."""
        return {
            "diagram_parser": {
                "supported_extensions": [".png", ".jpg", ".jpeg", ".svg", ".drawio", ".vsdx"],
                "component_detection": {
                    "min_component_size": 50,
                    "max_component_size": 500,
                    "confidence_threshold": 0.7
                }
            }
        }
    
    @pytest.fixture
    def parser(self, config):
        """Create a DiagramParser instance for testing."""
        return DiagramParser(config)
    
    def test_init(self, parser):
        """Test initialization of DiagramParser."""
        assert parser is not None
        assert hasattr(parser, "supported_formats")
        assert ".png" in parser.supported_formats
        assert ".jpg" in parser.supported_formats
        assert ".svg" in parser.supported_formats
        assert ".drawio" in parser.supported_formats
        assert ".vsdx" in parser.supported_formats
    
    def test_parse_nonexistent_file(self, parser):
        """Test parsing a nonexistent file."""
        with pytest.raises(DiagramParsingError) as excinfo:
            parser.parse("nonexistent_file.png")
        assert "not found" in str(excinfo.value)
    
    def test_parse_unsupported_format(self, parser):
        """Test parsing an unsupported file format."""
        # Create a temporary file with an unsupported extension
        with open("test_file.txt", "w") as f:
            f.write("test")
        
        try:
            with pytest.raises(DiagramParsingError) as excinfo:
                parser.parse("test_file.txt")
            assert "Unsupported diagram format" in str(excinfo.value)
        finally:
            # Clean up the temporary file
            if os.path.exists("test_file.txt"):
                os.remove("test_file.txt")
    
    @patch("cv2.imread")
    @patch("cv2.cvtColor")
    def test_parse_image(self, mock_cvtColor, mock_imread, parser):
        """Test parsing an image file."""
        # Mock the image processing functions
        mock_image = MagicMock()
        mock_imread.return_value = mock_image
        mock_cvtColor.return_value = mock_image
        
        # Mock the component and connection identification methods
        parser._identify_components = MagicMock(return_value=[])
        parser._identify_connections = MagicMock(return_value=[])
        
        # Create a temporary image file
        with open("test_image.png", "w") as f:
            f.write("dummy image data")
        
        try:
            # Parse the image
            architecture = parser.parse("test_image.png")
            
            # Verify the result
            assert isinstance(architecture, Architecture)
            assert architecture.name == "test_image.png"
            assert len(architecture.components) == 0
            assert len(architecture.connections) == 0
            
            # Verify that the image processing functions were called
            mock_imread.assert_called_once_with("test_image.png")
            mock_cvtColor.assert_called_once()
            parser._identify_components.assert_called_once()
            parser._identify_connections.assert_called_once()
            
        finally:
            # Clean up the temporary file
            if os.path.exists("test_image.png"):
                os.remove("test_image.png")
