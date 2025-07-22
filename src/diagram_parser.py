"""
Diagram Parser Module

This module is responsible for parsing different types of architectural diagrams
and converting them into a standardized internal representation for analysis.
"""

import logging
import os
from typing import Dict, Any, List

import cv2
import numpy as np

from arch_threat_analyzer.src.utils.exceptions import DiagramParsingError
from arch_threat_analyzer.src.models.architecture import Architecture, Component, Connection

logger = logging.getLogger(__name__)


class DiagramParser:
    """
    Parser for architectural diagrams that extracts components and their relationships.
    
    Supports various diagram formats including image-based diagrams (PNG, JPG),
    draw.io diagrams, and Visio diagrams.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the diagram parser with configuration.
        
        Args:
            config: Configuration dictionary containing parser settings
        """
        self.config = config
        self.supported_formats = {
            ".png": self._parse_image,
            ".jpg": self._parse_image,
            ".jpeg": self._parse_image,
            ".svg": self._parse_svg,
            ".drawio": self._parse_drawio,
            ".vsdx": self._parse_visio
        }
        logger.debug(f"DiagramParser initialized with supported formats: {list(self.supported_formats.keys())}")
        
    def parse(self, diagram_path: str) -> Architecture:
        """
        Parse the architectural diagram and return a structured representation.
        
        Args:
            diagram_path: Path to the diagram file
            
        Returns:
            Architecture: Structured representation of the architecture
            
        Raises:
            DiagramParsingError: If the diagram cannot be parsed
        """
        if not os.path.exists(diagram_path):
            error_msg = f"Diagram file not found: {diagram_path}"
            logger.error(error_msg)
            raise DiagramParsingError(error_msg)
            
        file_ext = os.path.splitext(diagram_path)[1].lower()
        
        if file_ext not in self.supported_formats:
            error_msg = f"Unsupported diagram format: {file_ext}"
            logger.error(error_msg)
            raise DiagramParsingError(error_msg)
            
        try:
            logger.info(f"Parsing diagram: {diagram_path}")
            parser_func = self.supported_formats[file_ext]
            architecture = parser_func(diagram_path)
            logger.info(f"Successfully parsed diagram with {len(architecture.components)} components and {len(architecture.connections)} connections")
            return architecture
        except Exception as e:
            error_msg = f"Failed to parse diagram: {str(e)}"
            logger.exception(error_msg)
            raise DiagramParsingError(error_msg) from e
    
    def _parse_image(self, image_path: str) -> Architecture:
        """
        Parse an image-based architectural diagram using computer vision techniques.
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Architecture: Structured representation of the architecture
        """
        logger.debug(f"Parsing image diagram: {image_path}")
        
        try:
            # Load the image
            image = cv2.imread(image_path)
            if image is None:
                raise DiagramParsingError(f"Failed to load image: {image_path}")
                
            # Convert to grayscale for processing
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply image processing techniques to identify components
            # This is a simplified placeholder - real implementation would use more advanced CV
            components = self._identify_components(gray)
            
            # Identify connections between components
            connections = self._identify_connections(gray, components)
            
            # Create architecture representation
            architecture = Architecture(
                name=os.path.basename(image_path),
                components=components,
                connections=connections,
                metadata={"source_type": "image", "source_path": image_path}
            )
            
            return architecture
            
        except Exception as e:
            logger.exception(f"Error parsing image diagram: {e}")
            raise DiagramParsingError(f"Failed to parse image diagram: {str(e)}") from e
    
    def _parse_svg(self, svg_path: str) -> Architecture:
        """
        Parse an SVG architectural diagram.
        
        Args:
            svg_path: Path to the SVG file
            
        Returns:
            Architecture: Structured representation of the architecture
        """
        logger.debug(f"Parsing SVG diagram: {svg_path}")
        
        # Placeholder for SVG parsing logic
        # In a real implementation, this would use an SVG parsing library
        
        # For now, return a simple placeholder architecture
        components = [
            Component(id="comp1", name="Component 1", type="service", 
                     properties={"x": 100, "y": 100, "width": 120, "height": 80}),
            Component(id="comp2", name="Component 2", type="database", 
                     properties={"x": 300, "y": 200, "width": 100, "height": 100})
        ]
        
        connections = [
            Connection(id="conn1", source="comp1", target="comp2", type="data_flow")
        ]
        
        return Architecture(
            name=os.path.basename(svg_path),
            components=components,
            connections=connections,
            metadata={"source_type": "svg", "source_path": svg_path}
        )
    
    def _parse_drawio(self, drawio_path: str) -> Architecture:
        """
        Parse a draw.io architectural diagram.
        
        Args:
            drawio_path: Path to the draw.io file
            
        Returns:
            Architecture: Structured representation of the architecture
        """
        logger.debug(f"Parsing draw.io diagram: {drawio_path}")
        
        # Placeholder for draw.io parsing logic
        # In a real implementation, this would use XML parsing since draw.io files are XML-based
        
        # For now, return a simple placeholder architecture
        components = [
            Component(id="comp1", name="API Gateway", type="gateway", 
                     properties={"x": 100, "y": 100, "width": 120, "height": 80}),
            Component(id="comp2", name="Lambda Function", type="compute", 
                     properties={"x": 300, "y": 200, "width": 100, "height": 100}),
            Component(id="comp3", name="DynamoDB", type="database", 
                     properties={"x": 500, "y": 300, "width": 100, "height": 100})
        ]
        
        connections = [
            Connection(id="conn1", source="comp1", target="comp2", type="request"),
            Connection(id="conn2", source="comp2", target="comp3", type="data_access")
        ]
        
        return Architecture(
            name=os.path.basename(drawio_path),
            components=components,
            connections=connections,
            metadata={"source_type": "drawio", "source_path": drawio_path}
        )
    
    def _parse_visio(self, visio_path: str) -> Architecture:
        """
        Parse a Visio architectural diagram.
        
        Args:
            visio_path: Path to the Visio file
            
        Returns:
            Architecture: Structured representation of the architecture
        """
        logger.debug(f"Parsing Visio diagram: {visio_path}")
        
        # Placeholder for Visio parsing logic
        # In a real implementation, this would use a library to parse VSDX files
        
        # For now, return a simple placeholder architecture
        components = [
            Component(id="comp1", name="Web Server", type="server", 
                     properties={"x": 100, "y": 100, "width": 120, "height": 80}),
            Component(id="comp2", name="Application Server", type="server", 
                     properties={"x": 300, "y": 200, "width": 100, "height": 100}),
            Component(id="comp3", name="Database Server", type="database", 
                     properties={"x": 500, "y": 300, "width": 100, "height": 100})
        ]
        
        connections = [
            Connection(id="conn1", source="comp1", target="comp2", type="http"),
            Connection(id="conn2", source="comp2", target="comp3", type="jdbc")
        ]
        
        return Architecture(
            name=os.path.basename(visio_path),
            components=components,
            connections=connections,
            metadata={"source_type": "visio", "source_path": visio_path}
        )
    
    def _identify_components(self, image: np.ndarray) -> List[Component]:
        """
        Identify components in the image using computer vision techniques.
        
        Args:
            image: Grayscale image as numpy array
            
        Returns:
            List of identified components
        """
        # Placeholder for component identification logic
        # In a real implementation, this would use more advanced CV techniques
        
        # For demonstration purposes, return some placeholder components
        components = [
            Component(id="comp1", name="Component 1", type="unknown", 
                     properties={"x": 100, "y": 100, "width": 120, "height": 80}),
            Component(id="comp2", name="Component 2", type="unknown", 
                     properties={"x": 300, "y": 200, "width": 100, "height": 100})
        ]
        
        return components
    
    def _identify_connections(self, image: np.ndarray, components: List[Component]) -> List[Connection]:
        """
        Identify connections between components in the image.
        
        Args:
            image: Grayscale image as numpy array
            components: List of identified components
            
        Returns:
            List of identified connections
        """
        # Placeholder for connection identification logic
        # In a real implementation, this would use line detection algorithms
        
        # For demonstration purposes, return a placeholder connection
        if len(components) >= 2:
            connections = [
                Connection(id="conn1", source=components[0].id, target=components[1].id, type="unknown")
            ]
        else:
            connections = []
        
        return connections
