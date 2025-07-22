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
            
            # Apply image preprocessing to enhance features
            # 1. Apply Gaussian blur to reduce noise
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            
            # 2. Apply adaptive thresholding to handle different lighting conditions
            thresh = cv2.adaptiveThreshold(
                blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                cv2.THRESH_BINARY_INV, 11, 2
            )
            
            # 3. Perform morphological operations to clean up the image
            kernel = np.ones((3, 3), np.uint8)
            opening = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel, iterations=1)
            closing = cv2.morphologyEx(opening, cv2.MORPH_CLOSE, kernel, iterations=2)
            
            # 4. Additional preprocessing for better component detection
            # Dilate to connect nearby edges
            dilated = cv2.dilate(closing, kernel, iterations=1)
            
            # Save preprocessed image for debugging if verbose logging is enabled
            if logger.getEffectiveLevel() <= logging.DEBUG:
                debug_path = os.path.join(os.path.dirname(image_path), "debug_preprocessed.png")
                cv2.imwrite(debug_path, dilated)
                logger.debug(f"Saved preprocessed image for debugging: {debug_path}")
            
            # Identify components using contour detection
            components = self._identify_components_advanced(image, dilated)
            
            # Identify connections between components
            connections = self._identify_connections_advanced(image, dilated, components)
            
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
    

    

    def _identify_components_advanced(self, image: np.ndarray, processed_image: np.ndarray) -> List[Component]:
        """
        Identify components in the image using advanced computer vision techniques.
        
        Args:
            image: Original color image as numpy array
            processed_image: Preprocessed binary image
            
        Returns:
            List of identified components
        """
        logger.debug("Identifying components using advanced techniques")
        
        # Find contours in the processed image
        contours, _ = cv2.findContours(processed_image, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        # Get image dimensions
        height, width = processed_image.shape
        
        # Calculate minimum and maximum component sizes based on image dimensions
        # These are more adaptive than fixed values
        min_area = (width * height * 0.001)  # 0.1% of image area
        max_area = (width * height * 0.2)    # 20% of image area
        
        logger.debug(f"Min component area: {min_area}, Max component area: {max_area}")
        
        # Filter contours by size to eliminate noise and background elements
        valid_contours = []
        for contour in contours:
            area = cv2.contourArea(contour)
            if min_area < area < max_area:
                valid_contours.append(contour)
        
        logger.debug(f"Found {len(valid_contours)} potential components after filtering")
        
        # Extract components from valid contours
        components = []
        for i, contour in enumerate(valid_contours):
            # Get bounding rectangle
            x, y, w, h = cv2.boundingRect(contour)
            
            # Extract the component region for further analysis
            component_roi = image[y:y+h, x:x+w]
            
            # Determine component type based on shape and color features
            component_type = self._classify_component(component_roi, contour)
            
            # Create a component
            component = Component(
                id=f"comp{i+1}",
                name=f"{component_type} {i+1}",
                type=component_type,
                properties={
                    "x": int(x),
                    "y": int(y),
                    "width": int(w),
                    "height": int(h),
                    "area": int(cv2.contourArea(contour)),
                    "aspect_ratio": float(w) / float(h) if h > 0 else 0
                }
            )
            components.append(component)
            
        logger.debug(f"Identified {len(components)} components")
        return components
    
    def _classify_component(self, component_roi: np.ndarray, contour: np.ndarray) -> str:
        """
        Classify the type of component based on visual features.
        
        Args:
            component_roi: Region of interest containing the component
            contour: Contour of the component
            
        Returns:
            Component type as string
        """
        # Extract shape features
        area = cv2.contourArea(contour)
        perimeter = cv2.arcLength(contour, True)
        x, y, w, h = cv2.boundingRect(contour)
        aspect_ratio = float(w) / float(h) if h > 0 else 0
        
        # Calculate circularity (1 for perfect circle)
        circularity = 4 * np.pi * area / (perimeter * perimeter) if perimeter > 0 else 0
        
        # Calculate average color (can help identify certain components)
        avg_color = np.mean(component_roi, axis=(0, 1)) if component_roi.size > 0 else np.array([0, 0, 0])
        
        # Approximate the contour to simplify the shape
        epsilon = 0.04 * perimeter
        approx = cv2.approxPolyDP(contour, epsilon, True)
        corners = len(approx)
        
        # Classify based on shape features
        if 0.9 < circularity <= 1.0:
            # Circular shapes often represent databases or storage
            return "database"
        elif 0.7 < circularity < 0.9 and aspect_ratio > 0.8 and aspect_ratio < 1.2:
            # Rounded rectangles often represent cloud services
            return "cloud_service"
        elif corners == 4 and 0.95 < aspect_ratio < 1.05:
            # Squares often represent compute resources
            return "compute"
        elif corners == 4 and aspect_ratio > 1.5:
            # Wide rectangles often represent API gateways or load balancers
            return "gateway"
        elif corners == 4 and aspect_ratio < 0.7:
            # Tall rectangles often represent servers
            return "server"
        elif corners > 4 and corners < 10:
            # Polygons often represent network components
            return "network"
        elif corners >= 10:
            # Complex shapes might be user interfaces or clients
            return "client"
        else:
            # Default fallback
            return "service"
    def _identify_connections_advanced(self, image: np.ndarray, processed_image: np.ndarray, components: List[Component]) -> List[Connection]:
        """
        Identify connections between components using advanced computer vision techniques.
        
        Args:
            image: Original color image as numpy array
            processed_image: Preprocessed binary image
            components: List of identified components
            
        Returns:
            List of identified connections
        """
        logger.debug("Identifying connections using advanced techniques")
        
        if len(components) < 2:
            logger.debug("Not enough components to identify connections")
            return []
        
        # Create a copy of the processed image for line detection
        line_image = processed_image.copy()
        
        # Mask out the component regions to focus on lines
        for component in components:
            x = component.properties.get("x", 0)
            y = component.properties.get("y", 0)
            w = component.properties.get("width", 0)
            h = component.properties.get("height", 0)
            cv2.rectangle(line_image, (x, y), (x+w, y+h), (0, 0, 0), -1)
        
        # Apply edge detection to find lines
        edges = cv2.Canny(line_image, 50, 150, apertureSize=3)
        
        # Use Hough Line Transform to detect lines with more sensitive parameters
        lines = cv2.HoughLinesP(
            edges, 
            rho=1, 
            theta=np.pi/180, 
            threshold=30,  # Lower threshold to detect more lines
            minLineLength=20,  # Shorter minimum line length
            maxLineGap=20  # Larger max gap to connect broken lines
        )
        
        # If no lines are detected, try a different approach
        if lines is None:
            logger.debug("No lines detected with Hough transform, trying distance-based approach")
            return self._identify_connections_by_distance(components)
        
        # Process detected lines to identify connections
        connections = []
        connection_id = 1
        
        for line in lines:
            x1, y1, x2, y2 = line[0]
            
            # Find components connected by this line
            source_component = None
            target_component = None
            min_source_dist = float('inf')
            min_target_dist = float('inf')
            
            for component in components:
                cx = component.properties.get("x", 0) + component.properties.get("width", 0) / 2
                cy = component.properties.get("y", 0) + component.properties.get("height", 0) / 2
                
                # Calculate distance from line start to component center
                dist_to_start = np.sqrt((cx - x1)**2 + (cy - y1)**2)
                # Calculate distance from line end to component center
                dist_to_end = np.sqrt((cx - x2)**2 + (cy - y2)**2)
                
                # Update source component if this is closer to line start
                if dist_to_start < min_source_dist:
                    min_source_dist = dist_to_start
                    source_component = component
                
                # Update target component if this is closer to line end
                if dist_to_end < min_target_dist:
                    min_target_dist = dist_to_end
                    target_component = component
            
            # Only create connection if both source and target are found and they're different
            if (source_component and target_component and 
                source_component.id != target_component.id and
                min_source_dist < 100 and min_target_dist < 100):  # Increased threshold for connection
                
                # Determine connection type based on line properties
                connection_type = self._classify_connection(image, x1, y1, x2, y2)
                
                connection = Connection(
                    id=f"conn{connection_id}",
                    source=source_component.id,
                    target=target_component.id,
                    type=connection_type,
                    properties={
                        "start_x": x1,
                        "start_y": y1,
                        "end_x": x2,
                        "end_y": y2,
                        "length": np.sqrt((x2-x1)**2 + (y2-y1)**2)
                    }
                )
                connections.append(connection)
                connection_id += 1
        
        # If no connections were found with line detection, fall back to distance-based approach
        if not connections:
            logger.debug("No connections identified from lines, using distance-based approach")
            connections = self._identify_connections_by_distance(components)
        
        logger.debug(f"Identified {len(connections)} connections")
        return connections
    
    def _identify_connections_by_distance(self, components: List[Component]) -> List[Connection]:
        """
        Identify connections between components based on their proximity.
        
        Args:
            components: List of identified components
            
        Returns:
            List of identified connections
        """
        connections = []
        connection_id = 1
        
        # Calculate a dynamic threshold based on component sizes
        max_width = max([comp.properties.get("width", 0) for comp in components]) if components else 100
        max_height = max([comp.properties.get("height", 0) for comp in components]) if components else 100
        max_distance = max(max_width, max_height) * 3  # 3 times the largest component dimension
        
        logger.debug(f"Using max distance threshold for connections: {max_distance}")
        
        # Calculate distances between all component pairs
        for i, comp1 in enumerate(components):
            for j, comp2 in enumerate(components[i+1:], i+1):
                # Calculate centers
                c1x = comp1.properties.get("x", 0) + comp1.properties.get("width", 0) / 2
                c1y = comp1.properties.get("y", 0) + comp1.properties.get("height", 0) / 2
                c2x = comp2.properties.get("x", 0) + comp2.properties.get("width", 0) / 2
                c2y = comp2.properties.get("y", 0) + comp2.properties.get("height", 0) / 2
                
                # Calculate distance
                distance = np.sqrt((c2x - c1x)**2 + (c2y - c1y)**2)
                
                # If components are close enough, create a connection
                if distance < max_distance:
                    connection = Connection(
                        id=f"conn{connection_id}",
                        source=comp1.id,
                        target=comp2.id,
                        type="data_flow",  # Default type
                        properties={
                            "distance": distance
                        }
                    )
                    connections.append(connection)
                    connection_id += 1
        
        return connections
    
    def _classify_connection(self, image: np.ndarray, x1: int, y1: int, x2: int, y2: int) -> str:
        """
        Classify the type of connection based on line properties.
        
        Args:
            image: Original color image
            x1, y1: Start point of the line
            x2, y2: End point of the line
            
        Returns:
            Connection type as string
        """
        # Calculate line properties
        length = np.sqrt((x2-x1)**2 + (y2-y1)**2)
        angle = np.arctan2(y2-y1, x2-x1) * 180 / np.pi
        
        # Extract line region for color analysis
        # Create a mask along the line
        mask = np.zeros(image.shape[:2], dtype=np.uint8)
        cv2.line(mask, (x1, y1), (x2, y2), 255, 5)
        
        # Apply mask to get line pixels
        line_pixels = cv2.bitwise_and(image, image, mask=mask)
        
        # Calculate average color along the line
        non_zero_pixels = line_pixels[np.nonzero(mask)]
        avg_color = np.mean(non_zero_pixels, axis=0) if non_zero_pixels.size > 0 else np.array([0, 0, 0])
        
        # Classify based on line properties
        if length < 50:
            return "direct_connection"
        elif abs(angle) < 10 or abs(angle) > 170:
            return "horizontal_flow"
        elif abs(angle - 90) < 10 or abs(angle + 90) < 10:
            return "vertical_flow"
        elif avg_color[0] < 100 and avg_color[1] < 100 and avg_color[2] > 150:
            return "network_connection"
        elif avg_color[0] > 150 and avg_color[1] < 100 and avg_color[2] < 100:
            return "secure_connection"
        elif avg_color[0] < 100 and avg_color[1] > 150 and avg_color[2] < 100:
            return "data_flow"
        else:
            return "connection"
