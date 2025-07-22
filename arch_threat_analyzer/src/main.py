#!/usr/bin/env python3
"""
Architectural Diagram Threat Analyzer

This module serves as the entry point for the application that analyzes
architectural diagrams and produces threat modeling and risk assessment information.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from arch_threat_analyzer.src.diagram_parser import DiagramParser
from arch_threat_analyzer.src.threat_analyzer import ThreatAnalyzer
from arch_threat_analyzer.src.report_generator import ReportGenerator
from arch_threat_analyzer.src.utils.config import load_config
from arch_threat_analyzer.src.utils.exceptions import (
    DiagramParsingError,
    ThreatAnalysisError,
    ReportGenerationError,
    ConfigurationError
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("arch_threat_analyzer.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze architectural diagrams for security threats and risks"
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the architectural diagram file or directory containing diagrams"
    )
    parser.add_argument(
        "-o", "--output",
        default="./output",
        help="Directory to save the threat modeling and risk assessment reports"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["pdf", "html", "markdown", "json"],
        default="pdf",
        help="Output format for the report"
    )
    
    return parser.parse_args()


def setup_logging(verbose):
    """Configure logging level based on verbosity."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    else:
        logging.getLogger().setLevel(logging.INFO)


def process_diagram(input_path, output_dir, config, output_format):
    """
    Process a single architectural diagram.
    
    Args:
        input_path (str): Path to the diagram file
        output_dir (str): Directory to save the output report
        config (dict): Configuration settings
        output_format (str): Format for the output report
        
    Returns:
        bool: True if processing was successful, False otherwise
    """
    try:
        logger.info(f"Processing diagram: {input_path}")
        
        # Parse the diagram
        parser = DiagramParser(config)
        architecture = parser.parse(input_path)
        logger.info(f"Successfully parsed diagram: {input_path}")
        
        # Analyze for threats
        analyzer = ThreatAnalyzer(config)
        threats = analyzer.analyze(architecture)
        logger.info(f"Identified {len(threats)} potential threats")
        
        # Generate report
        report_generator = ReportGenerator(config)
        output_path = os.path.join(
            output_dir, 
            f"{Path(input_path).stem}_threat_report.{output_format}"
        )
        report_generator.generate(architecture, threats, output_path, output_format)
        logger.info(f"Report generated at: {output_path}")
        
        return True
        
    except DiagramParsingError as e:
        logger.error(f"Failed to parse diagram: {e}")
        return False
    except ThreatAnalysisError as e:
        logger.error(f"Failed to analyze threats: {e}")
        return False
    except ReportGenerationError as e:
        logger.error(f"Failed to generate report: {e}")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error processing diagram: {e}")
        return False


def main():
    """Main entry point for the application."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Setup logging based on verbosity
        setup_logging(args.verbose)
        
        # Load configuration
        try:
            config = load_config(args.config)
            logger.debug("Configuration loaded successfully")
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            return 1
            
        # Create output directory if it doesn't exist
        os.makedirs(args.output, exist_ok=True)
        
        # Process input (file or directory)
        input_path = args.input
        if os.path.isfile(input_path):
            success = process_diagram(input_path, args.output, config, args.format)
            return 0 if success else 1
        elif os.path.isdir(input_path):
            # Process all supported diagram files in the directory
            supported_extensions = config.get("supported_extensions", [".png", ".jpg", ".jpeg", ".svg", ".drawio", ".vsdx"])
            
            success_count = 0
            failure_count = 0
            
            for root, _, files in os.walk(input_path):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in supported_extensions):
                        file_path = os.path.join(root, file)
                        if process_diagram(file_path, args.output, config, args.format):
                            success_count += 1
                        else:
                            failure_count += 1
            
            logger.info(f"Processed {success_count + failure_count} diagrams: {success_count} successful, {failure_count} failed")
            return 0 if failure_count == 0 else 1
        else:
            logger.error(f"Input path does not exist: {input_path}")
            return 1
            
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
