"""
Configuration Module

This module handles loading and validating configuration settings.
"""

import logging
import os
import yaml
from typing import Dict, Any

from arch_threat_analyzer.src.utils.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Configuration dictionary
        
    Raises:
        ConfigurationError: If the configuration file cannot be loaded or is invalid
    """
    try:
        logger.debug(f"Loading configuration from: {config_path}")
        
        # Check if the config file exists
        if not os.path.exists(config_path):
            # If not, use default configuration
            logger.warning(f"Configuration file not found: {config_path}. Using default configuration.")
            return get_default_config()
            
        # Load the configuration file
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        # Validate the configuration
        validate_config(config)
        
        logger.debug("Configuration loaded successfully")
        return config
        
    except yaml.YAMLError as e:
        error_msg = f"Error parsing YAML configuration: {str(e)}"
        logger.error(error_msg)
        raise ConfigurationError(error_msg) from e
    except Exception as e:
        error_msg = f"Error loading configuration: {str(e)}"
        logger.exception(error_msg)
        raise ConfigurationError(error_msg) from e


def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate the configuration.
    
    Args:
        config: Configuration dictionary
        
    Raises:
        ConfigurationError: If the configuration is invalid
    """
    # Check for required sections
    required_sections = ["diagram_parser", "threat_analyzer", "report_generator"]
    for section in required_sections:
        if section not in config:
            # If a required section is missing, use default values for that section
            logger.warning(f"Configuration section missing: {section}. Using default values.")
            config[section] = get_default_config()[section]
    
    # Additional validation could be added here
    
    logger.debug("Configuration validation successful")


def get_default_config() -> Dict[str, Any]:
    """
    Get the default configuration.
    
    Returns:
        Default configuration dictionary
    """
    return {
        "diagram_parser": {
            "supported_extensions": [".png", ".jpg", ".jpeg", ".svg", ".drawio", ".vsdx"],
            "component_detection": {
                "min_component_size": 50,
                "max_component_size": 500,
                "confidence_threshold": 0.7
            }
        },
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
        },
        "report_generator": {
            "templates_path": "templates",
            "default_format": "pdf",
            "include_mitigations": True,
            "include_risk_matrix": True
        },
        "supported_extensions": [".png", ".jpg", ".jpeg", ".svg", ".drawio", ".vsdx"]
    }
