"""
Report Generator Module

This module generates threat modeling and risk assessment reports
based on the analysis of architectural diagrams.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, List

from arch_threat_analyzer.src.models.architecture import Architecture
from arch_threat_analyzer.src.models.threat import Threat
from arch_threat_analyzer.src.utils.exceptions import ReportGenerationError

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates threat modeling and risk assessment reports in various formats.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the report generator with configuration.
        
        Args:
            config: Configuration dictionary containing report settings
        """
        self.config = config
        self.report_generators = {
            "pdf": self._generate_pdf_report,
            "html": self._generate_html_report,
            "markdown": self._generate_markdown_report,
            "json": self._generate_json_report
        }
        logger.debug(f"ReportGenerator initialized with supported formats: {list(self.report_generators.keys())}")
        
    def generate(self, architecture: Architecture, threats: List[Threat], output_path: str, format: str = "pdf") -> str:
        """
        Generate a threat modeling and risk assessment report.
        
        Args:
            architecture: Structured representation of the architecture
            threats: List of identified threats
            output_path: Path to save the report
            format: Report format (pdf, html, markdown, json)
            
        Returns:
            Path to the generated report
            
        Raises:
            ReportGenerationError: If the report generation fails
        """
        try:
            logger.info(f"Generating {format} report for {architecture.name}")
            
            if format.lower() not in self.report_generators:
                error_msg = f"Unsupported report format: {format}"
                logger.error(error_msg)
                raise ReportGenerationError(error_msg)
                
            # Create the output directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Generate the report using the appropriate generator
            generator_func = self.report_generators[format.lower()]
            report_path = generator_func(architecture, threats, output_path)
            
            logger.info(f"Report generated successfully: {report_path}")
            return report_path
            
        except Exception as e:
            error_msg = f"Failed to generate report: {str(e)}"
            logger.exception(error_msg)
            raise ReportGenerationError(error_msg) from e
    
    def _generate_pdf_report(self, architecture: Architecture, threats: List[Threat], output_path: str) -> str:
        """
        Generate a PDF report.
        
        Args:
            architecture: Structured representation of the architecture
            threats: List of identified threats
            output_path: Path to save the report
            
        Returns:
            Path to the generated report
        """
        logger.debug(f"Generating PDF report: {output_path}")
        
        try:
            # In a real implementation, this would use a PDF generation library like ReportLab
            # For now, generate a markdown report and note that it would be converted to PDF
            markdown_path = output_path.replace(".pdf", ".md")
            self._generate_markdown_report(architecture, threats, markdown_path)
            
            with open(output_path, "w") as f:
                f.write("PDF report would be generated from the markdown content")
                
            logger.debug(f"PDF report placeholder created: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating PDF report: {e}")
            raise ReportGenerationError(f"Failed to generate PDF report: {str(e)}") from e
    
    def _generate_html_report(self, architecture: Architecture, threats: List[Threat], output_path: str) -> str:
        """
        Generate an HTML report.
        
        Args:
            architecture: Structured representation of the architecture
            threats: List of identified threats
            output_path: Path to save the report
            
        Returns:
            Path to the generated report
        """
        logger.debug(f"Generating HTML report: {output_path}")
        
        try:
            # Create a basic HTML report
            with open(output_path, "w") as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Model Report: {architecture.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .high {{ background-color: #ffdddd; }}
        .medium {{ background-color: #ffffcc; }}
        .low {{ background-color: #ddffdd; }}
        .summary {{ margin-bottom: 30px; }}
    </style>
</head>
<body>
    <h1>Threat Model and Risk Assessment Report</h1>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report presents the results of an automated threat modeling and risk assessment 
        for the architecture diagram "{architecture.name}". The analysis identified {len(threats)} 
        potential security threats that should be addressed.</p>
        
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <h2>Architecture Overview</h2>
    <p>The analyzed architecture consists of {len(architecture.components)} components 
    and {len(architecture.connections)} connections.</p>
    
    <h3>Components</h3>
    <table>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Type</th>
        </tr>
""")

                # Add component rows
                for component in architecture.components:
                    f.write(f"""        <tr>
            <td>{component.id}</td>
            <td>{component.name}</td>
            <td>{component.type}</td>
        </tr>
""")

                f.write(f"""    </table>
    
    <h2>Identified Threats</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Category</th>
            <th>Risk Level</th>
            <th>Affected Component</th>
        </tr>
""")

                # Add threat rows
                for threat in threats:
                    f.write(f"""        <tr class="{threat.risk.level}">
            <td>{threat.id}</td>
            <td>{threat.name}</td>
            <td>{threat.category}</td>
            <td>{threat.risk.level.upper()}</td>
            <td>{threat.affected_component}</td>
        </tr>
""")

                f.write(f"""    </table>
    
    <h2>Detailed Threat Analysis</h2>
""")

                # Add detailed threat information
                for threat in threats:
                    f.write(f"""    <div class="threat">
        <h3>{threat.name} ({threat.id})</h3>
        <p><strong>Category:</strong> {threat.category}</p>
        <p><strong>Description:</strong> {threat.description}</p>
        <p><strong>Risk Level:</strong> {threat.risk.level.upper()}</p>
        <p><strong>Impact:</strong> {threat.risk.impact}</p>
        <p><strong>Likelihood:</strong> {threat.risk.likelihood}</p>
        <p><strong>Affected Component:</strong> {threat.affected_component}</p>
        <p><strong>Recommended Mitigation:</strong> {threat.mitigation}</p>
    </div>
""")

                f.write("""</body>
</html>
""")
                
            logger.debug(f"HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating HTML report: {e}")
            raise ReportGenerationError(f"Failed to generate HTML report: {str(e)}") from e
    
    def _generate_markdown_report(self, architecture: Architecture, threats: List[Threat], output_path: str) -> str:
        """
        Generate a Markdown report.
        
        Args:
            architecture: Structured representation of the architecture
            threats: List of identified threats
            output_path: Path to save the report
            
        Returns:
            Path to the generated report
        """
        logger.debug(f"Generating Markdown report: {output_path}")
        
        try:
            # Create a markdown report
            with open(output_path, "w") as f:
                f.write(f"""# Threat Model and Risk Assessment Report

## Executive Summary

This report presents the results of an automated threat modeling and risk assessment 
for the architecture diagram "{architecture.name}". The analysis identified {len(threats)} 
potential security threats that should be addressed.

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Architecture Overview

The analyzed architecture consists of {len(architecture.components)} components 
and {len(architecture.connections)} connections.

### Components

| ID | Name | Type |
|----|------|------|
""")

                # Add component rows
                for component in architecture.components:
                    f.write(f"| {component.id} | {component.name} | {component.type} |\n")

                f.write(f"""
## Identified Threats

| ID | Name | Category | Risk Level | Affected Component |
|----|------|----------|------------|-------------------|
""")

                # Add threat rows
                for threat in threats:
                    f.write(f"| {threat.id} | {threat.name} | {threat.category} | {threat.risk.level.upper()} | {threat.affected_component} |\n")

                f.write(f"""
## Detailed Threat Analysis

""")

                # Add detailed threat information
                for threat in threats:
                    f.write(f"""### {threat.name} ({threat.id})

**Category:** {threat.category}

**Description:** {threat.description}

**Risk Level:** {threat.risk.level.upper()}

**Impact:** {threat.risk.impact}

**Likelihood:** {threat.risk.likelihood}

**Affected Component:** {threat.affected_component}

**Recommended Mitigation:** {threat.mitigation}

""")
                
            logger.debug(f"Markdown report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating Markdown report: {e}")
            raise ReportGenerationError(f"Failed to generate Markdown report: {str(e)}") from e
    
    def _generate_json_report(self, architecture: Architecture, threats: List[Threat], output_path: str) -> str:
        """
        Generate a JSON report.
        
        Args:
            architecture: Structured representation of the architecture
            threats: List of identified threats
            output_path: Path to save the report
            
        Returns:
            Path to the generated report
        """
        logger.debug(f"Generating JSON report: {output_path}")
        
        try:
            # Create a JSON report
            report_data = {
                "report_metadata": {
                    "title": f"Threat Model and Risk Assessment Report: {architecture.name}",
                    "generated_at": datetime.now().isoformat(),
                    "version": "1.0"
                },
                "architecture": architecture.to_dict(),
                "threats": [threat.to_dict() for threat in threats],
                "summary": {
                    "total_components": len(architecture.components),
                    "total_connections": len(architecture.connections),
                    "total_threats": len(threats),
                    "threat_categories": {},
                    "risk_levels": {}
                }
            }
            
            # Calculate summary statistics
            for threat in threats:
                # Count by category
                if threat.category not in report_data["summary"]["threat_categories"]:
                    report_data["summary"]["threat_categories"][threat.category] = 0
                report_data["summary"]["threat_categories"][threat.category] += 1
                
                # Count by risk level
                if threat.risk.level not in report_data["summary"]["risk_levels"]:
                    report_data["summary"]["risk_levels"][threat.risk.level] = 0
                report_data["summary"]["risk_levels"][threat.risk.level] += 1
            
            # Write the JSON report
            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2)
                
            logger.debug(f"JSON report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating JSON report: {e}")
            raise ReportGenerationError(f"Failed to generate JSON report: {str(e)}") from e
