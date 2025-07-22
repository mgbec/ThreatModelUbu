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
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
            from reportlab.platypus.flowables import HRFlowable
            from reportlab.lib.units import inch
            
            # Create document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            
            # Create custom styles
            title_style = ParagraphStyle(
                name='CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=12
            )
            heading2_style = ParagraphStyle(
                name='CustomHeading2',
                parent=styles['Heading2'],
                fontSize=18,
                spaceAfter=10
            )
            heading3_style = ParagraphStyle(
                name='CustomHeading3',
                parent=styles['Heading3'],
                fontSize=14,
                spaceAfter=8
            )
            normal_style = ParagraphStyle(
                name='CustomNormal',
                parent=styles['Normal'],
                fontSize=10,
                spaceAfter=6
            )
            table_header_style = ParagraphStyle(
                name='TableHeader',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.white,
                alignment=1  # Center alignment
            )
            
            # Start building the document content
            content = []
            
            # Title
            content.append(Paragraph("Threat Model and Risk Assessment Report", title_style))
            content.append(Spacer(1, 0.25*inch))
            content.append(HRFlowable(width="100%", thickness=1, color=colors.black))
            content.append(Spacer(1, 0.25*inch))
            
            # Executive Summary
            content.append(Paragraph("Executive Summary", heading2_style))
            content.append(Paragraph(
                f"This report presents the results of an automated threat modeling and risk assessment "
                f"for the architecture diagram \"{architecture.name}\". The analysis identified {len(threats)} "
                f"potential security threats that should be addressed.",
                normal_style
            ))
            content.append(Paragraph(
                f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                normal_style
            ))
            content.append(Spacer(1, 0.25*inch))
            
            # Architecture Overview
            content.append(Paragraph("Architecture Overview", heading2_style))
            content.append(Paragraph(
                f"The analyzed architecture consists of {len(architecture.components)} components "
                f"and {len(architecture.connections)} connections.",
                normal_style
            ))
            content.append(Spacer(1, 0.15*inch))
            
            # Components Table
            content.append(Paragraph("Components", heading3_style))
            component_data = [["ID", "Name", "Type"]]
            for component in architecture.components:
                component_data.append([component.id, component.name, component.type])
                
            component_table = Table(component_data, colWidths=[1*inch, 2.5*inch, 1.5*inch])
            component_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            content.append(component_table)
            content.append(Spacer(1, 0.25*inch))
            
            # Threat Summary
            content.append(Paragraph("Threat Summary", heading2_style))
            
            # Count threats by risk level
            high_threats = len([t for t in threats if t.risk.level.lower() == 'high'])
            medium_threats = len([t for t in threats if t.risk.level.lower() == 'medium'])
            low_threats = len([t for t in threats if t.risk.level.lower() == 'low'])
            
            # Create threat summary table
            summary_data = [
                ["Risk Level", "Count", "Percentage"],
                ["High", str(high_threats), f"{high_threats/len(threats)*100:.1f}%"],
                ["Medium", str(medium_threats), f"{medium_threats/len(threats)*100:.1f}%"],
                ["Low", str(low_threats), f"{low_threats/len(threats)*100:.1f}%"],
                ["Total", str(len(threats)), "100%"]
            ]
            
            summary_table = Table(summary_data, colWidths=[1.5*inch, 1*inch, 1.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, 1), colors.lightcoral),  # High risk row
                ('BACKGROUND', (0, 2), (-1, 2), colors.lightyellow),  # Medium risk row
                ('BACKGROUND', (0, 3), (-1, 3), colors.lightgreen),  # Low risk row
                ('BACKGROUND', (0, 4), (-1, 4), colors.lightgrey),  # Total row
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (1, 0), (2, -1), 'CENTER'),  # Center-align count and percentage columns
            ]))
            content.append(summary_table)
            content.append(Spacer(1, 0.25*inch))
            
            # Identified Threats Table
            content.append(Paragraph("Identified Threats", heading2_style))
            threat_data = [["ID", "Name", "Category", "Risk Level", "Affected Component"]]
            for threat in threats:
                threat_data.append([
                    threat.id, 
                    threat.name, 
                    threat.category, 
                    threat.risk.level.upper(), 
                    threat.affected_component
                ])
                
            threat_table = Table(threat_data, colWidths=[0.8*inch, 1.5*inch, 1.2*inch, 1*inch, 1.5*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Add conditional formatting for risk levels
            for i, threat in enumerate(threats, 1):
                if threat.risk.level.lower() == 'high':
                    threat_table.setStyle(TableStyle([
                        ('BACKGROUND', (3, i), (3, i), colors.lightcoral)
                    ]))
                elif threat.risk.level.lower() == 'medium':
                    threat_table.setStyle(TableStyle([
                        ('BACKGROUND', (3, i), (3, i), colors.lightyellow)
                    ]))
                elif threat.risk.level.lower() == 'low':
                    threat_table.setStyle(TableStyle([
                        ('BACKGROUND', (3, i), (3, i), colors.lightgreen)
                    ]))
            
            # Detailed Threat Analysis
            content.append(Paragraph("Detailed Threat Analysis", heading2_style))
            
            # Group threats by category for better organization
            threats_by_category = {}
            for threat in threats:
                if threat.category not in threats_by_category:
                    threats_by_category[threat.category] = []
                threats_by_category[threat.category].append(threat)
            
            # Add each threat with detailed information
            for category, category_threats in threats_by_category.items():
                content.append(Paragraph(f"{category} Threats", heading3_style))
                
                for threat in category_threats:
                    # Threat header with colored background based on risk level
                    if threat.risk.level.lower() == 'high':
                        bg_color = colors.lightcoral
                    elif threat.risk.level.lower() == 'medium':
                        bg_color = colors.lightyellow
                    else:
                        bg_color = colors.lightgreen
                    
                    # Create a table for the threat header
                    header_data = [[f"{threat.name} ({threat.id})"]]
                    header_table = Table(header_data, colWidths=[6*inch])
                    header_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ]))
                    content.append(header_table)
                    
                    # Threat details
                    content.append(Paragraph(f"<b>Description:</b> {threat.description}", normal_style))
                    content.append(Paragraph(f"<b>Category:</b> {threat.category}", normal_style))
                    content.append(Paragraph(f"<b>Risk Level:</b> {threat.risk.level.upper()}", normal_style))
                    content.append(Paragraph(f"<b>Impact:</b> {threat.risk.impact}", normal_style))
                    content.append(Paragraph(f"<b>Likelihood:</b> {threat.risk.likelihood}", normal_style))
                    content.append(Paragraph(f"<b>Affected Component:</b> {threat.affected_component}", normal_style))
                    
                    # Enhanced mitigation information
                    content.append(Paragraph("<b>Recommended Mitigation:</b>", normal_style))
                    mitigation_steps = self._get_enhanced_mitigation(threat)
                    for i, step in enumerate(mitigation_steps, 1):
                        content.append(Paragraph(f"{i}. {step}", normal_style))
                    
                    # Add additional threat information
                    additional_info = self._get_additional_threat_info(threat)
                    if additional_info:
                        content.append(Paragraph("<b>Additional Information:</b>", normal_style))
                        content.append(Paragraph(additional_info, normal_style))
                    
                    # Add references
                    references = self._get_threat_references(threat)
                    if references:
                        content.append(Paragraph("<b>References:</b>", normal_style))
                        for ref in references:
                            content.append(Paragraph(f"• {ref}", normal_style))
                    
                    content.append(Spacer(1, 0.25*inch))
            
            # Build the PDF
            doc.build(content)
            logger.debug(f"PDF report generated: {output_path}")
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
    def _get_enhanced_mitigation(self, threat: Threat) -> List[str]:
        """
        Get enhanced mitigation steps for a threat.
        
        Args:
            threat: The threat to get mitigation steps for
            
        Returns:
            List of mitigation steps
        """
        # Basic mitigation is always included
        mitigation_steps = [threat.mitigation]
        
        # Add more specific mitigation steps based on threat category and type
        if threat.category == "Spoofing":
            if "API" in threat.name:
                mitigation_steps.extend([
                    "Implement OAuth 2.0 or OpenID Connect for authentication",
                    "Use strong, properly implemented JWT tokens with appropriate expiration",
                    "Implement IP-based rate limiting to prevent brute force attacks",
                    "Consider using an API gateway with built-in authentication capabilities"
                ])
            else:
                mitigation_steps.extend([
                    "Implement multi-factor authentication",
                    "Use strong password policies",
                    "Implement account lockout after failed attempts"
                ])
                
        elif threat.category == "Tampering":
            if "Data" in threat.name:
                mitigation_steps.extend([
                    "Use AES-256 encryption for sensitive data",
                    "Implement proper key management",
                    "Use digital signatures to detect tampering",
                    "Implement data integrity checks"
                ])
            else:
                mitigation_steps.extend([
                    "Implement input validation",
                    "Use parameterized queries to prevent SQL injection",
                    "Implement proper access controls"
                ])
                
        elif threat.category == "Repudiation":
            mitigation_steps.extend([
                "Implement centralized logging with tamper-evident logs",
                "Use a SIEM solution for log analysis",
                "Ensure all security-relevant events are logged",
                "Include unique request IDs in logs for traceability"
            ])
                
        elif threat.category == "Information Disclosure":
            if "Unencrypted" in threat.name:
                mitigation_steps.extend([
                    "Use TLS 1.3 for all data transfers",
                    "Implement proper certificate validation",
                    "Use strong cipher suites",
                    "Implement HSTS to prevent downgrade attacks"
                ])
            else:
                mitigation_steps.extend([
                    "Implement proper access controls",
                    "Use the principle of least privilege",
                    "Sanitize error messages to prevent information leakage"
                ])
                
        elif threat.category == "Denial of Service":
            mitigation_steps.extend([
                "Implement rate limiting",
                "Use a CDN for static content",
                "Implement auto-scaling for dynamic resources",
                "Use a DDoS protection service"
            ])
                
        elif threat.category == "Elevation of Privilege":
            mitigation_steps.extend([
                "Implement proper authorization checks",
                "Use the principle of least privilege",
                "Validate all user input",
                "Implement proper session management"
            ])
        
        return mitigation_steps
    
    def _get_additional_threat_info(self, threat: Threat) -> str:
        """
        Get additional information about a threat.
        
        Args:
            threat: The threat to get additional information for
            
        Returns:
            Additional information about the threat
        """
        additional_info = ""
        
        if threat.category == "Spoofing":
            additional_info = (
                "Spoofing attacks involve attackers pretending to be someone or something else. "
                "These attacks can lead to unauthorized access to systems or data. Common spoofing "
                "techniques include IP spoofing, email spoofing, and website spoofing."
            )
        elif threat.category == "Tampering":
            additional_info = (
                "Tampering involves the unauthorized modification of data or code. This can lead to "
                "data corruption, system compromise, or unauthorized actions being performed. Tampering "
                "can occur during storage, transmission, or processing of data."
            )
        elif threat.category == "Repudiation":
            additional_info = (
                "Repudiation threats involve users denying that they performed an action, and the system "
                "lacking the ability to prove otherwise. Proper logging and auditing are essential to "
                "mitigate repudiation threats."
            )
        elif threat.category == "Information Disclosure":
            additional_info = (
                "Information disclosure threats involve the exposure of sensitive information to "
                "unauthorized parties. This can include data breaches, unencrypted communications, "
                "or improper access controls leading to data leakage."
            )
        elif threat.category == "Denial of Service":
            additional_info = (
                "Denial of Service (DoS) attacks aim to make a system or resource unavailable to its "
                "intended users. This can be achieved by overwhelming the system with traffic, "
                "exploiting vulnerabilities, or exhausting system resources."
            )
        elif threat.category == "Elevation of Privilege":
            additional_info = (
                "Elevation of privilege threats involve users gaining access to resources or functions "
                "that they should not have access to. This can lead to unauthorized actions being "
                "performed or sensitive data being accessed."
            )
            
        return additional_info
    
    def _get_threat_references(self, threat: Threat) -> List[str]:
        """
        Get references for a threat.
        
        Args:
            threat: The threat to get references for
            
        Returns:
            List of references
        """
        references = []
        
        # Add general references based on threat category
        if threat.category == "Spoofing":
            references.extend([
                "OWASP Top 10 2021: A07 - Identification and Authentication Failures",
                "NIST SP 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management",
                "CWE-287: Improper Authentication"
            ])
        elif threat.category == "Tampering":
            references.extend([
                "OWASP Top 10 2021: A03 - Injection",
                "CWE-89: SQL Injection",
                "NIST SP 800-53: SC-8 Transmission Confidentiality and Integrity"
            ])
        elif threat.category == "Repudiation":
            references.extend([
                "OWASP Top 10 2021: A09 - Security Logging and Monitoring Failures",
                "CWE-778: Insufficient Logging",
                "NIST SP 800-53: AU-2 Audit Events"
            ])
        elif threat.category == "Information Disclosure":
            references.extend([
                "OWASP Top 10 2021: A02 - Cryptographic Failures",
                "CWE-311: Missing Encryption of Sensitive Data",
                "NIST SP 800-53: SC-8 Transmission Confidentiality and Integrity"
            ])
        elif threat.category == "Denial of Service":
            references.extend([
                "OWASP Top 10 2021: A05 - Security Misconfiguration",
                "CWE-400: Uncontrolled Resource Consumption",
                "NIST SP 800-53: SC-5 Denial of Service Protection"
            ])
        elif threat.category == "Elevation of Privilege":
            references.extend([
                "OWASP Top 10 2021: A01 - Broken Access Control",
                "CWE-269: Improper Privilege Management",
                "NIST SP 800-53: AC-6 Least Privilege"
            ])
            
        # Add specific references based on threat name
        if "API" in threat.name:
            references.append("OWASP API Security Top 10 2023")
        if "Encryption" in threat.name or "Unencrypted" in threat.name:
            references.append("NIST SP 800-57: Recommendation for Key Management")
        if "Database" in threat.name or "Data Storage" in threat.name:
            references.append("CWE-311: Missing Encryption of Sensitive Data")
        
        return references
