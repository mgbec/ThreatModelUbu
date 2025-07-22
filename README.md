# Architectural Diagram Threat Analyzer

A Python-based tool for automated threat modeling and risk assessment of architectural diagrams.

## Overview

This tool analyzes architectural diagrams to identify potential security threats and vulnerabilities, and generates comprehensive threat modeling and risk assessment reports. It uses computer vision and image processing techniques to extract components and their relationships from various diagram formats, and applies the STRIDE threat modeling methodology to identify potential security issues.

## Features

- **Diagram Parsing**: Extract components and connections from architectural diagrams in various formats (PNG, JPG, SVG, draw.io, Visio)
- **Threat Analysis**: Identify potential security threats using the STRIDE methodology
- **Risk Assessment**: Evaluate the risk level of identified threats
- **Report Generation**: Generate comprehensive reports in various formats (PDF, HTML, Markdown, JSON)
- **Customizable**: Configure threat rules, risk assessment parameters, and report templates

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenCV (for image processing)
- PyYAML (for configuration)

### Install from source

```bash
git clone https://github.com/yourusername/arch-threat-analyzer.git
cd arch-threat-analyzer
pip install -e .
```

### Install from PyPI

```bash
pip install arch-threat-analyzer
```

## Usage

### Command Line Interface

```bash
# Analyze a single diagram
arch-threat-analyzer -i path/to/diagram.png -o path/to/output/directory

# Analyze multiple diagrams in a directory
arch-threat-analyzer -i path/to/diagrams/directory -o path/to/output/directory

# Specify output format
arch-threat-analyzer -i path/to/diagram.png -o path/to/output/directory -f pdf

# Use a custom configuration file
arch-threat-analyzer -i path/to/diagram.png -o path/to/output/directory -c path/to/config.yaml

# Enable verbose logging
arch-threat-analyzer -i path/to/diagram.png -o path/to/output/directory -v
```

### Python API

```python
from arch_threat_analyzer.src.diagram_parser import DiagramParser
from arch_threat_analyzer.src.threat_analyzer import ThreatAnalyzer
from arch_threat_analyzer.src.report_generator import ReportGenerator
from arch_threat_analyzer.src.utils.config import load_config

# Load configuration
config = load_config("config.yaml")

# Parse diagram
parser = DiagramParser(config)
architecture = parser.parse("path/to/diagram.png")

# Analyze threats
analyzer = ThreatAnalyzer(config)
threats = analyzer.analyze(architecture)

# Generate report
report_generator = ReportGenerator(config)
report_path = report_generator.generate(architecture, threats, "output/report.pdf", "pdf")
```

## Configuration

The tool can be configured using a YAML configuration file. See the `config.yaml` file for an example configuration.

### Diagram Parser Configuration

```yaml
diagram_parser:
  supported_extensions:
    - .png
    - .jpg
    - .jpeg
    - .svg
    - .drawio
    - .vsdx
  component_detection:
    min_component_size: 50
    max_component_size: 500
    confidence_threshold: 0.7
```

### Threat Analyzer Configuration

```yaml
threat_analyzer:
  threat_rules_path: rules/threats.yaml
  risk_assessment:
    impact_weights:
      confidentiality: 0.3
      integrity: 0.3
      availability: 0.4
```

### Report Generator Configuration

```yaml
report_generator:
  templates_path: templates
  default_format: pdf
  include_mitigations: true
  include_risk_matrix: true
```

## Extending the Tool

### Adding New Diagram Formats

To add support for a new diagram format, extend the `DiagramParser` class and implement a new parsing method.

### Adding New Threat Rules

Threat rules are defined in the `threat_rules.yaml` file. You can add new rules by following the existing format.

### Adding New Report Formats

To add support for a new report format, extend the `ReportGenerator` class and implement a new report generation method.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
