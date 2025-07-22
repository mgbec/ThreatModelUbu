#!/usr/bin/env python3
"""
Setup script for the Architectural Diagram Threat Analyzer package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="arch-threat-analyzer",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A tool for automated threat modeling and risk assessment of architectural diagrams",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/arch-threat-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "opencv-python>=4.5.0",
        "numpy>=1.20.0",
        "pyyaml>=6.0",
        "reportlab>=3.6.0",
        "markdown>=3.3.0",
        "jinja2>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "arch-threat-analyzer=arch_threat_analyzer.src.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "arch_threat_analyzer": ["templates/*", "rules/*"],
    },
)
