"""
VCF file validation utilities.

This module contains validation functions for genomic data files that are
handled at the CLI level rather than delegated to individual protocols.
"""

import gzip
from pathlib import Path
from typing import Optional


def validate_vcf_format(vcf_file_path: str) -> None:
    """Validate VCF file format using pysam.
    
    Uses pysam to validate VCF file format and structure.
    
    Args:
        vcf_file_path: Path to the VCF file to validate
        
    Raises:
        FileNotFoundError: If the VCF file doesn't exist
        ValueError: If the VCF file format is invalid
    """
    import pysam
    
    vcf_path = Path(vcf_file_path)
    
    if not vcf_path.exists():
        raise FileNotFoundError(f"VCF file not found: {vcf_file_path}")
        
    try:
        # Open and validate VCF using pysam
        vcf = pysam.VariantFile(vcf_file_path)
        # Access header to validate format
        _ = vcf.header
        vcf.close()
        
    except ValueError as e:
        raise ValueError(f"Invalid VCF format: {e}")
    except Exception as e:
        raise ValueError(f"Error validating VCF file: {e}")


def validate_vcf_accessibility(vcf_file_path: str) -> None:
    """Validate that VCF file is accessible and readable.
    
    Performs basic accessibility checks without parsing VCF content.
    
    Args:
        vcf_file_path: Path to the VCF file to check
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        PermissionError: If the file isn't readable
        ValueError: If the file appears to be empty
    """
    vcf_path = Path(vcf_file_path)
    
    if not vcf_path.exists():
        raise FileNotFoundError(f"VCF file not found: {vcf_file_path}")
    
    if not vcf_path.is_file():
        raise ValueError(f"Path is not a file: {vcf_file_path}")
    
    if vcf_path.stat().st_size == 0:
        raise ValueError(f"VCF file is empty: {vcf_file_path}")
    
    # Test file readability
    try:
        if vcf_file_path.endswith('.gz'):
            with gzip.open(vcf_file_path, 'rt') as f:
                f.read(1)  # Try to read first byte
        else:
            with open(vcf_file_path, 'r') as f:
                f.read(1)  # Try to read first character
    except PermissionError:
        raise PermissionError(f"Permission denied reading VCF file: {vcf_file_path}")
    except Exception as e:
        raise ValueError(f"Cannot read VCF file: {e}") 