#!/usr/bin/env python3
"""
Deduplication Functions for Vulnerability Scanner

This module provides functions to deduplicate assets, threats, and vulnerabilities
in the output JSON files. It can be used both as a standalone script to clean
existing JSON files or imported into the main scraper for real-time deduplication.
"""

import os
import sys
import json
import logging

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s"
)

def deduplicate_assets(assets, dedup_field="name"):
    """
    Deduplicate assets based on a specific field.
    
    Args:
        assets (list): List of asset dictionaries
        dedup_field (str): Field to use for deduplication
        
    Returns:
        list: Deduplicated list of assets
    """
    seen = {}
    deduplicated = []
    
    logging.info(f"Deduplicating {len(assets)} assets based on '{dedup_field}'")
    
    for asset in assets:
        if dedup_field in asset:
            key = asset[dedup_field]
            if key not in seen:
                seen[key] = True
                deduplicated.append(asset)
            else:
                logging.debug(f"Skipping duplicate asset with {dedup_field}={key}")
        else:
            # If no dedup field, include it
            deduplicated.append(asset)
    
    logging.info(f"Deduplicated assets: {len(assets)} → {len(deduplicated)}")
    return deduplicated

def deduplicate_threats(threats, dedup_field="name"):
    """
    Deduplicate threats based on a specific field.
    
    Args:
        threats (list): List of threat dictionaries
        dedup_field (str): Field to use for deduplication
        
    Returns:
        list: Deduplicated list of threats
    """
    seen = {}
    deduplicated = []
    
    logging.info(f"Deduplicating {len(threats)} threats based on '{dedup_field}'")
    
    for threat in threats:
        if dedup_field in threat:
            key = threat[dedup_field]
            if key not in seen:
                seen[key] = True
                deduplicated.append(threat)
            else:
                logging.debug(f"Skipping duplicate threat with {dedup_field}={key}")
        else:
            # If no dedup field, include it
            deduplicated.append(threat)
    
    logging.info(f"Deduplicated threats: {len(threats)} → {len(deduplicated)}")
    return deduplicated

def deduplicate_vulnerabilities(vulnerabilities, dedup_field="name", merge_similar=True, similarity_threshold=0.8):
    """
    Deduplicate vulnerabilities based on a specific field.
    
    Args:
        vulnerabilities (list): List of vulnerability dictionaries
        dedup_field (str): Field to use for deduplication
        merge_similar (bool): Whether to merge similar vulnerabilities
        similarity_threshold (float): Threshold for considering vulnerabilities similar
        
    Returns:
        list: Deduplicated list of vulnerabilities
    """
    seen = {}
    deduplicated = []
    
    logging.info(f"Deduplicating {len(vulnerabilities)} vulnerabilities based on '{dedup_field}'")
    
    for vuln in vulnerabilities:
        if dedup_field in vuln:
            key = vuln[dedup_field]
            
            # Check for exact match
            if key not in seen:
                seen[key] = vuln
                deduplicated.append(vuln)
            else:
                # For exact matches, keep the one with the highest risk_level
                existing_vuln = seen[key]
                existing_risk = _get_risk_level(existing_vuln)
                current_risk = _get_risk_level(vuln)
                
                if current_risk > existing_risk:
                    # Replace with the higher risk one
                    idx = deduplicated.index(existing_vuln)
                    deduplicated[idx] = vuln
                    seen[key] = vuln
                    logging.debug(f"Replaced vulnerability with higher risk level: {key}")
        else:
            # If no dedup field, include it
            deduplicated.append(vuln)
    
    logging.info(f"Deduplicated vulnerabilities: {len(vulnerabilities)} → {len(deduplicated)}")
    return deduplicated

def _get_risk_level(vuln):
    """Helper to extract risk level value for comparison"""
    # Try different formats of risk level
    if "risk_level" in vuln:
        risk_level = vuln["risk_level"]
    elif "risk_assessment" in vuln and isinstance(vuln["risk_assessment"], dict):
        if "severity" in vuln["risk_assessment"]:
            risk_level = vuln["risk_assessment"]["severity"]
        elif "score" in vuln["risk_assessment"]:
            return float(vuln["risk_assessment"]["score"])
    else:
        risk_level = "low"
    
    # Convert text levels to numeric values
    risk_levels = {
        "critical": 4,
        "high": 3, 
        "medium": 2,
        "low": 1,
        "info": 0
    }
    
    # Convert to lowercase for case-insensitive comparison
    if isinstance(risk_level, str):
        risk_level = risk_level.lower()
    
    return risk_levels.get(risk_level, 1)  # Default to low if unknown

def deduplicate_json_file(input_file, output_file=None, dedup_field="name"):
    """
    Deduplicate items in a JSON file based on a specific field.
    
    Args:
        input_file (str): Path to input JSON file
        output_file (str, optional): Path to output JSON file. If None, overwrites input
        dedup_field (str): Field to use for deduplication
        
    Returns:
        bool: True if deduplication was successful, False otherwise
    """
    if not os.path.exists(input_file):
        logging.error(f"Input file does not exist: {input_file}")
        return False
    
    if output_file is None:
        output_file = input_file
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            logging.error(f"Expected a JSON array in {input_file}, got {type(data)}")
            return False
        
        # Determine data type and use appropriate deduplication function
        if "vulnerabilities" in input_file:
            deduplicated = deduplicate_vulnerabilities(data, dedup_field)
        elif "assets" in input_file:
            deduplicated = deduplicate_assets(data, dedup_field)
        elif "threats" in input_file:
            deduplicated = deduplicate_threats(data, dedup_field)
        else:
            # Generic deduplication
            deduplicated = deduplicate_assets(data, dedup_field)
        
        with open(output_file, 'w') as f:
            json.dump(deduplicated, f, indent=2)
        
        logging.info(f"Successfully wrote deduplicated data to {output_file}")
        return True
        
    except Exception as e:
        logging.error(f"Error deduplicating file {input_file}: {e}")
        return False

def main():
    """Command-line interface for the deduplication tool."""
    if len(sys.argv) < 2:
        print("Usage: python dedup.py [file.json] [dedup_field] [output_file]")
        print("Examples:")
        print("  python dedup.py output/assets.json                 # Deduplicates assets based on 'name'")
        print("  python dedup.py output/threats.json type           # Deduplicates threats based on 'type'")
        print("  python dedup.py output/vulnerabilities.json name new_vulns.json  # Writes to a new file")
        return
    
    input_file = sys.argv[1]
    dedup_field = sys.argv[2] if len(sys.argv) > 2 else "name"
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    success = deduplicate_json_file(input_file, output_file, dedup_field)
    if success:
        print(f"Successfully deduplicated {input_file}")
    else:
        print(f"Failed to deduplicate {input_file}")
        sys.exit(1)

if __name__ == "__main__":
    main() 