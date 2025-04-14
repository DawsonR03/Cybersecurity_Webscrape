#!/usr/bin/env python3
"""
Path Checker for Web Scraper

This script displays the paths that scrape.py is looking for various files.
Use this to debug file location issues.
"""

import os
import sys
import json

# Configure paths (same as in scrape.py)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "config")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
INPUT_FILE = os.path.join(SCRIPT_DIR, "keywords.json")

def check_file(filepath, description):
    """Check if a file exists and print information about it"""
    print(f"{description}: {filepath}")
    
    if os.path.exists(filepath):
        # Get file size
        size = os.path.getsize(filepath)
        print(f"  ✓ File exists ({size} bytes)")
        
        # Try to read it if it's a JSON file
        if filepath.endswith('.json'):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    
                if isinstance(data, dict) and 'keywords' in data:
                    keyword_count = len(data['keywords'])
                    print(f"  ✓ Contains {keyword_count} keywords")
                    
                    # Print first few keywords
                    if keyword_count > 0:
                        print("  Sample keywords:")
                        for i, kw in enumerate(data['keywords'][:3]):
                            if isinstance(kw, dict) and 'word' in kw:
                                print(f"    {i+1}. {kw['word']}")
                            else:
                                print(f"    {i+1}. {kw}")
                else:
                    print("  ✗ File does not contain a 'keywords' array")
            except json.JSONDecodeError:
                print("  ✗ Not a valid JSON file")
            except Exception as e:
                print(f"  ✗ Error reading file: {e}")
    else:
        print("  ✗ File does not exist")

def main():
    """Check paths and files"""
    print("\n=== Web Scraper Path Checker ===\n")
    
    # Print working directory
    print(f"Current directory: {os.getcwd()}")
    print(f"Script directory: {SCRIPT_DIR}")
    
    # Check directories
    print("\n=== Directories ===")
    for dir_path, dir_name in [
        (CONFIG_DIR, "Config directory"),
        (OUTPUT_DIR, "Output directory")
    ]:
        print(f"{dir_name}: {dir_path}")
        if os.path.exists(dir_path):
            print(f"  ✓ Directory exists")
        else:
            print(f"  ✗ Directory does not exist")
    
    # Check essential files
    print("\n=== Essential Files ===")
    check_file(INPUT_FILE, "Keywords file")
    check_file(os.path.join(CONFIG_DIR, "api_keys.json"), "API keys file")
    
    print("\n=== Possible Alternative Locations ===")
    alt_locations = [
        os.path.join(SCRIPT_DIR, "config", "keywords.json"),
        os.path.join(os.getcwd(), "keywords.json"),
        os.path.join(os.path.dirname(os.getcwd()), "keywords.json")
    ]
    
    for alt in alt_locations:
        if alt != INPUT_FILE:  # Skip if it's the same as the primary location
            check_file(alt, "Alternate keywords file")
    
    print("\n=== Recommendation ===")
    if not os.path.exists(INPUT_FILE):
        print(f"Create a keywords.json file at: {INPUT_FILE}")
        print("Example content:")
        print('''
{
    "keywords": [
        {
            "word": "James Webb Space Telescope cyber attack",
            "category": "security",
            "priority": "high"
        },
        {
            "word": "JWST zero-day vulnerability",
            "category": "CVE",
            "priority": "critical"
        }
    ]
}
''')
    else:
        print("Your keywords.json file exists but might have format issues.")
        print("Make sure it contains a 'keywords' array with proper keyword objects.")

if __name__ == "__main__":
    main() 