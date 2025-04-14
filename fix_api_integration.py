#!/usr/bin/env python3
"""
API Integration Fix for Web Scraper

This script fixes integration issues between api_manager.py and scrape.py
by ensuring the API keys are stored in a compatible format.

Usage:
    python fix_api_integration.py
"""

import os
import sys
import json
import shutil

# Configure paths (same as in both scripts)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "config")
KEY_FILE = os.path.join(CONFIG_DIR, "api_keys.json")

def check_config_dir():
    """Ensure config directory exists"""
    if not os.path.exists(CONFIG_DIR):
        print(f"Creating config directory: {CONFIG_DIR}")
        os.makedirs(CONFIG_DIR)
        return True
    return True

def backup_existing_keys():
    """Backup existing API keys file if it exists"""
    if os.path.exists(KEY_FILE):
        backup_file = f"{KEY_FILE}.backup"
        print(f"Backing up existing API keys file to: {backup_file}")
        shutil.copy2(KEY_FILE, backup_file)
        return True
    return False

def load_existing_keys():
    """Try to load existing API keys"""
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading existing API keys: {e}")
            
            # Try to recover valid JSON from the file
            try:
                with open(KEY_FILE, "r") as f:
                    content = f.read()
                    
                # Look for patterns of valid JSON
                if "{" in content and "}" in content:
                    # Try to extract JSON between first { and last }
                    start = content.find("{")
                    end = content.rfind("}") + 1
                    if start >= 0 and end > start:
                        json_content = content[start:end]
                        try:
                            return json.loads(json_content)
                        except:
                            pass
            except:
                pass
    return {}

def save_clean_keys(api_keys):
    """Save API keys in a clean, compatible format"""
    try:
        with open(KEY_FILE, "w") as f:
            json.dump(api_keys, f, indent=2)
        print(f"Successfully saved clean API keys to: {KEY_FILE}")
        return True
    except Exception as e:
        print(f"Error saving clean API keys: {e}")
        return False

def main():
    """Main function to fix API integration"""
    print("\n=== Web Scraper API Integration Fix ===\n")
    
    # Step 1: Check config directory
    check_config_dir()
    
    # Step 2: Backup existing keys
    had_existing = backup_existing_keys()
    
    # Step 3: Try to load existing keys
    api_keys = load_existing_keys()
    
    if had_existing:
        print(f"Found {len(api_keys)} existing API keys.")
    else:
        print("No existing API keys found.")
    
    # Step 4: Save keys in a clean format
    if api_keys:
        if save_clean_keys(api_keys):
            print("\nAPI integration fixed successfully!")
            print("Your API keys are now compatible with both api_manager.py and scrape.py.")
        else:
            print("\nFailed to fix API integration.")
            print("Please run 'python api_manager.py set' to manually configure your API keys.")
    else:
        # Create an empty API keys file
        save_clean_keys({})
        print("\nCreated an empty API keys file.")
        print("Please run 'python api_manager.py set' to configure your API keys.")
    
    print("\n=== Next Steps ===")
    print("1. Run 'python api_manager.py verify' to check compatibility")
    print("2. Run 'python api_manager.py set' to set or update your API keys")
    print("3. Run 'python scrape.py --skip-missing --disable-mongodb' to start the scraper\n")

if __name__ == "__main__":
    main() 