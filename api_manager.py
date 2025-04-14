#!/usr/bin/env python3
"""
API Key Manager for Vulnerability Scanner

This script provides a simple CLI interface to manage API keys for the vulnerability scanner.
Users can view, add, update, and delete API keys without modifying the main code.

Usage:
    python api_manager.py list     - List all configured API services (without showing keys)
    python api_manager.py show     - Show all API keys
    python api_manager.py set      - Interactive prompt to set API keys
    python api_manager.py delete   - Interactive prompt to delete API keys
"""

import os
import sys
import json
import getpass

# Configure paths - use the same paths as scrape.py
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "config")
KEY_FILE = os.path.join(CONFIG_DIR, "api_keys.json")

# Create config directory if it doesn't exist
if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)

# Available API services that can be configured
AVAILABLE_SERVICES = {
    "nvd": "NVD API Key",
    "google": "Google API Key",
    "cse_id": "Google Custom Search Engine ID",
    "shodan": "Shodan API Key",
    "otx": "AlienVault OTX API Key",
    "xforce": "IBM X-Force API Key",
    "urlscan": "URLScan API Key",
    "virustotal": "VirusTotal API Key",
    "securitytrails": "SecurityTrails API Key",
    "github": "GitHub API Key",
    "hibp": "Have I Been Pwned API Key",
    "threatcrowd": "ThreatCrowd API Key"
}

def load_api_keys():
    """Load API keys from storage - plaintext only for compatibility."""
    if not os.path.exists(KEY_FILE):
        return {}
        
    try:
        with open(KEY_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load API keys: {e}")
        return {}

def save_api_keys(api_keys):
    """Save API keys to storage in plaintext for maximum compatibility."""
    try:
        with open(KEY_FILE, "w") as f:
            json.dump(api_keys, f, indent=2)
        print("API keys saved successfully.")
        return True
    except Exception as e:
        print(f"ERROR: Failed to save API keys: {e}")
        return False

def list_services():
    """List all available API services."""
    print("\n=== Available API Services ===")
    print("These services can be configured with API keys:\n")
    
    for service_id, service_name in AVAILABLE_SERVICES.items():
        print(f"- {service_name} [{service_id}]")
    
    print("\nTo set keys, run: python api_manager.py set")

def show_keys():
    """Show all configured API keys."""
    api_keys = load_api_keys()
    
    if not api_keys:
        print("\nNo API keys are currently configured.")
        print("To add keys, run: python api_manager.py set")
        return
    
    print("\n=== Configured API Keys ===\n")
    
    for service_id, key in api_keys.items():
        service_name = AVAILABLE_SERVICES.get(service_id, service_id)
        # Mask key for security, showing only the last 4 characters
        masked_key = "****" + key[-4:] if len(key) > 4 else "****"
        print(f"{service_name} [{service_id}]: {masked_key}")
    
    # Show which API services will be active
    print("\n=== Active Services ===\n")
    active_count = 0
    for service_id, service_name in AVAILABLE_SERVICES.items():
        if service_id in api_keys and api_keys[service_id]:
            print(f"✓ {service_name}")
            active_count += 1
    
    if active_count == 0:
        print("No API services are active. Add keys with: python api_manager.py set")
    else:
        print(f"\n{active_count} out of {len(AVAILABLE_SERVICES)} API services are active.")
        print("The scraper will use these services and skip the others.")

def set_key():
    """Interactive prompt to set API keys."""
    api_keys = load_api_keys()
    
    print("\n=== Set API Keys ===")
    print("Available services (leave blank to skip):\n")
    
    for service_id, service_name in AVAILABLE_SERVICES.items():
        current_key = api_keys.get(service_id, "")
        masked_key = ""
        if current_key:
            masked_key = f" (current: ****{current_key[-4:]})" if len(current_key) > 4 else " (current: ****)"
            
        new_key = input(f"{service_name}{masked_key}: ").strip()
        
        if new_key:
            api_keys[service_id] = new_key
            print(f"✓ {service_name} key updated")
    
    save_api_keys(api_keys)
    print("\nAPI key configuration complete!")
    print("Your keys are saved in plaintext format for compatibility with the scanner.")
    print("You can now run the scraper with your API keys.")

def delete_key():
    """Interactive prompt to delete API keys."""
    api_keys = load_api_keys()
    
    if not api_keys:
        print("\nNo API keys are currently configured.")
        return
    
    print("\n=== Delete API Keys ===")
    print("Enter 'y' to delete a key, anything else to keep it:\n")
    
    for service_id in list(api_keys.keys()):
        service_name = AVAILABLE_SERVICES.get(service_id, service_id)
        response = input(f"Delete {service_name} key? (y/n): ").strip().lower()
        
        if response == 'y':
            del api_keys[service_id]
            print(f"✓ {service_name} key deleted")
    
    save_api_keys(api_keys)
    print("\nAPI key deletion complete!")

def verify_scrape_compatibility():
    """Check if the API keys are compatible with scrape.py"""
    if os.path.exists(KEY_FILE):
        print("\n=== Checking API Key Compatibility ===")
        try:
            with open(KEY_FILE, "r") as f:
                json.load(f) # Try to parse the JSON
            print("✓ API keys file is valid JSON and should work with scrape.py")
            return True
        except json.JSONDecodeError:
            print("✗ API keys file is not valid JSON. Please recreate it with 'python api_manager.py set'")
            return False
    else:
        print("\nNo API keys file found. Run 'python api_manager.py set' to create one.")
        return False

def print_help():
    """Print help information."""
    print("\nAPI Key Manager for Vulnerability Scanner")
    print("----------------------------------------")
    print("This utility helps you manage API keys for the vulnerability scanner.\n")
    print("Available commands:")
    print("  list    - List all API services that can be configured")
    print("  show    - Show your configured API keys (masked)")
    print("  set     - Set or update API keys")
    print("  delete  - Delete API keys")
    print("  verify  - Check if your API keys file is compatible with scrape.py")
    print("  help    - Show this help information\n")
    print("Example usage:")
    print("  python api_manager.py set\n")

def main():
    """Main function to handle command-line arguments."""
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        print_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "list":
        list_services()
    elif command == "show":
        show_keys()
    elif command == "set":
        set_key()
    elif command == "delete":
        delete_key()
    elif command == "verify":
        verify_scrape_compatibility()
    else:
        print(f"Unknown command: {command}")
        print_help()

if __name__ == "__main__":
    main() 
