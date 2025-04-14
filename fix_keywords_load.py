#!/usr/bin/env python3
"""
Keywords Loading Fix for Web Scraper

This script helps fix issues with the scraper not loading keywords.
It creates an explicit keywords.json symlink in the expected location and
modifies the scrape.py script if needed to properly load keywords.
"""

import os
import sys
import json
import shutil
import fileinput
import re

# Configure paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYWORDS_FILE = os.path.join(SCRIPT_DIR, "keywords.json")
SCRAPE_PY = os.path.join(SCRIPT_DIR, "scrape.py")

def check_keywords_file():
    """Check if keywords.json exists and has the proper format"""
    if not os.path.exists(KEYWORDS_FILE):
        print(f"Keywords file not found at: {KEYWORDS_FILE}")
        print("Creating a sample keywords file...")
        
        sample_keywords = {
            "keywords": [
                {
                    "word": "James Webb Space Telescope cyber attack",
                    "category": "security",
                    "priority": "high",
                    "date_added": "2025-02-19"
                },
                {
                    "word": "JWST zero-day vulnerability",
                    "category": "CVE",
                    "priority": "critical",
                    "date_added": "2025-01-05"
                }
            ]
        }
        
        with open(KEYWORDS_FILE, "w") as f:
            json.dump(sample_keywords, f, indent=4)
        print(f"Created sample keywords.json at {KEYWORDS_FILE}")
        return True
    
    # File exists, check format
    try:
        with open(KEYWORDS_FILE, "r") as f:
            data = json.load(f)
        
        if not isinstance(data, dict) or 'keywords' not in data:
            print("Keywords file exists but has incorrect format.")
            print("Fixing format...")
            
            # Try to fix the format
            if isinstance(data, list):
                # It's a list of keywords directly
                fixed_data = {"keywords": data}
                with open(KEYWORDS_FILE, "w") as f:
                    json.dump(fixed_data, f, indent=4)
                print("Fixed keywords.json format (wrapped list in a 'keywords' object)")
            else:
                print("Can't automatically fix the format.")
                print("Please check the file manually to ensure it has a 'keywords' array.")
                return False
        else:
            # Correct format, count keywords
            keyword_count = len(data.get('keywords', []))
            print(f"Keywords file exists and contains {keyword_count} keywords.")
            return True
            
    except json.JSONDecodeError:
        print("Keywords file exists but is not valid JSON.")
        print("Please check the file manually to fix JSON syntax errors.")
        return False
    except Exception as e:
        print(f"Error checking keywords file: {e}")
        return False

def check_scrape_py():
    """Check if scrape.py has the correct code to load keywords"""
    if not os.path.exists(SCRAPE_PY):
        print(f"Scrape.py not found at: {SCRAPE_PY}")
        return False
    
    # Look for the load_keywords function in scrape.py
    keyword_loading_found = False
    input_file_found = False
    
    try:
        with open(SCRAPE_PY, "r") as f:
            content = f.read()
            
            # Check if load_keywords function exists
            if "def load_keywords(" in content:
                keyword_loading_found = True
                print("Found load_keywords function in scrape.py")
            
            # Check if INPUT_FILE is defined
            if "INPUT_FILE" in content:
                input_file_pattern = r"INPUT_FILE\s*=\s*['\"](.+)['\"]"
                matches = re.findall(input_file_pattern, content)
                if matches:
                    input_file_path = matches[0]
                    input_file_found = True
                    print(f"Found INPUT_FILE definition in scrape.py: {input_file_path}")
            
        return keyword_loading_found and input_file_found
    
    except Exception as e:
        print(f"Error checking scrape.py: {e}")
        return False

def add_debug_print():
    """Add debug print statements to scrape.py to help diagnose keyword loading issues"""
    if not os.path.exists(SCRAPE_PY):
        print(f"Scrape.py not found at: {SCRAPE_PY}")
        return False
    
    try:
        # Create a backup
        backup_file = f"{SCRAPE_PY}.bak"
        shutil.copy2(SCRAPE_PY, backup_file)
        print(f"Created backup of scrape.py at {backup_file}")
        
        # Find the load_keywords function
        with open(SCRAPE_PY, "r") as f:
            lines = f.readlines()
        
        load_keywords_found = False
        in_function = False
        keyword_return_line = -1
        
        for i, line in enumerate(lines):
            if "def load_keywords(" in line:
                load_keywords_found = True
                in_function = True
                print(f"Found load_keywords function at line {i+1}")
            
            if in_function and "return" in line and "keywords" in line:
                keyword_return_line = i
                print(f"Found return statement at line {i+1}")
                break
                
            if in_function and line.strip() == "}" and keyword_return_line == -1:
                # End of function
                in_function = False
        
        if not load_keywords_found:
            print("Could not find load_keywords function in scrape.py")
            return False
            
        if keyword_return_line == -1:
            print("Could not find keywords return statement in load_keywords function")
            return False
        
        # Insert debug prints before the return
        debug_lines = [
            f"    logging.info(f\"Loading keywords from: {{keywords_file if keywords_file else INPUT_FILE}}\")\n",
            f"    logging.info(f\"Found {{len(keywords)}} keywords in the file\")\n",
            f"    if keywords:\n",
            f"        logging.info(f\"First keyword: {{keywords[0] if keywords else 'None'}}\")\n"
        ]
        
        modified_lines = lines[:keyword_return_line] + debug_lines + lines[keyword_return_line:]
        
        # Write modified file
        with open(SCRAPE_PY, "w") as f:
            f.writelines(modified_lines)
            
        print("Added debug print statements to load_keywords function")
        return True
    
    except Exception as e:
        print(f"Error adding debug statements to scrape.py: {e}")
        return False

def print_keywords_summary():
    """Print a summary of the keywords in the file"""
    if not os.path.exists(KEYWORDS_FILE):
        print("Keywords file doesn't exist.")
        return
        
    try:
        with open(KEYWORDS_FILE, "r") as f:
            data = json.load(f)
            
        if isinstance(data, dict) and 'keywords' in data:
            keywords = data['keywords']
            print(f"\nKeywords summary ({len(keywords)} keywords):")
            
            for i, kw in enumerate(keywords[:5]):  # Just show first 5
                if isinstance(kw, dict):
                    word = kw.get('word', 'Unknown')
                    category = kw.get('category', 'Unknown')
                    priority = kw.get('priority', 'Unknown')
                    print(f"  {i+1}. {word} (Category: {category}, Priority: {priority})")
                else:
                    print(f"  {i+1}. {kw}")
                    
            if len(keywords) > 5:
                print(f"  ...and {len(keywords) - 5} more")
                
        elif isinstance(data, list):
            print(f"\nKeywords summary ({len(data)} keywords):")
            for i, kw in enumerate(data[:5]):
                if isinstance(kw, dict):
                    word = kw.get('word', 'Unknown')
                    print(f"  {i+1}. {word}")
                else:
                    print(f"  {i+1}. {kw}")
            
            if len(data) > 5:
                print(f"  ...and {len(data) - 5} more")
        else:
            print("\nCould not find a keywords array in the file.")
            
    except Exception as e:
        print(f"Error reading keywords file: {e}")

def main():
    """Main function to fix keywords loading"""
    print("\n=== Keywords Loading Fix ===\n")
    
    # Step 1: Check keywords.json file
    keywords_ok = check_keywords_file()
    
    # Step 2: Check scrape.py file
    scrape_py_ok = check_scrape_py()
    
    # Step 3: Print keywords summary
    print_keywords_summary()
    
    # Step 4: Add debug prints
    if keywords_ok and scrape_py_ok:
        add_debug_print()
    
    print("\n=== Next Steps ===")
    print("1. Make sure your keywords.json has the proper format:")
    print("   {")
    print('     "keywords": [')
    print('       {"word": "Keyword 1", "category": "security", "priority": "high"},')
    print('       {"word": "Keyword 2", "category": "CVE", "priority": "critical"}')
    print("     ]")
    print("   }")
    print("\n2. Run the scraper with debug flag:")
    print("   python scrape.py --disable-mongodb --skip-missing --debug")
    print("\n3. Check the logs for keyword loading messages.")

if __name__ == "__main__":
    main() 