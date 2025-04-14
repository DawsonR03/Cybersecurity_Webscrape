#!/usr/bin/env python3
"""
Cybersecurity Intelligence Platform - Status Monitor

This script provides a simple status monitor for the running cybersecurity
intelligence platform, displaying real-time information about the current scan,
progress, and found vulnerabilities.
"""

import os
import json
import time
import argparse
from datetime import datetime

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATUS_FILE = os.path.join(SCRIPT_DIR, "scan_status.json")
RESULTS_FILE = os.path.join(SCRIPT_DIR, "vulnerabilities.json")
TEMP_RESULTS_FILE = os.path.join(SCRIPT_DIR, "vulnerabilities_latest.json")


def format_simple_table(data, headers=None):
    """Simple function to format data as a text table without dependencies."""
    if not data:
        return "No data"
    
    # If headers are provided, add them as the first row
    if headers:
        all_rows = [headers] + data
    else:
        all_rows = data
    
    # Get the maximum width for each column
    col_widths = []
    for i in range(len(all_rows[0])):
        col_widths.append(max(len(str(row[i])) for row in all_rows) + 2)  # +2 for padding
    
    # Create a horizontal line
    h_line = "+" + "+".join("-" * w for w in col_widths) + "+"
    
    # Format the table
    table = [h_line]
    
    # Add the headers if provided
    if headers:
        header_row = "|" + "|".join(" " + str(h).ljust(w - 1) for h, w in zip(headers, col_widths)) + "|"
        table.append(header_row)
        table.append(h_line)
    
    # Add the data rows
    for row in data if headers else all_rows:
        data_row = "|" + "|".join(" " + str(cell).ljust(w - 1) for cell, w in zip(row, col_widths)) + "|"
        table.append(data_row)
    
    table.append(h_line)
    
    return "\n".join(table)


def format_time_diff(timestamp):
    """Calculate and format the time difference between now and a timestamp."""
    if not timestamp:
        return "N/A"
    
    try:
        timestamp_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        now = datetime.now().astimezone()
        diff = now - timestamp_dt.astimezone()
        
        if diff.total_seconds() < 60:
            return f"{int(diff.total_seconds())} seconds ago"
        elif diff.total_seconds() < 3600:
            return f"{int(diff.total_seconds() / 60)} minutes ago"
        else:
            return f"{int(diff.total_seconds() / 3600)} hours ago"
    except Exception:
        return "Invalid timestamp"


def read_status_file():
    """Read the current status from the status file."""
    try:
        if not os.path.exists(STATUS_FILE):
            print(f"Status file not found at: {STATUS_FILE}")
            print("The scanner may not have started yet or is not running.")
            return None
        
        try:
            with open(STATUS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError as json_err:
            print(f"Error parsing status file: {json_err}")
            print("This can happen if the file is being written to.")
            
            # Return a default status structure
            return {
                "scan_status": "unknown",
                "current_keyword": "Unknown - File parse error",
                "keywords_processed": 0,
                "total_keywords": 0,
                "vulnerabilities_found": 0,
                "scan_start_time": "",
                "timestamp": "",
                "errors": ["Status file could not be parsed correctly. The scanner might be writing to it."]
            }
    except Exception as e:
        print(f"Error accessing status file: {e}")
        return None


def read_results_file():
    """Read the current results from the results file."""
    try:
        results_file = TEMP_RESULTS_FILE if os.path.exists(TEMP_RESULTS_FILE) else RESULTS_FILE
        
        if not os.path.exists(results_file):
            return None
        
        try:
            with open(results_file, "r") as f:
                data = json.load(f)
                return data
        except json.JSONDecodeError as json_err:
            print(f"Error parsing results file: {json_err}")
            print(f"The file '{results_file}' appears to be incomplete or corrupted.")
            print("This can happen if the scanner is currently writing to the file.")
            
            # Try to get partial data - read as much as we can
            try:
                with open(results_file, "r") as f:
                    file_content = f.read()
                    
                # Find the last complete JSON object by finding the last complete vulnerability
                last_complete_idx = file_content.rfind('"timestamp"')
                if last_complete_idx != -1:
                    # Find the next closing brace after timestamp
                    closing_idx = file_content.find('}', last_complete_idx)
                    if closing_idx != -1:
                        # Find the next opening brace for a new vulnerability entry
                        next_vuln_idx = file_content.find('{', closing_idx)
                        
                        if next_vuln_idx != -1:
                            # We can salvage up to the last complete vulnerability
                            partial_content = file_content[:closing_idx+1] + "]}"
                            try:
                                # Try to parse what we have with added closing brackets
                                fixed_content = partial_content.rstrip(',') + "}"
                                # Make it a valid JSON by ensuring it's a complete structure
                                if '"vulnerabilities"' in fixed_content and not '"categorized_vulnerabilities"' in fixed_content:
                                    fixed_content = fixed_content + ', "categorized_vulnerabilities": {}, "manufacturer_vulnerabilities": {}, "metadata": {} }'
                                return json.loads(fixed_content)
                            except:
                                pass
            except:
                pass
                
            return {"vulnerabilities": [], "metadata": {"total_vulnerabilities": 0, "scan_time": ""}}
    except Exception as e:
        print(f"Error reading results file: {e}")
        return {"vulnerabilities": [], "metadata": {"total_vulnerabilities": 0, "scan_time": ""}}


def display_status(status, results, show_vulnerabilities=False):
    """Display the current status and results in a formatted way."""
    if not status:
        print("No status information available. Is the scanner running?")
        return
    
    # Display status header
    print("\n=== CYBERSECURITY INTELLIGENCE PLATFORM STATUS ===\n")
    
    # Basic status info
    status_info = [
        ["Status", status.get("scan_status", "Unknown")],
        ["Current Keyword", status.get("current_keyword", "N/A")],
        ["Progress", f"{status.get('keywords_processed', 0)}/{status.get('total_keywords', 0)} keywords"],
        ["Vulnerabilities Found", status.get("vulnerabilities_found", 0)],
        ["Last Updated", format_time_diff(status.get("timestamp", ""))],
        ["Scan Started", format_time_diff(status.get("scan_start_time", ""))],
    ]
    
    if status.get("scan_end_time"):
        status_info.append(["Scan Completed", format_time_diff(status.get("scan_end_time", ""))])
    
    print(format_simple_table(status_info))
    
    # Data source counts
    if "data_sources" in status:
        print("\n--- Data Source Counts ---\n")
        data_sources = [[k.upper(), v] for k, v in status["data_sources"].items()]
        print(format_simple_table(data_sources, headers=["Source", "Count"]))
    
    # Errors
    if status.get("errors") and len(status["errors"]) > 0:
        print("\n--- Errors ---\n")
        error_table = [[i+1, err] for i, err in enumerate(status["errors"])]
        print(format_simple_table(error_table, headers=["#", "Error"]))
    
    # Display vulnerabilities if requested and available
    if show_vulnerabilities and results:
        print("\n=== LATEST VULNERABILITY FINDINGS ===\n")
        
        # Get vulnerability metadata
        metadata = results.get("metadata", {})
        vuln_metadata = [
            ["Total Vulnerabilities", metadata.get("total_vulnerabilities", 0)],
            ["Scan Time", format_time_diff(metadata.get("scan_time", ""))],
        ]
        
        # Add risk level breakdown
        if "risk_levels" in metadata:
            for level, count in metadata.get("risk_levels", {}).items():
                vuln_metadata.append([f"{level.capitalize()} Risk", count])
                
        print(format_simple_table(vuln_metadata))
        
        # Show most recent vulnerabilities (top 10)
        vulnerabilities = results.get("vulnerabilities", [])
        if vulnerabilities:
            print("\n--- Recent Vulnerabilities ---\n")
            
            # Sort by timestamp (most recent first)
            sorted_vulns = sorted(
                vulnerabilities, 
                key=lambda x: x.get("timestamp", ""), 
                reverse=True
            )[:10]  # Get top 10
            
            vuln_table = []
            for i, vuln in enumerate(sorted_vulns):
                name = vuln.get("name", "Unknown")
                category = vuln.get("category", "Unknown")
                risk = vuln.get("risk_assessment", {}).get("severity", "Unknown")
                timestamp = format_time_diff(vuln.get("timestamp", ""))
                
                vuln_table.append([i+1, name, category, risk, timestamp])
            
            print(format_simple_table(
                vuln_table, 
                headers=["#", "Vulnerability", "Category", "Risk", "Found"]
            ))


def monitor_mode(refresh_interval=5):
    """Monitor the status continuously with updates."""
    try:
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            
            # Check if the scanner is running using ps command
            try:
                import subprocess
                ps_output = subprocess.check_output(["ps", "aux"]).decode('utf-8')
                scanner_running = "python" in ps_output and "scrape.py" in ps_output
                
                if not scanner_running:
                    print("\n=== CYBERSECURITY INTELLIGENCE PLATFORM STATUS ===\n")
                    print("\n⚠️ WARNING: The scanner process (scrape.py) does not appear to be running! ⚠️\n")
                    print("You may need to start the scanner with 'python scrape.py'\n")
            except:
                # If we can't check the process status, continue anyway
                pass
                
            status = read_status_file()
            results = read_results_file()
            
            display_status(status, results, show_vulnerabilities=True)
            
            print(f"\nRefreshing in {refresh_interval} seconds... (Ctrl+C to exit)")
            time.sleep(refresh_interval)
    except KeyboardInterrupt:
        print("\nExiting monitor mode...")


def main():
    """Main function to parse arguments and run the status checker."""
    parser = argparse.ArgumentParser(
        description="Check the status of the cybersecurity intelligence platform"
    )
    parser.add_argument(
        "-monitor", "-m", action="store_true",
        help="Monitor mode - continuously update the status"
    )
    parser.add_argument(
        "--interval", "-i", type=int, default=5,
        help="Refresh interval in seconds for monitor mode (default: 5)"
    )
    parser.add_argument(
        "--vulnerabilities", "-v", action="store_true",
        help="Show vulnerability information in addition to status"
    )
    
    args = parser.parse_args()
    
    if args.monitor:
        monitor_mode(args.interval)
    else:
        status = read_status_file()
        results = read_results_file()
        display_status(status, results, show_vulnerabilities=args.vulnerabilities)
    

if __name__ == "__main__":
    main() 
