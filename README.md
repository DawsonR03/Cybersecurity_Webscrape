# Cybersecurity Vulnerability Scanner

A comprehensive web scraping tool for discovering and monitoring cybersecurity vulnerabilities, assets, and threats related to any component by simply modifying the keywords in the JSON configuration.

## Features

- **Comprehensive Data Collection**: Scans multiple sources for vulnerabilities, assets, and threats
- **Customizable Keywords**: Define your own search keywords through a JSON configuration file
- **Continuous Scanning**: Schedule automatic scans at regular intervals
- **Data Deduplication**: Removes duplicate results for cleaner data
- **Rich Output Formats**: Saves results in structured JSON files
- **MongoDB Integration**: Optionally store results in MongoDB for better querying
- **API Integration**: Connects with various security APIs (NVD, CISA, Shodan, OTX, etc.)

## Setup and Installation

1. Clone this repository
2. Create a Python virtual environment:
   ```
   python3 -m venv myenv
   source myenv/bin/activate  # On Windows: myenv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Configure your API keys (see below)
5. Run the scanner:
   ```
   python scrape.py
   ```

## API Key Management

For optimal results, you should configure API keys for the various security services. We've made this easy with the included API manager:

### Using the API Manager

1. List available services:
   ```
   python api_manager.py list
   ```

2. Configure your API keys:
   ```
   python api_manager.py set
   ```

3. View your configured keys:
   ```
   python api_manager.py show
   ```

4. Delete keys:
   ```
   python api_manager.py delete
   ```

### Obtaining API Keys

- **Shodan API**: Register at https://account.shodan.io/register
- **NVD API**: Request at https://nvd.nist.gov/developers/request-an-api-key
- **AlienVault OTX**: Register at https://otx.alienvault.com/signup/
- **Google API**: Get a key at https://console.cloud.google.com/apis/credentials

## Customizing Keywords

Edit the `keywords.json` file to define your search terms:

```json
{
    "keywords": [
        {
            "word": "Component X vulnerability",
            "category": "security",
            "priority": "high",
            "date_added": "2025-02-19"
        },
        {
            "word": "Component X zero-day",
            "category": "CVE",
            "priority": "critical",
            "date_added": "2025-01-05"
        }
    ]
}
```

## Command Line Options

```
Usage: python scrape.py [OPTIONS]

Options:
  --once                 Run the scan only once and exit
  --interval SECONDS     Set the scan interval in seconds (default: 3600)
  --disable-mongodb      Disable MongoDB integration
  --report               Generate HTML report after scanning
  --keyword-limit N      Limit scanning to the first N keywords
  --skip-missing         Skip warnings about missing modules
```

## Troubleshooting

### Common Indentation Errors

If you see indentation errors when running the script, you may need to fix the indentation in these areas:

1. Around line ~719 in the `fetch_cisa_kev` function - Make sure code inside the `try` block is properly indented:
   ```python
   try:
       # URL for CISA KEV catalog
       url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
       
       # Make the request
       response = requests.get(url, timeout=10)
   ```

2. Around line ~858 in the `fetch_google_data` function - Indentation in the `if link and title:` block:
   ```python
   if link and title:
       results.append({
           "title": title,
           "link": link,
           "snippet": snippet
       })
   ```

3. Around line ~1904 in the `AdaptiveRateLimiter` class - Proper indentation for the `return` statement:
   ```python
   if domain not in self.domain_timers:
       return
   ```

### Missing Modules

If you see warnings about missing modules, make sure you've installed all requirements:
```
pip install -r requirements.txt
```

## Output Files

Results are saved in the `output` directory:
- `vulnerabilities.json` - Discovered security vulnerabilities
- `assets.json` - Identified assets
- `threats.json` - Detected threats
