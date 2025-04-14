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
- **HTML Report Generation**: Creates readable reports from scanning results

## Project Structure

```
/
├── scrape.py              # Main scanner script
├── api_manager.py         # API key management utility
├── cybersec_status.py     # Status monitoring tool
├── dedup.py               # Data deduplication utility
├── requirements.txt       # Python dependencies
├── config/                # Configuration files
│   ├── api_keys.json      # Your API keys (create this)
│   ├── config.json        # Scanner configuration
│   └── proxies.json       # Proxy configuration
├── output/                # Scanner results
├── reports/               # Generated HTML reports
└── MongoMockup/           # MongoDB integration files
```

## Setup and Installation

### Local Setup

1. Clone this repository:
   ```
   git clone https://github.com/YOUR-USERNAME/cybersecurity-vulnerability-scanner.git
   cd cybersecurity-vulnerability-scanner
   ```

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

### GitHub Setup

To upload this project to GitHub:

1. Create a new repository on GitHub
2. Initialize Git in your local project folder (if not already done):
   ```
   git init
   git add .
   git commit -m "Initial commit"
   ```

3. Connect to your GitHub repository:
   ```
   git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO-NAME.git
   git branch -M main
   git push -u origin main
   ```

4. Important: Add sensitive files to .gitignore before pushing:
   ```
   # Add to .gitignore
   config/api_keys.json
   output/*.json
   logs/
   __pycache__/
   myenv/
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

5. Verify compatibility:
   ```
   python api_manager.py verify
   ```

### Obtaining API Keys

See the `Obtain API keys.txt` file for detailed instructions on getting API keys for all supported services. The main services include:

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

## MongoDB Integration

The project includes MongoDB integration for storing and querying results:

### Using the Built-in MongoDB Mockup

1. Navigate to the MongoMockup directory:
   ```
   cd MongoMockup
   ```

2. Start the MongoDB container and file watcher:
   ```
   docker-compose up -d
   ```

3. Search stored data:
   ```
   node search.js
   ```

### Using Your Own MongoDB Instance

1. Configure your MongoDB connection in `config/config.json`

2. Run the scanner with MongoDB enabled:
   ```
   python scrape.py
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
  --debug                Enable debug logging
```

## Monitor Scanning Status

You can monitor the scanning status using the cybersec_status.py tool:

```
python cybersec_status.py
```

For continuous monitoring:
```
python cybersec_status.py --monitor
```

## Troubleshooting

### Common Issues and Fixes

1. **Keywords Not Loading**: Run the keywords fix script
   ```
   python fix_keywords_load.py
   ```

2. **API Integration Issues**: Run the API integration fix script
   ```
   python fix_api_integration.py
   ```

3. **Path Issues**: Check your file paths
   ```
   python check_paths.py
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

Reports are generated in the `reports` directory.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
