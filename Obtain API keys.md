# How to Obtain API Keys for Cybersecurity Vulnerability Scanner

This guide provides instructions on how to obtain API keys for all services supported by the vulnerability scanner.

## Essential API Keys

1. **National Vulnerability Database (NVD) API**
   - Website: https://nvd.nist.gov/developers/request-an-api-key
   - Registration: Fill out the form with your information
   - Free Tier: Yes, with rate limits (2,000 calls per 30 rolling days)

2. **Google Custom Search Engine API**
   - Website: https://developers.google.com/custom-search/v1/overview
   - CSE Setup: https://programmablesearchengine.google.com/cse/create/new
   - API Key: https://console.cloud.google.com/apis/credentials
   - Free Tier: Yes, limited to 100 queries per day

3. **Shodan API**
   - Website: https://shodan.io/
   - Registration: https://account.shodan.io/register
   - API Key Location: https://account.shodan.io/ (after registration)
   - Free Tier: Limited free tier, better functionality with paid plan

4. **AlienVault OTX API (Open Threat Exchange)**
   - Website: https://otx.alienvault.com/
   - Registration: https://otx.alienvault.com/auth/register
   - API Key Location: https://otx.alienvault.com/api (after login)
   - Free Tier: Yes, generous limits

5. **IBM X-Force Exchange API**
   - Website: https://exchange.xforce.ibmcloud.com/
   - Registration: https://exchange.xforce.ibmcloud.com/signup (requires IBM ID)
   - API Keys: https://exchange.xforce.ibmcloud.com/settings/api (after login)
   - Free Tier: Yes, with rate limits

6. **URLScan.io API**
   - Website: https://urlscan.io/
   - Registration: https://urlscan.io/user/signup
   - API Key: https://urlscan.io/user/profile/ (after registration)
   - Free Tier: Yes, with rate limits

7. **VirusTotal API**
   - Website: https://www.virustotal.com/
   - Registration: https://www.virustotal.com/gui/join-us
   - API Key: https://www.virustotal.com/gui/my-apikey (after login)
   - Free Tier: Yes, limited to 500 requests per day

8. **SecurityTrails API**
   - Website: https://securitytrails.com/
   - Registration: https://securitytrails.com/app/signup
   - API Key: https://securitytrails.com/app/account/credentials (after login)
   - Free Tier: Yes, limited to 50 queries per month

9. **GitHub API**
   - Website: https://github.com/
   - Registration: https://github.com/signup
   - API Key: https://github.com/settings/tokens (create a personal access token)
   - Free Tier: Yes, with rate limits (5,000 requests per hour)

10. **Have I Been Pwned (HIBP) API**
    - Website: https://haveibeenpwned.com/
    - Registration: https://haveibeenpwned.com/API/Key
    - API Key: Purchase required ($3.50 per month)
    - Free Tier: No, paid service only

11. **ThreatCrowd API**
    - Website: https://threatcrowd.org/
    - Note: ThreatCrowd API is currently free to use without an API key
    - Documentation: https://github.com/AlienVault-OTX/ApiV2

## Using the API Keys in Your Code

After obtaining your API keys, you have two ways to configure them:

### Option 1: Use the API Manager (Recommended)

Run the API Manager to set your keys:
```bash
python api_manager.py set
```

This will interactively prompt you to enter keys for each service. The keys will be saved in a configuration file and automatically loaded by the scanner.

### Option 2: Create a JSON Configuration File Manually

Create a file at `config/api_keys.json` with the following structure:
```json
{
  "nvd": "your-nvd-api-key",
  "google": "your-google-api-key",
  "cse_id": "your-google-cse-id",
  "shodan": "your-shodan-api-key",
  "otx": "your-otx-api-key",
  "xforce": "your-xforce-api-key",
  "urlscan": "your-urlscan-api-key",
  "virustotal": "your-virustotal-api-key",
  "securitytrails": "your-securitytrails-api-key",
  "github": "your-github-personal-access-token",
  "hibp": "your-hibp-api-key",
  "threatcrowd": "your-threatcrowd-api-key"
}
```

## Free vs. Paid Tiers

Most services offer free tiers that are sufficient for testing and personal use. For production environments or more extensive scanning, consider the paid options which typically offer:

- Higher rate limits
- More comprehensive data
- Additional features and endpoints
- Better support

The scanner will work with any combination of these API keys - if a key is missing, that particular data source will be skipped. 