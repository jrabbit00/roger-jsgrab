# Roger JSGrab 🐰

JavaScript file scraper for bug bounty reconnaissance. Finds and analyzes JavaScript files to discover endpoints, secrets, and parameters.

## Features

- Recursively find all JS files on a target
- Extract API endpoints (/api/, /v1/, etc.)
- Find hardcoded secrets and tokens
- Extract hidden parameters
- Analyze source maps
- Concurrent downloading
- Filter by domain

## Installation

```bash
git clone https://github.com/jrabbit00/roger-jsgrab.git
cd roger-jsgrab
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 jsgrab.py https://target.com

# Save to file
python3 jsgrab.py target.com -o results.txt

# Find only endpoints
python3 jsgrab.py target.com --endpoints-only

# Custom threads
python3 jsgrab.py target.com -t 20
```

## Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output results to file |
| `-t, --threads` | Number of threads (default: 10) |
| `-e, --endpoints-only` | Only extract API endpoints |
| `-s, --secrets-only` | Only look for secrets/tokens |
| `-q, --quiet` | Quiet mode (less output) |
| `--depth` | Max crawl depth (default: 3) |
| `--filter-domain` | Only include JS from this domain |

## What It Finds

### API Endpoints
- `/api/v1/*`
- `/api/v2/*`
- `/graphql`
- `/rest/*`

### Secrets
- API keys (`api_key`, `apikey`, `API_KEY`)
- Tokens (`token`, `access_token`, `jwt`)
- Passwords (`password`, `passwd`)
- AWS keys (`AKIA...`)
- Private keys

### Parameters
- `id=`, `user_id=`
- `admin=`, `debug=`
- `redirect=`, `url=`
- `file=`, `path=`

## Examples

```bash
# Full scan
python3 jsgrab.py https://example.com

# Quick endpoint scan
python3 jsgrab.py example.com -e

# Save everything
python3 jsgrab.py example.com -o jsfindings.txt
```

## License

MIT License