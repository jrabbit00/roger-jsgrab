# Roger JSGrab 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**JavaScript file scraper for bug bounty reconnaissance.**

Recursively finds and analyzes JavaScript files to discover API endpoints, hardcoded secrets, hidden parameters, and source maps.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

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

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger JSGrab helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)