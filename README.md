# WebAppScanner

**WebAppScanner** is an advanced **asynchronous** web vulnerability scanner built in Python to detect security issues like SSL/TLS vulnerabilities, SSRF, open redirects, and template injections.

## Features
- Uses **asyncio** and **aiohttp** for high performance.
- Detects multiple security vulnerabilities.
- Generates reports in **JSON**, **HTML**, and **YAML** formats.
- Multi-threaded scanning.

## Installation
```bash
git clone https://github.com/manilreddy1/WebAppScanner.git
cd WebAppScanner
pip install -r requirements.txt
```
## Usage

scanner.py [-h] [-o {json,html,yaml}] [-t THREADS] [--full] url

### Example: 
```bash
python3 scanner.py https://example.com -t 20 -o html --full
```

Or 
```bash
scanner.py -h
