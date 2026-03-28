# DNS Recon Tool

A small Python project for beginner-friendly domain reconnaissance. It collects
basic DNS information for a target domain and produces a readable JSON report.

## Features

- resolves A, AAAA, MX, NS, and CNAME records where available
- captures reverse DNS for resolved IP addresses
- exports results to JSON
- keeps the implementation simple and easy to explain in a portfolio

## Why it fits cybersecurity

DNS and infrastructure discovery are common early steps in reconnaissance.
This project shows understanding of host discovery, record types, and basic
reporting.

## Usage

```bash
python recon.py example.com
python recon.py example.com --output report.json
```

## Example output

```json
{
  "target": "example.com",
  "records": {
    "A": ["93.184.216.34"]
  }
}
```
