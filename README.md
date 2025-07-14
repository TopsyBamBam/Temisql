# TemiSql - Advanced SQL Injection Testing Framework

![TemiSql Banner](https://via.placeholder.com/800x200?text=TemiSql+SQL+Injection+Tester)

TemiSql is an advanced SQL injection testing framework designed for penetration testers and security researchers. It automates the detection of SQL injection vulnerabilities with sophisticated techniques to bypass security mechanisms like WAFs.

## Key Features

- **Multi-Database Support**: MSSQL, MySQL, PostgreSQL, Oracle
- **WAF Evasion**: 15+ bypass techniques including encoding, comments, and parameter pollution
- **Comprehensive Payload Library**: 100+ payloads across 10 categories:
  - Authentication bypass
  - Error-based injection
  - Time-based blind SQLi
  - Boolean-based blind SQLi
  - Union-based extraction
  - Out-of-band exfiltration
  - Second-order injection
  - File operations
- **Intelligent Target Profiling**: Automatic technology stack detection
- **Detailed Reporting**: Color-coded console output with vulnerability analysis

## Usage

```bash
python temisql.py