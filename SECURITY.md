# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in LogNorm, please report it responsibly.

**Do not open a public issue for security vulnerabilities.**

Instead, please send an email or direct message with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Suggested fix (if any)

## Security Considerations

LogNorm is designed as a **log normalization tool** for authorized use on data you own or have explicit permission to process.

- **Local Use Only:** The Flask web server is intended for local use. Do not expose it to the internet without proper authentication and HTTPS.
- **Uploaded Data:** Log files may contain sensitive information (usernames, IPs, commands). All data is stored locally in SQLite; nothing is transmitted externally.
- **File Uploads:** Only text-based log formats are processed. Maximum file size is configurable (default 50 MB).
- **No Active Connections:** LogNorm does not connect to external services unless Wazuh API integration is explicitly configured and invoked.
- **Wazuh Credentials:** Store Wazuh API credentials only in config.yaml (excluded from version control via .gitignore). Never commit credentials.
