# secureguard-zero-trust-encryption

SecureGuard is a lightweight, endpoint-level file encryption tool designed to protect sensitive files **before they reach the cloud**.

## Why This Exists

Cloud encryption (AWS KMS, S3 encryption, etc.) is powerful — but files often exist unencrypted on local machines before upload.

SecureGuard enforces zero-trust encryption at the file level, closing that gap.

## Features

- Encrypts files in place (no plaintext copies left behind)
- Tamper detection because modified files fail decryption
- Password-derived encryption keys
- Audit logging with timestamps
- CLI + optional GUI


## Use Cases
- Protecting configuration files and secrets
- Encrypting sensitive internal documents
- CI/CD pipeline artifact security
- Offline  environments

## Tech Stack
- Python
- cryptography
- logging
- tkinter for optional GUI

Note: In a real enterprise, audit logs should be centralized, append-only and tamper-evident. Local log files can be edited by users with filesystem access. Future improvements to this could include HMAC-signed log entries or integration with a secure logging service.

## Disclaimer

This project is for educational and portfolio purposes.



