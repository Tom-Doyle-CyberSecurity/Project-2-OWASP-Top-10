# Project-2-webapp-pentest-secure-coding
Automated web application security lab performing OWASP Top 10 vulnerability scanning, secure coding remediation, and CI/CD pipeline integration for DevSecOps workflows
# Project 2: WebApp Pentest & Secure Coding

This project is an automated web application security lab performing:
- OWASP Top 10 vulnerability scanning
- Secure coding remediation
- CI/CD pipeline integration for DevSecOps workflows

## Architecture

- Juice Shop as vulnerable target
- OWASP ZAP for vulnerability scanning
- Bandit for static code analysis
- GitHub Actions for CI/CD integration

## Usage

1. Spin up Docker lab:
    ```bash
    docker-compose up -d
    ```

2. Run scans:
    ```bash
    python scanners/zap_scanner.py
    python scanners/bandit_scanner.py
    ```

3. Review reports in `/reports/`.

## To Do

- Add full automation scripts
- Build reporting modules
- Write remediation steps
- Full CI/CD integration