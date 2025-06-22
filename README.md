# Project-2-webapp-pentest-secure-coding
Automated DevSecOps Security Lab for OWASP Top 10 Detection, Enforcement, and CI/CD Policy Integration

This project is an automated **DevSecOps security lab** that simulates a secure development lifecylce. It integrates:
- **OWASP Top 10 vulnerability scanning**
- **secure coding practices with SAST & DAST**
- **CI/CD pipeline enforcement (GitHub Actions)** to identify and respond to security risks automatically.
 
- It enforces policy thresholds and automatically triggers build failures, GitHub issues, and alerting when risks are detected - bringing real-world security maturity to automated development pipelines

## Project Architecture

Component Technology Used
- Vulnerable target        -> OWASP Juice Shop (Docker)
- Static Analysis (SAST)   -> Bandit (Python)
- Dynamic Analysis (DAST)  -> OWASP ZAP (via API & Docker)
- CI/CD pipeline           -> GitHub Actions 
- Reporting                -> Markdown + HTML (auto-generated)
- Alerting                 -> Auto-created GitHub Issues

## Key Capabilities
[+] Bandit scans Python code for **Security vulnerabilities** like hardcoded passwords, unsafe functions, etc.
[+] ZAP performs **Active scanning** for OWASP Top 10 issues (XSS, Injection, etc...)
[+] CI/CD Workflow (GitHub Actions)
- Parses JSON reports from scanners
- **Blocks PRs** if thresholds are breached
- Auto-generates human-readable **Markdown & HTML reports**
- Auto-created **GitHub issues** for high-risk findings

## Current Security Policy (thresholds)

                   
| Scanner | High |   Medium  |        Action        |
|---------|------|-----------|----------------------|
| Bandit  | > 0  |  > 5      | [!] Fails CI pipeline|
| ZAP     | > 0  |  > 10     | [!] Fails CI pipeline|
|---------|------|-----------|----------------------|

- These thresholds are **configurable in the GitHub Actions YAML** (`.github/workflows/security.yml`).

## Usage instructions
    1. Start Lab Environment
        docker compose up -d
    
    2. Run scanners locally (optional)
        - python scanners/zap_scanner.py
        - python scanners/bandit_scanner.py
    
    3. Trigger CI/CD pipeline
        - Just push to main or open a pull request
            - git add .
            git commit -m "Trigger scan"
            git push
        
    4. Review Reports
        - /reports/
        |
        |--bandit_report.json
        |--zap_report.json
        |--bandit_summary.md
        |--zap_summary.md
        |--zap_report.html

## Evolution of the Project

|          Milestone         |             Description                           |
|----------------------------|---------------------------------------------------|
| [+] Initial Setup          | Dokerised Juice Shop, basic scanner integration   |
| [+] CI/CD integration      | Added GitHub Actions to automate scanning         |
| [+] Threshold Enforcement  | Security policy blocks merges on violations       |
| [+] Report Generation      | Markdown + HTML summary reports                   |
| [+] GitHub Issue Alerts    | High risks trigger automatic GitHub issues        |
| [+] Future Work            | upload findings to dashboards or SIEM integrations|
|--------------------------------------------------------------------------------|


## Configurable Variables (Policy Enforcement)

|       Variable        |                   Description                   |     Default    |
|-----------------------|-------------------------------------------------|----------------|
| HIGH_COUNT            |   Bandit high-severity issues threshold         |        0       |
| MEDIUM_COUNT          |   Bandit medium-severity threshold              |        5       |
| ZAP_HIGH              |   ZAP high-risk alerts threshold                |        0       |
| ZAP_MEDIUM            |   ZAP medium-risk alerts threshold              |        10      |
| GH_TOKEN              |   Token used to authorize GitHub issue creation |                |
|-----------------------|-------------------------------------------------|----------------|

- Thresholds can be changed/configured in .github/workflows/security.yml

## Eample Output - Markdown summary (CI logs)
[+] Bandit Security Summary
- [HIGH] /app/secrets.py: Use of insecure function eval()
- [MEDIUM] /app/utils.py: Use of assert detected

## Auto-created GitHub issue:
    Bandit detected 2 high-severity issues.
    Review: reports/bandit_summary.md

    ZAP detected 1 high-risk alert(s)
    Review: reports/zap_summary.md

## Project Significance
- This project reflects real-world DevSecOps maturity
    - Demonstrates DevSecOps maturity with enforceble controls
    - Secure coding enforcement with SAST/DAST
    - Security as code embedded in CI/CD
    - Alerting and triaging via GitHub issues
    - Scalable and adaptable for different risk policies or frameworks

## Challenges & Lessons Learned

1. **Docker & ZAP Integration Failures**
    - **Challenge** Intially, the ZAP docker container did not respond properly to API calls, causing the scanner to silently fail and skip report generation
    - **Solution** Added a loop with curl health checks to ensure ZAP was ready before launching scans. This ensured the container was fully initialised before API usage.
    **Lesson** In asynchronous service environments (like Docker), readiness checks are essential before execution - especially for API-bound tools like ZAP 

2. **Missing Report Failures & Broken Pipelines**
    - **Challenge** The pipeline failed unexpectedly due to missing JSON reports, (zap_report.json), which were not being generated correctly or read by jq
    - **Solution**  Modified zap_scanner.py to export reports in a structured JSON format ZAP-style ({ "site": [ { "alerts": [...] } ] }), which made them compatible with jq parsing in GitHub Actions.
    - **Lesson** Output formats must be structured to match downstream tooling expectations. Report schema alignment is just as important as generating the report itself

3. **Threshold Enforcement & Exit Codes**
    - **Challenge** Even when scans were successful, no meaningful control existed to block merges or notify teams when security issues were found.
    - **Solution** Implemented environment variable checks and exit codes to halt the pipeline when Bandit or ZAP exceeded defined thresholds. Also added auto-generated GitHub issues for visibility.
    - **Lesson** Security automation is only valuable if it enforces policy. Exit codes and thresholds convert passive scanning into proactive enforcement

4. **CI Debugging in GitHub Actions**
    - **Challenge** Debugging GitHub Actions was time-consuming due to unclear output and the inability to interact with running containers.
    - **Solution**  Used extensive inline logging (echo, print, jq) and intermediate Markdown summaries to inspect the scanner's behavior during runtime
    - **Lesson** CI/CD debugging benefits from verbose output and staging artifacts (like .md or .json files) that provide traceability during failures

5. **Auto-Creation of GitHub Issues**
    - **Challenge** Creating GitHub issues dynamically using CLI (gh) with properly encoded body content, titles, and conditionals  was non-trivial.
    - **Solution** Parsed environment variables, escaped markdown properly with %0A for newlines, and constructed human-readable GitHub issue bodies directly in the workflow YAML
    - **Lesson** Communicating security issues effectively is part of DevSecOps. Automating triage improves response time and bridges developer-security workflows

## Overall lessons
- How to operationalise vulnerability scanning with real enforcement
- How to structure and troubleshoot CI/CD workflows with conditional logic
- The importance of fail-fast security automation in real pipelines
- Best practices for security report formatting and alerting
- How to document and communicate techincal security findings effectively to both devs and non-technical stakeholders

## Contact 
- Created by Tom D. (2025)
- For questions, inquiries, or collabortations. Reach out via GitHub or LinkedIn

