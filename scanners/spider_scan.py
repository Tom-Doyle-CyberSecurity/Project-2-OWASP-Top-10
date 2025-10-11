#!/usr/bin/env python3

"""
Classic Spider Scan from https://github.com/h3st4k3r/OWASP-ZAP/blob/main/owaspzap-auto.py
Classic Spider scan in OWASP ZAP automatically crawls Juice Shop web application, discovering URLs, links, and forms to build a 
comprehensive map of the application, It identifies the application's attack surface, by following hyperlinks and parsing HTML content.
Although it does not test for vulnerabilities actively, it enables passive and active scanners to analyze all discovered endpoints for 
Potential security issues.
"""

import sys, time

def _tune(zap, max_depth=10, threads=5, max_children=10):
    try:
        zap.spider.set_option_max_depth(max_depth)
        zap.spider.set_option_thread_count(threads)
        zap.spider.set_option_max_children(max_children)
    except Exception:
        pass  

def run_spider(zap, target, *, recurse=True, max_depth=10, threads=5, max_children=10):
    _tune(zap, max_depth, threads, max_children)
    print(f"[+] Spidering: {target}")
    scan_id = zap.spider.scan(target, recurse=recurse)
    while True:
        try:
            pct = int(zap.spider.status(scan_id))
        except Exception:
            pct = 0
        print(f"\rSpider progress: {pct}%", end="", flush=True)
        if pct >= 100:
            break
        time.sleep(2)
    print("\n[+] Spider complete.")
