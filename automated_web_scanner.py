#!/usr/bin/env python3
"""
Automated Web Scanner
Audits HTTP security headers and basic CORS response behavior for explicitly
authorized targets.

Safety: This tool sends ordinary HTTP GET/OPTIONS requests only. It does not
exploit vulnerabilities, bypass access controls, crawl links, brute-force,
or attempt authentication. Scan only websites you own or have permission to test.
"""
from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "HIGH",
        "description": "Encourages HTTPS-only connections in supported browsers.",
        "recommendation": "For HTTPS sites, configure an appropriate Strict-Transport-Security policy."
    },
    "content-security-policy": {
        "severity": "MEDIUM",
        "description": "Helps mitigate script injection and other content-loading risks.",
        "recommendation": "Define a restrictive Content-Security-Policy and test it before enforcement."
    },
    "x-content-type-options": {
        "severity": "LOW",
        "description": "Prevents MIME-type sniffing when set to nosniff.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "x-frame-options": {
        "severity": "MEDIUM",
        "description": "Legacy browser control against framing and clickjacking.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
    },
    "referrer-policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information browsers send.",
        "recommendation": "Choose a policy such as strict-origin-when-cross-origin based on application needs."
    },
    "permissions-policy": {
        "severity": "LOW",
        "description": "Controls access to selected browser features.",
        "recommendation": "Set a Permissions-Policy appropriate to the features the site uses."
    },
}

USER_AGENT = "AutomatedWebScanner/1.0 (authorized security-header audit)"

def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid URL '{url}'. Use a full http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return url

def request_url(url: str, method: str, timeout: float) -> dict:
    req = Request(url, method=method, headers={
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Origin": "https://scanner-test.example"
    })
    try:
        with urlopen(req, timeout=timeout) as response:
            return {
                "status_code": response.status,
                "final_url": response.geturl(),
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "error": None,
            }
    except HTTPError as exc:
        return {
            "status_code": exc.code,
            "final_url": exc.geturl(),
            "headers": {k.lower(): v for k, v in exc.headers.items()},
            "error": f"HTTP {exc.code}",
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {"status_code": None, "final_url": url, "headers": {}, "error": str(exc)}

def analyze_headers(headers: dict[str, str], scheme: str) -> list[dict]:
    findings = []
    for name, meta in SECURITY_HEADERS.items():
        value = headers.get(name)
        if not value:
            # HSTS is meaningful only for HTTPS endpoints.
            if name == "strict-transport-security" and scheme != "https":
                continue
            findings.append({
                "type": "missing_security_header",
                "header": name,
                "severity": meta["severity"],
                "observed": None,
                "description": meta["description"],
                "recommendation": meta["recommendation"],
            })
        elif name == "x-content-type-options" and value.strip().lower() != "nosniff":
            findings.append({
                "type": "weak_security_header",
                "header": name,
                "severity": meta["severity"],
                "observed": value,
                "description": meta["description"],
                "recommendation": meta["recommendation"],
            })
    return findings

def analyze_cors(headers: dict[str, str], test_origin: str) -> list[dict]:
    findings = []
    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials", "").strip().lower()
    if allow_origin == "*":
        findings.append({
            "type": "cors_wildcard_origin",
            "severity": "INFO",
            "observed": allow_origin,
            "description": "The response allows any origin for CORS-readable resources.",
            "recommendation": "Use an explicit origin allowlist when resources contain non-public data."
        })
        if allow_credentials == "true":
            findings.append({
                "type": "cors_wildcard_with_credentials_header",
                "severity": "REVIEW",
                "observed": {
                    "access-control-allow-origin": allow_origin,
                    "access-control-allow-credentials": allow_credentials
                },
                "description": "Wildcard origin and credentials header were both observed.",
                "recommendation": "Review the actual browser behavior and server configuration. Browsers reject wildcard ACAO with credentialed requests, but the combination can indicate misconfiguration."
            })
    elif allow_origin == test_origin:
        findings.append({
            "type": "cors_reflects_test_origin",
            "severity": "REVIEW",
            "observed": allow_origin,
            "description": "The response allowed the scanner's controlled test Origin.",
            "recommendation": "Verify that allowed origins are matched against a strict allowlist and that untrusted origins are rejected."
        })
    elif allow_origin:
        findings.append({
            "type": "cors_origin_present",
            "severity": "INFO",
            "observed": allow_origin,
            "description": "The server returned an Access-Control-Allow-Origin value.",
            "recommendation": "Confirm the returned origin is intentional and appropriately restricted."
        })
    return findings

def scan_target(url: str, timeout: float) -> dict:
    validate_url(url)
    parsed = urlparse(url)
    get_result = request_url(url, "GET", timeout)
    # OPTIONS is a simple observation, not an attempt to invoke an application action.
    options_result = request_url(url, "OPTIONS", timeout)
    findings = []
    if get_result["status_code"] is not None:
        findings.extend(analyze_headers(get_result["headers"], parsed.scheme))
        findings.extend(analyze_cors(get_result["headers"], "https://scanner-test.example"))
    if options_result["status_code"] is not None:
        findings.extend(analyze_cors(options_result["headers"], "https://scanner-test.example"))
    return {
        "target": url,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "requests": {
            "GET": {k: v for k, v in get_result.items() if k != "headers"},
            "OPTIONS": {k: v for k, v in options_result.items() if k != "headers"},
        },
        "observed_headers": {
            "GET": get_result["headers"],
            "OPTIONS": options_result["headers"],
        },
        "findings": findings,
        "note": "Automated observations require manual validation; missing headers are not always vulnerabilities."
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Audit security headers and basic CORS behavior.")
    parser.add_argument("urls", nargs="+", help="Authorized http(s) URL(s) to audit.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8).")
    parser.add_argument("--output", default="web_scan_report.json", help="JSON output file (default: web_scan_report.json).")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")
    results = []
    for url in args.urls:
        try:
            results.append(scan_target(url, args.timeout))
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
    report = {
        "tool": "Automated Web Scanner",
        "version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "targets_scanned": len(results),
        "results": results,
        "safety_scope": "Ordinary GET and OPTIONS requests only; authorized targets only."
    }
    with open(args.output, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
    for result in results:
        print(f"\n{result['target']}")
        print(f"  GET status: {result['requests']['GET']['status_code']}")
        print(f"  OPTIONS status: {result['requests']['OPTIONS']['status_code']}")
        print(f"  Findings: {len(result['findings'])}")
        for finding in result["findings"]:
            print(f"  - [{finding['severity']}] {finding['type']}: {finding.get('header', finding.get('observed', ''))}")
    print(f"\nJSON report written to: {args.output}")
    return 0 if results else 2

if __name__ == "__main__":
    raise SystemExit(main())
