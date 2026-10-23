# Automated Web Scanner
### Security Headers and CORS Configuration Review

A lightweight Python utility for checking selected HTTP security headers and observing basic Cross-Origin Resource Sharing (CORS) response behavior on websites you own or are explicitly authorized to assess.

**Safety scope:** The scanner sends ordinary HTTP `GET` and `OPTIONS` requests. It does not crawl links, exploit vulnerabilities, bypass access controls, brute-force, or attempt authentication. Scan only authorized targets.

## Files

- `automated_web_scanner.py` — scanner source code.
- `requirements.pdf` — hardware/software and project requirements.
- `project_report.pdf` — project report with Sandip University logo.
- `sandip_university_logo.png` — supplied logo asset.
- `sample_report.json` — illustrative example of the output format (synthetic; not a real scan result).

## Requirements

- Python 3.10 or newer
- Internet/network access to the authorized target
- No third-party Python packages; standard library only

## Usage

```bash
python automated_web_scanner.py https://example.com
```

Scan more than one authorized URL:

```bash
python automated_web_scanner.py https://example.com https://www.example.org --output report.json
```

Set a timeout:

```bash
python automated_web_scanner.py https://example.com --timeout 12 --output web_scan_report.json
```

The script writes a JSON report containing status codes, observed response headers, findings, and timestamps.

## Checks performed

### Security headers
- `Strict-Transport-Security` (for HTTPS targets)
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

### CORS observations
- Wildcard `Access-Control-Allow-Origin`
- Wildcard origin together with `Access-Control-Allow-Credentials`
- Response that allows the scanner's controlled test origin
- Other explicit `Access-Control-Allow-Origin` values

The scanner sends a test Origin value of `https://scanner-test.example`. A response to one Origin is only an observation, not proof that all origins are accepted or that sensitive data is exposed. Browser enforcement, credentials, methods, headers, and application context matter.

## Interpreting results

A missing header is not automatically a vulnerability. Severity labels are triage hints, not a formal risk rating. Review each finding manually, account for application requirements, and validate in a test environment before making changes. The tool does not attempt to prove exploitability.

## Suggested workflow

1. Obtain written authorization and define target URLs.
2. Run against a staging site or approved scope.
3. Review the JSON report.
4. Validate findings using server configuration and browser behavior.
5. Apply changes through normal change control.
6. Re-scan and document before/after results.

## License

Educational project template. Add an appropriate license before redistribution.
