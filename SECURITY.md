English | [日本語](SECURITY.ja.md)

# Security policy

Please report vulnerabilities in ZES (Zero-Exec Shield) itself through GitHub's private reporting, not through a public issue.

1. Open the repository's **Security** tab
2. Choose **Report a vulnerability**

## Scope

- The latest main branch (fixes are not made to past versions)

What we want reported (examples):

- `zes-scan.sh` executes a file or program in the scan target (a break of Zero-Exec)
- The contents of a scanned repository can take over the scanner's behavior (command injection, crafted paths, and so on)
- `index.html` sends file contents to an external party, or displays them on screen

What we accept as public issues:

- Missed detections, false positives, and errors in the IoC data (please include the URL of the primary source)

## Response

This project is maintained by one person, so responses are made as far as possible. There is no guaranteed response time. After a fix is published, the report and the fix are recorded in the CHANGELOG (the reporter's name is included if they wish).
