# Security policy

Goral handles SSH credentials, private keys, proxy secrets, terminal data,
and connection history. Please do not disclose secrets, private hostnames,
addresses, logs, screenshots, or key material in a public issue.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/749755576/goral/security/advisories/new)
for suspected vulnerabilities. Include a minimal reproduction, affected
version or commit, platform, and impact. Give the maintainers reasonable time
to investigate before public disclosure.

Do not run destructive tests against systems you do not own or have permission
to test. This policy does not replace the license or create a security warranty.

## Safe diagnostics

- Redact API keys, passwords, private keys, session tokens, host addresses, and
  terminal output before sharing diagnostics.
- Prefer the fixed error code and a short reproduction over a full debug log.
