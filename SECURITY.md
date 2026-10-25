# Security Policy

## Intended Use

This project is a local Windows account recovery and security-auditing toolkit intended
for use only on devices you own or are explicitly authorized in writing to service.

It reads local Windows security data, derives NTLM hashes for local accounts, and tests
candidate passwords against those hashes offline. The toolkit performs these operations
locally and does not transmit credential data over a network.

Use this software only with appropriate authorization. Unauthorized access may violate
applicable laws, including India's Information Technology Act, 2000, or the U.S. Computer
Fraud and Abuse Act, depending on the circumstances and jurisdiction.

This project is intended for legitimate account recovery, security auditing, and
educational research. It is not intended to facilitate unauthorized access to accounts or
devices.

## Sensitive Data Handling

The following files may contain sensitive credentials or security information:

- `sam_dump.json` — exported Windows security data.
- `passstore.txt` — extracted password hashes.
- Password lists, diagnostic logs, and other files containing real credentials or
  personal information.

Do not commit these files to version control, publish them, upload them to third-party
services, or share them publicly.

Store sensitive data securely and delete it when it is no longer needed for the authorized
task. Use `.gitignore` to help prevent accidental commits.

## Reporting a Problem

### Security Vulnerabilities

Please do not disclose security vulnerabilities or exploitable details through public
issues.

Use GitHub's private vulnerability reporting feature if it is enabled for this repository.

If private reporting is unavailable, open a minimal issue requesting a private reporting
contact. Do not include vulnerability details, passwords, hashes, exploit code, or
sensitive personal information in that public issue.

### General Bugs

For non-security-related bugs, open a repository issue with:

- Steps to reproduce the problem.
- The affected script or component.
- The Python version and Windows version.
- Relevant error messages with credentials and personal information removed.

### Abuse and Policy Concerns

For concerns about misuse of this project, contact the repository maintainer through an
appropriate private reporting channel. Do not include real credentials or other sensitive
information in public reports.

## Scope

This project does not provide support for using the toolkit against systems or accounts
without appropriate authorization.

## Disclaimer and Data-Loss Warning

This software is provided "as is", without warranty of any kind. The maintainers are not
responsible for unauthorized use or data loss resulting from its use.

Administratively resetting a Windows account password may make EFS-encrypted files and
some DPAPI-protected data, such as saved application credentials or private keys,
inaccessible. Recovery may be impossible if the necessary recovery keys or backups are
unavailable.

Before resetting a password, consider the potential impact on encrypted files and stored
credentials. Preserve appropriate backups and recovery keys where possible.

After a password reset, verify that you can sign in with the new password and confirm
access to important files and applications before ending the recovery session.
