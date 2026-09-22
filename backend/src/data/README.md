# Password Blocklist

The SecureByte registration module checks proposed passwords against a
local blocklist of commonly used passwords.

## Source

- Collection: SecLists
- File: `Passwords/Common-Credentials/10k-most-common.txt`
- Repository: `danielmiessler/SecLists`
- Retrieved: 2026-09-22
- Local file: `common-passwords.txt`

## Usage

The blocklist is loaded locally by the backend when the application starts.

Password comparison against the blocklist is case-insensitive. This
comparison is used only to determine whether a proposed password is blocked.

The user's actual password is not converted to lowercase, trimmed, or
otherwise normalized before password hashing.

The blocklist is not treated as an exhaustive collection of all compromised
passwords. It is the documented local weak/common-password list selected for
this academic prototype.