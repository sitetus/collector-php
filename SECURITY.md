# Security Policy

## Reporting

If you believe you have found a vulnerability, write to **security@sitetus.com**. Please do **not** open a public issue.

- First response: within 3 working days.
- Assessment and fix target: 14 days for critical findings.
- Coordinated disclosure: we ask that details stay private until a fix is released; your contribution is credited in the release notes if you wish.

## Scope

This repository: the single-file collector and its build chain. The Laravel wrapper (`sitetus/laravel-collector`), the other collectors and the panel (sitetus.com) can be reported to the same address.

## Threat model (summary)

The collector is a web-exposed file on a customer's server, in the middle of a hostile internet. The design follows from that:

| Threat | Measure |
|---|---|
| Unauthorised request → data disclosure | Ed25519 / RSA signature verification; every invalid request gets a bodyless **404** (as if the file did not exist). An authorisation bypass is the most critical bug class for this product |
| Key or identifier leak through a timing side channel | Constant-time comparison (`hash_equals`) |
| Replay | ±10-minute time window plus a nonce store (file-locked, pruned, 1000 entries) |
| Leak of a panel key | Signatures use a key pair **per installation**; the blast radius of a leak is one installation, re-keyed from the panel with one click (the old file falls back to 404) |
| Orphaned or forgotten file | Optional `expires_at`, and **permanent sleep** (404) after 90 days without a valid request; the way out is installing a new package |
| Code or path injection through request data | No request parameter is ever used as a file path, a command or an include target |
| Data-minimisation violation | The envelope carries only numbers, statuses and name/version pairs; from the configuration only a fixed allow-list of flags; fixed message keys (`msg.*`) instead of free text |
| Supply chain | The single file is built by a reproducible script that prints its SHA-256; every envelope reports the hash of the installed file and the panel compares it with the fingerprint recorded at generation time |

## Supported versions

Only the latest version is supported; the panel raises an "update needed" finding for files below its minimum supported version. There is **no** automatic update, by design: no self-modifying code on your server.
