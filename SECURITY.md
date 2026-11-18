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
| Unauthorised request → data disclosure | Ed25519 / RSA signature verification; a request without the signature headers or with another project key gets a bodyless **404** (as if the file did not exist); one that carries the right project key and fails gets a bodyless **403** with a fixed reason word, decided before anything is written to the nonce store; an expired or sleeping installation answers 404 to everyone. An authorisation bypass is the most critical bug class for this product |
| Key or identifier leak through a timing side channel | Constant-time comparison (`hash_equals`) |
| Replay | ±10-minute time window plus a nonce store (file-locked, pruned, 1000 entries) |
| Leak of a panel key | Signatures use a key pair **per installation**; the blast radius of a leak is one installation, re-keyed from the panel with one click (the old file refuses every request signed with the new key) |
| Orphaned or forgotten file | Optional `expires_at`, and **permanent sleep** (404) after 90 days without a valid request; the way out is installing a new package |
| Code or path injection through request data | No request parameter is ever used as a file path, a command or an include target |
| Data-minimisation violation | The envelope carries only numbers, statuses and name/version pairs; from the configuration only a fixed allow-list of flags; fixed message keys (`msg.*`) instead of free text |
| An application key that is already public (product default, key published in a repository) | Opt-in module `secret_check`, off by default; a file built without it contains neither its code nor its list, and then no configuration value is read for its content. When selected, `APP_KEY` is hashed in memory (SHA-256) and the first 6 bytes are looked up in a list of 1,258 truncated hashes of publicly known keys embedded in the file. One yes/no leaves the server; the key, its length, its hash or a part of its hash never do, and none of them is written, logged or put in an error message. The embedded list contains no key. A "yes" discloses that the key is an entry of a public list; a key on no list can match by chance with a probability of 1,258 in 2^48 (about 1 in 224 billion) |
| Supply chain | The single file is built by a reproducible script that prints its SHA-256; every envelope reports the hash of the installed file and the panel compares it with the fingerprint recorded at generation time |

## Supported versions

Only the latest version is supported; the panel raises an "update needed" finding for files below its minimum supported version. There is **no** automatic update, by design: no self-modifying code on your server.
