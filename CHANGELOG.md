# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-02-02

### Fixed

- Fixed `find_verification_method` to match keys stored with fragment-only IDs (e.g., `#key-1` instead of `did:web:example.com#key-1`)
- Improved key lookup to handle various DID document formats where verification method IDs may be stored as relative references

## [0.1.0] - 2026-02-02

### Added

- Initial release of the DID Resolver gem
- Core `DidResolver::Resolver` class with pluggable method resolver architecture
- `DidResolver::ParsedDID` for parsing DID strings according to W3C DID Core spec
- `DidResolver::DIDDocument` for representing DID Documents
- `DidResolver::ResolutionResult` for representing resolution results
- `DidResolver::Cache` for in-memory caching with TTL support

### DID Methods

- **did:web** - Resolve DIDs from HTTPS domain endpoints
  - Supports path-based DIDs (e.g., `did:web:example.com:users:alice`)
  - Supports port numbers via percent-encoding (e.g., `did:web:localhost%3A8080`)

- **did:key** - Self-describing cryptographic key DIDs
  - Ed25519 (multicodec: 0xed)
  - X25519 (multicodec: 0xec)
  - secp256k1 (multicodec: 0xe7)
  - P-256 (multicodec: 0x1200)
  - P-384 (multicodec: 0x1201)
  - P-521 (multicodec: 0x1202)
  - RSA (multicodec: 0x1205)
  - **jwk_jcs-pub** (multicodec: 0xeb51) - EBSI/JCS encoded JWK format

- **did:jwk** - DIDs with base64url-encoded JWK
  - Supports EC (P-256, P-384, P-521, secp256k1)
  - Supports OKP (Ed25519, X25519)
  - Supports RSA
