# Changelog

## [Unreleased]
### Features
* SSH public key recipients through key shares (ECDSA P-256 keys only). New recipient type `RUHNU`
  with `recipient_id` `ruhnu/pk/<base64 OpenSSH public key blob>`:
  * encrypt with `EncryptionKeyMaterial.fromSshPublicKey(line, shareLifetime)` or
    `fromSshPublicKeyFile(path, shareLifetime)`; the optional lifetime is sent as `x-expiry-time`
  * decrypt with `DecryptionKeyMaterial.fromSshAgentKey(recipientId)`: the auth token (SD-JWT,
    ES256) is signed by ssh-agent (`$SSH_AUTH_SOCK`), no auth server, RP server or session token
  * `SshAgentClient` and `SshAgentJWSSigner` (ssh-agent over Unix domain socket)
* Key shares recipient type is now read from the container (was always Smart-ID/Mobile-ID)
* Key shares client: session headers optional (key-shares API 1.4.0-draft),
  `KeySharesClient.storeKeyShare(KeyShare, OffsetDateTime)` requests an expiry time

### Maven package versions:
```
cdoc2-schema 2.2.0-SNAPSHOT
cdoc2-lib 3.8.0-SNAPSHOT
cdoc2-client 2.4.0-SNAPSHOT
cdoc2-cli 1.10.0-SNAPSHOT
```

## [3.5.2]
### Improvements
* Directory accessibility check operates correctly on multiple platforms
* Update to auth-server and rp-server Openapi interfaces

### Maven package versions:
```
cdoc2 3.5.1
cdoc2-schema 2.1.0
cdoc2-lib 3.7.3
cdoc2-client 2.3.2
cdoc2-cli 1.9.4
```

## [3.5.1]
### Improvements
* Add additional check to make sure the decrypted file can fit on the disc.
* Improved error messages for encryption and decryption
* Changed the rules for password encryption to match the rules in the CDOC2 documentation
* New configuration options for client polling behavior:
  * `rp-server.client.polling.intervalMs` - default 1000
  * `rp-server.client.polling.maxCount` - default 0, meaning indefinite polling until COMPLETE
    status or network error
* Increased all default client read and connect timeouts to 5000ms
* Improved feedback when auth process does not complete successfully
* New command line option `--truncate-display-text`. When specified, display text will be 
  automatically truncated to SID/MID maximum allowed length. No truncation is performed by default.

### Bug Fixes
* Fix bug with disk size checks, when path/partiton doesn't exist
* Add correct cli and lib version to be returned with the cli `--version` command.

### Maven package versions:
```
cdoc2 3.5.1
cdoc2-schema 2.1.0
cdoc2-lib 3.7.2
cdoc2-client 2.3.1
cdoc2-cli 1.9.3
```

## [3.5.0]
### Improvements
* Updated auth-server openapi version
* Updated cdoc2-auth-token
* Refactored API clients for Auth and RP APIs to match general pattern - Cdoc2AuthApiClient and 
  Cdoc2RpApiClient are now available in cdoc2-client module
* New configuration options for client timeouts:
  * `auth-server.client.read-timeout` - default 2000
  * `auth-server.client.connect-timeout` - default 1000
  * `rp-server.client.read-timeout` - default 2000
  * `rp-server.client.connect-timeout` - default 1000
  * `key-shares.client.read-timeout` - default 2000
  * `key-shares.client.connect-timeout` - default 1000
* New configuration options for client polling behavior: 
  * `auth-server.client.polling.intervalMs` - default 1000
  * `auth-server.client.polling.maxCount` - default 0, meaning indefinite polling until COMPLETE 
    status or network error
* Changed default read timeouts for all API clients from 500ms to 2000ms
* Code cleanup

### Bug Fixes
* Fixed issue where capsule and shares server client read and connect timeouts were never applied

### Maven package versions:
```
cdoc2 3.5.0
cdoc2-schema 2.1.0
cdoc2-lib 3.7.1
cdoc2-client 2.3.0
cdoc2-cli 1.9.2
```

## [3.4.3]
### Improvements
* Added command line options to allow specifying the interaction language and display text for 
  SID/MID decryption. The provided display text is shown on the user's device when creating 
  authentication tokens for decryption. Display text for session token creation is controlled by 
  auth-server.
  * `-l`, `--interaction-language`
  * `-dt`, `--display-text`
* Command line parameters that are converted to enums are now case-insensitive:
  * `"-c", "--crypto-stick"`
  * `"-l", "--interaction-language"`
* Updated rp-server openapi version

### Bug Fixes
* Fix TarDeflate.checkAvailableDiskSpace available disc space calculation.

### Maven package versions:
```
cdoc2 3.4.3
cdoc2-schema 2.1.0
cdoc2-lib 3.7.0
cdoc2-client 2.2.5
cdoc2-cli 1.9.2
```

## [3.4.2]

### Improvements
* Add attentional unit tests.
* New optional constructor for Cdoc2AuthClient with configurable read timeout.
* Updated openapi versions for cdoc2-client

### Bug Fixes
* For password based decryption, use the kdf_iterations from the capsule instead of hardcoded value.
* xExpiryTime header added to createKeyShare method of Cdoc2KeySharesApiClient
* Fix invalid parameter name in DirectPKCS11Wrapper
* Throw CDocParseException instead of IllegalArgumentException when RecipientRecord.keyLabel contains corrupt CDOC2 header

### Maven package versions:
```
cdoc2 3.4.2
cdoc2-schema 2.1.0
cdoc2-lib 3.6.2
cdoc2-client 2.2.4
cdoc2-cli 1.9.1
```

## [3.4.1] 

### Improvements
* Improve re-encryption error messages
* Improve error messages for missing services needed for SID/MID
* Improve decryption time
* Remove unused properties from rp-server configuration
* Improve error messages for encryption and decryption with SiD/MiD

### Maven package versions:
```
cdoc2 3.4.1
cdoc2-schema 2.1.0
cdoc2-lib 3.6.1
cdoc2-client 2.2.3
cdoc2-cli 1.9.1
```

## [3.4.0]

### Improvements
* Support for legacy MID accounts with RSA certificates

### Maven package versions:
```
cdoc2 3.4.0
cdoc2-schema 2.1.0
cdoc2-lib 3.6.0
cdoc2-client 2.2.2
cdoc2-cli 1.9.0
```

## [3.3.0] Updates for Mobile-ID (2026-05-18)

### Bug Fixes
* Fix file not being deleted if the decryption fails on windows

### Internal
* MID interaction changed to use Cdoc2RpClient, MobileIdClient removed
* HTTP signatures from rp-server forwarded to shares server on GET /key-shares/{shareId} requests

### Maven package versions:
```
cdoc2 3.3.0
cdoc2-schema 2.1.0
cdoc2-lib 3.5.0
cdoc2-client 2.2.2
cdoc2-cli 1.9.0
```

## [3.2.0] Support for updated Smart-ID usage (2026-04-29)

### Internal
* Created new client Cdoc2AuthClient for the cdoc2 authentication server.
* Created new client Cdoc2RpClient for cdoc2 rp server
* SID interaction changed to use Cdoc2RpClient, SmartIdClient removed
* Auth token signature implementation in SIDAuthJWSSigner changed to use SID RPv3 protocol.
* Session token creation and usage
* Auth token certificate header `x-cdoc2-auth-x5c` format changed from single-line PEM with header 
  and footer to Base64Url-encoded DER

### Maven package versions:
```
cdoc2 3.2.0
cdoc2-schema 2.1.0
cdoc2-lib 3.4.0
cdoc2-client 2.2.1
cdoc2-cli 1.9.0
```

## [3.1.2] Adding support for `secp521r1` elliptic curve (2026-03-06)

### Features
* Implement support for `secp521r1` elliptic curve.

### Bug Fixes
* Fixed a bug causing key alias to be ignored for RSA crypto sticks
* Add support for Zetes LDAP

### Maven package versions:
```
cdoc2 3.1.2
cdoc2-schema 2.1.0
cdoc2-lib 3.3.0
cdoc2-client 2.1.0
cdoc2-cli 1.9.0
```

## [3.1.1] Bug fixes (2026-03-02)
* Fixed a bug causing the DirectPKCS11Wrapper to fail on Windows.
* Do not require application.properties for offline RSA decryption.

## [3.1.0] Adding support for RSA based crypto sticks (2026-01-30)

### Features
* Implement support for RSA based crypto sticks.

### Bug Fixes
* Add the `--crypto-stick` option to the cdoc2-cli commands `list` and `re-encrypt`.

### Internal
* Improve the cdoc2-cli [README.md](cdoc2-cli/README.md).
* Add attentional unit tests to cdoc2-cli for `secp256r1` elliptic curve support.
* Add bats tests for `secp256r1` elliptic curve support.
* Upgraded Spring boot 3.3.3 -> 4.0.1 + other third-party dependency updates.
* Censor the file name in the logs.

### Maven package versions:
```
cdoc2 2.0.0
cdoc2-schema 2.0.0
cdoc2-lib 3.2.1
cdoc2-client 2.0.1
cdoc2-cli 1.8.0
```

## [3.0.0] Adding support for `secp256r1` elliptic curves (2025-12-01)

### Features

* Implement support for `secp256r1` elliptic curves, used by crypto sticks.

### Maven package versions:
```
cdoc2 2.0.0
cdoc2-schema 2.0.0
cdoc2-lib 3.1.0
cdoc2-client 2.0.0
cdoc2-cli 1.7.0
```

## [2.0.1] Use .cdoc2 for file extension (2025-XX-XX)

### Internal
* Change all mentions of `cdoc` file extension to `cdoc2` in README-s, `cdoc2-cli` commands 
  description and bats tests.
* Change `cdoc2-lib` version to 3.0.1-SNAPSHOT.


## [2.0.0] Version update (2025-02-26)

### Maven package versions:
```
cdoc2 2.0.0
cdoc2-schema 1.4.0
cdoc2-lib 3.0.0
cdoc2-client 2.0.0
cdoc2-cli 1.6.0
```

## [2.0.0-RC] Support for Smart-ID and Mobile-ID

### Features

* CDOC2 encryption/decryption with symmetric key from/to N-of-N shares (Smart-ID/Mobile-ID)

### Internal

* cdoc2-cli bats tests for Smart-ID/Mobile-ID using SK test env and `docker compose`

### Maven package versions:
```
cdoc2 2.0.0-SNAPSHOT
cdoc2-schema 1.4.0-SNAPSHOT
cdoc2-lib 3.0.0-SNAPSHOT
cdoc2-client 2.0.0-SNAPSHOT
cdoc2-cli 1.6.0-SNAPSHOT
```

## [1.4.1] Bug fixes, documentation, tests improvements (2024-09-19)

### Bug Fixes
* Fix `cdoc2-cli decrypt` crash, when using server scenario
* Fix Junit tests on Windows
* Fix pkcs11 (smart-card) test properties loading from filesystem  

### Internal
* Added [cdoc2-lib Usage Guide](cdoc2-lib/README.md)
* cdoc2-cli bats tests for server scenario (using docker compose)
* Update cdoc2-example-app to use `cdoc2-lib:2.0.0`

## [1.4.0] Key label formatting (2024-09-02)

### Features

* Support for [machine-readable KeyLabel format](https://open-eid.github.io/CDOC2/1.1/02_protocol_and_cryptography_spec/appendix_d_keylabel/)
  - When encrypting, then this formatted key label is enabled by default. Can be disabled by setting `ee.cyber.cdoc2.key-label.machine-readable-format.enabled=false` system property (`-D`)
  - When decrypting, then both formatted and unformatted key label field versions are supported.

### Bug Fixes

* Fix cdoc2-cli encrypting functionality for SymmetricKey (`--secret` parameter). Bug was introduced with 1.1.0 release
  - Rewrote symmetric key (secret) and password handling in cdoc2-cli/cdoc2-lib
  - Bumped cdoc2-lib major version to `2.0.0`, as broken classes (`FormattedOptionParts`) were removed and replaced with a new ones (`LabeledPassword` and `LabeledSecret`)
  - cdoc2-lib was not broken, when using `EncryptionKeyMaterial#fromSecret(SecretKey,String)` directly (without `FormattedOptionParts`)
  - broken example cdoc2 files were removed from `test/testvectors` and replaced with a correct ones
* Fix cdoc2-client ApiClient timeouts (`cdoc2.client.server.*-timeout` were not working)
* Allow loading [pkcs11 (smart-card) test properties](README.md#pkcs11-tests) from file system (previously only classpath was working)

### Internal

* Third-party dependency updates to latest
* Added GitHub workflows for building and releasing
* Resolve issues reported by SonarCloud/SonarQube
* Update client and server certificates used for unit-tests. Add scripts for future updates

## [1.3.0] '/key-capsules' OAS v2.1.0 support (2024-07-02)

### Features

* Support for '/key-capsules' OAS v2.1.0 in cdoc2-client and cdoc2-cli (added `-exp`  option)
* cli: Improvements to interactive password asking (Don't ask password twice for decrypt).
  Label is not required, when CDOC2 file contains single password recipient.
* Add example project to demonstrate usage of cdoc2-java-ref-impl with cdoc4j (convert cdoc -> cdoc2)

## [1.2.0] Repository split and maintenance (2024-05-30)

### Features

* Expose Prometheus metrics endpoint for servers

### Internal

* Split repository into cdoc2-java-ref-impl and cdoc2-capsule-server
* Upgraded Spring 2.7.5 -> 3.2.5 + other third-party dependency updates
* Use 'cdoc2' instead of 'cdoc20' everywhere (packages, documents etc). Salt strings remain unchanged (cdoc20kek, cdoc20cek and so)
* Fix jacoco test coverage reports (broken previously)
* Add gitlab CI build files
* Added scripts for making releases and managing versions (see VERSIONS.md)
* Refactoring required to build cdoc2-capsule-server repo without cdoc2-lib dependency (cdoc2-lib dependency is still needed for running tests )
* Upload/consume cdoc2-key-capsule-openapi.yaml as maven artifact
* Added bats tests to check backward compatibility of CDOC2 format with previous releases

### Bugfixes

* With rename cdoc20-cdoc2 salts values were also incorrectly changed. Broke backward compatibility. Fixed before release 1.2.0


## [1.1.0] Version update (2024-03-26)

### Features

* Added possibility to encrypt and decrypt CDOC2 container with password.
* Removed an option for Symmetric Key creation from plain text, left only Base64 encoded format.
* Added CDOC2 container re-encryption functionality for long-term cryptography.
* Added Bats tests automatic installation.

### Bug Fixes

* Fixed CDOC2 container decryption failure with few files inside.


## [1.0.0] Version update (2024-01-23)
No changes, only version update in all components.


## [0.5.0] Jenkins pipeline updates (2023-01-31)

### Features

* Added Jenkins pipeline for uploading CDOC2 jar artifacts to RIA Nexus repository
* Update and run key server instances also on cdoc2-keyserver-02.dev.riaint.ee host


## [0.4.0] ChaCha Poly1305 MAC is checked before other errors are reported (2023-01-30)

### Features

* Rewrite tar processing/ChaCha decryption so that Poly1305 MAC is always checked (even when zlib/tar processing errors happen)
* Added sample CDOC2 containers with keys and configuration files
* Added Unicode Right-To-Left Override (U+202E) to forbidden characters

### Bug Fixes

* Incomplete CDOC container file is removed, when creation of CDOC container fails
* Remove keyserver secrets logging from CLI debug log


## [0.3.0] (2023-01-23)

### Features

* client authenticate certificate revocation checks (OCSP) for get-server
* enable monitoring endpoints, see cdoc2-server/admin-guide.md
* only tls v1.3 is supported by servers
* remove deprecated ecc-details API
* gatling-tests updates

### Bug Fixes
* constraint violation in OpenAPI spec are reported as http 400 (previously http 500)


## [0.2.0] User error codes (2022-12-16)

### Features
* Add error codes for common user errors
* Gatling test updates

## [0.1.0] Enable Posix extensions for tar (2022-12-12)
Switch to semantic versioning

### Features
* Enable POSIX (PAX) extension for tar:
  * support long filenames (over 100 bytes)
  * support big file sizes (over 8GB)
  * always use utf-8 in filenames (even, when platform default is not utf-8)
* Synchronize flatbuffers schema files with Specification v0.7 

## [0.0.13] Symmetric Key support (long term crypto) (2022-12-07)

### Features
* Symmetric Key scenario implementation
* Added `cdoc info` cli command that lists recipients in CDOC header

## [0.0.12] RSA-OAEP server scenario (2022-11-25)

### Features
* RSA-OAEP server scenario implementation
* Client uses cdoc2-key-capsules API to create/download key capsules
* Server configuration changes for client (single configuration file for create and decrypt `--server` configuration)
* E-Resident certificate support (find e-resident certificate from SK LDAP)
* Basic filename validation in container (illegal symbols and filenames)
* CLI supports certificate and private key loading from .p12 file (PKCS12)

### Bug Fixes
* `cdoc list` command supports `--server` option

## [0.0.11] RsaPublicKey  (2022-11-21)

### Bug Fixes
* Use RsaPublicKey encoding (RFC8017 RSA Public Key Syntax (A.1.1)) instead of X.509 (Java default encoding)

## [0.0.10] Key server RSA support (2022-11-14)

### Features
* Added support for RSA keys in key server
* Added support for 2 key server instances when using cdoc2-cli
* Added key server administration manual

## [0.0.9] RSA-OAEP support (2022-11-02)

### Features
* Support for creating and decrypting CDOC2 documents with RSA keys
* Improved Recipient.KeyLabel field support in cdoc2-lib (PublicKey used for encryption is paired with keyLabel)
* Removed cdoc2-cli -ZZ hidden feature (disable compression for payload)
* Added additional EC infinity point (X: null, Y: null) checks and tests


## [0.0.8] Two key capsule server instances (2022-10-31)

### Features
* The key server is composed of 2 server instances, each with its own configuration.
* The API for creating key capsules does not require client authentication (mTLS).

## [0.0.7] Minimal support for Recipient.KeyLabel field (2022-10-14)

### Features
* Minimal support for Recipient.KeyLabel in FBS header (field is present in FB header, but lib is not filling its value
  with info from recipient certificate)
* Upgrade flatbuffers-java to version 2.0.8
* Move gatling-tests to main branch

## [0.0.6] server scenario implementation (2022-10-11)

### Features

* Key exchange server implementation
* CLI and libary support for key scenario
* Server OpenAPI changes (more strict string format for recipient_pub_key and server_pub_key fields)

## [0.0.5] PKCS11, LDAP and generated sender keys (2022-05-13)

### Features

* Refactor EllipticCurve code so that EC curve is created from certificate or public key. Interface support other EC curves
  besides secp384r1. No actual support for other curves implemented yet.
* Generate sender key pair to for recipient public key. Remove option to use pre-generated sender key pair
* Support for decrypting with private decryption key from PKCS11 (support for id-kaart)
* Support for downloading recipient Esteid certificate from 
  [SK LDAP](https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/)
* Documentation updates
* First version server OpenAPI specification


### Bug Fixes

* Use zlib compression instead of gzip compression
* Delete all files, when decryption fails (last file was not deleted)
* EllipticCurve was incorrectly created from fmkEncryption method not Details.EccPublicKey curve 
  (no actual error as both had same byte value).


## [0.0.4] First release (2022-04-22)

### Features

* Create/decrypt Cdoc2 files with software generated EC keys
