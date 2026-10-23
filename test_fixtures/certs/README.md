# Test Certificates for Code Signing

This directory contains cryptographic test fixtures for developing and testing code signing
support in `swim` (specifically Windows Authenticode signatures on `.msi` packages and binaries).

> [!CAUTION]
> The private keys in this directory are [publicly known test vectors with trivial private scalars][we-have-a-problem].
> They are intended **exclusively for local offline unit testing and development**. Never trust,
> install in Windows certificate stores, or use these certificates in production.

## 1. Inventory

| File | Type | Entity | Algorithm / Curve | Validity |
| :--- | :--- | :--- | :--- | :--- |
| `codesign_ca_g3b_nl.pem` | Intermediate CA | eMudhra BV (NL) | ECDSA `secp384r1` | 2025–2028 |
| `codesign_ca_g3b_nl.key` | CA Private Key | eMudhra BV (NL) | ECDSA `secp384r1` | N/A |
| `codesign_ca_g3c_us.pem` | Intermediate CA | eMudhra Inc (US) | ECDSA `secp384r1` | 2025–2028 |
| `codesign_ca_g3c_us.key` | CA Private Key | eMudhra Inc (US) | ECDSA `secp384r1` | N/A |
| `leaf_g3b_nl.pem` | Leaf Certificate | eMudhra BV (NL) | ECDSA `secp384r1` | 2025–2028 |
| `leaf_g3b_nl.key` | Leaf Private Key | eMudhra BV (NL) | ECDSA `secp384r1` | N/A |
| `leaf_g3c_us.pem` | Leaf Certificate | eMudhra Inc (US) | ECDSA `secp384r1` | 2025–2028 |
| `leaf_g3c_us.key` | Leaf Private Key | eMudhra Inc (US) | ECDSA `secp384r1` | N/A |
| `rsa_codesign.pem` | Self-Signed Cert | Test RSA Corp (US) | RSA 2048-bit | 2026–2126 (100y) |
| `rsa_codesign.key` | Private Key | Test RSA Corp (US) | RSA 2048-bit | N/A |

## 2. Technical Specifications

### `codesign_ca_g3b_nl` (Intermediate CA, Netherlands)

- **Subject:** `CN = EM OV CS CA - G3B, O = eMudhra BV, C = NL`
- **Issuer:** `CN = AAA Certificate Services, O = Comodo CA Limited, C = GB`
- **Serial Number:** `41:e3:2b:73:ac:18:5d:6c:e0:d7:48:0b:ac:f8:4e:69`
- **Validity:** May 14, 2025 to Dec 31, 2028 GMT
- **Key Algorithm:** `id-ecPublicKey` on `secp384r1` (NIST P-384, 384-bit)
- **Basic Constraints:** `critical, CA:TRUE, pathlen:0`
- **Key Usage:** `critical, Certificate Sign, CRL Sign`
- **Extended Key Usage (EKU):** `Code Signing` (`1.3.6.1.5.5.7.3.3`)

### `codesign_ca_g3c_us` (Intermediate CA, United States)

- **Subject:** `CN = EM OV CS CA - G3C, O = eMudhra Inc, C = US`
- **Issuer:** `CN = AAA Certificate Services, O = Comodo CA Limited, C = GB`
- **Serial Number:** `d6:a5:ef:61:3b:39:0f:32:ef:9c:df:34:9f:77:28:41`
- **Validity:** May 14, 2025 to Dec 31, 2028 GMT
- **Key Algorithm:** `id-ecPublicKey` on `secp384r1` (NIST P-384, 384-bit)
- **Basic Constraints:** `critical, CA:TRUE, pathlen:0`
- **Key Usage:** `critical, Certificate Sign, CRL Sign`
- **Extended Key Usage (EKU):** `Code Signing` (`1.3.6.1.5.5.7.3.3`)

### `leaf_g3b_nl` (Leaf Certificate, Mismatch Test Vector)

- **Subject:** `CN = EM OV Code Signing Leaf - G3B, O = eMudhra BV, C = NL`
- **Issuer:** `CN = EM OV CS CA - G3B, O = eMudhra BV, C = NL`
- **Validity:** May 14, 2025 to Dec 31, 2028 GMT (aligned with CA)
- **Key Algorithm:** `id-ecPublicKey` on `secp384r1` (NIST P-384, 384-bit)
- **Basic Constraints:** `critical, CA:FALSE`
- **Key Usage:** `critical, Digital Signature`
- **Extended Key Usage (EKU):** `Code Signing` (`1.3.6.1.5.5.7.3.3`)
- **Role:** Primary negative test fixture to verify `error.CertificateMismatch` when an input
  binary was signed with G3B while the installer is signed with G3C.

### `leaf_g3c_us` (Leaf Certificate, Primary ECDSA Test Vector)

- **Subject:** `CN = EM OV Code Signing Leaf - G3C, O = eMudhra Inc, C = US`
- **Issuer:** `CN = EM OV CS CA - G3C, O = eMudhra Inc, C = US`
- **Validity:** May 14, 2025 to Dec 31, 2028 GMT (aligned with CA)
- **Key Algorithm:** `id-ecPublicKey` on `secp384r1` (NIST P-384, 384-bit)
- **Basic Constraints:** `critical, CA:FALSE`
- **Key Usage:** `critical, Digital Signature`
- **Extended Key Usage (EKU):** `Code Signing` (`1.3.6.1.5.5.7.3.3`)
- **Role:** Primary positive test fixture for end-to-end ECDSA P-384 code signing.

### `rsa_codesign` (Self-Signed RSA Test Vector)

- **Subject:** `CN = Test RSA Code Signing, O = Test RSA Corp, C = US`
- **Issuer:** `CN = Test RSA Code Signing, O = Test RSA Corp, C = US`
- **Validity:** Oct 22, 2026 to Sep 28, 2126 GMT (100-year validity)
- **Key Algorithm:** `rsaEncryption` (2048-bit modulus)
- **Basic Constraints:** `critical, CA:FALSE`
- **Key Usage:** `critical, Digital Signature`
- **Extended Key Usage (EKU):** `Code Signing` (`1.3.6.1.5.5.7.3.3`)
- **Role:** Positive test fixture for RSA PKCS#1 v1.5 code signing.

[we-have-a-problem]: https://emudhra.we-have-a-problem.com
