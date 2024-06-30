## 3.1.6

- Upgrade lints to 4.0.0

## 3.1.5

- Upgrade SDK and update cryptography to 2.7.0.

## 3.1.4

- Switch to Dart 3.

## 3.1.3

- Introduce stricter linter rules.

## 3.1.2

- Re-export simple key pair eliminating future imports of cryptography package.
- Re-export simple public key eliminating future imports of cryptography package.

## 3.1.1

- Set library name, move lib files to lib/src.

## 3.1.0

- Hashcash:
  - Challenge.
  - Verification.

## 3.0.0

- Namespaces:
  - IV Data.
  - Symmetric key crypto.
  - Public key crypto.
  - Hash.
  - Password.

## 2.1.0

- Hash:
  - SHA3 256 hash.

## 2.0.0

- Password helpers:
  - Derivation of a key with Argon2.
  - Password generation.
  - Password checks.

## 1.2.0

- Symmetric key cryptography:
  - AES GCM 256:
    - Synchronous encryption.
    - Synchronous decryption.

## 1.1.0

- Random bytes generation:
  - Generate a specified number of cryptographically secure bytes.

## 1.0.0

- Public key cryptography (Ed25519):
  - Key pair generation.
  - Keys serialization / deserialization.
  - Message signing and verification.
