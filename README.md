[![Build](https://github.com/zxbase/zxbase_crypto/actions/workflows/build.yml/badge.svg)](https://github.com/zxbase/zxbase_crypto/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/zxbase/zxbase_crypto/branch/main/graph/badge.svg?token=5GEZHD3E6W)](https://codecov.io/gh/zxbase/zxbase_crypto)
[![Dependencies](https://github.com/zxbase/zxbase_crypto/actions/workflows/dependencies.yml/badge.svg)](https://github.com/zxbase/zxbase_crypto/actions/workflows/dependencies.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Zxbase crypto helpers.

## Features

- Public key cryptography (Ed25519):
  - Key pair generation.
  - Keys serialization / deserialization.
  - Message signing and verification.

- Random bytes generation:
  - Generate a specified number of cryptographically secure bytes.

- Symmetric key cryptography:
  - AES GCM 256:
    - Synchronous encryption.
    - Synchronous decryption.

- Password helpers:
  - Derivation of a key with Argon2.
  - Password generation.
  - Password checks.

- Hash:
  - SHA3 256 hash.

- Hashcash:
  - Challenge.
  - Verification.

## Getting started
In _pubspec.yaml_:
```yaml
dependencies:
  zxbase_crypto: ^3.0.0
```

In your code:
```
import 'package:zxbase_crypto/zxbase_crypto.dart';
```

## Usage

Check examples in test files:
  - test/hash_test.dart  
  - test/hashcash_test.dart  
  - test/password_test.dart
  - test/pk_crypto_test.dart
  - test/random_test.dart
  - test/sk_crypto_test.dart
