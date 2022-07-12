<!-- 
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages). 

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages). 
-->

[![Build](https://github.com/zxbase/zxbase_crypto/actions/workflows/build.yml/badge.svg)](https://github.com/zxbase/zxbase_crypto/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/zxbase/zxbase_crypto/branch/main/graph/badge.svg?token=5GEZHD3E6W)](https://codecov.io/gh/zxbase/zxbase_crypto)
[![Dependencies](https://github.com/zxbase/zxbase_crypto/actions/workflows/dependencies.yml/badge.svg)](https://github.com/zxbase/zxbase_crypto/actions/workflows/dependencies.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Zxbase crypto helpers.

## Features

* Public key cryptography (Ed25519):
  * Key pair generation.
  * Keys serialization / deserialization.
  * Message signing and verification.

* Random bytes generation:
  * Generate a specified number of cryptographically secure bytes.

* Symmetric key cryptogrpahy:
  * AES GCM 256:
    * Synchronous encryption.
    * Synchronous decryption.

## Getting started
In _pubspec.yaml_:
```yaml
dependencies:
  zxbase_crypto: ^1.0.0
```

## Usage

Check examples in test files:
* test/pk_crypto_test.dart
* test/random_test.dart
* test/sk_crypto_test.dart
