// Copyright (C) 2022 Zxbase, LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Public key cryptography Ed25519 helpers:
//   * Generation.
//   * Serialization / deserialization.
//   * Signing and verification.

import 'dart:convert';
import 'package:cryptography/cryptography.dart';

class PKCrypto {
  static final _algorithm = Ed25519();

  static void _checkEd25519Jwk(Map<String, dynamic> json) {
    if (!(json['crv'] == 'Ed25519' && json['kty'] == 'OKP')) {
      throw FormatException('Key type is not supported $json');
    }
  }

  static String _padBase64(String str) {
    if (str.length % 4 > 0) {
      int pad = str.length % 4;
      str += '=' * (4 - pad);
    }
    return str;
  }

  /// Generation.

  static Future<SimpleKeyPair> generateKeyPair() async {
    return await _algorithm.newKeyPair();
  }

  /// Serialization / deserialization.

  static Map<String, dynamic> publicKeyToJwk(SimplePublicKey publicKey) {
    // Ed25519 raw key is 32 bits.
    return {
      'kty': 'OKP',
      'crv': 'Ed25519',
      'x': base64Url.encode(publicKey.bytes),
    };
  }

  static SimplePublicKey jwkToPublicKey(Map<String, dynamic> json) {
    _checkEd25519Jwk(json);
    final strKey = _padBase64(json['x']);
    final binaryKey = base64Url.decode(strKey);
    return SimplePublicKey(binaryKey, type: KeyPairType.ed25519);
  }

  static Future<Map<String, dynamic>> keyPairToJwk(
    SimpleKeyPair keyPair,
  ) async {
    final bytes = await keyPair.extractPrivateKeyBytes();
    return {'kty': 'OKP', 'crv': 'Ed25519', 'x': base64Url.encode(bytes)};
  }

  static Future<SimpleKeyPair> jwkToKeyPair(Map<String, dynamic> json) async {
    _checkEd25519Jwk(json);
    final strKey = _padBase64(json['x']);
    final binaryKey = base64Url.decode(strKey);
    return await _algorithm.newKeyPairFromSeed(binaryKey);
  }

  /// Signing and verification.

  static Future<String> sign(String msg, SimpleKeyPair keyPair) async {
    final sig = await _algorithm.sign(utf8.encode(msg), keyPair: keyPair);
    return base64Url.encode(sig.bytes);
  }

  static Future<bool> verifySignatureWithPublicKey(
    String msg,
    String sig,
    SimplePublicKey publicKey,
  ) async {
    final signature = Signature(base64Url.decode(sig), publicKey: publicKey);
    return await _algorithm.verify(utf8.encode(msg), signature: signature);
  }

  static Future<bool> verifySignature(
    String msg,
    String sig,
    SimpleKeyPair keyPair,
  ) async {
    final pubKey = await keyPair.extractPublicKey();
    return await verifySignatureWithPublicKey(msg, sig, pubKey);
  }
}
