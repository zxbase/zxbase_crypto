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

import 'package:test/test.dart';
import 'package:zxbase_crypto/zxbase_crypto.dart';

void main() {
  test('Check jwk format', () async {
    expect(() => PKCrypto.jwkToPublicKey({'kty': 'OKT'}),
        throwsA(isA<FormatException>()));
  });

  test('Generate 2 different Ed25519 keys', () async {
    final SimpleKeyPair keyPair1 = await PKCrypto.generateKeyPair();
    final SimpleKeyPair keyPair2 = await PKCrypto.generateKeyPair();

    expect(keyPair1.extractPrivateKeyBytes(),
        isNot(keyPair2.extractPrivateKeyBytes()));
    expect(keyPair1.extractPublicKey(), isNot(keyPair2.extractPublicKey()));
  });

  test('Serialize and deserialize public key', () async {
    // generate key pair, extact public key, serialize, deserialize
    final SimpleKeyPair keyPair = await PKCrypto.generateKeyPair();
    final SimplePublicKey publicKey = await keyPair.extractPublicKey();

    final json = PKCrypto.publicKeyToJwk(publicKey);
    expect(json['kty'], equals('OKP'));
    expect(json['crv'], equals('Ed25519'));

    final deserializedPublicKey = PKCrypto.jwkToPublicKey(json);
    expect(deserializedPublicKey.bytes, isNot(null));
  });

  test('Deserialize and serialize public key', () {
    final json = {
      'kty': 'OKP',
      'crv': 'Ed25519',
      // padding is required
      'x': 'km6x_mSpVZA0hOuRtun3RoMXRhqfHesRuoBfZbZ2J7E'
    };
    final SimplePublicKey publicKey = PKCrypto.jwkToPublicKey(json);
    final serializedPublicKey = PKCrypto.publicKeyToJwk(publicKey);
    expect(serializedPublicKey['x'],
        equals('km6x_mSpVZA0hOuRtun3RoMXRhqfHesRuoBfZbZ2J7E='));
  });

  test('Serialize and deserialize key pair', () async {
    // generate key pair, sign, serialize, deserialize, verify
    final msg = 'xxx';
    final SimpleKeyPair keyPair = await PKCrypto.generateKeyPair();
    final sig = await PKCrypto.sign(msg, keyPair);

    final json = await PKCrypto.keyPairToJwk(keyPair);
    final deserializedKeyPair = await PKCrypto.jwkToKeyPair(json);
    expect(await PKCrypto.verifySignature(msg, sig, deserializedKeyPair),
        equals(true));
  });

  test('Sign and verify message', () async {
    final SimpleKeyPair keyPair = await PKCrypto.generateKeyPair();
    final msg = 'xxx';
    final sig = await PKCrypto.sign(msg, keyPair);
    final rv = await PKCrypto.verifySignature(msg, sig, keyPair);
    expect(rv, equals(true));
  });
}
