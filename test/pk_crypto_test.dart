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

import 'package:zxbase_crypto/pk_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('Check jwk format', () async {
    expect(
        () => jwkToPublicKey({'kty': 'OKT'}), throwsA(isA<FormatException>()));
  });

  test('Generate 2 different Ed25519 keys', () async {
    var keyPair1 = await generateKeyPair();
    var keyPair2 = await generateKeyPair();

    expect(keyPair1.extractPrivateKeyBytes(),
        isNot(keyPair2.extractPrivateKeyBytes()));
    expect(keyPair1.extractPublicKey(), isNot(keyPair2.extractPublicKey()));
  });

  test('Serialize and deserialize public key', () async {
    // generate key pair, extact public key, serialize, deserialize
    var keyPair = await generateKeyPair();
    var publicKey = await keyPair.extractPublicKey();

    var json = publicKeyToJwk(publicKey);
    expect(json['kty'], equals('OKP'));
    expect(json['crv'], equals('Ed25519'));

    var deserializedPublicKey = jwkToPublicKey(json);
    expect(deserializedPublicKey.bytes, isNot(null));
  });

  test('Deserialize and serialize public key', () {
    var json = {
      'kty': 'OKP',
      'crv': 'Ed25519',
      // padding is required
      'x': 'km6x_mSpVZA0hOuRtun3RoMXRhqfHesRuoBfZbZ2J7E'
    };
    var publicKey = jwkToPublicKey(json);
    var serializedPublicKey = publicKeyToJwk(publicKey);
    expect(serializedPublicKey['x'],
        equals('km6x_mSpVZA0hOuRtun3RoMXRhqfHesRuoBfZbZ2J7E='));
  });

  test('Serialize and deserialize key pair', () async {
    // generate key pair, sign, serialize, deserialize, verify
    var msg = 'xxx';
    var keyPair = await generateKeyPair();
    var sig = await sign(msg, keyPair);

    var json = await keyPairToJwk(keyPair);
    var deserializedKeyPair = await jwkToKeyPair(json);
    expect(await verifySignature(msg, sig, deserializedKeyPair), equals(true));
  });

  test('Sign and verify message', () async {
    var keyPair = await generateKeyPair();
    var msg = 'xxx';
    var sig = await sign(msg, keyPair);
    var rv = await verifySignature(msg, sig, keyPair);
    expect(rv, equals(true));
  });
}
