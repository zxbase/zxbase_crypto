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

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:zxbase_crypto/zxbase_crypto.dart';

void main() {
  final clear = Uint8List.fromList([
    250,
    220,
    60,
    167,
    31,
    62,
    24,
    197,
    175,
    211,
    93,
    57,
    197,
    100,
    117,
    147,
    159,
    195,
    35,
    157,
    47,
    214,
    223,
    152,
    180,
    162,
    135,
    235,
    123,
    152,
    126,
    132,
  ]);

  test('Decrypt', () {
    final key = Uint8List.fromList([
      187,
      45,
      197,
      76,
      195,
      218,
      149,
      182,
      131,
      81,
      102,
      113,
      31,
      163,
      45,
      170,
      119,
      96,
      32,
      3,
      171,
      180,
      194,
      106,
      108,
      210,
      172,
      253,
      42,
      37,
      188,
      98,
    ]);
    final iv = Uint8List.fromList([
      211,
      33,
      139,
      203,
      28,
      220,
      247,
      22,
      68,
      1,
      87,
      85,
    ]);
    final enc = Uint8List.fromList([
      224,
      21,
      206,
      161,
      93,
      216,
      255,
      196,
      56,
      253,
      193,
      61,
      223,
      121,
      128,
      186,
      23,
      25,
      152,
      95,
      179,
      98,
      153,
      127,
      140,
      57,
      44,
      198,
      116,
      213,
      247,
      156,
      29,
      217,
      155,
      71,
      94,
      38,
      214,
      47,
      254,
      23,
      38,
      215,
      86,
      95,
      9,
      186,
    ]);

    final dec = SKCrypto.decryptSync(iv: iv, buffer: enc, key: key);
    expect(clear, equals(dec));
  });

  test('Generate 256 bits keys', () {
    final key1 = SKCrypto.generate256BitKey();
    final key2 = SKCrypto.generate256BitKey();

    expect(key1.length, SKCrypto.keyByteSize);
    expect(key2.length, SKCrypto.keyByteSize);
    expect(key1, isNot(key2));
  });

  test('Encrypt and decrypt AES GCM 256', () {
    final key = SKCrypto.generate256BitKey();

    IVData enc = SKCrypto.encryptSync(buffer: clear, key: key);
    final dec = SKCrypto.decryptSync(iv: enc.iv, buffer: enc.data, key: key);

    expect(dec, equals(clear));
  });
}
