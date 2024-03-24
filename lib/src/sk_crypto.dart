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

// Symmetric key cryptography helpers.
// Synchronous AES GCM 256 functionality.

import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:zxbase_crypto/src/iv_data.dart';
import 'package:zxbase_crypto/src/random.dart';

class SKCrypto {
  static const ivByteSize = 12;
  static const keyByteSize = 32;
  static const macBitSize = 128;

  static IVData encryptSync(
      {required Uint8List buffer, required Uint8List key}) {
    final iv = generateRandomBytes(ivByteSize);

    final aesCipher = GCMBlockCipher(AESEngine())
      ..init(
          true,
          AEADParameters(
              KeyParameter(key), macBitSize, iv, Uint8List.fromList([])));

    return IVData(iv: iv, data: aesCipher.process(buffer));
  }

  static Uint8List decryptSync(
      {required Uint8List iv,
      required Uint8List buffer,
      required Uint8List key}) {
    final aesCipher = GCMBlockCipher(AESEngine())
      ..init(
          false,
          AEADParameters(
              KeyParameter(key), macBitSize, iv, Uint8List.fromList([])));

    return aesCipher.process(buffer);
  }

  static Uint8List generate256BitKey() {
    return generateRandomBytes(keyByteSize);
  }
}
