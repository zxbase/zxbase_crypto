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

/// Password helpers:
///   * Derivation of a key with Argon2.
///   * Password generation.
///   * Password checks.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:zxbase_crypto/random.dart';
import 'package:zxbase_crypto/sk_crypto.dart';

const saltBytesSize = 16;

class PasswordComponent {
  static const specialChars = '#?!@\$%^&*-';
  static const lowerCase = 'abcdefghijklmnopqrstuvwxyz';
  static const upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  static const numbers = '0123456789';
  static const minLength = 8;

  static Uint8List specialCharsBuf =
      Uint8List.fromList(utf8.encode(specialChars));
  static Uint8List lowerCaseBuf = Uint8List.fromList(utf8.encode(lowerCase));
  static Uint8List upperCaseBuf = Uint8List.fromList(utf8.encode(upperCase));
  static Uint8List numbersBuf = Uint8List.fromList(utf8.encode(numbers));
}

/// Password checks:
///   * upper and lower case characters present
///   * number and special character present
///   * password contains upper and lower case characters,
///     numbers and special character present,
///     length is between 8 and 32,
class PasswordCheck {
  static final upperLowerCaseRE = RegExp(r'^(?=.*[a-z])(?=.*[A-Z])');
  static final numberSpecialRE = RegExp(r'^(?=.*\d)(?=.*[#?!@$%^&*-])');
  static final okRE =
      RegExp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#?!@$%^&*-]).{8,32}$');
}

/// Generate 128-bits salt.
Uint8List generateSalt() {
  return generateRandomBytes(saltBytesSize);
}

/// Derive 256-bit key from the password string and 128-bit salt using Argon2i.
Uint8List derive256BitsKey({required String pwd, required Uint8List salt}) {
  final passwordBytes = Uint8List.fromList(utf8.encode(pwd));

  final generator = Argon2BytesGenerator()
    ..init(Argon2Parameters(
      Argon2Parameters.ARGON2_i,
      salt,
      desiredKeyLength: keyBytesSize,
      version: Argon2Parameters.ARGON2_VERSION_13,
      iterations: 2,
      memoryPowerOf2: 16,
    ));

  return generator.process(passwordBytes);
}

/// Generate password.
String generatePassword(
    {bool lowerCase = true,
    bool upperCase = true,
    bool numbers = true,
    bool special = true,
    int length = 10}) {
  if (length < PasswordComponent.minLength) {
    throw Exception('Insufficient password length $length');
  }

  final buf = Uint8List(length);
  List<int> allBuf = [];

  int randomIndex;
  int i = 0;

  if (lowerCase) {
    randomIndex =
        Random.secure().nextInt(PasswordComponent.lowerCaseBuf.length);
    buf[i] = PasswordComponent.lowerCaseBuf[randomIndex];
    i++;
    allBuf.addAll(PasswordComponent.lowerCaseBuf);
  }

  if (upperCase) {
    randomIndex =
        Random.secure().nextInt(PasswordComponent.upperCaseBuf.length);
    buf[i] = PasswordComponent.upperCaseBuf[randomIndex];
    i++;
    allBuf.addAll(PasswordComponent.upperCaseBuf);
  }

  if (numbers) {
    randomIndex = Random.secure().nextInt(PasswordComponent.numbersBuf.length);
    buf[i] = PasswordComponent.numbersBuf[randomIndex];
    i++;
    allBuf.addAll(PasswordComponent.numbersBuf);
  }

  if (special) {
    randomIndex =
        Random.secure().nextInt(PasswordComponent.specialCharsBuf.length);
    buf[i] = PasswordComponent.specialCharsBuf[randomIndex];
    i++;
    allBuf.addAll(PasswordComponent.specialCharsBuf);
  }

  while (i < length) {
    randomIndex = Random.secure().nextInt(allBuf.length);
    buf[i] = allBuf[randomIndex];
    i++;
  }

  return utf8.decode(buf);
}
