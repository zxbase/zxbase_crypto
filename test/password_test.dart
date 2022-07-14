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
import 'package:zxbase_crypto/zxbase_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('Generate salts', () {
    final salt1 = generateSalt();
    final salt2 = generateSalt();

    expect(salt1.length, saltBytesSize);
    expect(salt2.length, saltBytesSize);
    expect(salt1, isNot(salt2));
  });

  test('Derived key length', () {
    final salt = generateSalt();
    final pwd = 'password';
    final derivedPwd = derive256BitsKey(pwd: pwd, salt: salt);

    expect(derivedPwd.length, equals(SKCrypto.keyByteSize));
  });

  test('Derive same keys with the same password and the same salt', () {
    final salt = generateSalt();
    final pwd = 'password1';
    final pwd2 = 'password1';

    final derivedPwd1 = derive256BitsKey(pwd: pwd, salt: salt);
    final derivedPwd2 = derive256BitsKey(pwd: pwd2, salt: salt);

    expect(derivedPwd1, equals(derivedPwd2));
  });

  test('Derive different keys with the same password but different salts', () {
    final salt1 = generateSalt();
    final salt2 = generateSalt();

    final pwd = 'password';
    final pwd2 = 'password';

    final derivedPwd1 = derive256BitsKey(pwd: pwd, salt: salt1);
    final derivedPwd2 = derive256BitsKey(pwd: pwd2, salt: salt2);

    expect(derivedPwd1, isNot(derivedPwd2));
  });

  test('Derive different keys with different passwords', () {
    final salt1 = generateSalt();
    final salt2 = generateSalt();

    final pwd = 'password';
    final pwd2 = 'password1';

    final derivedPwd1 = derive256BitsKey(pwd: pwd, salt: salt1);
    final derivedPwd2 = derive256BitsKey(pwd: pwd2, salt: salt2);

    expect(derivedPwd1.length, equals(SKCrypto.keyByteSize));
    expect(derivedPwd2.length, equals(SKCrypto.keyByteSize));

    expect(derivedPwd1, isNot(derivedPwd2));
  });

  test('Determenistic password derivation', () {
    final salt = Uint8List.fromList(
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    final pwd = 'password';

    final derivedPwd = derive256BitsKey(pwd: pwd, salt: salt);

    final expectedPwd = Uint8List.fromList([
      10,
      181,
      215,
      245,
      132,
      244,
      170,
      172,
      43,
      124,
      9,
      229,
      3,
      161,
      241,
      143,
      42,
      34,
      68,
      156,
      167,
      137,
      212,
      102,
      82,
      188,
      24,
      52,
      65,
      15,
      80,
      27
    ]);

    expect(derivedPwd, equals(expectedPwd));
  });

  test('Generate password with all components', () async {
    final pwd = generatePassword();
    expect(PasswordCheck.okRE.hasMatch(pwd), equals(true));
  });

  test('Generate password no lower case', () async {
    final pwd = generatePassword(length: 11, lowerCase: false);
    expect(pwd.length, equals(11));
    expect(PasswordCheck.okRE.hasMatch(pwd), equals(false));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pwd), equals(true));
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pwd), equals(false));
  });

  test('Generate password no upper case', () async {
    final pwd = generatePassword(length: 11, upperCase: false);
    expect(pwd.length, equals(11));
    expect(PasswordCheck.okRE.hasMatch(pwd), equals(false));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pwd), equals(true));
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pwd), equals(false));
  });

  test('Generate password no numbers', () async {
    final pwd = generatePassword(length: 11, numbers: false);
    expect(pwd.length, equals(11));
    expect(PasswordCheck.okRE.hasMatch(pwd), equals(false));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pwd), equals(false));
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pwd), equals(true));
  });

  test('Generate password no special characters', () async {
    final pwd = generatePassword(special: false);
    expect(pwd.length, equals(10));
    expect(PasswordCheck.okRE.hasMatch(pwd), equals(false));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pwd), equals(false));
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pwd), equals(true));
  });

  test('Try to generate password of insufficient length', () async {
    expect(() => generatePassword(length: 7), throwsA(isA<Exception>()));
  });

  test('Validate password 1', () async {
    String pass = 'Gubeer1^pwd';
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pass), equals(true));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pass), equals(true));
    expect(PasswordCheck.okRE.hasMatch(pass), equals(true));
  });

  test('Validate password 2', () async {
    String pass = '...^pwd';
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pass), equals(false));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pass), equals(false));
    expect(PasswordCheck.okRE.hasMatch(pass), equals(false));
  });

  test('Validate password 3', () async {
    String pass = 'J6.IgR&^H';
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pass), equals(true));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pass), equals(true));
    expect(PasswordCheck.okRE.hasMatch(pass), equals(true));
  });

  test('Validate password 4', () async {
    // brackets are not special characters
    String pass = 'U3GJo(frofR';
    expect(PasswordCheck.upperLowerCaseRE.hasMatch(pass), equals(true));
    expect(PasswordCheck.numberSpecialRE.hasMatch(pass), equals(false));
    expect(PasswordCheck.okRE.hasMatch(pass), equals(false));
  });
}
