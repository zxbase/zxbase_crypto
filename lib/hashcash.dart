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

/// Hashcash:
///   * Challenge.
///   * Verification.

import 'dart:convert';
import 'package:zxbase_crypto/hash.dart';
import 'package:zxbase_crypto/random.dart';

enum Fields { version, bits, date, resource, ext, rand, counter }

class Hashcash {
  static const timeThreshold = 60000; // 1 minute
  static const version = 1;

  static String createChallenge(String resource, String ext, int bits) {
    final randomBytes = generateRandomBytes(32);
    final rand = base64Url.encode(randomBytes);
    final date = DateTime.now().toUtc().millisecondsSinceEpoch;
    return '$version:$bits:$date:$resource:$ext:$rand';
  }

  /// Verify proof-of-work.
  static bool verifyPoW(String response, int strength) {
    final hash = Hash.hash3_256(response);
    for (int i = 0; i < strength; i++) {
      if (hash[i] != '0') return false;
    }
    return true;
  }

  static String solveChallenge(String challenge) {
    final fields = challenge.split(':');
    final strength = int.parse(fields[Fields.bits.index]) / 4;
    int counter = 0;
    while (true) {
      final response =
          '$challenge:${base64Url.encode(utf8.encode(counter.toRadixString(2)))}';
      if (verifyPoW(response, strength.round())) {
        return response;
      }
      counter++;
    }
  }

  /// Verify the challenge is no older than 1 minute.
  static bool verifyDate(String challenge) {
    final fields = challenge.split(':');
    final date = int.parse(fields[Fields.date.index]);
    final currentDate = DateTime.now().toUtc().millisecondsSinceEpoch;

    if ((currentDate - date) > timeThreshold) {
      return false;
    }

    return true;
  }

  /// Check response matches challenge.
  static bool checkMatch(String challenge, String response) {
    final fields = response.split(':');
    final supposedChallenge =
        '${fields[Fields.version.index]}:${fields[Fields.bits.index]}:${fields[Fields.date.index]}:${fields[Fields.resource.index]}:${fields[Fields.ext.index]}:${fields[Fields.rand.index]}';
    return (challenge == supposedChallenge);
  }

  /// Full check: challenge to response, timely response and PoW.
  static bool check(String challenge, String response) {
    final fields = response.split(':');
    final strength = (int.parse(fields[Fields.bits.index]) / 4).round();
    if (!checkMatch(challenge, response)) return false;
    if (!verifyDate(response)) return false;
    if (!verifyPoW(response, strength)) return false;
    return true;
  }
}
