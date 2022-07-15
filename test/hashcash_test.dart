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

import 'package:zxbase_crypto/zxbase_crypto.dart';
import 'package:test/test.dart';

void main() {
  var challenge =
      '1:20:1631982770503:78b35d56-c0a8-4589-bcbb-0342099d7015:axc:kMM9D16d7Xn/+nKGgLTFg6zv+myy0wJ4uDQFp5mcyq0=';
  var response =
      '1:20:1631982770503:78b35d56-c0a8-4589-bcbb-0342099d7015:axc:kMM9D16d7Xn/+nKGgLTFg6zv+myy0wJ4uDQFp5mcyq0=:MTAxMTEwMTExMDAxMTAwMDAwMA==';

  test('Solve a challenge', () {
    Stopwatch stopwatch = Stopwatch()..start();
    var rv = Hashcash.solveChallenge(challenge);
    expect(rv, equals(response));
    // print(
    //    'Challenge solved in ${stopwatch.elapsed.inMilliseconds} milliseconds');
    stopwatch.stop();
  });

  test('Verify response', () {
    var rv = Hashcash.verifyPoW(response, 5);
    expect(rv, equals(true));
  });

  test('Fail old challenge', () {
    expect(Hashcash.verifyDate(challenge), equals(false));
  });

  test('Create challenge', () {
    var msg =
        'eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IklVbnliMDRMRWRYS0FLUzNreFNzVmNKRHU0bWJYRFFkUl94aU9Ib1B3cFU9Iiwia2lkIjoiMTQ0YzE4NGUtZTZmMy00YjU1LTg0ZjktZWU3ODdkYzE2YWQ4In0=';
    var msg2 =
        'eyJjcnYiOiJFZDI1NTE5IiwieCI6Imhaa3JyZ3JBWmpqdVhqZmU4X2tfQXV5RVl0OUl0elhLdE9WUUxFOEdScUUiLCJrdHkiOiJPS1AiLCJraWQiOiJkYWUzOGUxMy1hNjI1LTQxMmMtYmVjNS02NTgzZWJiMTNlOWEifQ%3D%3D';

    var challenge = Hashcash.createChallenge(msg, msg2, 0);
    var response = Hashcash.solveChallenge(challenge);
    expect(response != challenge, true);
  });

  test('Challenge response match', () {
    expect(Hashcash.checkMatch(challenge, response), true);
  });

  test('Full check', () {
    var challenge = Hashcash.createChallenge('a', 'b', 4);
    var response = Hashcash.solveChallenge(challenge);
    expect(Hashcash.check(challenge, response), true);
  });
}
