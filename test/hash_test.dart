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
  test('SHA3 256 hash', () {
    String msg = 'balblabla';
    String dig = hash(msg);
    expect(
        dig,
        equals(
            '6571c8f32b08e551836fb66f248aabbbd45a7f1ed14779f6d028cdd73bbf83d7'));
  });

  test('SHA3 256 hash hello world', () {
    String msg = 'Hello World';
    String dig = hash(msg);
    expect(
        dig,
        equals(
            'e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51'));
  });
}
