import 'package:zxbase_crypto/pk_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('Generate 2 different Ed25519 keys', () async {
    var kp1 = await generateKeyPair();
    var kp2 = await generateKeyPair();

    expect(kp1.extractPrivateKeyBytes(), isNot(kp2.extractPrivateKeyBytes()));
    expect(kp1.extractPublicKey(), isNot(kp2.extractPublicKey()));
  });

  test('Sign and verify message', () async {
    var kp = await generateKeyPair();
    var msg = 'xxx';
    var sig = await sign(msg, kp);
    var rv = await verifySignature(msg, sig, kp);
    expect(rv, equals(true));
  });

  test('Export and import key pair', () async {
    // generate key, sign, export key, import, verify
    var msg = 'xxx';
    var kp = await generateKeyPair();
    var sig = await sign(msg, kp);

    var json = await keyPairToJwk(kp);
    var importedKp = await jwkToKeyPair(json);
    expect(await verifySignature(msg, sig, importedKp), equals(true));
  });

  test('Check jwk format', () async {
    expect(
        () => jwkToPublicKey({'kty': 'OKT'}), throwsA(isA<FormatException>()));
  });
}
