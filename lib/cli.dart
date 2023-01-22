import 'dart:convert';
import 'dart:io';
import 'package:collection/collection.dart';
import 'encryption/aes_encryption.dart';
import 'package:cryptography/cryptography.dart';

Future<SecretKey> _keyDerive(String password) async {
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 100,
    bits: 128,
  );

  final secretKey = SecretKey(utf8.encode(password));
  final nonce = utf8.encode("safe_write");
  return await pbkdf2.deriveKey(secretKey: secretKey, nonce: nonce);
}

Future<String?> enc(String? plaintext, String? password) async {
  if (password == null || password.isEmpty) {
    return null;
  }
  if (plaintext == null || plaintext.isEmpty) {
    return "";
  }
  final skey = await _keyDerive(password);
  final data = utf8.encode(plaintext);
  final ciphertext = await AesCbc.with128bits(macAlgorithm: Hmac.sha256())
      .encrypt(data, secretKey: skey);
  return base64.encode(ciphertext.nonce) +
      "\n" +
      base64.encode(ciphertext.cipherText) +
      "\n" +
      base64.encode(ciphertext.mac.bytes);
}

Future<String?> dec(String? ciphertext, String? password) async {
  if (password == null || password.isEmpty) {
    print("password is null or empty");
    return null;
  }
  if (ciphertext == null || ciphertext.isEmpty) {
    print("ciphertext is null or empty");
    return "";
  }
  final skey = await _keyDerive(password);

  final parts = ciphertext.split("\n");
  if (parts.length < 3) {
    print("invalid ciphertext format");
    return null;
  }

  final nonce = base64.decode(parts[0]);
  final ct = base64.decode(parts[1]);
  final mac = base64.decode(parts[2]);
  SecretBox secretBox = SecretBox(ct, nonce: nonce, mac: Mac(mac));
  try {
    final plaintext = await AesCbc.with128bits(macAlgorithm: Hmac.sha256())
        .decrypt(secretBox, secretKey: skey);
    return utf8.decode(plaintext);
  } catch (e) {
    print(e);
    return null;
  }
}

class Passage {
  String title;
  String content;
  Passage(this.title, this.content);

  String toBase64() {
    return "${base64.encode(utf8.encode(title))}-${base64.encode(utf8.encode(content))}";
  }
}

class Plaintext {
  int fontSize;
  List<Passage> passages;
  Plaintext(this.passages, {this.fontSize = 18});

  Future<String?> encrypt(String? password) async {
    final plaintext =
        passages.map((p) => p.toBase64()).join("|") + ":FontSize=$fontSize";
    return enc(plaintext, password);
  }
}

void main(List<String> arguments) async {
  if (arguments.length < 1) {
    print("Usage: dart run cli.dart path");
    return;
  }
  var path = arguments[0];
  var file = File(path);
  var data = await file.readAsString();
  print('Enter password: ');
  stdin.echoMode = false;
  var password = stdin.readLineSync();
  Map<String, dynamic> obj = jsonDecode(data);
  var records = obj["records"];
  Map<String, List<List<String>>> books = {};
  for (var record in records) {
    var title = decryptAES(record["title"], password as String);
    var body = decryptAES(record["description"], password as String);
    String booktitle = title;
    String? chaptertitle = null;
    int indexOfColon = title.indexOf(':');
    if (indexOfColon > 0) {
      booktitle = title.substring(0, indexOfColon);
      chaptertitle = title.substring(indexOfColon + 1);
    }
    books[booktitle];
    if (!books.containsKey(booktitle)) {
      books[booktitle] = [
        [chaptertitle ?? "0", body]
      ];
    } else {
      var book = books[booktitle]!;
      book.add([chaptertitle ?? "${book.length}", body]);
    }
  }
  for (var book in books.values) {
    book.sort((a, b) => compareNatural(a[0], b[0]));
  }
  for (var booktitle in books.keys) {
    var book = books[booktitle];
    List<Passage> passages = [];
    for (var item in book!) {
      passages.add(Passage(item[0], item[1]));
    }
    var plaintext = Plaintext(passages);
    var ct = await plaintext.encrypt(password);
    var ctfile = File('/tmp/${booktitle}.safe');
    var wt = ctfile.openWrite();
    wt.write(ct);
  }
}
