import 'dart:convert';
import 'dart:io';
import 'encryption/aes_encryption.dart';


void main(List<String> arguments) async {
  if(arguments.length < 1) {
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
  String pt = "";
  for (var record in records) {
    var title = decryptAES(record["title"], password as String);
    var body = decryptAES(record["description"], password as String);
    pt += title + "\n\n";
    pt += body + "\n\n";
  }
  var ptfile = File('/tmp/pt.txt');
  var wt = ptfile.openWrite();
  wt.write(pt);
}
