import 'package:password_manager/password_maker.dart' as pass_gen;
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:convert/convert.dart';
import 'package:argon2/argon2.dart' as argon2;
import 'package:pointycastle/export.dart'
    show PBKDF2KeyDerivator, HMac, SHA256Digest, Pbkdf2Parameters;
import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'dart:io';

void main() {
  print("Welcome to the password manager!");

  print("1. Generate a password\n2. Access the manager");
  String input = stdin.readLineSync()!;
  while (input != '1' && input != '2') {
    print("Invalid input. Please try again.");
    input = stdin.readLineSync()!;
  }

  switch (input) {
    case '1':
      print("Generated password: ${pass_gen.passGen()}");
      break;
    case '2':
      print("Accessing the manager...");
      manager();
      break;
  }
}

Future<void> manager() async {
  if (await accessControll()) {
    print("Access granted.");

    File file = File('passwords.json');

    do {
      print('1. Add a new password\n2. Find a password');
      String input = stdin.readLineSync() ?? '';
      if (input == '3') break;
      while (input != '1' && input != '2') {
        print("Invalid input. Please try again.");
        input = stdin.readLineSync() ?? '';
      }

      switch (input) {
        case '1':
          await addNewPassword(file);
          break;
        case '2':
          await findPassword(file);
          break;
      }
    } while (true);
  } else {
    print("Access denied.");
  }
}

Future<void> addNewPassword(File file) async {
  print('Insert the service name:');
  String service = stdin.readLineSync() ?? '';
  while (service.isEmpty) {
    print('Service name cannot be empty. Please try again.');
    service = stdin.readLineSync() ?? '';
  }
  print('Creating a password for $service...');
  String password = pass_gen.passGen();

  await encryptPassword(service, password, file);
}

Future<void> findPassword(File file) async {
  try {
    print('Insert the service name:');
    String service = stdin.readLineSync() ?? '';
    while (service.isEmpty) {
      print('Service name cannot be empty. Please try again.');
      service = stdin.readLineSync() ?? '';
    }

    Map<String, dynamic> data = jsonDecode(await file.readAsString());
    Uint8List? salt;
    var masterPassword = '';

    for (var password in data['passwords']) {
      if (password['service'] == 'master') {
        salt = Uint8List.fromList(hex.decode(password['salt']));
        masterPassword = password['password'];
      }

      if (password['service'] == service && salt != null) {
        final key = deriveKey(masterPassword, salt, 32); // 32 bytes = 256 bits
        final iv = encrypt.IV.fromBase64(password['iv']);

        final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));

        try {
          final decrypted = encrypter.decrypt64(password['password'], iv: iv);
          print('Password found: $decrypted');
        } catch (e) {
          print('An error occurred during decryption: $e');
        }
        return;
      }
    }
    print('No password found for $service.');
  } on Exception catch (e) {
    print('An error occurred: $e');
  }
}

Future<bool> accessControll() async {
  try {
    File file = File('passwords.json');

    if (!await file.exists()) {
      print(
          'I see it\'s your first time using the manager. Let\'s create a new file for you.');
      await file.create();

      print('Insert the master password: ');
      String masterPassword = stdin.readLineSync() ?? '';
      while (masterPassword.isEmpty) {
        print('Password cannot be empty. Please try again.');
        masterPassword = stdin.readLineSync() ?? '';
      }

      final salt = generateSalt();

      Map<String, dynamic> data = {
        "passwords": [
          {
            "service": "master",
            "password": await passwordHashing(masterPassword, salt),
            "salt": hex.encode(salt)
          }
        ]
      };

      await file.writeAsString(jsonEncode(data));
      print('Master password saved successfully.');
      return true;
    } else {
      String fileContent = await file.readAsString();

      print("Please insert the master password:");
      String input = stdin.readLineSync() ?? '';
      while (input.isEmpty) {
        print("Password cannot be empty. Please try again.");
        input = stdin.readLineSync() ?? '';
      }

      Map<String, dynamic> data = jsonDecode(fileContent);
      String saltHex = data['passwords'][0]['salt'];
      Uint8List salt = Uint8List.fromList(hex.decode(saltHex));

      input = await passwordHashing(input, salt);

      for (var password in data['passwords']) {
        if (password['service'] == 'master' && password['password'] == input) {
          return true;
        }
      }
      return false;
    }
  } catch (e) {
    print('An error occurred: $e');
    return false;
  }
}

Future<String> passwordHashing(String password, Uint8List salt) async {
  try {
    final parameters = argon2.Argon2Parameters(
      argon2.Argon2Parameters.ARGON2_id,
      salt,
      version: argon2.Argon2Parameters.ARGON2_VERSION_13,
      iterations: 6,
      memoryPowerOf2: 16,
    );

    final argon2Generator = argon2.Argon2BytesGenerator();

    argon2Generator.init(parameters);

    final passwordBytes = parameters.converter.convert(password);

    var result = Uint8List(32);
    argon2Generator.generateBytes(passwordBytes, result, 0, result.length);

    return hex.encode(result);
  } catch (e) {
    print('An error occurred while hashing the password: $e');
    throw Exception('Hashing failed');
  }
}

Uint8List generateSalt([int length = 16]) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}

Future<void> encryptPassword(String service, String password, File file) async {
  try {
    final fileContent = file.readAsStringSync();

    Map<String, dynamic> data = jsonDecode(fileContent);
    bool masterPasswordFound = false;
    List<Map<String, String>> newPasswords = [];

    for (var passwordEntry in data['passwords']) {
      if (passwordEntry['service'] == 'master') {
        masterPasswordFound = true;
        final salt = Uint8List.fromList(hex.decode(passwordEntry['salt']));
        final key = deriveKey(
            passwordEntry['password'], salt, 32); // 32 bytes = 256 bits
        final iv = encrypt.IV.fromLength(16);

        final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));

        final encrypted = encrypter.encrypt(password, iv: iv);

        print('Password encrypted successfully.');

        newPasswords.add({
          "service": service,
          "password": encrypted.base64,
          "iv": iv.base64
        });
      }
    }

    if (!masterPasswordFound) {
      throw Exception('Master password not found.');
    }

    data['passwords'].addAll(newPasswords);
    await file.writeAsString(jsonEncode(data));
    print('$service password saved successfully.');
  } catch (e) {
    print('An error occurred while encrypting the password: $e');
    throw Exception('Encryption failed');
  }
}

Uint8List deriveKey(String password, Uint8List salt, int length) {
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 100000, length));
  return pbkdf2.process(utf8.encode(password));
}
