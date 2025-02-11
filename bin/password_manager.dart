import 'package:password_manager/password_maker.dart' as pass_gen;
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:convert/convert.dart';
import 'package:argon2/argon2.dart';
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

    print('1. Add a new password\n2. Find a password');
    String input = stdin.readLineSync() ?? '';
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

  final cryptedPassword = encryptPassword(password, file);

  Map<String, dynamic> data = jsonDecode(await file.readAsString());
  data['passwords'].add({"service": service, "password": cryptedPassword});
  await file.writeAsString(jsonEncode(data));
  print('$service password saved successfully.');
}

Future<void> findPassword(File file) async {
  print('Insert the service name:');
  String service = stdin.readLineSync() ?? '';
  while (service.isEmpty) {
    print('Service name cannot be empty. Please try again.');
    service = stdin.readLineSync() ?? '';
  }

  Map<String, dynamic> data = jsonDecode(await file.readAsString());
  for (var password in data['passwords']) {
    if (password['service'] == service) {
      print('Password for $service: ${password['password']}');
      return;
    }
  }
  print('No password found for $service.');
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
    final parameters = Argon2Parameters(
      Argon2Parameters.ARGON2_id,
      salt,
      version: Argon2Parameters.ARGON2_VERSION_13,
      iterations: 6,
      memoryPowerOf2: 16,
    );

    final argon2 = Argon2BytesGenerator();

    argon2.init(parameters);

    final passwordBytes = parameters.converter.convert(password);

    var result = Uint8List(32);
    argon2.generateBytes(passwordBytes, result, 0, result.length);

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

Future<String> encryptPassword(String password, File file) async {
  print(password);
  try {
    final fileContent = file.readAsStringSync();

    Map<String, dynamic> data = jsonDecode(fileContent);
    for (var passwordEntry in data['passwords']) {
      if (passwordEntry['service'] == 'master') {
        final key = encrypt.Key.fromUtf8(passwordEntry['password']);
        final iv = encrypt.IV.fromLength(16);

        final encrypter = encrypt.Encrypter(encrypt.AES(key));

        final encrypted = encrypter.encrypt(password, iv: iv);

        print('Password encrypted successfully.');
        return encrypted.base64;
      }
    }
    throw Exception('Master password not found.');
  } catch (e) {
    print('An error occurred while encrypting the password: $e');
    throw Exception('Encryption failed');
  }
}
