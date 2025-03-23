import 'package:password_manager/EncryptionManager.dart';
import 'package:password_manager/HashingManager.dart';
import 'package:password_manager/JsonManager.dart';
import 'package:password_manager/password_maker.dart' as pass_gen;
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart'
    show PBKDF2KeyDerivator, HMac, SHA256Digest, Pbkdf2Parameters;
import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'dart:io';

void main() {
  print('Welcome to the password manager!');

  print('1. Generate a password\n2. Access the manager');
  final input = _getUserInput(['1', '2']);

  if (input == '1') {
    print('Generated password: ${pass_gen.passGen()}');
  } else {
    print('Accessing the manager...');
    manager();
  }
}

Future<void> manager() async {
  if (!await accessControll()) {
    print('Access denied.');
    return;
  }

  print('Access granted.');
  final file = File('passwords.json');

  do {
    print(
      '1. Add a new password\n2. Find a password\n3. Delete the password manager file\n4. Exit',
    );
    final input = _getUserInput(['1', '2', '3', '4']);

    if (input == '4') break;

    switch (input) {
      case '1':
        await addNewPassword(file);
        break;
      case '2':
        await findPassword(file);
        break;
      case '3':
        print("ARE YOU SURE YOU WANT TO DELETE ALL YOUR DATA? (yes/no)");
        final confirm = _getUserInput(['yes', 'no']);
        if (confirm == 'yes') {
          await file.delete();
          print(
            'File deleted.\nYou will be able to create a new one next time you access the manager.',
          );
        }
        exit(0);
    }
  } while (true);
}

Future<bool> accessControll() async {
  JsonManager jsonManager = JsonManager(File('passwords.json'));
  HashingManager hashingManager = HashingManager();
  try {
    final File file = File('passwords.json');

    if (!await file.exists()) {
      print('First time using the manager. Creating a new file...');
      await file.create();

      final String masterPassword =
          _getNonEmptyInput('Insert the master password:');
      final Uint8List salt = generateSalt();

      final data = {
        'passwords': [
          {
            'service': 'master',
            'password': await hashingManager.hashPassword(masterPassword, salt),
            'salt': hex.encode(salt),
          },
        ],
      };

      jsonManager.writeJsonFile(data);
      print('Master password saved successfully.');
      return true;
    } else {
      final String masterPassword = _getNonEmptyInput(
        'Please insert the master password:',
      );
      final Map<String, dynamic> data = await jsonManager.readJsonFile();
      final Uint8List salt = Uint8List.fromList(
        hex.decode(data['passwords'][0]['salt']),
      );

      if (await hashingManager.verifyPassword(
        masterPassword,
        data['passwords'][0]['password'],
        salt,
      )) {
        return true;
      }
      return false;
    }
  } on IOException catch (e) {
    print('File error: $e');
    return false;
  } catch (e) {
    print('An unexpected error occurred: $e');
    return false;
  }
}

Future<void> addNewPassword(File file) async {
  final String service = _getNonEmptyInput('Insert the service name:');
  print('Creating a password for $service...');
  final String password = pass_gen.passGen();
  await encryptPassword(service, password, file);
}

Future<void> findPassword(File file) async {
  try {
    final service = _getNonEmptyInput('Insert the service name:');
    final data = await JsonManager(file).readJsonFile();
    Uint8List? salt;
    var masterPassword = '';

    for (final password in data['passwords']) {
      if (password['service'] == 'master') {
        salt = Uint8List.fromList(hex.decode(password['salt']));
        masterPassword = password['password'];
      }

      if (password['service'] == service && salt != null) {
        final key = deriveKey(masterPassword, salt, 32); // 32 bytes = 256 bits
        final iv = encrypt.IV.fromBase64(password[
            'iv']); // Assicurati che l'IV venga decodificato correttamente da base64

        final decrypted = EncryptionManager().decryptData(
          password['password'],
          key,
          iv,
        );
        print('Password found: $decrypted');

        return;
      }
    }
    print('No password found for $service.');
  } on FormatException catch (e) {
    print('Error parsing JSON: $e');
  } on IOException catch (e) {
    print('File read error: $e');
  } catch (e) {
    print('An unexpected error occurred: $e');
  }
}

Uint8List generateSalt([int length = 16]) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}

Future<void> encryptPassword(String service, String password, File file) async {
  try {
    final fileContent = file.readAsStringSync();
    final data = jsonDecode(fileContent) as Map<String, dynamic>;
    bool masterPasswordFound = false;
    final List<Map<String, String>> newPasswords = [];

    for (final passwordEntry in data['passwords']) {
      if (passwordEntry['service'] == 'master') {
        masterPasswordFound = true;
        final salt = Uint8List.fromList(hex.decode(passwordEntry['salt']));
        final key = deriveKey(passwordEntry['password'], salt, 32);

        // Aggiungi la generazione dell'IV (Initialization Vector)
        final iv = encrypt.IV.fromLength(16); // Genera un IV casuale di 16 byte
        final encrypted = EncryptionManager().encryptData(password, key, iv);

        print('Password encrypted successfully.');

        newPasswords.add({
          'service': service,
          'password': encrypted,
          'iv': iv
              .base64, // Assicurati che l'IV venga salvato correttamente in base64
        });
      }
    }

    if (!masterPasswordFound) {
      throw Exception('Master password not found.');
    }

    for (var passwordData in newPasswords) {
      await JsonManager(file).updateJsonFile(passwordData);
    }
    print('$service password saved successfully.');
  } catch (e) {
    print('Error encrypting password: $e');
  }
}

String _getUserInput(List<String> validInputs) {
  String input;
  do {
    input = stdin.readLineSync() ?? '';
  } while (!validInputs.contains(input));
  return input;
}

String _getNonEmptyInput(String message) {
  print(message);
  String input;
  do {
    input = stdin.readLineSync() ?? '';
  } while (input.isEmpty);
  return input;
}

Uint8List deriveKey(String password, Uint8List salt, int length) {
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 100000, length));
  return pbkdf2.process(utf8.encode(password));
}
