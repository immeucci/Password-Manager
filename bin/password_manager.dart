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
  // Print welcome message and main menu options.
  print('Welcome to the password manager!');
  print('1. Generate a password\n2. Access the manager');
  final String input = _getUserInput(['1', '2']);

  if (input == '1') {
    // Generate a password using the external password generator.
    print('Generated password: ${pass_gen.passGen()}');
  } else {
    // Proceed to access the manager.
    print('Accessing the manager...');
    manager();
  }
}

/// Main manager function that handles user authentication and options.
Future<void> manager() async {
  if (!await accessControl()) {
    print('Access denied.');
    return;
  }

  print('Access granted.');
  final File file = File('passwords.json');
  final JsonManager jsonManager = JsonManager(file);

  // Main loop for the manager options.
  while (true) {
    print(
      '1. Add a new password\n2. Find a password\n3. Delete the password manager file\n4. Exit',
    );
    final String input = _getUserInput(['1', '2', '3', '4']);

    if (input == '4') break;

    switch (input) {
      case '1':
        await addNewPassword(jsonManager);
        break;
      case '2':
        await findPassword(jsonManager);
        break;
      case '3':
        print("ARE YOU SURE YOU WANT TO DELETE ALL YOUR DATA? (yes/no)");
        final String confirm = _getUserInput(['yes', 'no']);
        if (confirm == 'yes') {
          await file.delete();
          print(
              'File deleted. You can create a new one next time you  access the manager.');
          exit(1);
        } else {
          print('File deletion cancelled.');
          break;
        }
    }
  }
}

/// Performs access control by verifying the master password.
/// If the file does not exist, creates it with the master password and salt.
Future<bool> accessControl() async {
  final File file = File('passwords.json');
  final JsonManager jsonManager = JsonManager(file);
  final HashingManager hashingManager = HashingManager();

  if (!await file.exists()) {
    // First time usage: create new file and save master password.
    print('First time using the manager. Creating a new file...');
    await file.create();

    final String masterPassword =
        _getNonEmptyInput('Insert the master password:');
    final Uint8List salt = generateSalt();

    final data = {
      // Store master password info under 'master' key.
      'master': {
        'password': await hashingManager.hashPassword(masterPassword, salt),
        'salt': hex.encode(salt),
      },
      // Initialize empty list for service passwords.
      'passwords': []
    };

    await jsonManager.writeJsonFile(data);
    print('Master password saved successfully.');
    return true;
  }

  // If file exists, verify the master password.
  final Map<String, dynamic> data = await jsonManager.readJsonFile();
  final String masterPassword =
      _getNonEmptyInput('Insert the master password:');

  if (!data.containsKey('master')) {
    print('Master password entry is missing or corrupted.');
    return false;
  }

  final Uint8List salt = Uint8List.fromList(hex.decode(data['master']['salt']));
  if (await hashingManager.verifyPassword(
      masterPassword, data['master']['password'], salt)) {
    return true;
  }
  return false;
}

/// Adds a new service password by encrypting it and saving it to the JSON file.
Future<void> addNewPassword(JsonManager jsonManager) async {
  final String service = _getNonEmptyInput('Insert the service name:');
  // Generate a password using the external generator.
  final String password = pass_gen.passGen();
  await encryptPassword(service, password, jsonManager);
}

/// Searches for a service password in the JSON file and decrypts it.
Future<void> findPassword(JsonManager jsonManager) async {
  final String service = _getNonEmptyInput('Insert the service name:');
  final Map<String, dynamic> data = await jsonManager.readJsonFile();

  if (!data.containsKey('passwords')) {
    print('No passwords stored.');
    return;
  }

  // Search for the password entry matching the service.
  final dynamic entry = (data['passwords'] as List).firstWhere(
    (element) => element['service'] == service,
    orElse: () => null,
  );

  if (entry == null) {
    print('No password found for $service.');
    return;
  }

  final String encryptedPassword = entry['password'];
  final String ivBase64 = entry['iv'];
  final Uint8List key = await deriveMasterKey(jsonManager);
  final encrypt.IV iv = encrypt.IV.fromBase64(ivBase64);

  final String decrypted =
      EncryptionManager().decryptData(encryptedPassword, key, iv);
  print('Password found: $decrypted');
}

/// Encrypts a service password and updates the JSON file with the new entry.
Future<void> encryptPassword(
    String service, String password, JsonManager jsonManager) async {
  try {
    final Map<String, dynamic> data = await jsonManager.readJsonFile();

    // Derive encryption key from master password stored in JSON.
    final Uint8List key = await deriveMasterKey(jsonManager);
    // Generate a random IV for AES.
    final encrypt.IV iv = encrypt.IV.fromLength(16);

    // Encrypt the service password.
    final String encrypted = EncryptionManager().encryptData(password, key, iv);
    // Create a new entry for the service password.
    final Map<String, dynamic> newEntry = {
      'service': service,
      'password': encrypted,
      'iv': iv.base64,
    };

    // Add new entry to the 'passwords' list.
    (data['passwords'] as List).add(newEntry);
    await jsonManager.writeJsonFile(data);

    print('$service password saved successfully.');
  } catch (e) {
    print('Error encrypting password: $e');
  }
}

/// Derives the master key from the stored master password and salt.
Future<Uint8List> deriveMasterKey(JsonManager jsonManager) async {
  final Map<String, dynamic> data = await jsonManager.readJsonFile();
  final Uint8List salt = Uint8List.fromList(hex.decode(data['master']['salt']));
  // Derive key using PBKDF2 based on the stored master password hash.
  return deriveKey(data['master']['password'], salt, 32);
}

/// Reads user input ensuring it is one of the [validInputs].
String _getUserInput(List<String> validInputs) {
  String input;
  do {
    input = stdin.readLineSync() ?? '';
  } while (!validInputs.contains(input));
  return input;
}

/// Reads user input until a non-empty string is entered.
String _getNonEmptyInput(String message) {
  print(message);
  String input;
  do {
    input = stdin.readLineSync() ?? '';
  } while (input.isEmpty);
  return input;
}

/// Computes a derived key using PBKDF2 with SHA-256.
/// [password]: the input password string.
/// [salt]: the salt bytes.
/// [length]: the desired length of the derived key in bytes.
Uint8List deriveKey(String password, Uint8List salt, int length) {
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 100000, length));
  return pbkdf2.process(utf8.encode(password));
}

/// Generates a random salt of [length] bytes.
Uint8List generateSalt([int length = 16]) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}
