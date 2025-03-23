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

/// Entry point of the password manager program.
void main() async {
  print('Welcome to the password manager!');

  /// Prompt user to either generate a password or access the manager.
  print('1. Generate a password\n2. Access the manager');
  final String input = _getUserInput(['1', '2']);

  if (input == '1') {
    // Generate and print a password using the password_maker library.
    print('Generated password: ${pass_gen.passGen()}');
  } else {
    print('Accessing the manager...');
    await manager();
  }
}

/// Manages the main operations of the password manager once access is granted.
Future<void> manager() async {
  // Check if the master password is correct and access is allowed.
  if (!await accessControl()) {
    print('Access denied.');
    return;
  }

  print('Access granted.');
  final File file = File('passwords.json');
  final JsonManager jsonManager = JsonManager(file);

  // Loop until the user decides to exit.
  while (true) {
    print(
        '1. Add a new password\n2. Find a password\n3. Delete the password manager file\n4. Exit');
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
              'File deleted.\nYou will be able to create a new one next time you access the manager.');
        }
        exit(0);
    }
  }
}

/// Checks and verifies master password access.
/// If the file does not exist, it creates a new file with a master password entry.
/// Returns true if the provided master password is verified successfully.
Future<bool> accessControl() async {
  final File file = File('passwords.json');
  final JsonManager jsonManager = JsonManager(file);
  final HashingManager hashingManager = HashingManager();

  // If the file does not exist, initialize it with a new master password.
  if (!await file.exists()) {
    print('First time using the manager. Creating a new file...');
    await file.create();

    final String masterPassword =
        _getNonEmptyInput('Insert the master password:');
    final Uint8List salt = generateSalt();

    // Create a data structure containing the master password hash and its salt,
    // along with an empty list for future passwords.
    final data = {
      'master': {
        'password': await hashingManager.hashPassword(masterPassword, salt),
        'salt': hex.encode(salt),
      },
      'passwords': [] // Initially empty list for other services' passwords.
    };

    await jsonManager.writeJsonFile(data);
    print('Master password saved successfully.');
    return true;
  }

  // If the file exists, read it and verify the master password.
  final Map<String, dynamic> data = await jsonManager.readJsonFile();
  final String masterPassword =
      _getNonEmptyInput('Please insert the master password:');

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

/// Adds a new service password by generating a password using the password_maker,
/// then encrypts it and stores it in the JSON file.
Future<void> addNewPassword(JsonManager jsonManager) async {
  final String service = _getNonEmptyInput('Insert the service name:');
  print('Creating a password for $service...');
  final String password = pass_gen.passGen();
  await encryptPassword(service, password, jsonManager);
}

/// Finds and decrypts the password for a given service from the JSON file.
Future<void> findPassword(JsonManager jsonManager) async {
  try {
    final String service = _getNonEmptyInput('Insert the service name:');
    final Map<String, dynamic> data = await jsonManager.readJsonFile();

    // Check if passwords list exists.
    if (!data.containsKey('passwords')) {
      print('No passwords stored.');
      return;
    }

    // Look for the service entry in the passwords list.
    final List passwordsList = data['passwords'];
    final dynamic entry = passwordsList.firstWhere(
      (element) => element['service'] == service,
      orElse: () => null,
    );

    if (entry == null) {
      print('No password found for $service.');
      return;
    }

    // Derive the key using the master password.
    // Here, we retrieve the master entry from data.
    if (!data.containsKey('master')) {
      print('Master password entry missing.');
      return;
    }

    final Uint8List salt =
        Uint8List.fromList(hex.decode(data['master']['salt']));
    final Uint8List key = deriveKey(data['master']['password'], salt, 32);
    final encrypt.IV iv = encrypt.IV.fromBase64(entry['iv']);

    final String decrypted = EncryptionManager().decryptData(
      entry['password'],
      key,
      iv,
    );
    print('Password found: $decrypted');
  } on FormatException catch (e) {
    print('Error parsing JSON: $e');
  } on IOException catch (e) {
    print('File read error: $e');
  } catch (e) {
    print('An unexpected error occurred: $e');
  }
}

/// Encrypts the provided [password] for the given [service] and updates the JSON file.
/// Uses the master password data to derive an encryption key.
Future<void> encryptPassword(
    String service, String password, JsonManager jsonManager) async {
  try {
    final Map<String, dynamic> data = await jsonManager.readJsonFile();

    // Retrieve master password info for key derivation.
    if (!data.containsKey('master')) {
      throw Exception('Master password not found.');
    }
    final Uint8List salt =
        Uint8List.fromList(hex.decode(data['master']['salt']));
    final Uint8List key = deriveKey(data['master']['password'], salt, 32);
    final encrypt.IV iv =
        encrypt.IV.fromLength(16); // Generate a random IV (16 bytes)

    final String encrypted = EncryptionManager().encryptData(password, key, iv);
    print('Password encrypted successfully.');

    // Create a new password entry for the service.
    final Map<String, String> newEntry = {
      'service': service,
      'password': encrypted,
      'iv': iv.base64, // Save IV in Base64 format
    };

    // Add the new entry to the passwords list.
    if (!data.containsKey('passwords') || data['passwords'] is! List) {
      data['passwords'] = [];
    }
    (data['passwords'] as List).add(newEntry);

    await jsonManager.writeJsonFile(data);
    print('$service password saved successfully.');
  } catch (e) {
    print('Error encrypting password: $e');
  }
}

/// Derives a cryptographic key from the given [password] and [salt] using PBKDF2.
///
/// [password]: The base password (usually the hashed master password).
/// [salt]: The salt used in key derivation.
/// [length]: The desired key length in bytes.
/// Returns a Uint8List representing the derived key.
Uint8List deriveKey(String password, Uint8List salt, int length) {
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 100000, length));
  return pbkdf2.process(utf8.encode(password));
}

/// Returns a user input that is contained in the [validInputs] list.
/// Keeps prompting until a valid input is provided.
String _getUserInput(List<String> validInputs) {
  String input;
  do {
    input = stdin.readLineSync() ?? '';
  } while (!validInputs.contains(input));
  return input;
}

/// Prints the [message] and returns a non-empty user input.
String _getNonEmptyInput(String message) {
  print(message);
  String input;
  do {
    input = stdin.readLineSync() ?? '';
  } while (input.isEmpty);
  return input;
}

/// Generates a random salt of [length] bytes (default is 16).
Uint8List generateSalt([int length = 16]) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}
