import 'dart:math';
import 'dart:typed_data';
import 'package:argon2/argon2.dart' as argon2;
import 'package:convert/convert.dart';

class HashingManager {
  /// Generates a hash of the given [password] using the provided [salt].
  /// Returns the hexadecimal string representation of the hash.
  Future<String> hashPassword(String password, Uint8List salt) async {
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
      print('Error hashing password: $e');
      throw Exception('Hashing failed');
    }
  }

  /// Verifies if the [inputPassword] matches the [storedHash] using the provided [salt].
  Future<bool> verifyPassword(
      String inputPassword, String storedHash, Uint8List salt) async {
    final hash = await hashPassword(inputPassword, salt);
    return hash == storedHash;
  }

  /// Generates a random salt of the specified [length] in bytes.
  Uint8List generateSalt([int length = 16]) {
    final random = Random.secure();
    return Uint8List.fromList(
        List.generate(length, (_) => random.nextInt(256)));
  }
}
