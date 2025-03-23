import 'dart:math';
import 'dart:typed_data';
import 'package:argon2/argon2.dart' as argon2;
import 'package:convert/convert.dart';

/// A class that manages hashing of passwords using Argon2.
class HashingManager {
  /// Generates a hash for the given [password] using the provided [salt].
  ///
  /// [password]: The plaintext password to be hashed.
  /// [salt]: A random salt used for hashing.
  /// Returns the hexadecimal string representation of the hash.
  Future<String> hashPassword(String password, Uint8List salt) async {
    try {
      final parameters = argon2.Argon2Parameters(
        argon2.Argon2Parameters.ARGON2_id, // Using Argon2id variant
        salt, // The salt provided
        version: argon2.Argon2Parameters.ARGON2_VERSION_13,
        iterations: 6, // Number of iterations for the algorithm
        memoryPowerOf2: 16, // Memory cost (2^16 KiB)
      );

      final argon2Generator = argon2.Argon2BytesGenerator();
      argon2Generator.init(parameters);

      // Convert the password into bytes using the parameter's converter.
      final passwordBytes = parameters.converter.convert(password);

      // Allocate a Uint8List for the output hash (32 bytes).
      var result = Uint8List(32);
      argon2Generator.generateBytes(passwordBytes, result, 0, result.length);

      // Return the hash as a hexadecimal string.
      return hex.encode(result);
    } catch (e) {
      print('Error hashing password: $e');
      throw Exception('Hashing failed');
    }
  }

  /// Verifies if the [inputPassword] matches the [storedHash] using the provided [salt].
  ///
  /// [inputPassword]: The password input to verify.
  /// [storedHash]: The hash stored previously.
  /// [salt]: The salt used when hashing the original password.
  /// Returns true if the input password is correct.
  Future<bool> verifyPassword(
      String inputPassword, String storedHash, Uint8List salt) async {
    final hash = await hashPassword(inputPassword, salt);
    return hash == storedHash;
  }

  /// Generates a random salt of the given [length] (default is 16 bytes).
  Uint8List generateSalt([int length = 16]) {
    final random = Random.secure();
    return Uint8List.fromList(
        List.generate(length, (_) => random.nextInt(256)));
  }
}
