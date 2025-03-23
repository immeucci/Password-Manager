import 'package:encrypt/encrypt.dart' as encrypt;
import 'dart:typed_data';

/// A class that manages the encryption and decryption of text data.
class EncryptionManager {
  /// Encrypts the [plainText] using AES with the given [key] and [iv].
  ///
  /// [plainText]: The text to be encrypted.
  /// [key]: The encryption key as a Uint8List.
  /// [iv]: The initialization vector (IV) required for AES.
  /// Returns the Base64 encoded encrypted string.
  String encryptData(String plainText, Uint8List key, encrypt.IV iv) {
    final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));
    final encrypted = encrypter.encrypt(plainText, iv: iv);
    return encrypted.base64;
  }

  /// Decrypts the [encryptedText] using AES with the given [key] and [iv].
  ///
  /// [encryptedText]: The Base64 encoded encrypted string.
  /// [key]: The encryption key as a Uint8List.
  /// [iv]: The initialization vector (IV) used during encryption.
  /// Returns the decrypted plaintext.
  String decryptData(String encryptedText, Uint8List key, encrypt.IV iv) {
    final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));
    final decrypted = encrypter.decrypt64(encryptedText, iv: iv);
    return decrypted;
  }
}
