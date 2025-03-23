import 'package:encrypt/encrypt.dart' as encrypt;
import 'dart:typed_data';

class EncryptionManager {
  /// Encrypts the [plainText] using AES encryption with the provided [key] and [iv].
  /// Returns the Base64 encoded ciphertext.
  String encryptData(String plainText, Uint8List key, encrypt.IV iv) {
    final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));
    final encrypted = encrypter.encrypt(plainText, iv: iv);
    return encrypted.base64;
  }

  /// Decrypts the [encryptedText] (in Base64) using AES decryption with the provided [key] and [iv].
  /// Returns the decrypted plaintext.
  String decryptData(String encryptedText, Uint8List key, encrypt.IV iv) {
    final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));
    final decrypted = encrypter.decrypt64(encryptedText, iv: iv);
    return decrypted;
  }
}
