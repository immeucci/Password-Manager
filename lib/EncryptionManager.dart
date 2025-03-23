import 'package:encrypt/encrypt.dart' as encrypt;
import 'dart:typed_data';

class EncryptionManager {
  String encryptData(String plainText, Uint8List key, encrypt.IV iv) {
    final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));
    final encrypted = encrypter.encrypt(plainText, iv: iv);

    return encrypted.base64;
  }

  String decryptData(String encryptedText, Uint8List key, encrypt.IV iv) {
    final encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key(key)));
    final decrypted = encrypter.decrypt64(encryptedText, iv: iv);

    return decrypted;
  }
}
