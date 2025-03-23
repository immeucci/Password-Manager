import 'dart:convert';
import 'dart:io';

class JsonManager {
  File file;

  JsonManager(this.file);

  Future<Map<String, dynamic>> readJsonFile() async {
    try {
      if (!await file.exists()) {
        await file.create();
        return {};
      }

      if (await file.length() == 0) {
        print('File is empty.');
        return {};
      }

      final jsonString = await file.readAsString();
      return jsonDecode(jsonString);
    } on FormatException catch (e) {
      print('Error parsing JSON: $e');
      return {};
    } on IOException catch (e) {
      print('File read error: $e');
      return {};
    } catch (e) {
      print('An unexpected error occurred: $e');
      return {};
    }
  }

  Future<void> writeJsonFile(Map<String, dynamic> data) async {
    try {
      final jsonString = jsonEncode(data);
      await file.writeAsString(jsonString);
    } on IOException catch (e) {
      print('File write error: $e');
    } catch (e) {
      print('An unexpected error occurred: $e');
    }
  }

  Future<void> updateJsonFile(Map<String, dynamic> newData) async {
    try {
      Map<String, dynamic> data = await readJsonFile();

      if (!data.containsKey('passwords') || data['passwords'] is! List) {
        data['passwords'] = [];
      }

      (data['passwords'] as List).add(newData);

      final jsonString = jsonEncode(data);
      await file.writeAsString(jsonString);
    } on IOException catch (e) {
      print('File write error: $e');
    } catch (e) {
      print('An unexpected error occurred: $e');
    }
  }
}
