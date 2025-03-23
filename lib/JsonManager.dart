import 'dart:convert';
import 'dart:io';

class JsonManager {
  final File file;

  JsonManager(this.file);

  /// Reads and returns the JSON content from the file as a Map.
  /// If the file does not exist or is empty, returns an empty Map.
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

  /// Writes the provided [data] Map to the file as JSON.
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

  /// Updates the JSON file by adding the [newData] to the 'passwords' list.
  /// If the 'passwords' key does not exist or is not a list, it initializes it.
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
