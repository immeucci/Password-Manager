import 'dart:convert';
import 'dart:io';

/// A class that manages reading from and writing to a JSON file.
class JsonManager {
  /// The file that stores the JSON data.
  final File file;

  /// Constructor that initializes the JsonManager with the given [file].
  JsonManager(this.file);

  /// Reads the JSON data from the file.
  /// Returns a Map representing the JSON data, or an empty Map if the file is empty or not valid.
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

  /// Writes the given [data] as JSON to the file, overwriting existing content.
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

  /// Updates the JSON file by adding the [newData] to the existing 'passwords' list.
  /// If the 'passwords' list does not exist, it is created.
  Future<void> updateJsonFile(Map<String, dynamic> newData) async {
    try {
      Map<String, dynamic> data = await readJsonFile();

      // Ensure 'passwords' is a list in the JSON data.
      if (!data.containsKey('passwords') || data['passwords'] is! List) {
        data['passwords'] = [];
      }

      // Add the newData to the passwords list.
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
