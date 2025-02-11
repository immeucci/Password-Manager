import 'dart:math';
import 'dart:io';

String passGen() {
  // Variable to store the generated password
  String password = "";

  // Lists of usable characters
  List<String> lowerCase = "abcdefghilmnopqrstuvzwyjkx".split("");
  List<String> capitalCase = "ABCDEFGHILMNOPQRSTUVZWJKX".split("");
  List<String> numbers = "0123456789".split("");
  List<String> specialChar = "!@&(){}[]".split("");

  // Prompt the user for password strength level
  print("Insert the password strenght level (lvl: 1,2,3).");

  String input = stdin.readLineSync() ?? "";

  // Validate user input
  while (input.isEmpty || (input != '1' && input != '2' && input != '3')) {
    print(
        "The password strength level can only be 1, 2, or 3.\nPlease reinsert the password level.");
    input = stdin.readLineSync() ?? "";
  }

  // Variables for random character selection
  int passwordLength = 0;
  List<String> characterPool = [];
  var random = Random();

  // Define password length and character pool based on user choice
  switch (input) {
    case "1":
      passwordLength = 20;
      characterPool.addAll(lowerCase);
      characterPool.addAll(capitalCase);
      break;
    case "2":
      passwordLength = 30;
      characterPool.addAll(lowerCase);
      characterPool.addAll(capitalCase);
      characterPool.addAll(numbers);
      break;
    case "3":
      passwordLength = 40;
      characterPool.addAll(lowerCase);
      characterPool.addAll(capitalCase);
      characterPool.addAll(numbers);
      characterPool.addAll(specialChar);
      break;
  }

  print(
      "Should the ambiguous charachters be removed?\n1. Remove\n2. Don't remove");

  input = stdin.readLineSync() ?? "";
  while (input.isEmpty || (input != '1' && input != '2')) {
    print("Please insert a valid option.");
    input = stdin.readLineSync() ?? "";
  }

  // Remove ambiguous characters if the user chooses to
  if (input == '1') {
    characterPool.removeWhere((element) =>
        element == 'i' ||
        element == 'l' ||
        element == 'I' ||
        element == 'L' ||
        element == 'o' ||
        element == 'O');
  }
  // Generate a random password using the selected characters
  for (int i = 0; i < passwordLength; i++) {
    password += characterPool[random.nextInt(characterPool.length)];
  }

  return password;
}
