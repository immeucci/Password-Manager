# Password Manager 

A simple and secure password manager written in **Dart**.  
This program allows you to generate, store, encrypt, and retrieve passwords using a **master password** for authentication.

## Features 
- Secure password storage using **AES-256 encryption**.
- Master password hashed with **Argon2** for added security.
- Password generation with different strength levels.
- JSON file-based storage.
- CLI-based interaction.

### Prerequisites
- Dart SDK installed ([Install Dart](https://dart.dev/get-dart))

## Installation
1. **Clone the Repository:**  
   Start with cloning the github repo in your system:
```bash
git clone https://github.com/immeucci/Password-Manager.git
```
2. **Navigate to the directory:**
```bash
cd Password-Manager
```
3. **Download the dependencies:**
```bash
dart pub get
```
4. **Run the program**
```bash
dart run
```

## Usage
- when the program is run 2 options will be shown in the command line interface
1. If you select the first option you can create a password using the generator
2. If you select the second option you enter the password manager:

### Password Manager
- The first time you access the password manager you have to create a master password, you need to remember it to access the manager a second time.
- Once you insert the master password you have 4 options:
1. Create a new password.  
   A strong password is generated and encrypted using AES-256, then stored in a local JSON file along with the service name.
2. Find a password associated with the relative service name.  
   Retrieve the password associated with a given service name, decrypted securely after authentication. 
3. Delete the password file.  
   This action will permanently delete the passwords.json file, removing all stored data.
4. Exit the manager

## Disclaimer
This project is intended for educational purposes and personal use.
Always take extra steps to ensure the safety of your data and don't store highly sensitive information in plain JSON files without additional protections.
