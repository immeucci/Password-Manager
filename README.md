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
1. Create a new password
2. Find a password associated with the relative service name
3. Delete the password file.
4. Exit the manager
