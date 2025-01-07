# Secure Password Manager

This project is a simple and secure password manager written in C, utilizing OpenSSL for AES-256 encryption. The program allows users to store, encrypt, and retrieve passwords securely.

## Features
- Securely encrypt and store passwords.
- View stored passwords in a decrypted format.
- AES-256 encryption with randomly generated Initialization Vector (IV).
- Key generation and secure storage of encryption keys.

## Requirements
- OpenSSL library
- GCC compiler (Linux/MacOS)
- MinGW or Visual Studio (Windows)

## Installation and Compilation

### Clone the Repository
Clone the repository to your local machine using Git:
```bash
git clone https://github.com/mhdthariq/PasswordManagerCLang.git
cd PasswordManagerCLang
```

### Linux (Debian, Ubuntu, Fedora, Arch, openSUSE)

**Debian/Ubuntu**:
1. Install OpenSSL development libraries if not already installed:
   ```bash
   sudo apt update
   sudo apt install libssl-dev
   ```
2. Compile the program:
   ```bash
   gcc -o PasswordManager PasswordManager.c -lssl -lcrypto
   ```
3. Run the program:
   ```bash
   ./PasswordManager
   ```

**Fedora**:
1. Install OpenSSL development libraries if not already installed:
   ```bash
   sudo dnf install openssl-devel
   ```
2. Compile the program:
   ```bash
   gcc -o PasswordManager PasswordManager.c -lssl -lcrypto
   ```
3. Run the program:
   ```bash
   ./PasswordManager
   ```

**Arch Linux**:
1. Install OpenSSL development libraries:
   ```bash
   sudo pacman -S openssl
   ```
2. Compile the program:
   ```bash
   gcc -o PasswordManager PasswordManager.c -lssl -lcrypto
   ```
3. Run the program:
   ```bash
   ./PasswordManager
   ```

**openSUSE**:
1. Install OpenSSL development libraries:
   ```bash
   sudo zypper install libopenssl-devel
   ```
2. Compile the program:
   ```bash
   gcc -o PasswordManager PasswordManager.c -lssl -lcrypto
   ```
3. Run the program:
   ```bash
   ./PasswordManager
   ```

### MacOS
1. Install OpenSSL if not already installed:
   ```bash
   brew install openssl
   ```
2. Compile the program:
   ```bash
   gcc -o PasswordManager PasswordManager.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
   ```
3. Run the program:
   ```bash
   ./PasswordManager
   ```

### Windows
1. Download and install OpenSSL for Windows.
2. Download and install MinGW or Visual Studio.
3. Compile with MinGW:
   ```bash
   gcc -o PasswordManager.exe PasswordManager.c -lssl -lcrypto
   ```
4. Run the program:
   ```bash
   .\PasswordManager.exe
   ```

## Usage

1. When you first run the program, it generates a new encryption key if none exists.
2. Options:
   - **view**: Display all stored passwords.
   - **add**: Add a new password to the store.
   - **q**: Quit the program.

3. Passwords are encrypted and stored in `password.txt`.
4. The encryption key is stored in `key.bin`.

## Notes
- Keep the `key.bin` file safe. If deleted, stored passwords cannot be decrypted.
- The password file (`password.txt`) can only be decrypted using the exact key used to encrypt it.
- Use strong passwords to ensure maximum security.

## Troubleshooting
- If you encounter errors related to OpenSSL, ensure the library paths are correctly specified during compilation.
- Ensure you have the correct permissions to read/write `key.bin` and `password.txt`.
