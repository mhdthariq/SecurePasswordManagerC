#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_FILE "key.bin"
#define PASSWORD_FILE "password.txt"
#define KEY_SIZE 32
#define IV_SIZE 16
#define BUFFER_SIZE 256

// Function prototypes
void greet_user();
void initialize_key(unsigned char *key);
void generate_key(unsigned char *key);
void save_key(const unsigned char *key);
void load_key(unsigned char *key);
void encrypt_password(const unsigned char *key, const char *plain, char *encrypted);
void decrypt_password(const unsigned char *key, const char *encrypted, char *plain);
void add_password(const unsigned char *key);
void view_passwords(const unsigned char *key);

int main() {
    unsigned char key[KEY_SIZE];
    initialize_key(key);

    greet_user();

    while (1) {
        printf("\nOptions: [view] View passwords | [add] Add passwords | [q] Quit\n");
        printf("Select an option: ");
        char option[10];
        scanf("%s", option);

        if (strcmp(option, "q") == 0) {
            printf("\nThank you for using the Secure Password Manager. Goodbye!\n");
            break;
        } else if (strcmp(option, "view") == 0) {
            view_passwords(key);
        } else if (strcmp(option, "add") == 0) {
            add_password(key);
        } else {
            printf("Invalid option. Please try again.\n");
        }
    }

    return 0;
}

void greet_user() {
    printf("============================================================\n");
    printf("Welcome to the Secure Password Manager!\n");
    printf("Easily store and view your encrypted password securely.\n");
    printf("============================================================\n");
}

void initialize_key(unsigned char *key) {
    FILE *file = fopen(KEY_FILE, "rb");
    if (!file) {
        printf("No encryption key found. Generating a new one.\n");
        generate_key(key);
        save_key(key);
    } else {
        fread(key, 1, KEY_SIZE, file);
        fclose(file);
    }
}

void generate_key(unsigned char *key) {
    RAND_bytes(key, KEY_SIZE);
}

void save_key(const unsigned char *key) {
    FILE *file = fopen(KEY_FILE, "wb");
    if (!file) {
        perror("Error saving the key");
        exit(1);
    }
    fwrite(key, 1, KEY_SIZE, file);
    fclose(file);
}

void encrypt_password(const unsigned char *key, const char *plain, char *encrypted) {
    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE); // Generate a random IV

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len, ciphertext_len;
    unsigned char ciphertext[BUFFER_SIZE];
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plain, strlen(plain));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Combine IV and ciphertext (IV is stored first)
    memcpy(encrypted, iv, IV_SIZE);
    memcpy(encrypted + IV_SIZE, ciphertext, ciphertext_len);
    encrypted[IV_SIZE + ciphertext_len] = '\0'; // Null-terminate for safety
}

void decrypt_password(const unsigned char *key, const char *encrypted, char *plain) {
    unsigned char iv[IV_SIZE];
    memcpy(iv, encrypted, IV_SIZE); // Extract IV from the first part of the encrypted data

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len, decrypted_len;
    unsigned char decrypted[BUFFER_SIZE];
    EVP_DecryptUpdate(ctx, decrypted, &len, (unsigned char *)(encrypted + IV_SIZE), strlen(encrypted) - IV_SIZE);
    decrypted_len = len;

    EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
    decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);

    decrypted[decrypted_len] = '\0'; // Null-terminate decrypted data
    strcpy(plain, (char *)decrypted);
}

void add_password(const unsigned char *key) {
    char username[BUFFER_SIZE], password[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    int encrypted_len;

    printf("Enter username: ");
    scanf("%s", username);

    printf("Enter password: ");
    scanf("%s", password);

    // Encrypt the password
    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    encrypted_len = 0;

    // Store IV at the beginning of encrypted buffer
    memcpy(encrypted, iv, IV_SIZE);
    encrypted_len += IV_SIZE;

    // Encrypt the actual password
    EVP_EncryptUpdate(ctx, encrypted + encrypted_len, &len, (unsigned char *)password, strlen(password));
    encrypted_len += len;

    EVP_EncryptFinal_ex(ctx, encrypted + encrypted_len, &len);
    encrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Write to file in binary mode
    FILE *file = fopen(PASSWORD_FILE, "ab");
    if (!file) {
        perror("Error opening password file");
        return;
    }

    // Write username length, username, encrypted data length, and encrypted data
    uint32_t username_len = strlen(username);
    fwrite(&username_len, sizeof(uint32_t), 1, file);
    fwrite(username, 1, username_len, file);
    fwrite(&encrypted_len, sizeof(uint32_t), 1, file);
    fwrite(encrypted, 1, encrypted_len, file);

    fclose(file);

    printf("Password for account '%s' has been saved securely.\n", username);
}

void view_passwords(const unsigned char *key) {
    FILE *file = fopen(PASSWORD_FILE, "rb");
    if (!file) {
        printf("No passwords saved yet. Add some passwords first.\n");
        return;
    }

    printf("\n%-20s | %-20s\n", "Username", "Password");
    printf("--------------------------------------------\n");

    while (!feof(file) && !ferror(file)) {
        uint32_t username_len, encrypted_len;
        char username[BUFFER_SIZE];
        unsigned char encrypted[BUFFER_SIZE];
        char decrypted[BUFFER_SIZE];

        // Read username length and username
        if (fread(&username_len, sizeof(uint32_t), 1, file) != 1) break;
        if (fread(username, 1, username_len, file) != username_len) break;
        username[username_len] = '\0';

        // Read encrypted data length and encrypted data
        if (fread(&encrypted_len, sizeof(uint32_t), 1, file) != 1) break;
        if (fread(encrypted, 1, encrypted_len, file) != encrypted_len) break;

        // Decrypt the password
        unsigned char iv[IV_SIZE];
        memcpy(iv, encrypted, IV_SIZE);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        int len, plaintext_len = 0;
        unsigned char plaintext[BUFFER_SIZE];

        EVP_DecryptUpdate(ctx, plaintext, &len, encrypted + IV_SIZE, encrypted_len - IV_SIZE);
        plaintext_len = len;

        EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        plaintext[plaintext_len] = '\0';
        printf("%-20s | %-20s\n", username, plaintext);
    }

    fclose(file);
}
