#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <time.h>

#define SALT_LENGTH 2
#define MAX_HASH_LENGTH 65

// Function to convert bytes to a hexadecimal string
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

// Function to hash password with SHA-256
void hash_password(const char* password, const unsigned char* salt, char* hashed_password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char salted_password[MAX_HASH_LENGTH + SALT_LENGTH];

    // Prepend the salt to the password
    memcpy(salted_password, salt, SALT_LENGTH);
    strcpy(salted_password + SALT_LENGTH, password);

    // Hash the salted password
    SHA256((unsigned char*)salted_password, strlen(salted_password), hash);

    // Convert the hash to a hexadecimal string
    bytes_to_hex(hash, SHA256_DIGEST_LENGTH, hashed_password);
}

void generate_salt(unsigned char* salt, size_t length) {
    static int initialized = 0;
    if (!initialized) {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }

    for (size_t i = 0; i < length; i++) {
        salt[i] = (unsigned char)(rand() % 256);
    }
}