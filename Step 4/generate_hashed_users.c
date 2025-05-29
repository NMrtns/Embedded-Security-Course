#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash_utils.h"

#define MAX_LINE_LENGTH 100
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 100
#define MAX_HASH_LENGTH 65
#define SALT_LENGTH 2

#define COUNTER "0"
#define FILE_INPUT "users.txt"
#define FILE_OUTPUT "hashed_users.txt"

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

int main() {
    FILE *input_file = fopen(FILE_INPUT, "r");
    FILE *output_file = fopen(FILE_OUTPUT, "w");

    if (input_file == NULL) {
        printf("Could not open %s for reading\n", FILE_INPUT);
        return 1;
    }

    if (output_file == NULL) {
        printf("Could not open %s for writing\n", FILE_OUTPUT);
        fclose(input_file);
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];

    while (fgets(line, sizeof(line), input_file)) {
        // Remove the newline character
        trim_newline(line);

        // Split the line into username and password
        char* token = strtok(line, ":");
        if (token != NULL) {
            strcpy(username, token);
            token = strtok(NULL, ":");
            if (token != NULL) {
                strcpy(password, token);
            }
        }

        // Generate a random salt
        unsigned char salt[SALT_LENGTH];
        generate_salt(salt, SALT_LENGTH);

        // Hash the password with the salt
        char hashed_password[MAX_HASH_LENGTH];
        hash_password(password, salt, hashed_password);

        // Convert salt to hex
        char salt_hex[SALT_LENGTH * 2 + 1];
        bytes_to_hex(salt, SALT_LENGTH, salt_hex);

        // Write to output file
        fprintf(output_file, "%s:%s:%s:%s\n", username, salt_hex, hashed_password, COUNTER);
    }

    fclose(input_file);
    fclose(output_file);

    return 0;
}