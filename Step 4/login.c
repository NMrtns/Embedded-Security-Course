#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash_utils.h"

#define MAX_LINE_LENGTH 300
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50
#define SALT_LENGTH 2
#define MAX_HASH_LENGTH 65
#define FILE_USERS "hashed_users.txt"

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

// Function to check if username and password match an entry in users.txt
int check_login(const char* username, const char* password) {

    // Removal of hardcoded credentials
    //if (strcmp(username, "superuser") == 0 && strcmp(password, "h4rdc0d3d") == 0) {
    //    return 1;
    //}

    FILE* file = fopen(FILE_USERS, "r");
    if (file == NULL) {
        printf("Could not open hashed_users.txt\n");
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    char file_username[MAX_USERNAME_LENGTH];
    char file_salt[SALT_LENGTH * 2 + 1]; // For hex representation
    char file_password[MAX_HASH_LENGTH];

    while (fgets(line, sizeof(line), file)) {
        // Remove the newline character
        trim_newline(line);
        printf("line: %s\n", line);

        // Split the line into username, salt and password
        char* token = strtok(line, ":");
        if (token != NULL) {
            strcpy(file_username, token);
            printf("file_username: %s\n", file_username);
            token = strtok(NULL, ":");
            if (token != NULL) {
                strcpy(file_salt, token);
                printf("file_salt: %s\n", file_salt);
                token = strtok(NULL, ":");
                if (token != NULL) {
                    strcpy(file_password, token);
                    printf("file_password: %s\n", file_password);
                }
            }
        }

        // Convert the salt from hex to bytes
        unsigned char salt[SALT_LENGTH];
        for (int i = 0; i < SALT_LENGTH; i++) {
            if (sscanf(file_salt + (i * 2), "%2hhx", &salt[i]) != 1) {
                printf("Error: Failed to parse salt byte %d from file_salt '%s'\n", i, file_salt);
                fclose(file);
                return 0; // Exit if conversion fails
            }
        }

        // Print the salt in bytes
        printf("scanned Salt in hex: %02x %02x\n", salt[0], salt[1]);

        // Hash the entered password with the salt from the file
        unsigned char hashed_password[MAX_HASH_LENGTH];
        hash_password(password, salt, hashed_password);

        printf("comparing %s with %s\n", hashed_password, file_password);

        // Compare entered username and password with the file's values
        if (strcmp(username, file_username) == 0 && strcmp(hashed_password, file_password) == 0) {
            fclose(file);
            return 1;  // Login successful
        }
    }

    fclose(file);
    return 0;  // Login failed
}

int increase_counter(const char* username) {
    FILE* file = fopen(FILE_USERS, "r+");
    if (file == NULL) {
        printf("Could not open hashed_users.txt\n");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    char file_username[MAX_USERNAME_LENGTH];
    char file_salt[SALT_LENGTH * 2 + 1]; // For hex representation
    char file_password[MAX_HASH_LENGTH];
    char file_counter[1];

    while (fgets(line, sizeof(line), file)) {
        // Remove the newline character
        trim_newline(line);
        printf("line: %s\n", line);

        // Read user
        char* token = strtok(line, ":");
        if (token != NULL) {
            strcpy(file_username, token);
            printf("file_username: %s\n", file_username);
        }

        // Read last character in line
        size_t len = strlen(line);
        if (len > 0) {
            file_counter[0] = line[len - 2];
            printf("counter before increment: %c\n", file_counter);
        }

        // Compare entered username with the file's values
        if (strcmp(username, file_username) == 0) {
            // Increase the counter
            int counter = atoi(file_counter);
            counter++;
            line[len - 2] = counter + '0';  // Convert int to char
            //print line with new counter to file at index of fgets
            fseek(file, -len, SEEK_CUR);  // Move the file pointer back to the start of the line
            //fseek(file, -strlen(file_counter), SEEK_CUR);
            fprintf(file, "%s\n", line);
            printf("counter after increment: %d\n", counter);
            return counter;  // Return the new counter value
        }
    }

    fclose(file);
}

int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char command[MAX_COMMAND_LENGTH];

    // Prompt user for username and password
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    trim_newline(username);  // Remove newline character

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    trim_newline(password);  // Remove newline character

    // Check login credentials
    if (check_login(username, password)) {
        printf("Login successful!\n");

        // Command prompt loop
        while (1) {
            printf("> ");
            scanf("%s", command);

            if (strcmp(command, "exit") == 0) {
                break;
            } else {
                printf("Unknown command.\nAllowed command is exit.\n");
            }
        }
    } else {
        printf("Login failed.\n");
        int counter = increase_counter(username);
    }

    return 0;
}