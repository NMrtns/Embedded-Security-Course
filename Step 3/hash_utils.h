#ifndef HASH_UTILS_H
#define HASH_UTILS_H

void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex_str);
void hash_password(const char* password, const unsigned char* salt, char* hashed_password);
void generate_salt(unsigned char* salt, size_t length);

#endif