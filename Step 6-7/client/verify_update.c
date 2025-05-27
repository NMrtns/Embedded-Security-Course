#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define UPDATE_FILE "software_update.bin"
#define SIG_FILE "software_update.sig"
#define CERT_FILE "software_update.crt"
#define CA_FILE "rootCA.crt"
#define CHECKSUM_FILE "software_update.checksum"

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

X509 *load_cert(const char *filename) {
    FILE *fp = fopen(filename, "r");
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

int verify_certificate(const char *cert_file, const char *ca_file) {
    // Load the certificate to be verified
    X509 *cert = load_cert(cert_file);

    // Create a new X509_STORE for the CA
    X509_STORE *store = X509_STORE_new();
    // Load rootCA certificate
    X509 *ca_cert = load_cert(ca_file);
    if (ca_cert == NULL) {
        printf("Failed to load CA certificate from %s\n", ca_file);
        return 0;
    }
    // Add CA certificate to the store
    X509_STORE_add_cert(store, ca_cert);

    // Create contexxt to verify the certificate
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    // Init store
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    // Verify the certificate
    int result = X509_verify_cert(ctx);
    // Cleanup
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    ctx = NULL;
    store = NULL;
    return result;
}

int verify_signature(const char *update_file, const char *sig_file, const char *cert_file) {
    FILE *f_update = fopen(update_file, "rb");
    FILE *f_sig = fopen(sig_file, "rb");
    if (!f_update || !f_sig) {
        printf("Failed to open update or signature file\n");
        return 0;
    }

    // Read update file into buffer
    unsigned char buffer[4096];
    size_t update_len = fread(buffer, 1, sizeof(buffer), f_update);
    fclose(f_update);

    // Read signature file
    unsigned char sig[256];
    size_t sig_len = fread(sig, 1, sizeof(sig), f_sig);
    fclose(f_sig);

    // Load the certificate
    X509 *cert = load_cert(cert_file);
    // get public key from certificate
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    // create context for digest verification
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    
    // init digest verification
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        printf("Failed to initialize digest verify\n");
        return 0;
    }

    // Update the digest with the update file content
    if (EVP_DigestVerifyUpdate(mdctx, buffer, update_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        printf("Failed to update digest verify\n");
        return 0;
    }

    // Finalize the verification
    int result = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    
    // Cleanup
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pubkey);
    X509_free(cert);

    return result;
}

int verify_sha256(const char *update_file, const char *checksum_file) {
    // Open the update file and checksum file
    FILE *f_update = fopen(update_file, "rb");
    FILE *f_checksum = fopen(checksum_file, "r");
    if (!f_update || !f_checksum) {
        printf("Failed to open update or checksum file\n");
        return 0;
    }

    // Read the checksum from the file, assuming it's a hex string
    unsigned char expected_checksum_hex[64];
    fscanf(f_checksum, "%64s", expected_checksum_hex);
    fclose(f_checksum);
    // Convert the hex string to bytes
    unsigned char expected_checksum[32];
    for (int i = 0; i < 32; i++) {
        sscanf((const char *)&expected_checksum_hex[i * 2], "%2hhx", &expected_checksum[i]);
    }

    // Read the update file
    unsigned char buffer[4096];
    size_t update_len = fread(buffer, 1, sizeof(buffer), f_update);
    fclose(f_update);

    // Create a SHA-256 context
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    // Update the SHA-256 context with the update file content
    SHA256_Update(&sha256, buffer, update_len);
    // Finalize the SHA-256 hash
    unsigned char actual_checksum[32];
    SHA256_Final(actual_checksum, &sha256);

    // Compare checksums
    return memcmp(expected_checksum, actual_checksum, 32) == 0;
}

int verify_checksum(const char *update_file, const char *checksum_file) {
    // Open the update file and checksum file
    FILE *f_update = fopen(update_file, "rb");
    FILE *f_checksum = fopen(checksum_file, "r");
    if (!f_update || !f_checksum) {
        printf("Failed to open update or checksum file\n");
        return 0;
    }

    // Read the checksum from the file
    unsigned char expected_checksum[64];
    fscanf(f_checksum, "%64s", expected_checksum);
    fclose(f_checksum);

    // Calculate the checksum of the update file
    unsigned char actual_checksum[64];
    //unsigned char buffer[4096];
    //size_t bytes_read;
    // Init context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    unsigned char buffer[4096];
    size_t update_len = fread(buffer, 1, sizeof(buffer), f_update);
    fclose(f_update);
    // Update the digest with the update file content
    EVP_DigestUpdate(mdctx, buffer, update_len);
    //// Read the update file in chunks and update the digest
    //while ((bytes_read = fread(buffer, 1, sizeof(buffer), f_update)) > 0) {
    //    EVP_DigestUpdate(mdctx, buffer, bytes_read);
    //}
    //fclose(f_update);

    // Finalize the digest to get the checksum
    EVP_DigestFinal_ex(mdctx, actual_checksum, NULL);
    // Cleanup
    EVP_MD_CTX_free(mdctx);

    printf("Expected checksum: %s\n", expected_checksum);
    printf("Actual checksum: %s\n", actual_checksum);

    // Compare checksums
    return memcmp(expected_checksum, actual_checksum, 64) == 0;
}

int main() {
    initialize_openssl();
    //SSL_CTX *ctx = create_context();

    printf("Verifying certificate...\n");
    if (!verify_certificate(CERT_FILE, CA_FILE)) {
        printf("Certificate verification failed.\n");
        return 1;
    }
    printf("Certificate verified.\n");

    printf("Verifying signature...\n");
    if (!verify_signature(UPDATE_FILE, SIG_FILE, CERT_FILE)) {
        printf("Signature verification failed.\n");
        return 1;
    }
    printf("Signature verified.\n");

    printf("Verifying checksum...\n");
    if (!verify_sha256(UPDATE_FILE, CHECKSUM_FILE)) {
        printf("Checksum verification failed.\n");
        return 1;
    }
    printf("Checksum verified.\n");
    printf("Software update is valid.\n");
    return 0;
}