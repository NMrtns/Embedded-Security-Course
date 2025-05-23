#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>



#define PORT 8443
#define SERVER_IP "server"  // Use "server" for Docker or "127.0.0.1" for local testing
#define BUFFER_SIZE 4096
#define OUTPUT_FILE "received_package.zip"

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_load_verify_locations(ctx, "rootCA.crt", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

void receive_file(SSL *ssl) {
    FILE *file = fopen(OUTPUT_FILE, "wb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes;
    while ((bytes = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, bytes, file);
    }

    fclose(file);
    printf("File received and saved as %s\n", OUTPUT_FILE);
}

int main() {
    initialize_openssl();
    SSL_CTX *ctx = create_context();

    configure_context(ctx);

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    struct hostent *host;

    // Get server hostname
    const char *hostname = SERVER_IP; // The server's hostname
    host = gethostbyname(hostname);
    if (host == NULL) {
        herror("gethostbyname failed");
        exit(EXIT_FAILURE);
    }

    // Prepare address structure
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);  // Copy the resolved IP address

    printf("Connecting to server at IP: %s, Port: %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    // Attempt to connect
    if (connect(client_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connection failed");
        printf("Error code: %d\n", errno); // Print the error code
        exit(EXIT_FAILURE);
    }

    printf("Connected to server successfully.\n");

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected to server, receiving file...\n");
        receive_file(ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
