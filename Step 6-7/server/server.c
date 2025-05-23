#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define PORT 8443
#define BUFFER_SIZE 4096
#define SOFTWARE_FILE "software_package.zip"

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Load server's certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load and verify the client's certificate
    SSL_CTX_load_verify_locations(ctx, "rootCA.crt", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

void handle_client(SSL *ssl) {
    FILE *file = fopen(SOFTWARE_FILE, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    // Send file contents to client
    char buffer[BUFFER_SIZE];
    int bytes;
    while ((bytes = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (SSL_write(ssl, buffer, bytes) <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
    }
    fclose(file);
}

int main() {
    initialize_openssl();
    SSL_CTX *ctx = create_context();

    configure_context(ctx);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("Server listening on port %d\n", PORT);
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            printf("Client connected, sending software update...\n");
            handle_client(ssl);
            printf("Software update sent...\n");
        }

        printf("Shutting down connection...\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        printf("Listening for new incoming connection...\n");
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}