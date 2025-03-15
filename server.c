// tcp server to handle encrypted client messages
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define port 5050
#define max_buffer 2048

unsigned char aes_key[32] = "this is a key123this is a key123";
unsigned char aes_iv[16] = "1234567890123456";

void exit_on_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// decrypt incoming message with aes-256-cbc
int decrypt_message(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void *client_connection(void *socket_fd) {
    int client_sock = *(int *)socket_fd;
    unsigned char encrypted_buffer[max_buffer] = {0};
    unsigned char plaintext[max_buffer] = {0};

    // receive encrypted data from client
    int ciphertext_len = read(client_sock, encrypted_buffer, max_buffer);
    if (ciphertext_len <= 0) {
        close(client_sock);
        free(socket_fd);
        pthread_exit(NULL);
    }

    // print ciphertext in hex
    printf("[server] ciphertext received (hex): ");
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", encrypted_buffer[i]);
    printf("\n");

    // decrypt received message
    int plaintext_len = decrypt_message(encrypted_buffer, ciphertext_len, plaintext);
    plaintext[plaintext_len] = '\0';

    // log plaintext message
    printf("[server] decrypted message: %s\n", plaintext);

    // send acknowledgment
    char *response = "message received securely!";
    send(client_sock, response, strlen(response), 0);

    close(client_sock);
    free(socket_fd);
    pthread_exit(NULL);
}

int main() {
    int server_fd, *new_sock;
    pthread_t client_thread;

    struct sockaddr_in server_addr = {0};

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) exit_on_error("socket creation failed");

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        exit_on_error("bind failed");

    listen(server_fd, 5);
    printf("server listening on port %d...\n", port);

    while (1) {
        new_sock = malloc(sizeof(int));
        *new_sock = accept(server_fd, NULL, NULL);
        if (*new_sock < 0) {
            free(new_sock);
            continue;
        }
        pthread_create(&client_thread, NULL, client_connection, (void*)new_sock);
        pthread_detach(client_thread);
    }

    close(server_fd);
    return 0;
}
