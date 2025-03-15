// encrypted tcp client
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define port 5050
#define buffer_size 1024

unsigned char aes_key[32] = "this is a key123this is a key123";
unsigned char aes_iv[16] = "1234567890123456";

void exit_on_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// encrypt message using aes-256-cbc
int encrypt_message(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main() {
    int sock;
    struct sockaddr_in serv_addr;
    unsigned char plaintext[buffer_size];
    unsigned char ciphertext[buffer_size];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        exit_on_error("connection failed");

    printf("enter message to encrypt/send: ");
    fgets((char*)plaintext, buffer_size, stdin);
    plaintext[strcspn((char*)plaintext, "\n")] = 0;

    int ciphertext_len = encrypt_message(plaintext, strlen((char*)plaintext), ciphertext);

    // print ciphertext in hex before sending
    printf("[client] ciphertext being sent (hex): ");
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    send(sock, ciphertext, ciphertext_len, 0);

    char response[buffer_size] = {0};
    int len_received = recv(sock, response, buffer_size, 0);
    response[len_received] = '\0';
    printf("server response: %s\n", response);

    close(sock);
    return 0;
}
