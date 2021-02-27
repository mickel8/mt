#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <time.h>

int main(int argc, char **argv) {

    if (argc != 4) {
        printf("Pass remote ip, port and number of packets to encode\n");
        exit(EXIT_FAILURE);
    }
    
    char *remote_ip = argv[1];
    int remote_port = atoi(argv[2]);
    int packets = atoi(argv[3]);

    printf("Remote addr: %s %d\n", remote_ip, remote_port);
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(remote_port);
    addr.sin_addr.s_addr = inet_addr(remote_ip);
    
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL) {
        printf("Error creating SSL_CTX\n");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        printf("Error creating SSL\n");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_use_certificate_file(ssl_ctx, "./client.cert", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, "./client.key", SSL_FILETYPE_PEM);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) == 1) {
        printf("TLS handshake finished successfully\n");
    } else {
        printf("TLS handshake error\n");
        exit(EXIT_FAILURE);
    }

    char *msg = "GET / HTTP/1.1\r\n"
        "Accept: text/html\r\n"
        "Host: google.com\r\n"
        "\r\n";
    int size = strlen(msg);

    int bytes = SSL_write(ssl, msg, size);
    printf("Wrote %d to TLS connection\n", bytes);

    char buf[1500];
    bytes = SSL_read(ssl, buf, sizeof(buf));
    printf("Read %d from TLS connection\n%s\n", bytes, buf);

    // change bio
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    if (rbio == NULL || wbio == NULL) {
        printf("Error initializing bio");
        exit(EXIT_FAILURE);
    }

    SSL_set_bio(ssl, rbio, wbio);
    sleep(1);

    printf("Starting benchmark\n");
    clock_t start = clock();
    for(int i = 0; i < packets; i++) {
        bytes = SSL_write(ssl, msg, size);
        if (bytes != 55) {
            printf("error\n");
            exit(EXIT_FAILURE);
        }
    }
    clock_t end = clock();
    printf("Preaparing %d packets took: %f\n", packets, (float)(end-start) / CLOCKS_PER_SEC);

    return 0;
}

