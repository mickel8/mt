#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <openssl/ssl.h>

int main(int argc, char **argv) {

    if (argc != 3) {
        printf("Pass remote ip and port\n");
        exit(EXIT_FAILURE);
    }
    
    char *remote_ip = argv[1];
    int remote_port = atoi(argv[2]);

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

    return 0;
}

