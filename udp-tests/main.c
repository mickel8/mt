#include <stdio.h>
#include <sys/socket.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

int main(int argc, char **argv) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);    
    assert(fd >= 0);

    char buf[10000] = {0};
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8989);
    addr.sin_addr.s_addr = inet_addr("192.168.0.1");
    int ret = sendto(fd, &buf, 10000, 0, (struct sockaddr *)&addr, sizeof(addr));
    switch(errno) {
        case EMSGSIZE:
            printf("EMSGSIZE\n");
            break;
        default:
            printf("error %d\n", ret);
    };
    return 0;
}
