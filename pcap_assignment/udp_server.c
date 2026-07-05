#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

int main()
{
    struct sockaddr_in server;
    struct sockaddr_in client;
    socklen_t clientlen = sizeof(client); // Fixed warning: clientlen should be socklen_t
    char buf[1500];

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("ERROR opening socket");
        return 1;
    }

    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(9090);

    if (bind(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        perror("ERROR on binding");
        close(sock);
        return 1;
    }

    printf("[*] UDP Server listening on port 9090...\n");

    // We only process one packet in this test run to allow the program to exit gracefully
    bzero(buf, 1500);
    if (recvfrom(sock, buf, 1500-1, 0, (struct sockaddr *) &client, &clientlen) < 0) {
        perror("ERROR in recvfrom");
    } else {
        printf("[+] Received: %s\n", buf);
    }
    
    close(sock);
    return 0;
}
