#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>

#define PACKET_SIZE 64

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void get_mac_address(const char *ip_addr, unsigned char *mac)
{
    struct sockaddr_in addr;
    struct arpreq arp_req;
    memset(&arp_req, 0, sizeof(arp_req));

    inet_pton(AF_INET, ip_addr, &addr.sin_addr);
    memcpy(&arp_req.arp_pa, &addr, sizeof(addr));

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (ioctl(sockfd, SIOCGARP, &arp_req) == -1) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memcpy(mac, arp_req.arp_ha.sa_data, 6);
    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        //std::cerr << "Usage: " << argv[0] << " <IPv4 address>" << std::endl;
        printf("Usage: argv[0] <IPv4 address>\n");
        return EXIT_FAILURE;
    }

    const char *ip_addr = argv[1];

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_addr);

    struct icmphdr icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));

    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = getpid();
    icmp_hdr.un.echo.sequence = 1;
    icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

    if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        perror("sendto");
        close(sockfd);
        return EXIT_FAILURE;
    }

    char buffer[PACKET_SIZE];
    socklen_t addr_len = sizeof(addr);

    if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len) <= 0) {
        perror("recvfrom");
        close(sockfd);
        return EXIT_FAILURE;
    }

    unsigned char mac[6];
    get_mac_address(ip_addr, mac);

    printf("%d%d%d%d%d%d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(sockfd);
    return EXIT_SUCCESS;
}
