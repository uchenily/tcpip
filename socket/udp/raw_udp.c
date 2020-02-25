#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <arpa/inet.h>

// Structure definition for the pseudo header we're going to use to calculate
// UDP checksum. This encapsulates the standart UDP header: 
struct psd_udp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short udp_len;
	struct udphdr udp;
};

// Checksum function:
unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

// in_cksum_udp takes udp header, its length, source and destionation IP 
// addresses, puts them into the pseudo header, 
// and inputs it to the internet chekcsum function:
unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len)
{
	struct psd_udp buf;

	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_UDP;
	buf.udp_len = htons(len);
	memcpy(&(buf.udp), addr, len);
	return in_cksum((unsigned short *)&buf, 12 + len);
}

int
main(int argc, char **argv)
{
	struct ip ip;
	struct udphdr udp;
	int sd;
	const int on = 1;
	struct sockaddr_in sin;
	u_char *packet;


	// Grab some space for our packet:
	packet = (u_char *)malloc(60);

	// Just like in ICMP example, we fill in the IP header fields:
	ip.ip_hl = 0x5;
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = 60;
	ip.ip_id = htons(12345);
	ip.ip_off = 0x0;
	ip.ip_ttl = 64;
	ip.ip_p = IPPROTO_UDP;
	ip.ip_sum = 0x0;
	//ip.ip_src.s_addr = inet_addr("10.0.0.9");
	ip.ip_src.s_addr = inet_addr(argv[1]);
	//ip.ip_dst.s_addr = inet_addr("10.0.0.1");
	ip.ip_dst.s_addr = inet_addr(argv[2]);
	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
	memcpy(packet, &ip, sizeof(ip));

	/* We prepare our UDP header, calculate its cheksum, append it to the packet just after the IP header; */
	// source UDP port:
	udp.uh_sport = htons(50000);

	// Destination UDP port:
	udp.uh_dport = htons(53);

	// Length of the UDP datagram (UDP header length + UDP data):
	udp.uh_ulen = htons(8);

	// Set the checksum field to zero, and feed the checksum function, 
	// save the returned value in the checksum field:
	udp.uh_sum = 0;
	udp.uh_sum = in_cksum_udp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&udp, sizeof(udp));
	memcpy(packet + 20, &udp, sizeof(udp));

	// Below is just the same with the ICMP sample:
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(1);
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_dst.s_addr;

	if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		exit(1);
	}
	return 0;
}
