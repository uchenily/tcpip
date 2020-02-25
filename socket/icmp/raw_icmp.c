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
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

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

int
main(int argc, char **argv)
{
	struct ip ip;
	struct udphdr udp;
	struct icmp icmp;
	int sd;
	const int on = 1;
	struct sockaddr_in sin;
	u_char *packet;

	// Grab some space for our packet
	packet = (u_char *)malloc(60);

	// Fill Layer II (IP protocol) fields... 
	// Header length (including options) in units of 32 bits (4 bytes). 
	// Assuming we will not send any IP options, IP header length is 20 bytes,
	// so we need to stuff (20 / 4 = 5 here)
	ip.ip_hl = 0x5; // 5bytes --> 20bits

	// ipv4
	ip.ip_v = 0x4;

	// Type of Service. Packet precedence
	ip.ip_tos = 0x0;

	// Total length for our packet, all multibyte fields (fields bigger than 
	// 8 bits) require to be converted to the network byte-order:
	ip.ip_len = htons(60);

	// ID field uniquely identifies each datagram sent by this host
	ip.ip_id = htons(12345);

	// Fragment offset for our packet. We set this to 0x0 since we don't 
	// desire any fragmentation
	ip.ip_off = 0x0;

	// Time to live. Maximum number of hops that the packet can pass while
	// traveling through its destination.
	ip.ip_ttl = 64;

	// Upper layer (Lyper III) protocol number
	ip.ip_p = IPPROTO_ICMP;

	// We set the checksum value to zero before passing the packet into the 
	// checksum function. Note that this checksum is calculate over the 
	// IP header only. Upper layer protocols have their own checksum fields, 
	// and must be calculated seperately. 
	ip.ip_sum = 0x0;

	// Source IP address, this might well be any IP address that may or 
	// may NOT be one of the assigned address to one of our interfaces
	//ip.ip_src.s_addr = inet_addr("10.0.0.1");
	ip.ip_src.s_addr = inet_addr(argv[1]);

	// Destination IP address
	//ip.ip_dst.s_addr = inet_addr("10.0.0.2");
	ip.ip_dst.s_addr = inet_addr(argv[2]);

	// We pass the IP header and its length into the internet checksum function.
	// The function returns us as 16-bit checksum value for the header
	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));

	// We're finished preparing our IP header. 
	// Let's copy it into the very begining of our packet
	memcpy(packet, &ip, sizeof(ip));

	// As for Layer III (ICMP) data, Icmp type
	icmp.icmp_type = ICMP_ECHO;

	// Code 0, Echo Request
	icmp.icmp_code = 0;
	
	// ID. random number
	icmp.icmp_id = 2333;

	// Icmp sequence number
	icmp.icmp_seq = 0;

	// Just like with the Ip header, we set the ICMP header checksum to zero 
	// and pass the icmp packet into the cheksum function.
	// We store the returned value in the checksum field of ICMP header
	icmp.icmp_cksum = 0;
	icmp.icmp_cksum = in_cksum((unsigned short *)&icmp, 8);

	// We append the ICMP header to the packet at offset 20
	memcpy(packet + 20, &icmp, 8);

	// We crafted our packet byte-by-byte. 
	// It's time we inject it into the network.
	//First create our raw socket
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}

	// We tell kernel that we've also prepared the IP header;
	// there's nothing that the IP stack will do about it
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	// Still, the kernel is going to prepare Layer I data for us.
	// For that, we need to specify a destination for the kernel 
	// in order for it to decide where to send the raw datagram.
	// We fill in a struct in_addr with the desired destination IP address,
	// and pass this structure to the sendto(2) or sendmsg(2) system calls
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_dst.s_addr;

	// As for writing the packet... We cannot use send(2) system call for this,
	// since the socket is not a "connected" type of socket.
	// As stated in the above paragraph, we need to tell where to send the 
	// raw IP datagram. sendto(2) and sendmsg(2) system calls are designed to 
	// handle this
	if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		exit(1);
	}

	return 0;
}


/*
 * http://www.enderunix.org/docs/en/rawipspoof/
 * 
 * root@ubuntu:~/socket# tcpdump icmp -nvvvl
 * tcpdump: listening on enp1s0, link-type EN10MB (Ethernet), capture size 262144 bytes
 * 19:51:39.148709 IP (tos 0x0, ttl 64, id 12345, offset 0, flags [none], proto ICMP (1), length 60)
 *     10.0.0.9 > 10.0.0.1: ICMP echo request, id 7433, seq 0, length 40
 * 19:51:39.153645 IP (tos 0x0, ttl 64, id 26591, offset 0, flags [none], proto ICMP (1), length 60)
 *     10.0.0.1 > 10.0.0.9: ICMP echo reply, id 7433, seq 0, length 40
 * 
 * ./icmp 10.0.0.9 10.0.0.1
 * 
 */
