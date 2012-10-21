/*
 * Copyright (C) 2012 Jimmy Scott #jimmy#inet-solutions#be#. Belgium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. The names of the authors may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pcap.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define __FAVOR_BSD
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif /* __linux__ */

#include "udptable.h"

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif /* PCAP_NETMASK_UNKNOWN */

#define BSDLOOP_SIZE 4
#define ETHER_SIZE sizeof(struct ether_header)
#define IPV4_SIZE sizeof(struct ip) /* without options!! */
#define UDP_SIZE sizeof(struct udphdr)

typedef struct stackinfo_t {
	bpf_u_int32 offset;
} stackinfo_t;

typedef struct packetinfo_t {
	int link_type;
} packetinfo_t;

/* function prototypes */
static void usage(char *program);
static struct stackinfo_t *stackinfo_new(void);
static struct packetinfo_t *packetinfo_new(int link_type);
static pcap_t *setup_capture(char *device, char *filter);
static int setup_filter(pcap_t *capt, char *device, char *filter);
static int check_link_type(pcap_t *capt);
static int install_sigalrm(pcap_t *capt);
static void handle_sigalrm(int signo);
static void handle_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static void handle_loopback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet, int type);
static void handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static void handle_ipv4(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static void handle_udp(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

/* for pcap_breakloop in sigalrm */
pcap_t *alrm_pcap_handle = NULL;

int
main(int argc, char **argv)
{
	pcap_t *capt;
	int link_type;
	struct packetinfo_t *packetinfo;
	
	/* check usage */
	if (argc != 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	/* setup capturing using device and filter */
	capt = setup_capture(argv[1], argv[2]);
	if (!capt)
		return EXIT_FAILURE;
	
	/* install signal handler to break pcap_loop */
	if (install_sigalrm(capt) != 0)
		return EXIT_FAILURE;
	
	/* create udp table for max 100 source addresses */
	if (udptable_init(100) != 0) {
		perror("ERROR: Couldn't create udp table");
		return EXIT_FAILURE;
	}
	
	/* check and get link type */
	if ((link_type = check_link_type(capt)) == -1)
		return EXIT_FAILURE;
	
	/* get packetinfo structure */
	packetinfo = packetinfo_new(link_type);
	
	/* stop capturing after 10 seconds */
	alarm(10);
	
	/* capture and process packets */
	pcap_loop(capt, 0, handle_packet, (u_char *)packetinfo);
	
	/* print the udp table entries */
	udptable_list();
	
	return EXIT_SUCCESS;
}

static void
usage(char *program)
{
	fprintf(stderr, "usage: %s <interface> <filter>\n", program);
}

/*
 * Re-initialize stackinfo to default values.
 *
 * The stackinfo structure is used to pass info down the protocol stack:
 *
 *  - The stackinfo.offset is the offset inside the captured packet
 *    where the header (or data) of the current layer starts. Each layer
 *    handler must update this offset to point to the next layer before
 *    calling the handler for the next layer.
 *
 * Returns a pointer to the static stackinfo buffer.
 */

static struct stackinfo_t *
stackinfo_new(void)
{
	static struct stackinfo_t stackinfo;
	
	stackinfo.offset = 0;
	
	return &stackinfo;
}

/*
 * Initialize packetinfo.
 *
 * The packetinfo structure is used to pass info to the packet handler:
 *
 *  - The packetinfo.link_type is the datalink type.
 *
 * Returns a pointer to the static packetinfo buffer.
 */

static struct packetinfo_t *
packetinfo_new(int link_type)
{
	static struct packetinfo_t packetinfo;
	
	packetinfo.link_type = link_type;
	
	return &packetinfo;
}

/*
 * Open capture device and setup capture filter.
 *
 * Returns a packet capture handle (pcap_t).
 */

static pcap_t *
setup_capture(char *device, char *filter)
{
	pcap_t *capt;
	char errbuf[PCAP_ERRBUF_SIZE] = "\0";
	
	/* open device to snoop; parameters:
	 * snaplen = BUFSIZ, promisc = 1, timeout = 100ms */
	capt = pcap_open_live(device, BUFSIZ, 1, 100, errbuf);
	if (capt == NULL) {
		fprintf(stderr, "ERROR: Couldn't open device '%s': %s\n",
			device, errbuf);
		return NULL;
	}
	
	/* set filter on capture device */
	if (setup_filter(capt, device, filter) == -1) {
		pcap_close(capt);
		return NULL;
	}
	
	return capt;
}

/*
 * Setup a capture filter on a device.
 *
 * Returns 0 if OK, -1 on error.
 */

static int
setup_filter(pcap_t *capt, char *device, char *filter)
{
	bpf_u_int32 network = 0;
	bpf_u_int32 netmask = 0;
	struct bpf_program bpfp;
	char errbuf[PCAP_ERRBUF_SIZE] = "\0";
	
	/* get network and netmask of device */
	if (pcap_lookupnet(device, &network, &netmask, errbuf) == -1)
		network = PCAP_NETMASK_UNKNOWN;
	
	/* compile the filter expression */
	if (pcap_compile(capt, &bpfp, filter, 0, network) == -1) {
		fprintf(stderr, "ERROR: Couldn't parse filter '%s': %s\n",
			filter, pcap_geterr(capt));
		return -1;
	}
	
	/* set the compiled filter */
	if (pcap_setfilter(capt, &bpfp) == -1) {
		fprintf(stderr, "ERROR: Couldn't install filter '%s': %s\n",
			filter, pcap_geterr(capt));
		return -1;
	}
	
	return 0;
}

/*
 * Check and return datalink type.
 *
 * Returns the link type or -1 if it is not supported.
 */

static int
check_link_type(pcap_t *capt)
{
	int link_type;
	
	/* get link layer type */
	link_type = pcap_datalink(capt);
	
	/* determine link layer protocol */
	switch (link_type)
	{
	case DLT_EN10MB:
	case DLT_NULL:
	case DLT_LOOP:
		return link_type;
		break;
	default:
		fprintf(stderr, "Link type %i not supported\n", link_type);
		return -1;
		break;
	}
	
	/* never reached */
	return -1;
}

/*
 * Install the SIGALRM handler.
 *
 * The SIGALRM handler is used to terminate the capture loop.
 *
 * Returns 0 if OK, -1 on error.
 */

static int
install_sigalrm(pcap_t *capt)
{
	struct sigaction new_action;
	
	/* pcap handle to stop */
	alrm_pcap_handle = capt;
	
	/* setup the new sigalrm handler */
	new_action.sa_handler = handle_sigalrm;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	
	/* install the handler */
	if (sigaction(SIGALRM, &new_action, NULL) == -1) {
		perror("ERROR: Couldn't install SIGALRM handler");
		return -1;
	}
	
	return 0;
}

/*
 * Handle the SIGALRM signal.
 *
 * This will terminate the capture loop in a safe way.
 */

static void
handle_sigalrm(int signo)
{
	int save_errno = errno;
	pcap_breakloop(alrm_pcap_handle);
	errno = save_errno;
}

/* ****************************************************************** */
/* ************************ Packet handlers ************************* */
/* ****************************************************************** */

/*
 * Basic packet handler. 
 */

static void
handle_packet(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	struct stackinfo_t *stackinfo;
	struct packetinfo_t *packetinfo;
	
	/* get clean stackinfo structure */
	stackinfo = stackinfo_new();
	
	/* extract the packetinfo structure */
	packetinfo = (struct packetinfo_t *)(args);
	
	/* print packet info */
	printf("[pcap] time: %ld.%06ld len: %lu caplen: %lu\n",
		(long)pkthdr->ts.tv_sec,
		(long)pkthdr->ts.tv_usec,
		(unsigned long)pkthdr->len,
		(unsigned long)pkthdr->caplen);
	
	/* handle the first protocol layer */
	switch (packetinfo->link_type)
	{
	case DLT_EN10MB:
		handle_ethernet((u_char *)stackinfo, pkthdr, packet);
		break;
	case DLT_NULL:
	case DLT_LOOP:
		handle_loopback((u_char *)stackinfo, pkthdr, packet,
			packetinfo->link_type);
		break;
	default:
		fprintf(stderr, "Link type %i not supported\n",
			packetinfo->link_type);
		return;
		break;
	}
	
	return;
}

/* ****************************************************************** */
/* *********************** Protocol handlers ************************ */
/* ****************************************************************** */

/*
 * Handle loopback encapsulation.
 */

static void
handle_loopback(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet, int type)
{
	uint32_t proto;
	struct stackinfo_t *stackinfo;
	pcap_handler handle_next = NULL;
	
	/* extract stackinfo */
	stackinfo = (struct stackinfo_t*)(args);
	
	/* check if header was captured completely */
	if (pkthdr->caplen - stackinfo->offset < BSDLOOP_SIZE) {
		printf("[eth] header missing or truncated\n");
		return;
	}
	
	/* extract link layer header by copying the first 4 bytes of
	 * the packet and turning it into a 32bit unsigned integer */
	switch (type)
	{
	case DLT_NULL:
		proto = *((uint32_t*)packet);
		printf("[bsd-null] ");
		break;
	case DLT_LOOP:
		proto = ntohl(*((uint32_t*)packet));
		printf("[bsd-loop] ");
		break;
	default:
		printf("[loopback] unknown loopback type: %i\n", type);
		return;
		break;
	}
	
	/* check packet type */
	switch (proto)
	{
	case PF_INET:
		printf("proto: ip\n");
		handle_next = handle_ipv4;
		break;
	case PF_INET6:
		printf("proto: ipv6\n");
		break;
	default:
		printf("proto: ?:%u\n", proto);
		break;
	}
	
	/* point to next layer */
	stackinfo->offset += BSDLOOP_SIZE;
	
	/* handle the next layer */
	if (handle_next)
		handle_next((u_char *)stackinfo, pkthdr, packet);
	
	return;
}

/*
 * Handle "10Mb/s" ethernet protocol.
 */

static void
handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	uint16_t ether_type;
	struct ether_header *eptr;
	struct stackinfo_t *stackinfo;
	pcap_handler handle_next = NULL;
	
	/* extract stackinfo */
	stackinfo = (struct stackinfo_t*)(args);
	
	/* check if header was captured completely */
	if (pkthdr->caplen - stackinfo->offset < ETHER_SIZE) {
		printf("[eth] header missing or truncated\n");
		return;
	}
	
	/* extract ethernet header */
	eptr = (struct ether_header *)(packet + stackinfo->offset);
	ether_type = ntohs(eptr->ether_type);
	
	printf("[eth] src: %s",
		ether_ntoa((struct ether_addr *)eptr->ether_shost));
	printf(" dst: %s ",
		ether_ntoa((struct ether_addr *)eptr->ether_dhost));
	
	/* check packet type */
	switch (ether_type)
	{
	case ETHERTYPE_IP:
		printf("proto: ip\n");
		handle_next = handle_ipv4;
		break;
	case ETHERTYPE_ARP:
		printf("proto: arp\n");
		break;
	case ETHERTYPE_REVARP:
		printf("proto: rarp\n");
		break;
	case ETHERTYPE_IPV6:
		printf("proto: ipv6\n");
		break;
	default:
		printf("proto: ?:%u\n", ether_type);
		break;
	}
	
	/* point to next layer */
	stackinfo->offset += ETHER_SIZE;
	
	/* handle the next layer */
	if (handle_next)
		handle_next((u_char *)stackinfo, pkthdr, packet);
	
	return;
}

/*
 * Handle IPv4 protocol.
 */

static void
handle_ipv4(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	struct ip *ip;
	struct stackinfo_t *stackinfo;
	uint16_t ip_len, ip_off, offset, ip_hsize;
	pcap_handler handle_next = NULL;
	
	/* extract stackinfo */
	stackinfo = (struct stackinfo_t*)(args);
	
	/* check if header (w/o options) was captured completely */
	if (pkthdr->caplen - stackinfo->offset < IPV4_SIZE) {
		printf("[ipv4] header missing or truncated\n");
		return;
	}
	
	/* extract ip header (w/o options) */
	ip = (struct ip *)(packet + stackinfo->offset);
	
	/* extract ip fields to host byte order */
	ip_len = ntohs(ip->ip_len);	/* ip packet length   */
	ip_off = ntohs(ip->ip_off);	/* ip fragment offset */
	
	/* verify ip version */
	if (ip->ip_v != 4) {
		printf("[ipv4] invalid version: %d\n", ip->ip_v);
		return;
	}
	
	/* verify header length */
	if (ip->ip_hl < 5) {
		printf("[ipv4] invalid header length: %d\n", ip->ip_hl);
		return;
	}
	
	/* calculate header length in bytes */
	ip_hsize = ip->ip_hl * 4;
	
	/* verify packet length (on the wire) */
	if (pkthdr->len - stackinfo->offset < ip_len) {
		printf("[ipv4] truncated: %u bytes missing\n",
			ip_len - (pkthdr->len - stackinfo->offset));
		/* just a warning, don't return */
	}
	
	/* calculate offset */
	if ((offset = ip_off & IP_OFFMASK) != 0)
		offset <<= 3;
	
	/* determine if first fragment or not */
	if (offset) {
		/* is not the first fragment */
		printf("[ipv4-frag] ");
	} else {
		/* is the first/only fragment */
		printf("[ipv4] ");
	}
	
	/* determine protocol */
	switch (ip->ip_p)
	{
	case IPPROTO_UDP:
		printf("proto: udp ");
		if (!offset)
			/* first fragment handler */
			handle_next = handle_udp;
		/* we know enough, put it in the table */
		udptable_update(ip->ip_src, pkthdr->len);
		break;
	case IPPROTO_TCP:
		printf("proto: tcp ");
		break;
	case IPPROTO_ICMP:
		printf("proto: icmp ");
		break;
	default:
		printf("proto: ?:%u ", ip->ip_p);
		break;
	}
	
	/* print remaining info */
	printf("src: %s ", inet_ntoa(ip->ip_src));
	printf("dst: %s ", inet_ntoa(ip->ip_dst));
	printf("len: %u off: %u%s\n",
		ip_len, offset, (ip_off & IP_MF) ? " +" : "");
	
	/* check if header (w/ options) was captured completely */
	if (pkthdr->caplen - stackinfo->offset < ip_hsize) {
		printf("[ipv4] header options missing or truncated\n");
		return;
	}
	
	/* point to next layer */
	stackinfo->offset += ip_hsize;
	
	/* handle the next layer */
	if (handle_next)
		handle_next((u_char *)stackinfo, pkthdr, packet);
	
	return;
}

/*
 * Handle UDP protocol.
 */

static void
handle_udp(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	struct udphdr *udp;
	struct stackinfo_t *stackinfo;
	
	/* extract stackinfo */
	stackinfo = (struct stackinfo_t*)(args);
	
	/* check if header was captured completely */
	if (pkthdr->caplen - stackinfo->offset < UDP_SIZE) {
		printf("[udp] header missing or truncated\n");
		return;
	}
	
	/* extract udp header */
	udp = (struct udphdr *)(packet + stackinfo->offset);
	
	/* print udp info */
	printf("[udp] src-port: %u dst-port: %u len: %u\n",
		ntohs(udp->uh_sport), ntohs(udp->uh_dport),
		ntohs(udp->uh_ulen));
	
	/* point to next layer */
	stackinfo->offset += UDP_SIZE;
	
	/* handle the next layer */
	
	return;
}
	
