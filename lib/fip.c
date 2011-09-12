/*
 * Copyright(c) 2010 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Maintained at www.Open-FCoE.org
 */

/* Routines for automatic FIP VLAN discovery and creation */
/* Shared by fcoemon and fipvlan */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include "fip.h"
#include "fcoemon_utils.h"
#include "rtnetlink.h"

#define FIP_LOG(...)			sa_log(__VA_ARGS__)
#define FIP_LOG_ERR(error, ...)		sa_log_err(error, __func__, __VA_ARGS__)
#define FIP_LOG_ERRNO(...)		sa_log_err(errno, __func__, __VA_ARGS__)
#define FIP_LOG_DBG(...)		sa_log_debug(__VA_ARGS__)

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

static int fip_mac_is_valid(unsigned char *mac)
{
	if (0x01 & mac[0])
		return 0;
	return !!(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}

/**
 * fip_get_sanmac - get SAN MAC through dcbnl interface
 * @ifindex: network interface index to send on
 * @addr: output buffer to the SAN MAC address
 *
 * Returns 0 for success, none 0 for failure
 */
static int fip_get_sanmac(int ifindex, unsigned char *addr)
{
	int s;
	int rc = -EIO;
	struct ifreq ifr;

	memset(addr, 0, ETHER_ADDR_LEN);
	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
		return s;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;
	rc = ioctl(s, SIOCGIFNAME, &ifr);
	close(s);
	if (rc)
		return rc;

	rc = rtnl_get_sanmac(ifr.ifr_name, addr);
	if (rc)
		return rc;

	return !fip_mac_is_valid(addr);
}

/**
 * fip_socket_sanmac - add SAN MAC to the unicast list for input socket
 * @s: ETH_P_FIP packet socket to setsockopt on
 * @ifindex: network interface index to send on
 * @add: 1 to add 0 to del
 */
static void fip_socket_sanmac(int s, int ifindex, int add)
{
	struct packet_mreq mr;
	unsigned char smac[ETHER_ADDR_LEN];

	if (fip_get_sanmac(ifindex, smac))
		return;

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifindex;
	mr.mr_type = PACKET_MR_UNICAST;
	mr.mr_alen = ETHER_ADDR_LEN;
	memcpy(mr.mr_address, smac, ETHER_ADDR_LEN);
	if (setsockopt(s, SOL_PACKET,
		       (add) ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
		       &mr, sizeof(mr)) < 0)
		FIP_LOG_DBG("PACKET_%s_MEMBERSHIP:failed\n",
			    (add) ? "ADD" : "DROP");
}

/**
 * fip_ethhdr - fills up the ethhdr for FIP
 * @ifindex: network interface index to send on
 * @mac: mac address of the sending network interface
 * @eh: buffer for ether header
 *
 * Note: assuming no VLAN
 */
static void fip_ethhdr(int ifindex, unsigned char *mac, struct ethhdr *eh)
{
	unsigned char smac[ETHER_ADDR_LEN];
	unsigned char dmac[ETHER_ADDR_LEN] = FIP_ALL_FCF_MACS;
	if (fip_get_sanmac(ifindex, smac))
		memcpy(smac, mac, ETHER_ADDR_LEN);

	eh->h_proto = htons(ETH_P_FIP);
	memcpy(eh->h_source, smac, ETHER_ADDR_LEN);
	memcpy(eh->h_dest, dmac, ETHER_ADDR_LEN);
}

/**
 * drain_socket - Discard receive packets on a socket
 */
static void drain_socket(int s)
{
	char buf[4096];
	struct sockaddr_ll sa;
	struct iovec iov[] = {
		{ .iov_base = buf, .iov_len = sizeof(buf), },
	};
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
	};

	while (recvmsg(s, &msg, MSG_DONTWAIT) > 0) {
		/* Drop the packet */
	}
}

/**
 * fip_socket - create and bind a packet socket for FIP
 */
int fip_socket(int ifindex)
{
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_FIP),
		.sll_ifindex = ifindex,
	};
	int s;
	int rc;

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_FIP));
	if (s < 0)
		return s;

	fip_socket_sanmac(s, ifindex, 1);

	rc = bind(s, (struct sockaddr *) &sa, sizeof(sa));
	if (rc < 0) {
		close(s);
		return rc;
	}

	/*
	 * Drain the packets that were received between socket and bind. We
	 * could've received packets not meant for our interface. This can
	 * interfere with vlan discovery
	 */
	drain_socket(s);

	return s;
}


/**
 * fip_send_vlan_request - send a FIP VLAN request
 * @s: ETH_P_FIP packet socket to send on
 * @ifindex: network interface index to send on
 * @mac: mac address of the sending network interface
 *
 * Note: sends to FIP_ALL_FCF_MACS
 */
ssize_t fip_send_vlan_request(int s, int ifindex, unsigned char *mac)
{
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_FIP),
		.sll_ifindex = ifindex,
		.sll_hatype = ARPHRD_ETHER,
		.sll_pkttype = PACKET_MULTICAST,
		.sll_halen = ETHER_ADDR_LEN,
		.sll_addr = FIP_ALL_FCF_MACS,
	};
	struct fiphdr fh = {
		.fip_version = FIP_VERSION(1),
		.fip_proto = htons(FIP_PROTO_VLAN),
		.fip_subcode = FIP_VLAN_REQ,
		.fip_desc_len = htons(2),
		.fip_flags = 0,
	};
	struct {
		struct fip_tlv_mac_addr mac;
	} tlvs = {
		.mac = {
			.hdr.tlv_type = FIP_TLV_MAC_ADDR,
			.hdr.tlv_len = 2,
		},
	};
	struct ethhdr eh;
	struct iovec iov[] = {
		{ .iov_base = &eh, .iov_len = sizeof(eh), },
		{ .iov_base = &fh, .iov_len = sizeof(fh), },
		{ .iov_base = &tlvs, .iov_len = sizeof(tlvs), },
	};
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
	};
	int rc;

	fip_ethhdr(ifindex, mac, &eh);
	memcpy(tlvs.mac.mac_addr, eh.h_source, ETHER_ADDR_LEN);
	FIP_LOG_DBG("sending FIP VLAN request");
	rc = sendmsg(s, &msg, 0);
	if (rc < 0) {
		rc = -errno;
		FIP_LOG_ERRNO("sendmsg error");
	}
	return rc;
}

/**
 * fip_recv - receive from a FIP packet socket
 * @s: packet socket with data ready to be received
 * @fn: FIP receive callback to process the payload
 * @arg: argument to pass through to @fn
 */
int fip_recv(int s, fip_handler *fn, void *arg)
{
	char buf[4096];
	struct sockaddr_ll sa;
	struct iovec iov[] = {
		{ .iov_base = buf, .iov_len = sizeof(buf), },
	};
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
	};
	struct fiphdr *fh;
	ssize_t len, desc_len;
	struct ethhdr *eth = (struct ethhdr *)buf;

	len = recvmsg(s, &msg, MSG_DONTWAIT);
	if (len < 0) {
		FIP_LOG_ERRNO("packet socket recv error");
		return len;
	}

	if (len < sizeof(*fh)) {
		FIP_LOG_ERR(EINVAL, "received packed smaller that FIP header");
		return -1;
	}

	if (eth->h_proto == htons(ETH_P_8021Q))
		fh = (struct fiphdr *) (buf + sizeof(struct ethhdr) + VLAN_HLEN);
	else
		fh = (struct fiphdr *) (buf + sizeof(struct ethhdr));

	desc_len = ntohs(fh->fip_desc_len);
	if (len < (sizeof(*fh) + (desc_len << 2))) {
		FIP_LOG_ERR(EINVAL, "received data less that FIP descriptor");
		return -1;
	}

	if (fn)
		return fn(fh, &sa, arg);
	return 0;
}
