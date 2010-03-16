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
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "fip.h"
#include "fcoemon_utils.h"

#define FIP_LOG(...)			sa_log(__VA_ARGS__)
#define FIP_LOG_ERR(error, ...)		sa_log_err(error, __func__, __VA_ARGS__)
#define FIP_LOG_ERRNO(...)		sa_log_err(errno, __func__, __VA_ARGS__)
#define FIP_LOG_DBG(...)		sa_log_debug(__VA_ARGS__)

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

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
	struct iovec iov[] = {
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

	memcpy(tlvs.mac.mac_addr, mac, ETHER_ADDR_LEN);

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

	FIP_LOG_DBG("%s", __func__);

	len = recvmsg(s, &msg, 0);
	if (len < 0) {
		FIP_LOG_ERRNO("packet socket recv error");
		return len;
	}

	if (len < sizeof(*fh)) {
		FIP_LOG_ERR(EINVAL, "received packed smaller that FIP header");
		return -1;
	}

	fh = (struct fiphdr *) buf;

	desc_len = ntohs(fh->fip_desc_len);
	if (len < (sizeof(*fh) + (desc_len << 2))) {
		FIP_LOG_ERR(EINVAL, "received data less that FIP descriptor");
		return -1;
	}

	if (fn)
		return fn(fh, &sa, arg);
	return 0;
}
