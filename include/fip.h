/*
 * Copyright(c) 2009 Intel Corporation. All rights reserved.
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

#ifndef FIP_H
#define FIP_H

#include <stdint.h>
#include <net/ethernet.h>

#define ETH_P_FCOE	0x8906
#define ETH_P_FIP	0x8914

#define VLAN_HLEN 4

#define FIP_ALL_FCOE_MACS	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x00 }
#define FIP_ALL_ENODE_MACS	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x01 }
#define FIP_ALL_FCF_MACS	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x02 }

struct fiphdr {
	uint8_t		fip_version;	/* version, upper 4 bits only */
	uint8_t		__resvd_0;
	uint16_t	fip_proto;	/* protocol code */
	uint8_t		__resvd_1;
	uint8_t		fip_subcode;	/* subcode */
	uint16_t	fip_desc_len;	/* descriptor list length */
	uint16_t	fip_flags;
};

#define FIP_VERSION(n)	(n << 4)
#define FIP_F_FP	(1 << 15)	/* FPMA supported/requested/granted */
#define FIP_F_SP	(1 << 14)	/* SPMA supported/requested/granted */
#define FIP_F_A		(1 << 2)	/* Available for Login */
#define FIP_F_S		(1 << 1)	/* Solicited advertisement */
#define FIP_F_F		(1 << 0)	/* FCF */

/* FCF Discovery Protocol */
#define FIP_PROTO_DISC	1
#define FIP_DISC_SOL	1
#define FIP_DISC_ADV	2

/* Virtual Link Instantiation (encapsulated ELS) */
#define FIP_PROTO_VLI	2
#define FIP_VLI_REQ	1
#define FIP_VLI_REPLY	2

/* FIP Keep Alive */
#define FIP_PROTO_FKA	3
#define FIP_FKA		1
#define FIP_FKA_CLEAR	2

/* VLAN Discovery */
#define FIP_PROTO_VLAN	4
#define FIP_VLAN_REQ	1
#define FIP_VLAN_NOTE	2

struct fip_tlv_hdr {
	uint8_t		tlv_type;
	uint8_t		tlv_len;	/* length in quad-words of entire TLV */
};

#define FIP_TLV_PRIORITY		1
#define FIP_TLV_MAC_ADDR		2
#define FIP_TLV_FC_MAP			3
#define FIP_TLV_NAME_IDENTIFIER		4
#define FIP_TLV_FABRIC_NAME		5
#define FIP_TLV_MAX_RECV_SIZE		6
#define FIP_TLV_FLOGI			7
#define FIP_TLV_FDISC			8
#define FIP_TLV_LOGO			9
#define FIP_TLV_ELP			10

#define FIP_TLV_VLAN			14

#define DEFAULT_FIP_PRIORITY		128

/* Priority Descriptor */
struct fip_tlv_priority {
	struct fip_tlv_hdr hdr;
	unsigned char __resvd;
	uint8_t priority;
};

/* MAC Address Descriptor */
struct fip_tlv_mac_addr {
	struct fip_tlv_hdr hdr;
	unsigned char mac_addr[ETHER_ADDR_LEN];
};

/* FC-MAP Descriptor */
struct fip_tlv_fc_map {
	struct fip_tlv_hdr hdr;
	unsigned char __resvd[3];
	uint8_t map[3];
};

/* Name Identifier Descriptor (also used for Fabric Name Descriptor) */
struct fip_tlv_name_id {
	struct fip_tlv_hdr hdr;
	unsigned char __resvd[2];
	unsigned char wwn[8];
};

/* Max Receive Size Descriptor */
struct fip_tlv_max_recv_size {
	struct fip_tlv_hdr hdr;
	uint16_t mtu;
};

/* VLAN */
struct fip_tlv_vlan {
	struct fip_tlv_hdr hdr;
	uint16_t vlan;	/* only lower 12 bits matter */
};


/* libutil / fip.c functionality */

int fip_socket(int ifindex);

/* FIP message handler, passed into fip_recv */
typedef int fip_handler(struct fiphdr *fh, struct sockaddr_ll *sa, void *arg);

/**
 * fip_recv - receive from a FIP packet socket
 * @s: packet socket with data ready to be received
 */
int fip_recv(int s, fip_handler *fn, void *arg);

/**
 * fip_send_vlan_request - send a FIP VLAN request
 * @s: ETH_P_FIP packet socket to send on
 * @ifindex: network interface index to send on
 * @mac: mac address of the netif
 *
 * Note: sends to FIP_ALL_FCF_MACS
 */
ssize_t fip_send_vlan_request(int s, int ifindex, unsigned char *mac);

#endif /* FIP_H */
