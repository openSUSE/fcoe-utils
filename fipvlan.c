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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "fcoe_utils_version.h"
#include "fip.h"
#include "fcoemon_utils.h"

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

#define FIP_LOG(...)		sa_log(__VA_ARGS__)
#define FIP_LOG_ERR(error, ...)	sa_log_err(error, __func__, __VA_ARGS__)
#define FIP_LOG_ERRNO(...)	sa_log_err(errno, __func__, __VA_ARGS__)
#define FIP_LOG_DBG(...)	sa_log_debug(__VA_ARGS__)

/* global configuration */

char *exe;

TAILQ_HEAD(iff_list_head, iff);

struct iff {
	int ifindex;
	char *ifname;
	unsigned char mac_addr[ETHER_ADDR_LEN];
	TAILQ_ENTRY(iff) list_node;
};

struct iff_list_head interfaces = TAILQ_HEAD_INITIALIZER(interfaces);

TAILQ_HEAD(fcf_list_head, fcf);

struct fcf {
	int ifindex;
	uint16_t vlan;
	unsigned char mac_addr[ETHER_ADDR_LEN];
	TAILQ_ENTRY(fcf) list_node;
};

struct fcf_list_head fcfs = TAILQ_HEAD_INITIALIZER(fcfs);

struct iff *lookup_iff(int ifindex, char *ifname)
{
	struct iff *iff;

	if (!ifindex && !ifname)
		return NULL;

	TAILQ_FOREACH(iff, &interfaces, list_node)
		if ((!ifindex || ifindex == iff->ifindex) &&
		    (!ifname  || strcmp(ifname, iff->ifname) == 0))
			return iff;
	return NULL;
}

/**
 * packet_socket - create a packet socket bound to the FIP ethertype
 */
int packet_socket(void)
{
	int s;

	FIP_LOG_DBG("creating ETH_P_FIP packet socket");
	s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_FIP));
	if (s < 0)
		FIP_LOG_ERRNO("packet socket error");

	return s;
}

struct fip_tlv_ptrs {
	struct fip_tlv_mac_addr		*mac;
	struct fip_tlv_vlan		*vlan[370];
	unsigned int 			vlanc;
};

#define SET_BIT(b, n)	((b) |= (1 << (n)))

#define TLV_LEN_CHECK(t, l) ({ \
	int _tlc = ((t)->tlv_len != (l)) ? 1 : 0; \
	if (_tlc) \
		FIP_LOG("bad length for TLV of type %d", (t)->tlv_type); \
	_tlc; \
})

/**
 * fip_parse_tlvs - parse type/length/value encoded FIP descriptors
 * @ptr: pointer to beginning of FIP TLV payload, the first descriptor
 * @len: total length of all TLVs, in double words
 * @tlv_ptrs: pointers to type specific structures to fill out
 */
unsigned int fip_parse_tlvs(void *ptr, int len, struct fip_tlv_ptrs *tlv_ptrs)
{
	struct fip_tlv_hdr *tlv = ptr;
	unsigned int bitmap = 0;

	tlv_ptrs->vlanc = 0;
	while (len > 0) {
		switch (tlv->tlv_type) {
		case FIP_TLV_MAC_ADDR:
			if (TLV_LEN_CHECK(tlv, 2))
				break;
			SET_BIT(bitmap, FIP_TLV_MAC_ADDR);
			tlv_ptrs->mac = (struct fip_tlv_mac_addr *) tlv;
			break;
		case FIP_TLV_VLAN:
			if (TLV_LEN_CHECK(tlv, 1))
				break;
			SET_BIT(bitmap, FIP_TLV_VLAN);
			tlv_ptrs->vlan[tlv_ptrs->vlanc++] = (void *) tlv;
			break;
		default:
			/* unexpected or unrecognized descriptor */
			FIP_LOG("unrecognized TLV type %d", tlv->tlv_type);
			break;
		}
		len -= tlv->tlv_len;
		tlv = ((void *) tlv) + (tlv->tlv_len << 2);
	};
	return bitmap;
}

/**
 * fip_recv_vlan_note - parse a FIP VLAN Notification
 * @fh: FIP header, the beginning of the received FIP frame
 * @ifindex: index of interface this was received on
 */
int fip_recv_vlan_note(struct fiphdr *fh, int ifindex)
{
	struct fip_tlv_ptrs tlvs;
	struct fcf *fcf;
	unsigned int bitmap, required_tlvs;
	int len;
	int i;

	FIP_LOG_DBG("received FIP VLAN Notification");

	len = ntohs(fh->fip_desc_len);

	required_tlvs = (1 << FIP_TLV_MAC_ADDR) | (1 << FIP_TLV_VLAN);

	bitmap = fip_parse_tlvs((fh + 1), len, &tlvs);
	if ((bitmap & required_tlvs) != required_tlvs)
		return -1;

	for (i = 0; i < tlvs.vlanc; i++) {
		fcf = malloc(sizeof(*fcf));
		if (!fcf) {
			FIP_LOG_ERRNO("malloc failed");
			break;
		}
		memset(fcf, 0, sizeof(*fcf));
		fcf->ifindex = ifindex;
		fcf->vlan = ntohs(tlvs.vlan[i]->vlan);
		memcpy(fcf->mac_addr, tlvs.mac->mac_addr, ETHER_ADDR_LEN);
		TAILQ_INSERT_TAIL(&fcfs, fcf, list_node);
	}

	return 0;
}

int fip_vlan_handler(struct fiphdr *fh, struct sockaddr_ll *sa, void *arg)
{
	int rc = -1;

	/* We only care about VLAN Notifications */
	if (ntohs(fh->fip_proto) != FIP_PROTO_VLAN) {
		FIP_LOG_DBG("ignoring FIP packet, protocol %d",
			    ntohs(fh->fip_proto));
		return -1;
	}

	switch (fh->fip_subcode) {
	case FIP_VLAN_NOTE:
		rc = fip_recv_vlan_note(fh, sa->sll_ifindex);
		break;
	default:
		FIP_LOG_DBG("ignored FIP VLAN packet with subcode %d",
			    fh->fip_subcode);
		break;
	}
	return rc;
}

/**
 * rtnl_socket - create and bind a routing netlink socket
 */
int rtnl_socket(void)
{
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_pid = getpid(),
		.nl_groups = RTMGRP_LINK,
	};
	int s;
	int rc;

	FIP_LOG_DBG("creating netlink socket");
	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		FIP_LOG_ERRNO("netlink socket error");
		return s;
	}

	rc = bind(s, (struct sockaddr *) &sa, sizeof(sa));
	if (rc < 0) {
		FIP_LOG_ERRNO("netlink bind error");
		close(s);
		return rc;
	}

	return s;
}

/**
 * send_getlink_dump - send an RTM_GETLINK dump request to list all interfaces
 * @s: routing netlink socket to use
 */
ssize_t send_getlink_dump(int s)
{
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_pid = 0,
	};
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_pid = 0,
		},
		.ifm = {
			.ifi_family = AF_UNSPEC,
			.ifi_type = ARPHRD_ETHER,
		},
	};
	struct iovec iov[] = {
		{ .iov_base = &req, .iov_len = sizeof(req), },
	};
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
	};
	int rc;

	FIP_LOG_DBG("sending RTM_GETLINK dump request");
	rc = sendmsg(s, &msg, 0);
	if (rc < 0)
		FIP_LOG_ERRNO("netlink sendmsg error");

	return rc;
}

/**
 * rtnl_recv_newlink - parse response to RTM_GETLINK, or an RTM_NEWLINK event
 * @nh: netlink message header, beginning of received netlink frame
 */
void rtnl_recv_newlink(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifm;
	struct rtattr *rta;
	struct iff *iff;
	unsigned int len;

	FIP_LOG_DBG("RTM_NEWLINK");

	ifm = NLMSG_DATA(nh);
	FIP_LOG_DBG("ifindex %d, type %d", ifm->ifi_index, ifm->ifi_type);

	/* We only deal with Ethernet interfaces */
	if (ifm->ifi_type != ARPHRD_ETHER)
		return;

	/* if there's no link, we're not going to wait for it */
	if ((ifm->ifi_flags & IFF_RUNNING) != IFF_RUNNING)
		return;

	iff = malloc(sizeof(*iff));
	if (!iff) {
		FIP_LOG_ERRNO("malloc failed");
		return;
	}
	memset(iff, 0, sizeof(*iff));

	iff->ifindex = ifm->ifi_index;

	len = IFLA_PAYLOAD(nh);
	for (rta = IFLA_RTA(ifm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {
		case IFLA_ADDRESS:
			memcpy(iff->mac_addr, RTA_DATA(rta), ETHER_ADDR_LEN);
			FIP_LOG_DBG("\tIFLA_ADDRESS\t%x:%x:%x:%x:%x:%x",
					iff->mac_addr[0], iff->mac_addr[1],
					iff->mac_addr[2], iff->mac_addr[3],
					iff->mac_addr[4], iff->mac_addr[5]);
			break;
		case IFLA_IFNAME:
			iff->ifname = strdup(RTA_DATA(rta));
			FIP_LOG_DBG("\tIFLA_IFNAME\t%s", iff->ifname);
			break;
		default:
			/* other attributes don't matter */
			break;
		}
	}

	TAILQ_INSERT_TAIL(&interfaces, iff, list_node);
}

#define NLMSG(c) ((struct nlmsghdr *) (c))

/**
 * rtnl_recv - receive from a routing netlink socket
 * @s: routing netlink socket with data ready to be received
 *
 * Returns:	0 when NLMSG_DONE is received
 * 		<0 on error
 * 		>0 when more data is expected
 */
int rtnl_recv(int s)
{
	char buf[8192];
	struct sockaddr_nl sa;
	struct iovec iov[] = {
		[0] = { .iov_base = buf, .iov_len = sizeof(buf), },
	};
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
	};
	struct nlmsghdr *nh;
	int len;
	int rc;

	FIP_LOG_DBG("%s", __func__);

	len = recvmsg(s, &msg, 0);
	if (len < 0) {
		FIP_LOG_ERRNO("netlink recvmsg error");
		return len;
	}

	rc = 1;
	for (nh = NLMSG(buf); NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		switch (nh->nlmsg_type) {
		case RTM_NEWLINK:
			rtnl_recv_newlink(nh);
			break;
		case NLMSG_DONE:
			FIP_LOG_DBG("NLMSG_DONE");
			break;
		case NLMSG_ERROR:
			FIP_LOG_DBG("NLMSG_ERROR");
			break;
		default:
			FIP_LOG("unexpected netlink message type %d",
				 nh->nlmsg_type);
			break;
		}

		if (nh->nlmsg_type == NLMSG_DONE) {
			rc = 0;
			break;
		}
		if (!(nh->nlmsg_flags & NLM_F_MULTI))
			break;
	}
	return rc;
}

/* command line arguments */

#define GETOPT_STR "ahv"

static const struct option long_options[] = {
	{ "auto", no_argument, NULL, 'a' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};

static void help(int status)
{
	printf(
"Usage: %s [ options ] [ network interfaces ]\n"
"Options:\n"
"  -a, --auto           Auto select Ethernet interfaces\n"
"  -h, --help           Display this help and exit\n"
"  -v, --version        Display version information and exit\n",
	exe);

	exit(status);
}

/* array of interface names to use */
char **namev;
/* length of namev */
int namec;

int parse_cmdline(int argc, char **argv)
{
	char c;
	int automode = 0;

	while (1) {
		c = getopt_long(argc, argv, GETOPT_STR, long_options, NULL);
		if (c < 0)
			break;
		switch (c) {
		case 'a':
			automode = 1;
			break;
		case 'h':
			help(0);
			break;
		case 'v':
			printf("%s version %s\n", exe, FCOE_UTILS_VERSION);
			exit(0);
			break;
		default:
			fprintf(stderr, "Try '%s --help' "
					"for more information\n", exe);
			exit(1);
		}
	}

	if ((optind == argc) && (!automode))
		help(1);

	namev = &argv[optind];
	namec = argc - optind;
	return automode;
}

/* exit after waiting 2 seconds without receiving anything */
#define TIMEOUT 2000

int autodetect()
{
	struct pollfd pfd[1];
	int ns;
	int rc;

	ns = rtnl_socket();
	if (ns < 0)
		return ns;

	send_getlink_dump(ns);
	pfd[0].fd = ns;
	pfd[0].events = POLLIN;

	while (1) {
		rc = poll(pfd, ARRAY_SIZE(pfd), TIMEOUT);
		FIP_LOG_DBG("return from poll %d", rc);
		if (rc == 0) /* timeout */
			break;
		if (rc == -1) {
			FIP_LOG_ERRNO("poll error");
			break;
		}
		if (pfd[0].revents) {
			rc = rtnl_recv(pfd[0].fd);
			if (rc == 0)
				break;
		}
		pfd[0].revents = 0;
	}
	close(ns);
	return 0;
}

int check_interface(char *name, int ps)
{
	struct ifreq ifr;
	struct iff *iff;

	iff = malloc(sizeof(*iff));
	if (!iff) {
		FIP_LOG_ERRNO("malloc failed");
		return -1;
	}
	memset(iff, 0, sizeof(*iff));

	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	if (ioctl(ps, SIOCGIFINDEX, &ifr) != 0) {
		FIP_LOG_ERRNO("SIOCGIFINDEX");
		goto err;
	}
	iff->ifname = strdup(ifr.ifr_name);
	iff->ifindex = ifr.ifr_ifindex;

	if (ioctl(ps, SIOCGIFHWADDR, &ifr) != 0) {
		FIP_LOG_ERRNO("SIOCGIFHWADDR");
		goto err;
	}
	if (ifr.ifr_addr.sa_family != ARPHRD_ETHER) {
		FIP_LOG_ERR(ENODEV, "%s is not an Ethernet interface", name);
		goto err;
	}
	memcpy(iff->mac_addr, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);

	TAILQ_INSERT_TAIL(&interfaces, iff, list_node);
	return 0;
err:
	free(iff);
	return -1;
}

void print_results()
{
	struct iff *iff;
	struct fcf *fcf;

	if (TAILQ_EMPTY(&fcfs)) {
		printf("No Fibre Channel Forwarders Found\n");
		return;
	}

	printf("Fibre Channel Forwarders Discovered\n");
	printf("%-10.10s| %-5.5s| %-10.10s\n", "interface", "VLAN", "FCF MAC");
	printf("------------------------------------\n");
	TAILQ_FOREACH(fcf, &fcfs, list_node) {
		iff = lookup_iff(fcf->ifindex, NULL);
		printf("%-10.10s| %-5d| %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
			iff->ifname, fcf->vlan,
			fcf->mac_addr[0], fcf->mac_addr[1], fcf->mac_addr[2],
			fcf->mac_addr[3], fcf->mac_addr[4], fcf->mac_addr[5]);
	}
}

void recv_loop(int ps)
{
	struct pollfd pfd[1] = {
		[0].fd = ps,
		[0].events = POLLIN,
	};
	int rc;

	while (1) {
		rc = poll(pfd, ARRAY_SIZE(pfd), TIMEOUT);
		FIP_LOG_DBG("return from poll %d", rc);
		if (rc == 0) /* timeout */
			break;
		if (rc == -1) {
			FIP_LOG_ERRNO("poll error");
			break;
		}
		if (pfd[0].revents)
			fip_recv(pfd[0].fd, fip_vlan_handler, NULL);
		pfd[0].revents = 0;
	}
}

int main(int argc, char **argv)
{
	int ps;
	struct iff *iff;
	int i;
	int automode;

	exe = strrchr(argv[0], '/');
	if (exe)
		exe++;
	else
		exe = argv[0];

	automode = parse_cmdline(argc, argv);
	sa_log_prefix = exe;
	sa_log_flags = 0;
	enable_debug_log(0);

	ps = packet_socket();

	if (automode) {
		autodetect();
	} else {
		for (i = 0; i < namec; i++)
			check_interface(namev[i], ps);
	}

	if (TAILQ_EMPTY(&interfaces)) {
		FIP_LOG_ERR(ENODEV, "no interfaces to perform discovery on");
		close(ps);
		exit(1);
	}

	TAILQ_FOREACH(iff, &interfaces, list_node)
		fip_send_vlan_request(ps, iff->ifindex, iff->mac_addr);

	recv_loop(ps);
	print_results();

	close(ps);
	exit(0);
}

