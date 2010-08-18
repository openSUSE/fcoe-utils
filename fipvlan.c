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
#include <stdbool.h>
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
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include <linux/capability.h>
#include <sys/syscall.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "fcoe_utils_version.h"
#include "fip.h"
#include "fcoemon_utils.h"
#include "fcoe_utils.h"
#include "rtnetlink.h"

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

#define FIP_LOG(...)		sa_log(__VA_ARGS__)
#define FIP_LOG_ERR(error, ...)	sa_log_err(error, __func__, __VA_ARGS__)
#define FIP_LOG_ERRNO(...)	sa_log_err(errno, __func__, __VA_ARGS__)
#define FIP_LOG_DBG(...)	sa_log_debug(__VA_ARGS__)

/* global configuration */

struct {
	char **namev;
	int namec;
	bool automode;
	bool create;
	bool start;
} config = {
	.namev = NULL,
	.namec = 0,
	.automode = false,
	.create = false,
};

char *exe;

static struct pollfd *pfd = NULL;
static int pfd_len = 0;

void pfd_add(int fd)
{
	struct pollfd *npfd;
	int i;

	for (i = 0; i < pfd_len; i++)
		if (pfd[i].fd == fd)
			return;

	npfd = realloc(pfd, (pfd_len + 1) * sizeof(struct pollfd));
	if (!npfd) {
		perror("realloc fail");
		return;
	}
	pfd = npfd;
	pfd[pfd_len].fd = fd;
	pfd[pfd_len].events = POLLIN;
	pfd_len++;
}

void pfd_remove(int fd)
{
	struct pollfd *npfd;
	int i;

	for (i = 0; i < pfd_len; i++) {
		if (pfd[i].fd == fd)
			break;
	}
	if (i == pfd_len)
		return;
	memmove(&pfd[i], &pfd[i+1], (--pfd_len - i) * sizeof(struct pollfd));
	npfd = realloc(pfd, pfd_len * sizeof(struct pollfd));
	if (npfd)
		pfd = npfd;
}

TAILQ_HEAD(iff_list_head, iff);

struct iff {
	int ps;			/* packet socket file descriptor */
	int ifindex;
	int iflink;
	char ifname[IFNAMSIZ];
	unsigned char mac_addr[ETHER_ADDR_LEN];
	bool running;
	bool is_vlan;
	short int vid;
	bool req_sent;
	bool resp_recv;
	TAILQ_ENTRY(iff) list_node;
	struct iff_list_head vlans;
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

struct iff *lookup_vlan(int ifindex, short int vid)
{
	struct iff *real_dev, *vlan;
	TAILQ_FOREACH(real_dev, &interfaces, list_node)
		if (real_dev->ifindex == ifindex)
			TAILQ_FOREACH(vlan, &real_dev->vlans, list_node)
				if (vlan->vid == vid)
					return vlan;
	return NULL;
}

struct iff *find_vlan_real_dev(struct iff *vlan)
{
	struct iff *real_dev;
	TAILQ_FOREACH(real_dev, &interfaces, list_node) {
		if (real_dev->ifindex == vlan->iflink)
			return real_dev;
	}
	return NULL;
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
	struct iff *iff;
	unsigned int bitmap, required_tlvs;
	int len;
	int i;

	FIP_LOG_DBG("received FIP VLAN Notification");

	len = ntohs(fh->fip_desc_len);

	required_tlvs = (1 << FIP_TLV_MAC_ADDR) | (1 << FIP_TLV_VLAN);

	bitmap = fip_parse_tlvs((fh + 1), len, &tlvs);
	if ((bitmap & required_tlvs) != required_tlvs)
		return -1;

	iff = lookup_iff(ifindex, NULL);
	if (iff)
		iff->resp_recv = true;

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
 * rtnl_recv_newlink - parse response to RTM_GETLINK, or an RTM_NEWLINK event
 * @nh: netlink message header, beginning of received netlink frame
 */
void rtnl_recv_newlink(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifm = NLMSG_DATA(nh);
	struct rtattr *ifla[__IFLA_MAX];
	struct rtattr *linkinfo[__IFLA_INFO_MAX];
	struct rtattr *vlan[__IFLA_VLAN_MAX];
	struct iff *iff, *real_dev;
	int origdev = 1;

	FIP_LOG_DBG("RTM_NEWLINK: ifindex %d, type %d",
		    ifm->ifi_index, ifm->ifi_type);

	/* We only deal with Ethernet interfaces */
	if (ifm->ifi_type != ARPHRD_ETHER)
		return;

	iff = lookup_iff(ifm->ifi_index, NULL);
	if (iff) {
		/* already tracking, update operstate and return */
		iff->running = (ifm->ifi_flags & IFF_RUNNING) == IFF_RUNNING;
		if (iff->running)
			pfd_add(iff->ps);
		else
			pfd_remove(iff->ps);
		return;
	}

	iff = malloc(sizeof(*iff));
	if (!iff) {
		FIP_LOG_ERRNO("malloc failed");
		return;
	}
	memset(iff, 0, sizeof(*iff));
	TAILQ_INIT(&iff->vlans);

	parse_ifinfo(ifla, nh);

	iff->ifindex = ifm->ifi_index;
	iff->running = (ifm->ifi_flags & IFF_RUNNING) == IFF_RUNNING;
	if (ifla[IFLA_LINK])
		iff->iflink = *(int *)RTA_DATA(ifla[IFLA_LINK]);
	else
		iff->iflink = iff->ifindex;
	memcpy(iff->mac_addr, RTA_DATA(ifla[IFLA_ADDRESS]), ETHER_ADDR_LEN);
	strncpy(iff->ifname, RTA_DATA(ifla[IFLA_IFNAME]), IFNAMSIZ);

	if (ifla[IFLA_LINKINFO]) {
		parse_linkinfo(linkinfo, ifla[IFLA_LINKINFO]);
		/* Track VLAN devices separately */
		if (linkinfo[IFLA_INFO_KIND] &&
		    !strcmp(RTA_DATA(linkinfo[IFLA_INFO_KIND]), "vlan")) {
			iff->is_vlan = true;
			parse_vlaninfo(vlan, linkinfo[IFLA_INFO_DATA]);
			iff->vid = *(int *)RTA_DATA(vlan[IFLA_VLAN_ID]);
			real_dev = find_vlan_real_dev(iff);
			if (!real_dev) {
				FIP_LOG_ERR(ENODEV, "VLAN found without parent");
				return;
			}
			TAILQ_INSERT_TAIL(&real_dev->vlans, iff, list_node);
			return;
		}
		/* ignore bonding interfaces */
		if (linkinfo[IFLA_INFO_KIND] &&
		    !strcmp(RTA_DATA(linkinfo[IFLA_INFO_KIND]), "bond")) {
			free(iff);
			return;
		}
	}
	iff->ps = fip_socket(iff->ifindex);
	setsockopt(iff->ps, SOL_PACKET, PACKET_ORIGDEV,
		   &origdev, sizeof(origdev));
	if (iff->running)
		pfd_add(iff->ps);
	TAILQ_INSERT_TAIL(&interfaces, iff, list_node);
}

/* command line arguments */

#define GETOPT_STR "acshv"

static const struct option long_options[] = {
	{ "auto", no_argument, NULL, 'a' },
	{ "create", no_argument, NULL, 'c' },
	{ "start", no_argument, NULL, 's' },
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
"  -c, --create		Create system VLAN devices\n"
"  -s, --start		Start FCoE login automatically\n"
"  -h, --help           Display this help and exit\n"
"  -v, --version        Display version information and exit\n",
	exe);

	exit(status);
}

void parse_cmdline(int argc, char **argv)
{
	char c;

	while (1) {
		c = getopt_long(argc, argv, GETOPT_STR, long_options, NULL);
		if (c < 0)
			break;
		switch (c) {
		case 'a':
			config.automode = true;
			break;
		case 'c':
			config.create = true;
			break;
		case 's':
			config.start = true;
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

	if ((optind == argc) && (!config.automode))
		help(1);

	config.namev = &argv[optind];
	config.namec = argc - optind;
}

int rtnl_listener_handler(struct nlmsghdr *nh, void *arg)
{
	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
		rtnl_recv_newlink(nh);
		return 0;
	}
	return -1;
}

void create_missing_vlans()
{
	struct fcf *fcf;
	struct iff *real_dev, *vlan;
	char vlan_name[IFNAMSIZ];
	int rc;

	if (!config.create)
		return;

	TAILQ_FOREACH(fcf, &fcfs, list_node) {
		real_dev = lookup_iff(fcf->ifindex, NULL);
		if (!real_dev) {
			FIP_LOG_ERR(ENODEV, "lost device %d with discoved FCF?",
				    fcf->ifindex);
			continue;
		}
		vlan = lookup_vlan(fcf->ifindex, fcf->vlan);
		if (vlan) {
			FIP_LOG_DBG("VLAN %s.%d already exists as %s",
				    real_dev->ifname, fcf->vlan, vlan->ifname);
			continue;
		}
		snprintf(vlan_name, IFNAMSIZ, "%s.%d-fcoe",
			 real_dev->ifname, fcf->vlan);
		rc = vlan_create(fcf->ifindex, fcf->vlan, vlan_name);
		if (rc < 0)
			printf("Failed to crate VLAN device %s\n\t%s\n",
			       vlan_name, strerror(-rc));
		else
			printf("Created VLAN device %s\n", vlan_name);
		rtnl_set_iff_up(0, vlan_name);
	}
	printf("\n");
}

int fcoe_instance_start(char *ifname)
{
	int fd, rc;
	FIP_LOG_DBG("%s on %s\n", __func__, ifname);
	fd = open(SYSFS_FCOE "/create", O_WRONLY);
	if (fd < 0) {
		FIP_LOG_ERRNO("failed to open fcoe create file");
		return fd;
	}
	rc = write(fd, ifname, strlen(ifname));
	close(fd);
	return rc < 0 ? rc : 0;
}

void start_fcoe()
{
	struct fcf *fcf;
	struct iff *iff;

	TAILQ_FOREACH(fcf, &fcfs, list_node) {
		iff = lookup_vlan(fcf->ifindex, fcf->vlan);
		if (!iff) {
			FIP_LOG_ERR(ENODEV,
				    "Cannot start FCoE on VLAN %d, ifindex %d, "
				    "because the VLAN device does not exist",
				    fcf->vlan, fcf->ifindex);
			continue;
		}
		printf("Starting FCoE on interface %s\n", iff->ifname);
		fcoe_instance_start(iff->ifname);
	}
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
	printf("%-16.16s| %-5.5s| %-17.17s\n", "interface", "VLAN", "FCF MAC");
	printf("------------------------------------------\n");
	TAILQ_FOREACH(fcf, &fcfs, list_node) {
		iff = lookup_iff(fcf->ifindex, NULL);
		printf("%-16.16s| %-5d| %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
			iff->ifname, fcf->vlan,
			fcf->mac_addr[0], fcf->mac_addr[1], fcf->mac_addr[2],
			fcf->mac_addr[3], fcf->mac_addr[4], fcf->mac_addr[5]);
	}
	printf("\n");
}

void recv_loop(int timeout)
{
	int i;
	int rc;

	while (1) {
		rc = poll(pfd, pfd_len, timeout);
		FIP_LOG_DBG("return from poll %d", rc);
		if (rc == 0) /* timeout */
			break;
		if (rc == -1) {
			FIP_LOG_ERRNO("poll error");
			break;
		}
		/* pfd[0] must be the netlink socket */
		if (pfd[0].revents & POLLIN)
			rtnl_recv(pfd[0].fd, rtnl_listener_handler, NULL);
		/* everything else should be FIP packet sockets */
		for (i = 1; i < pfd_len; i++) {
			if (pfd[i].revents & POLLIN)
				fip_recv(pfd[i].fd, fip_vlan_handler, NULL);
		}
	}
}

void find_interfaces(int ns)
{
	send_getlink_dump(ns);
	rtnl_recv(ns, rtnl_listener_handler, NULL);
}

int send_vlan_requests(void)
{
	struct iff *iff;
	int i;
	int skipped = 0;

	if (config.automode) {
		TAILQ_FOREACH(iff, &interfaces, list_node) {
			if (iff->resp_recv)
				continue;
			if (!iff->running) {
				skipped++;
				iff->req_sent = false;
				continue;
			}
			fip_send_vlan_request(iff->ps,
					      iff->ifindex,
					      iff->mac_addr);
			iff->req_sent = true;
		}
	} else {
		for (i = 0; i < config.namec; i++) {
			iff = lookup_iff(0, config.namev[i]);
			if (!iff) {
				skipped++;
				continue;
			}
			if (iff->resp_recv)
				continue;
			if (!iff->running) {
				skipped++;
				iff->req_sent = false;
				continue;
			}
			fip_send_vlan_request(iff->ps,
					      iff->ifindex,
					      iff->mac_addr);
			iff->req_sent = true;
		}
	}
	return skipped;
}

void do_vlan_discovery(void)
{
	struct iff *iff;
	int retry_count = 0;
	int skip_retry_count = 0;
	int skipped = 0;
retry:
	skipped += send_vlan_requests();
	if (skipped && skip_retry_count++ < 30) {
		FIP_LOG_DBG("waiting for IFF_RUNNING [%d]\n", skip_retry_count);
		recv_loop(500);
		skipped = 0;
		retry_count = 0;
		goto retry;
	}
	recv_loop(200);
	TAILQ_FOREACH(iff, &interfaces, list_node)
		/* if we did not receive a response, retry */
		if (iff->req_sent && !iff->resp_recv && retry_count++ < 10) {
			FIP_LOG_DBG("VLAN discovery RETRY [%d]", retry_count);
			goto retry;
		}
}

/* this is to not require headers from libcap */
static inline int capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
	return syscall(__NR_capget, hdrp, datap);
}

int checkcaps()
{
	struct __user_cap_header_struct caphdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3];

	capget(&caphdr, caps);
	return !(caps[CAP_TO_INDEX(CAP_NET_RAW)].effective &
		 CAP_TO_MASK(CAP_NET_RAW));
}

int main(int argc, char **argv)
{
	int ns;
	int rc = 0;

	exe = strrchr(argv[0], '/');
	if (exe)
		exe++;
	else
		exe = argv[0];

	parse_cmdline(argc, argv);
	sa_log_prefix = exe;
	sa_log_flags = 0;
	enable_debug_log(0);

	if (checkcaps()) {
		FIP_LOG("must run as root or with the NET_RAW capability");
		exit(1);
	}

	ns = rtnl_socket();
	if (ns < 0) {
		rc = ns;
		goto ns_err;
	}
	pfd_add(ns);

	find_interfaces(ns);

	if (TAILQ_EMPTY(&interfaces)) {
		FIP_LOG_ERR(ENODEV, "no interfaces to perform discovery on");
		exit(1);
	}

	do_vlan_discovery();

	print_results();
	if (config.create) {
		create_missing_vlans();
		/*
		 * need to listen for the RTM_NETLINK messages
		 * about the new VLAN devices
		 */
		recv_loop(500);
	}
	if (config.start)
		start_fcoe();
	close(ns);
ns_err:
	exit(rc);
}

