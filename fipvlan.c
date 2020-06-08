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

#define FIP_LOG(...)		sa_log(__VA_ARGS__)
#define FIP_LOG_ERR(error, ...)	sa_log_err(error, __func__, __VA_ARGS__)
#define FIP_LOG_ERRNO(...)	sa_log_err(errno, __func__, __VA_ARGS__)
#define FIP_LOG_DBG(...)	sa_log_debug(__VA_ARGS__)

#define MAX_VLAN_RETRIES	50

/* global configuration */

struct {
	char **namev;
	int namec;
	bool automode;
	bool create;
	bool start;
	bool vn2vn;
	bool debug;
	bool link_up;
	int link_retry;
	char suffix[256];
} config = {
	.namev = NULL,
	.namec = 0,
	.automode = false,
	.create = false,
	.vn2vn = false,
	.debug = false,
	.link_up = false,
	.link_retry = 20,
	.suffix = "",
};

int (*fcoe_instance_start)(const char *ifname);

char *exe;

static struct pollfd *pfd = NULL;
static int pfd_len = 0;

static void pfd_add(int fd)
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

static void pfd_remove(int fd)
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
	else
		perror("realloc failed");
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
	bool linkup_sent;
	bool req_sent;
	bool resp_recv;
	bool fip_ready;
	bool fcoe_started;
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
static struct fcf_list_head vn2vns = TAILQ_HEAD_INITIALIZER(vn2vns);

static int create_and_start_vlan(struct fcf *fcf, bool vn2vn);

static struct fcf *lookup_fcf(struct fcf_list_head *head, int ifindex,
			      uint16_t vlan, unsigned char *mac)
{
	struct fcf *fcf;

	TAILQ_FOREACH(fcf, head, list_node)
		if ((ifindex == fcf->ifindex) && (vlan == fcf->vlan)) {
			if ((!mac) || (memcmp(mac, fcf->mac_addr, ETHER_ADDR_LEN) == 0))
				return fcf;
		}
	return NULL;
}

static struct iff *lookup_iff(int ifindex, const char *ifname)
{
	struct iff *iff;
	struct iff *vlan;

	if (!ifindex && !ifname)
		return NULL;

	TAILQ_FOREACH(iff, &interfaces, list_node) {
		if ((!ifindex || ifindex == iff->ifindex) &&
		    (!ifname  || strcmp(ifname, iff->ifname) == 0))
			return iff;

		TAILQ_FOREACH(vlan, &iff->vlans, list_node)
			if ((!ifindex || ifindex == vlan->ifindex) &&
			    (!ifname  || strcmp(ifname, vlan->ifname) == 0))
				return vlan;
	}
	return NULL;
}

static struct iff *lookup_vlan(int ifindex, short int vid)
{
	struct iff *real_dev, *vlan;
	TAILQ_FOREACH(real_dev, &interfaces, list_node)
		if (real_dev->ifindex == ifindex)
			TAILQ_FOREACH(vlan, &real_dev->vlans, list_node)
				if (vlan->vid == vid)
					return vlan;
	return NULL;
}

static struct iff *find_vlan_real_dev(struct iff *vlan)
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

#define TLV_LEN_CHECK(t, l) ({						\
	int _tlc = ((t)->tlv_len != (l)) ? 1 : 0;			\
	if (_tlc)							\
		FIP_LOG("bad length for TLV of type %d", (t)->tlv_type); \
	_tlc;								\
	})

/**
 * fip_parse_tlvs - parse type/length/value encoded FIP descriptors
 * @ptr: pointer to beginning of FIP TLV payload, the first descriptor
 * @len: total length of all TLVs, in double words
 * @tlv_ptrs: pointers to type specific structures to fill out
 */
static unsigned int
fip_parse_tlvs(void *ptr, int len, struct fip_tlv_ptrs *tlv_ptrs)
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
 * @vn2vn: true if vn2vn notification
 */
static int fip_recv_vlan_note(struct fiphdr *fh, int ifindex, bool vn2vn)
{
	struct fip_tlv_ptrs tlvs;
	struct fcf_list_head *head;
	struct fcf *fcf;
	struct iff *iff;
	uint16_t vlan;
	unsigned int bitmap, required_tlvs;
	int len;
	unsigned int i;

	FIP_LOG_DBG("received FIP VLAN Notification");

	len = ntohs(fh->fip_desc_len);

	required_tlvs = (1 << FIP_TLV_MAC_ADDR) | (1 << FIP_TLV_VLAN);

	tlvs.mac = NULL;	/* Silence incorrect GCC warning */
	bitmap = fip_parse_tlvs((fh + 1), len, &tlvs);
	if ((bitmap & required_tlvs) != required_tlvs)
		return -1;

	if (vn2vn)
		head = &vn2vns;
	else
		head = &fcfs;

	iff = lookup_iff(ifindex, NULL);
	if (iff)
		iff->resp_recv = true;

	for (i = 0; i < tlvs.vlanc; i++) {
		vlan = ntohs(tlvs.vlan[i]->vlan);
		if (lookup_fcf(head, ifindex, vlan, tlvs.mac->mac_addr))
			continue;

		fcf = malloc(sizeof(*fcf));
		if (!fcf) {
			FIP_LOG_ERRNO("malloc failed");
			break;
		}
		memset(fcf, 0, sizeof(*fcf));
		fcf->ifindex = ifindex;
		fcf->vlan = vlan;
		memcpy(fcf->mac_addr, tlvs.mac->mac_addr, ETHER_ADDR_LEN);
		TAILQ_INSERT_TAIL(head, fcf, list_node);
		if (!config.create)
			continue;
		create_and_start_vlan(fcf, vn2vn);
	}

	return 0;
}

static int fip_vlan_handler(struct fiphdr *fh, struct sockaddr_ll *sa,
			    UNUSED void *arg)
{
	/* We only care about VLAN Notifications */
	if (ntohs(fh->fip_proto) != FIP_PROTO_VLAN) {
		FIP_LOG_DBG("ignoring FIP packet, protocol %d",
			    ntohs(fh->fip_proto));
		return -1;
	}

	switch (fh->fip_subcode) {
	case FIP_VLAN_NOTE:
		if (config.vn2vn) {
			FIP_LOG_DBG("ignoring FCF response in vn2vn mode\n");
			return -1;
		}
		return fip_recv_vlan_note(fh, sa->sll_ifindex, false);
	case FIP_VLAN_NOTE_VN2VN:
		if (!config.vn2vn) {
			FIP_LOG_DBG("ignoring VN2VN response in fabric mode\n");
			return -1;
		}
		return fip_recv_vlan_note(fh, sa->sll_ifindex, true);
	default:
		FIP_LOG_DBG("ignored FIP VLAN packet with subcode %d",
			    fh->fip_subcode);
		return -1;
	}
}

/**
 * rtnl_recv_newlink - parse response to RTM_GETLINK, or an RTM_NEWLINK event
 * @nh: netlink message header, beginning of received netlink frame
 */
static void rtnl_recv_newlink(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifm = NLMSG_DATA(nh);
	struct rtattr *ifla[__IFLA_MAX];
	struct rtattr *linkinfo[__IFLA_INFO_MAX];
	struct rtattr *vlan[__IFLA_VLAN_MAX];
	struct iff *iff, *real_dev;
	struct fcf_list_head *head;
	bool running;

	if (config.vn2vn)
		head = &vn2vns;
	else
		head = &fcfs;

	FIP_LOG_DBG("RTM_NEWLINK: ifindex %d, type %d, flags %x",
		    ifm->ifi_index, ifm->ifi_type, ifm->ifi_flags);

	/* We only deal with Ethernet interfaces */
	if (ifm->ifi_type != ARPHRD_ETHER)
		return;

	/* not on bond master, but rather allow FIP on the slaves below */
	if (ifm->ifi_flags & IFF_MASTER)
		return;

	running = !!(ifm->ifi_flags & (IFF_RUNNING | IFF_SLAVE));
	iff = lookup_iff(ifm->ifi_index, NULL);
	if (iff) {
		int ifindex;

		/* already tracking, update operstate and return */
		iff->running = running;
		if (!iff->running) {
			pfd_remove(iff->ps);
			return;
		}
		pfd_add(iff->ps);
		if (!config.start)
			return;

		FIP_LOG_DBG("Checking for FCoE on %sif %d",
			    iff->is_vlan ? "VLAN " : "", iff->ifindex);
		if (iff->is_vlan) {
			real_dev = find_vlan_real_dev(iff);
			if (!real_dev) {
				FIP_LOG_ERR(ENODEV, "VLAN %d without a parent",
					    iff->ifindex);
				return;
			}
			ifindex = real_dev->ifindex;
		} else
			ifindex = iff->ifindex;

		if (!iff->fcoe_started &&
		    lookup_fcf(head, ifindex, iff->vid, NULL)) {
			printf("Starting FCoE on interface %s\n",
			       iff->ifname);
			fcoe_instance_start(iff->ifname);
			iff->fcoe_started = true;
		}
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
	iff->running = running;
	iff->fip_ready = false;
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
				free(iff);
				return;
			}
			TAILQ_INSERT_TAIL(&real_dev->vlans, iff, list_node);
			if (!iff->running) {
				FIP_LOG_DBG("vlan if %d not running, "
					    "starting", iff->ifindex);
				rtnl_set_iff_up(iff->ifindex, NULL);
			}
			return;
		}
		/* ignore bonding interfaces */
		if (linkinfo[IFLA_INFO_KIND] &&
		    !strcmp(RTA_DATA(linkinfo[IFLA_INFO_KIND]), "bond")) {
			free(iff);
			return;
		}
	}
	TAILQ_INSERT_TAIL(&interfaces, iff, list_node);
}

/* command line arguments */

#define GETOPT_STR "acdf:l:m:suhv"

static const struct option long_options[] = {
	{ "auto", no_argument, NULL, 'a' },
	{ "create", no_argument, NULL, 'c' },
	{ "start", no_argument, NULL, 's' },
	{ "debug", no_argument, NULL, 'd' },
	{ "suffix", required_argument, NULL, 'f' },
	{ "link-retry", required_argument, NULL, 'l' },
	{ "mode", required_argument, NULL, 'm' },
	{ "link-up", required_argument, NULL, 'u' },
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
		"  -c, --create         Create system VLAN devices\n"
		"  -d, --debug          Enable debugging output\n"
		"  -s, --start          Start FCoE login automatically\n"
		"  -f, --suffix		Append the suffix to VLAN interface name\n"
		"  -l, --link-retry     Number of retries for link up\n"
		"  -m, --mode           Link mode, either fabric or vn2vn\n"
		"  -u, --link-up        Leave link up after FIP response\n"
		"  -h, --help           Display this help and exit\n"
		"  -v, --version        Display version information and exit\n",
		exe);

	exit(status);
}

static void parse_cmdline(int argc, char **argv)
{
	signed char c;

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
		case 'd':
			config.debug = true;
			break;
		case 's':
			config.start = true;
			break;
		case 'f':
			if (optarg && strlen(optarg))
				strncpy(config.suffix, optarg, 256);
			break;
		case 'l':
			config.link_retry = strtoul(optarg, NULL, 10);
			break;
		case 'm':
			if (strcasecmp(optarg, "vn2vn") == 0)
				config.vn2vn = true;
			else if (strcasecmp(optarg, "fabric") == 0)
				config.vn2vn = false;
			else {
				fprintf(stderr, "%s: Unknown value for mode: %s\n",
					exe, optarg);
				exit(1);
			}
			break;
		case 'u':
			config.link_up = true;
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

static int rtnl_listener_handler(struct nlmsghdr *nh, UNUSED void *arg)
{
	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
		rtnl_recv_newlink(nh);
		return 0;
	}
	return -1;
}

static int
safe_makevlan_name(char *vlan_name, size_t vsz,
		char *ifname, int vlan_num, char *suffix)
{
	size_t ifsz = strlen(ifname);
	size_t susz = strlen(suffix);	/* should never be NULL */
	int nusz;
	char numbuf[16];
	char *cp = vlan_name;

	nusz = snprintf(numbuf, sizeof(numbuf), "%d", vlan_num);

	if ((ifsz + susz + nusz + 2) > vsz) {
		FIP_LOG_ERR(EINVAL,
			"Cannot make VLAN name from ifname=\"%s\", vlan %d, and suffix=\"%s\"\n",
			ifname, vlan_num, suffix);
		return -EINVAL;
	}
	memcpy(cp, ifname, ifsz);
	cp += ifsz;
	memcpy(cp, numbuf, nusz);
	cp += nusz;
	if (susz > 0) {
		memcpy(cp, suffix, susz);
		cp += susz;
	}
	*cp = '\0';
	return 0;
}

static int
create_and_start_vlan(struct fcf *fcf, bool vn2vn)
{
	struct iff *real_dev, *vlan;
	char vlan_name[IFNAMSIZ];
	int rc;

	real_dev = lookup_iff(fcf->ifindex, NULL);
	if (!real_dev) {
		FIP_LOG_ERR(ENODEV,
			    "lost device %d with discovered %s?\n",
			    fcf->ifindex, vn2vn ? "VN2VN" : "FCF");
		return -ENXIO;
	}
	if (!fcf->vlan) {
		/*
		 * If the vlan notification has VLAN id 0,
		 * skip creating vlan interface, and FCoE is
		 * started on the physical interface itself.
		 */
		FIP_LOG_DBG("VLAN id is 0 for %s\n", real_dev->ifname);
		vlan = real_dev;
	} else {
		vlan = lookup_vlan(fcf->ifindex, fcf->vlan);
		if (vlan) {
			FIP_LOG_DBG("VLAN %s.%d already exists as %s\n",
				    real_dev->ifname, fcf->vlan, vlan->ifname);
			rc = 0;
		} else {
			rc = safe_makevlan_name(vlan_name, sizeof(vlan_name),
				 real_dev->ifname, fcf->vlan, config.suffix);
			if (rc < 0)
				return rc;
			rc = vlan_create(fcf->ifindex, fcf->vlan, vlan_name);
			if (rc < 0)
				printf("Failed to create VLAN device %s\n\t%s\n",
				       vlan_name, strerror(-rc));
			else
				printf("Created VLAN device %s\n", vlan_name);
			return rc;
		}
	}
	if (!config.start)
		return rc;

	if (!vlan->running) {
		FIP_LOG_DBG("%s if %d not running, starting",
			    vlan == real_dev ? "real" : "vlan",
			    vlan->ifindex);
		rtnl_set_iff_up(vlan->ifindex, NULL);
	} else if (!vlan->fcoe_started) {
		printf("Starting FCoE on interface %s\n",
		       vlan->ifname);
		fcoe_instance_start(vlan->ifname);
		vlan->fcoe_started = true;
	}
	return rc;
}

static int fcoe_mod_instance_start(const char *ifname)
{
	enum fcoe_status ret;
	const char *path;

	if (config.vn2vn)
		path = FCOE_CREATE_VN2VN;
	else
		path = FCOE_CREATE;

	ret = fcm_write_str_to_sysfs_file(path, ifname);
	if (ret) {
		FIP_LOG_ERRNO("Failed to open file: %s", FCOE_CREATE);
		FIP_LOG_ERRNO("May be fcoe stack not loaded, starting"
			      " fcoe service will fix that");

		return EFAIL;
	}

	return 0;
}

static int fcoe_bus_instance_start(const char *ifname)
{
	enum fcoe_status ret;
	char fchost[FCHOSTBUFLEN];
	char ctlr[FCHOSTBUFLEN];

	ret = fcm_write_str_to_sysfs_file(FCOE_BUS_CREATE, ifname);
	if (ret) {
		FIP_LOG_ERRNO("Failed to open file: %s", FCOE_BUS_CREATE);
		FIP_LOG_ERRNO("May be fcoe stack not loaded, starting"
			      " fcoe service will fix that");
		return ret;
	}

	if (fcoe_find_fchost(ifname, fchost, FCHOSTBUFLEN)) {
		FIP_LOG_DBG("Failed to find fc_host for %s\n", ifname);
		return ENOSYSFS;
	}

	if (fcoe_find_ctlr(fchost, ctlr, FCHOSTBUFLEN)) {
		FIP_LOG_DBG("Failed to get ctlr for %s\n", ifname);
		return ENOSYSFS;
	}

	if (config.vn2vn) {
		ret = fcm_write_str_to_ctlr_attr(ctlr, FCOE_CTLR_ATTR_MODE,
						 "vn2vn");
		if (ret)
			FIP_LOG_DBG("Failed to set mode interface %s\n",
				    ifname);
	}

	ret = fcm_write_str_to_ctlr_attr(ctlr, FCOE_CTLR_ATTR_ENABLED, "1");
	if (ret)
		FIP_LOG_DBG("Failed to enable interface %s\n", ifname);

	return 0;
}

static void determine_libfcoe_interface(void)
{
	if (!access(FCOE_BUS_CREATE, F_OK)) {
		FIP_LOG_DBG("Using /sys/bus/fcoe interfaces\n");
		fcoe_instance_start = &fcoe_bus_instance_start;
	} else {
		FIP_LOG_DBG("Using libfcoe module parameter interfaces\n");
		fcoe_instance_start = &fcoe_mod_instance_start;
	}
}

static void print_list(struct fcf_list_head *list, const char *label)
{
	struct iff *iff;
	struct fcf *fcf;

	printf("%-16.16s| %-5.5s| %-17.17s\n", "interface", "VLAN", label);
	printf("------------------------------------------\n");
	TAILQ_FOREACH(fcf, list, list_node) {
		iff = lookup_iff(fcf->ifindex, NULL);
		printf("%-16.16s| %-5d| %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
		       iff->ifname, fcf->vlan,
		       fcf->mac_addr[0], fcf->mac_addr[1], fcf->mac_addr[2],
		       fcf->mac_addr[3], fcf->mac_addr[4], fcf->mac_addr[5]);
	}
	printf("\n");
}

static int print_results(void)
{
	if (TAILQ_EMPTY(&fcfs) && TAILQ_EMPTY(&vn2vns)) {
		printf("No Fibre Channel Forwarders or VN2VN Responders Found\n");
		return ENODEV;
	}

	if (!TAILQ_EMPTY(&fcfs)) {
		printf("Fibre Channel Forwarders Discovered\n");
		print_list(&fcfs, "FCF MAC");
	}
	if (!TAILQ_EMPTY(&vn2vns)) {
		printf("VN2VN Responders Discovered\n");
		print_list(&vn2vns, "VN2VN MAC");
	}

	return 0;
}

static void recv_loop(int timeout)
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
			if (pfd[i].revents & POLLIN) {
				rc = fip_recv(pfd[i].fd, fip_vlan_handler,
					      NULL);
				if (rc < 0)
					break;
			}
		}
		if (i < pfd_len)
			break;
	}
}

static void find_interfaces(int ns)
{
	send_getlink_dump(ns);
	rtnl_recv(ns, rtnl_listener_handler, NULL);
}

static int probe_fip_interface(struct iff *iff)
{
	int origdev = 1, rc;

	if (iff->resp_recv)
		return 0;
	if (!iff->running) {
		if (iff->linkup_sent) {
			FIP_LOG_DBG("if %d not running, waiting for link up",
				    iff->ifindex);
		} else {
			FIP_LOG_DBG("if %d not running, starting",
				    iff->ifindex);
			rtnl_set_iff_up(iff->ifindex, NULL);
			iff->linkup_sent = true;
		}
		iff->req_sent = false;
		return 1;
	}
	if (iff->req_sent)
		return 0;

	if (!iff->fip_ready) {
		iff->ps = fip_socket(iff->ifindex, iff->mac_addr, FIP_NONE);
		if (iff->ps < 0) {
			FIP_LOG_DBG("if %d not ready\n", iff->ifindex);
			return 0;
		}
		setsockopt(iff->ps, SOL_PACKET, PACKET_ORIGDEV,
			   &origdev, sizeof(origdev));
		pfd_add(iff->ps);
		iff->fip_ready = true;
	}

	if (config.vn2vn)
		rc = fip_send_vlan_request(iff->ps, iff->ifindex,
					   iff->mac_addr, FIP_ALL_VN2VN);
	else
		rc = fip_send_vlan_request(iff->ps, iff->ifindex,
					   iff->mac_addr, FIP_ALL_FCF);
	if (rc == 0)
		iff->req_sent = true;
	return rc == 0 ? 0 : 1;
}

static int send_vlan_requests(void)
{
	struct iff *iff;
	int skipped = 0;
	int i;

	if (config.automode) {
		TAILQ_FOREACH(iff, &interfaces, list_node) {
			skipped += probe_fip_interface(iff);
		}
	} else {
		for (i = 0; i < config.namec; i++) {
			iff = lookup_iff(0, config.namev[i]);
			if (!iff) {
				skipped++;
				continue;
			}
			skipped += probe_fip_interface(iff);
		}
	}
	return skipped;
}

static void do_vlan_discovery(void)
{
	struct iff *iff;
	int retry_count = 0;
	int skip_retry_count = 0;
	int skipped = 0, retry_iff = 0;
retry:
	skipped += send_vlan_requests();
	if (skipped && skip_retry_count++ < config.link_retry) {
		FIP_LOG_DBG("waiting for IFF_RUNNING [%d/%d]\n",
			    skip_retry_count, config.link_retry);
		recv_loop(500);
		skipped = 0;
		retry_count = 0;
		goto retry;
	}
	recv_loop(200);
	TAILQ_FOREACH(iff, &interfaces, list_node) {
		if (!iff->fip_ready) {
			FIP_LOG_DBG("if %d: skipping, FIP not ready\n",
				    iff->ifindex);
			continue;
		}
		if (!iff->running && iff->linkup_sent) {
			FIP_LOG_DBG("if %d: waiting for IFF_RUNNING [%d]\n",
				    iff->ifindex, retry_count);
			retry_iff++;
			continue;
		}
		/* if we did not receive a response, retry */
		if (iff->req_sent && !iff->resp_recv) {
			FIP_LOG_DBG("if %d: VLAN discovery RETRY [%d]",
				    iff->ifindex, retry_count);
			iff->req_sent = false;
			retry_iff++;
			continue;
		}
		if (config.create) {
			struct iff *vlan;

			TAILQ_FOREACH(vlan, &iff->vlans, list_node) {
				if (!vlan->running) {
					FIP_LOG_DBG("vlan %d: waiting for "
						    "IFF_RUNNING [%d]",
						    vlan->ifindex, retry_count);
					retry_iff++;
					continue;
				}
			}
		}
	}
	if (retry_iff && retry_count++ < config.link_retry) {
		recv_loop(1000);
		retry_iff = 0;
		goto retry;
	}
}

static void cleanup_interfaces(void)
{
	struct iff *iff;

	TAILQ_FOREACH(iff, &interfaces, list_node) {
		if (iff->linkup_sent) {
			if (config.link_up && iff->resp_recv)
				continue;
			if (iff->fcoe_started)
				continue;
			if (TAILQ_EMPTY(&iff->vlans)) {
				FIP_LOG_DBG("shutdown if %d",
					    iff->ifindex);
				rtnl_set_iff_down(iff->ifindex, NULL);
				iff->linkup_sent = false;
			}
		}
	}
}

/* this is to not require headers from libcap */
static inline int capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
	return syscall(__NR_capget, hdrp, datap);
}

static int checkcaps(void)
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
	int find_cnt = 0;

	exe = strrchr(argv[0], '/');
	if (exe)
		exe++;
	else
		exe = argv[0];

	parse_cmdline(argc, argv);
	sa_log_prefix = exe;
	sa_log_flags = 0;
	enable_debug_log(config.debug);

	if (checkcaps()) {
		FIP_LOG("must run as root or with the NET_RAW capability");
		exit(1);
	}

	ns = rtnl_socket(RTMGRP_LINK);
	if (ns < 0) {
		rc = 1;
		goto ns_err;
	}
	pfd_add(ns);

	determine_libfcoe_interface();

	find_interfaces(ns);
	if (config.automode)
		while ((TAILQ_EMPTY(&interfaces)) && ++find_cnt < 5) {
			FIP_LOG_DBG("no interfaces found, trying again");
			find_interfaces(ns);
		}

	if (TAILQ_EMPTY(&interfaces)) {
		if (config.automode)
			FIP_LOG_ERR(ENODEV,
				    "no interfaces to perform discovery on");
		else
			FIP_LOG("no interfaces to perform discovery on");
		exit(ENODEV);
	}

	do_vlan_discovery();

	rc = print_results();

	cleanup_interfaces();

	close(ns);
ns_err:
	exit(rc);
}

