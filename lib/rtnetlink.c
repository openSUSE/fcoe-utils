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
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/dcbnl.h>
#include "rtnetlink.h"
#include "fcoemon_utils.h"

#define RTNL_LOG(...)		sa_log(__VA_ARGS__)
#define RTNL_LOG_ERR(error, ...)	sa_log_err(error, __func__, __VA_ARGS__)
#define RTNL_LOG_ERRNO(...)	sa_log_err(errno, __func__, __VA_ARGS__)
#define RTNL_LOG_DBG(...)	sa_log_debug(__VA_ARGS__)

#define NLA_DATA(nla)  ((void *)((char*)(nla) + NLA_HDRLEN))

/**
 * rtnl_socket - create and bind a routing netlink socket
 */
int rtnl_socket(unsigned int groups)
{
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = groups,
	};
	int s;
	int rc;

	RTNL_LOG_DBG("creating netlink socket");
	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		RTNL_LOG_ERRNO("netlink socket error");
		return s;
	}

	rc = bind(s, (struct sockaddr *) &sa, sizeof(sa));
	if (rc < 0) {
		RTNL_LOG_ERRNO("netlink bind error");
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
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		},
		.ifm = {
			.ifi_type = ARPHRD_ETHER,
		},
	};
	int rc;

	RTNL_LOG_DBG("sending RTM_GETLINK dump request");
	rc = send(s, &req, req.nh.nlmsg_len, 0);
	if (rc < 0)
		RTNL_LOG_ERRNO("netlink sendmsg error");

	return rc;
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
int rtnl_recv(int s, rtnl_handler *fn, void *arg)
{
	char buf[8192];
	struct nlmsghdr *nh;
	size_t len;
	int rc = 0;
	int ret;
	bool more = false;

more:
	ret = recv(s, buf, sizeof(buf), 0);
	if (ret < 0) {
		RTNL_LOG_ERRNO("netlink recvmsg error");
		return ret;
	}

	len = ret;
	for (nh = NLMSG(buf); NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_flags & NLM_F_MULTI)
			more = true;

		switch (nh->nlmsg_type) {
		case NLMSG_NOOP:
			RTNL_LOG_DBG("NLMSG_NOOP");
			break;
		case NLMSG_ERROR:
			rc = ((struct nlmsgerr *)NLMSG_DATA(nh))->error;
			RTNL_LOG_DBG("NLMSG_ERROR (%d) %s", rc, strerror(-rc));
			break;
		case NLMSG_DONE:
			more = false;
			RTNL_LOG_DBG("NLMSG_DONE");
			break;
		default:
			if (!fn || fn(nh, arg) < 0)
				RTNL_LOG("unexpected netlink message type %d",
					 nh->nlmsg_type);
			break;
		}
	}
	if (more)
		goto more;
	return rc;
}

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static void add_rtattr(struct nlmsghdr *n, int type, const void *data, int alen)
{
	struct rtattr *rta = NLMSG_TAIL(n);
	int len = RTA_LENGTH(alen);

	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

static struct rtattr *add_rtattr_nest(struct nlmsghdr *n, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	add_rtattr(n, type, NULL, 0);
	return nest;
}

static void end_rtattr_nest(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
}

static ssize_t rtnl_send_set_iff_up(int s, int ifindex, char *ifname)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
		char attrbuf[RTA_SPACE(IFNAMSIZ)];
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_SETLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		},
		.ifm = {
			.ifi_index = ifindex,
			.ifi_flags = IFF_UP,
			.ifi_change = IFF_UP,
		},
	};
	int rc;

	if (ifname)
		add_rtattr(&req.nh, IFLA_IFNAME, ifname, strlen(ifname));

	RTNL_LOG_DBG("sending RTM_SETLINK request");
	rc = send(s, &req, req.nh.nlmsg_len, 0);
	if (rc < 0)
		RTNL_LOG_ERRNO("netlink send error");

	return rc;
}

int rtnl_set_iff_up(int ifindex, char *ifname)
{
	int s;
	int rc;

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;
	rc = rtnl_send_set_iff_up(s, ifindex, ifname);
	if (rc < 0)
		goto out;
	rc = rtnl_recv(s, NULL, NULL);
out:
	close(s);
	return rc;
}

static ssize_t rtnl_send_set_iff_down(int s, int ifindex, char *ifname)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
		char attrbuf[RTA_SPACE(IFNAMSIZ)];
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_SETLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		},
		.ifm = {
			.ifi_index = ifindex,
			.ifi_flags = 0,
			.ifi_change = IFF_UP,
		},
	};
	int rc;

	if (ifname)
		add_rtattr(&req.nh, IFLA_IFNAME, ifname, strlen(ifname));

	RTNL_LOG_DBG("sending RTM_SETLINK request");
	rc = send(s, &req, req.nh.nlmsg_len, 0);
	if (rc < 0)
		RTNL_LOG_ERRNO("netlink send error");

	return rc;
}

int rtnl_set_iff_down(int ifindex, char *ifname)
{
	int s;
	int rc;

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;
	rc = rtnl_send_set_iff_down(s, ifindex, ifname);
	if (rc < 0)
		goto out;
	rc = rtnl_recv(s, NULL, NULL);
out:
	close(s);
	return rc;
}

static ssize_t rtnl_send_vlan_newlink(int s, int ifindex, int vid, char *name)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
		char attrbuf[1024];
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_NEWLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE |
				       NLM_F_EXCL | NLM_F_ACK,
		},
	};
	struct rtattr *linkinfo, *data;
	int rc;

	add_rtattr(&req.nh, IFLA_LINK, &ifindex, 4);
	add_rtattr(&req.nh, IFLA_IFNAME, name, strlen(name));
	linkinfo = add_rtattr_nest(&req.nh, IFLA_LINKINFO);
	add_rtattr(&req.nh, IFLA_INFO_KIND, "vlan", strlen("vlan"));
	data = add_rtattr_nest(&req.nh, IFLA_INFO_DATA);
	add_rtattr(&req.nh, IFLA_VLAN_ID, &vid, 2);
	end_rtattr_nest(&req.nh, data);
	end_rtattr_nest(&req.nh, linkinfo);

	RTNL_LOG_DBG("sending RTM_NEWLINK request");
	rc = send(s, &req, req.nh.nlmsg_len, 0);
	if (rc < 0)
		RTNL_LOG_ERRNO("netlink send error");

	return rc;
}

int vlan_create(int ifindex, int vid, char *name)
{
	int s;
	int rc;

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;

	rc = rtnl_send_vlan_newlink(s, ifindex, vid, name);
	if (rc < 0)
		goto out;
	rc = rtnl_recv(s, NULL, NULL);
out:
	close(s);
	return rc;
}

static ssize_t rtnl_send_getlink(int s, int ifindex, char *name)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
		char attrbuf[RTA_SPACE(IFNAMSIZ)];
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.ifm = {
			.ifi_family = AF_UNSPEC,
			.ifi_index = ifindex,
		},
	};
	int rc;

	if (!ifindex && !name)
		return -1;

	if (name)
		add_rtattr(&req.nh, IFLA_IFNAME, name, strlen(name));

	RTNL_LOG_DBG("sending RTM_GETLINK");
	rc = send(s, &req, req.nh.nlmsg_len, 0);
	if (rc < 0)
		RTNL_LOG_ERRNO("netlink send error");

	return rc;
}

static int rtnl_getlinkname_handler(struct nlmsghdr *nh, void *arg)
{
	char *name = arg;
	struct rtattr *ifla[__IFLA_MAX];

	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
		parse_ifinfo(ifla, nh);
		strncpy(name, RTA_DATA(ifla[IFLA_IFNAME]), IFNAMSIZ);
		return 0;
	}
	return -1;
}

int rtnl_get_linkname(int ifindex, char *name)
{
	int s;
	int rc;

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;
	rc = rtnl_send_getlink(s, ifindex, NULL);
	if (rc < 0)
		return rc;
	rc = rtnl_recv(s, rtnl_getlinkname_handler, name);
	if (rc < 0)
		goto out;
out:
	close(s);
	return rc;
}

struct vlan_identifier {
	int ifindex;
	int vid;
	int found;
	unsigned char ifname[IFNAMSIZ];
};

static int rtnl_find_vlan_handler(struct nlmsghdr *nh, void *arg)
{
	struct vlan_identifier *vlan = arg;
	struct rtattr *ifla[__IFLA_MAX];
	struct rtattr *linkinfo[__IFLA_INFO_MAX];
	struct rtattr *vlaninfo[__IFLA_VLAN_MAX];

	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
		parse_ifinfo(ifla, nh);
		if (!ifla[IFLA_LINK])
			break;
		if (vlan->ifindex != *(int *)RTA_DATA(ifla[IFLA_LINK]))
			break;
		if (!ifla[IFLA_LINKINFO])
			break;
		parse_linkinfo(linkinfo, ifla[IFLA_LINKINFO]);
		if (!linkinfo[IFLA_INFO_KIND])
			break;
		if (strcmp(RTA_DATA(linkinfo[IFLA_INFO_KIND]), "vlan"))
			break;
		if (!linkinfo[IFLA_INFO_DATA])
			break;
		parse_vlaninfo(vlaninfo, linkinfo[IFLA_INFO_DATA]);
		if (!vlaninfo[IFLA_VLAN_ID])
			break;
		if (vlan->vid != *(int *)RTA_DATA(vlaninfo[IFLA_VLAN_ID]))
			break;
		if (!ifla[IFLA_IFNAME])
			break;
		vlan->found = 1;
		memcpy(vlan->ifname, RTA_DATA(ifla[IFLA_IFNAME]), IFNAMSIZ);
	}
	return 0;
}

int rtnl_find_vlan(int ifindex, int vid, char *ifname)
{
	int s;
	int rc;
	struct vlan_identifier vlan = {
		.ifindex = ifindex,
		.vid = vid,
		.found = 0,
	};

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;
	rc = send_getlink_dump(s);
	if (rc < 0)
		goto out;
	rc = rtnl_recv(s, rtnl_find_vlan_handler, &vlan);
	if (rc < 0)
		goto out;
	if (vlan.found) {
		memcpy(ifname, vlan.ifname, IFNAMSIZ);
		rc = 0;
	} else {
		rc = -ENODEV;
	}
out:
	close(s);
	return rc;
}

int rtnl_get_sanmac(const char *ifname, unsigned char *addr)
{
	int s;
	int rc = -EIO;
	struct {
		struct nlmsghdr nh;
		struct dcbmsg dcb;
		char attrbuf[1204];
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct dcbmsg)),
			.nlmsg_type = RTM_GETDCB,
			.nlmsg_pid = getpid(),
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.dcb = {
			.cmd = DCB_CMD_GPERM_HWADDR,
			.dcb_family = AF_UNSPEC,
			.dcb_pad = 0,
		},
	};

	struct nlmsghdr *nh = &req.nh;
	struct dcbmsg *dcb;
	struct rtattr *rta;

	/* prep the message */
	memset((void *)req.attrbuf, 0, sizeof(req.attrbuf));
	add_rtattr(nh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rtattr(nh, DCB_ATTR_PERM_HWADDR, NULL, 0);

	s = rtnl_socket(0);
	if (s < 0) {
		RTNL_LOG_ERRNO("failed to create the socket");
		return s;
	}

	rc = send(s, (void *)nh, nh->nlmsg_len, 0);
	if (rc < 0) {
		RTNL_LOG_ERRNO("failed to send to the socket");
		goto err_close;
	}

	memset((void *)&req, 0, sizeof(req));
	rc = recv(s, (void *)&req, sizeof(req), 0);
	if (rc < 0) {
		RTNL_LOG_ERRNO("failed to recv from the socket");
		rc = -EIO;
		goto err_close;
	}

	if (nh->nlmsg_type != RTM_GETDCB) {
		RTNL_LOG_DBG("Ignoring netlink msg %x\n", nh->nlmsg_type);
		rc = -EIO;
		goto err_close;
	}
	dcb = (struct dcbmsg *)NLMSG_DATA(nh);
	if (dcb->cmd != DCB_CMD_GPERM_HWADDR) {
		RTNL_LOG_DBG("Unexpected response for DCB command %x\n",
			     dcb->cmd);
		rc = -EIO;
		goto err_close;
	}
	rta = (struct rtattr *)(((char *)dcb) +
	      NLMSG_ALIGN(sizeof(struct dcbmsg)));
	if (rta->rta_type != DCB_ATTR_PERM_HWADDR) {
		RTNL_LOG_DBG("Unexpected DCB RTA attr %x\n", rta->rta_type);
		rc = -EIO;
		goto err_close;
	}
	/* SAN MAC follows the LAN MAC */
	memcpy(addr, NLA_DATA(rta) + ETH_ALEN, ETH_ALEN);
	rc = 0;
err_close:
	close(s);
	return rc;
}
