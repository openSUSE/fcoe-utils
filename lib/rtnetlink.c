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
#include "rtnetlink.h"
#include "fcoemon_utils.h"

#define RTNL_LOG(...)		sa_log(__VA_ARGS__)
#define RTNL_LOG_ERR(error, ...)	sa_log_err(error, __func__, __VA_ARGS__)
#define RTNL_LOG_ERRNO(...)	sa_log_err(errno, __func__, __VA_ARGS__)
#define RTNL_LOG_DBG(...)	sa_log_debug(__VA_ARGS__)

/**
 * rtnl_socket - create and bind a routing netlink socket
 */
int rtnl_socket(void)
{
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK,
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
	int len;
	int rc = 0;
	bool more = false;

	RTNL_LOG_DBG("%s", __func__);
more:
	len = recv(s, buf, sizeof(buf), 0);
	if (len < 0) {
		RTNL_LOG_ERRNO("netlink recvmsg error");
		return len;
	}

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
