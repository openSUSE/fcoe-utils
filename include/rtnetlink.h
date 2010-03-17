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

#ifndef _RTNETLINK_
#define _RTNETLINK_

int rtnl_socket(void);
typedef int rtnl_handler(struct nlmsghdr *nh, void *arg);
int rtnl_recv(int s, rtnl_handler *fn, void *arg);
ssize_t send_getlink_dump(int s);
int rtnl_set_iff_up(int ifindex, char *ifname);
int vlan_create(int ifindex, int vid, char *name);
int rtnl_find_vlan(int ifindex, int vid, char *ifname);
int rtnl_get_linkname(int ifindex, char *name);

static inline void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

static inline void parse_nested_rtattr(struct rtattr *tb[], int max, struct rtattr *rta)
{
	parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

static inline void parse_ifinfo(struct rtattr *tb[], struct nlmsghdr *nh)
{
	struct ifinfomsg *ifm = NLMSG_DATA(nh);
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifm), IFLA_PAYLOAD(nh));
}

static inline void parse_linkinfo(struct rtattr *tb[], struct rtattr *linkinfo)
{
	parse_nested_rtattr(tb, IFLA_INFO_MAX, linkinfo);
}

static inline void parse_vlaninfo(struct rtattr *tb[], struct rtattr *vlan)
{
	parse_nested_rtattr(tb, IFLA_VLAN_MAX, vlan);
}

#endif /* _RTNETLINK_ */
