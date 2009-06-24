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

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <libgen.h>
#include <ulimit.h>
#include <unistd.h>
#include <paths.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>

#include "net_types.h"
#include "fc_types.h"

#include "fcoemon_utils.h"
#include "fcoemon.h"

static char *fcoemon_version = "\
fcoemon v1.0.7\n\
Copyright (c) 2009, Intel Corporation.\n\
";

/*
 * Defines for FCoE config file.
 */
#ifndef SYSCONFDIR
#define SYSCONFDIR                  "/etc"
#endif
#define CONFIG_DIR                  SYSCONFDIR "/fcoe"
#define CONFIG_MIN_VAL_LEN          (1 + 2)
#define CONFIG_MAX_VAL_LEN          (20 + 2)
#define DCB_APP_0_DEFAULT_ENABLE    1
#define DCB_APP_0_DEFAULT_WILLING   1
#define FCM_DEFAULT_QOS_MASK        (1 << 3)
#define FILE_NAME_LEN               (NAME_MAX + 1)

/*
 * fcoe service configuration data
 * Note: These information are read in from the fcoe service
 *       files in CONFIG_DIR
 */
struct fcoe_port_config {
	struct fcoe_port_config *next;
	char ifname[IFNAMSIZ];
	int fcoe_enable;
	int has_fip;
	int dcb_required;
	int dcb_app_0_enable;
	int dcb_app_0_willing;
};

struct fcoe_config {
	int debug;
	int use_syslog;
	struct fcoe_port_config *port;
} fcoe_config;

enum fcoeadm_action {
	ADM_DESTROY = 0,
	ADM_CREATE,
	ADM_RESET
};

static u_int8_t fcm_def_qos_mask = FCM_DEFAULT_QOS_MASK;

struct clif;			/* for dcbtool.h only */
#include <dcbd/dcb_types.h>
#include <dcbd/dcbtool.h>	/* for typedef cmd_status */
#include <dcbd/clif.h>
#include <dcbd/clif_cmds.h>
#include <dcbd/common.h>	/* for event msg level definitions */

#define CLIF_NAME_PATH          _PATH_VARRUN "dcbd/clif"
#define CLIF_PID_FILE           _PATH_VARRUN "fcoemon.pid"
#define CLIF_LOCAL_SUN_PATH     _PATH_TMP "fcoemon.dcbd.%d"
#define FCM_DCBD_TIMEOUT_USEC   (10 * 1000 * 1000)	/* 10 seconds */
#define FCM_EVENT_TIMEOUT_USEC  (500 * 1000)		/* half a second */
#define FCM_PING_REQ_LEN	1 /* byte-length of dcbd PING request */
#define FCM_PING_RSP_LEN	8 /* byte-length of dcbd PING response */

/*
 * Interact with DCB daemon.
 */
static void fcm_event_timeout(void *);
static void fcm_dcbd_timeout(void *);
static void fcm_dcbd_disconnect(void);
static void fcm_dcbd_request(char *);
static void fcm_dcbd_rx(void *);
static void fcm_dcbd_ex(void *);
static void fcm_dcbd_next(void);
static void fcm_dcbd_event(char *, size_t);
static void fcm_dcbd_cmd_resp(char *, cmd_status);
static void fcm_dcbd_port_advance(struct fcm_fcoe *);
static void fcm_dcbd_setup(struct fcm_fcoe *, enum fcoeadm_action);

struct fcm_clif {
	int cl_fd;
	int cl_busy;		/* non-zero if command pending */
	int cl_ping_pending;
	struct sockaddr_un cl_local;
};

static struct fcm_clif fcm_clif_st;
static struct fcm_clif *fcm_clif = &fcm_clif_st;
static struct sa_timer fcm_dcbd_timer;

char *fcm_dcbd_cmd = CONFIG_DIR "/scripts/fcoeplumb";
int fcm_dcbd_debug;
int fcm_link_debug;
int fcm_use_syslog;

/* Debugging routine */
static void print_errors(char *buf, int errors);

struct fcm_fcoe_head fcm_fcoe_head = TAILQ_HEAD_INITIALIZER(fcm_fcoe_head);

static int fcm_link_socket;
static int fcm_link_seq;
static void fcm_link_recv(void *);
static void fcm_link_getlink(void);
static int fcm_link_buf_check(size_t);

/*
 * Table for getopt_long(3).
 */
static struct option fcm_options[] = {
	{"debug", 0, NULL, 'd'},
	{"exec", 1, NULL, 'e'},
	{"foreground", 0, NULL, 'f'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

char progname[20];

static char fcm_pidfile[] = CLIF_PID_FILE;

/*
 * Issue with buffer size:  It isn't clear how to read more than one
 * buffer's worth of GETLINK replies.  The kernel seems to just drop the
 * interface messages if they don't fit in the buffer, so we just make it
 * large enough to fit and expand it if we ever do a read that almost fills it.
 */
static char *fcm_link_buf;
static size_t fcm_link_buf_size = 4096;	/* initial size */
static const size_t fcm_link_buf_fuzz = 300;	/* "almost full" remainder */

/*
 * A value must be surrounded by quates, e.g. "x".
 * The minimum length of a value is 1 excluding the quotes.
 * The maximum length of a value is 20 excluding the quotes.
 */
static int
fcm_remove_quotes(char *buf, int len)
{
	char *s = buf;
	char *e = buf + len - 1;
	char tmp[CONFIG_MAX_VAL_LEN + 1];

	if (len < CONFIG_MIN_VAL_LEN)
		return -1;
	if ((*s >= '0' && *s <= '9') ||
	    (*s >= 'a' && *s <= 'z') ||
	    (*s >= 'A' && *s <= 'Z'))
		return -1;
	if ((*e >= '0' && *e <= '9') ||
	    (*e >= 'a' && *e <= 'z') ||
	    (*e >= 'A' && *e <= 'Z'))
		return -1;
	s = buf + 1;
	*e = '\0';
	strncpy(tmp, s, len - 1);
	strncpy(buf, tmp, len - 1);

	return 0;
}

/*
 * Read a configuration variable for a port from a config file.
 * There's no problem if the file doesn't exist.
 * The buffer is set to an empty string if the variable is not found.
 *
 * Returns:  1    found
 *           0    not found
 *           -1   error in format
 */
static size_t
fcm_read_config_variable(char *file, char *val_buf, size_t len,
			 FILE *fp, const char *var_name)
{
	char *s;
	char *var;
	char *val;
	char buf[FILE_NAME_LEN];
	int n;

	val_buf[0] = '\0';
	buf[sizeof(buf) - 1] = '\0';
	while ((s = fgets(buf, sizeof(buf) - 1, fp)) != NULL) {
		while (isspace(*s))
			s++;
		if (*s == '\0' || *s == '#')
			continue;
		var = s;
		if (!isalpha(*var))
			continue;
		val = strchr(s, '=');
		if (val == NULL)
			continue;
		*val++ = '\0';
		s = val;
		if (strcmp(var_name, var) != 0)
			continue;
		while (*s != '\0' && !isspace(*s))
			s++;
		*s = '\0';
		n = snprintf(val_buf, len, "%s", val);
		if (fcm_remove_quotes(val_buf, n) < 0) {
			SA_LOG("Invalid format in config file"
			       " %s: %s=%s\n",
			       file, var_name, val);
			/* error */
			return -1;
		}
		/* found */
		return 1;
	}
	/* not found */
	return 0;
}

static int
fcm_read_config_files(void)
{
	char file[80];
	FILE *fp;
	char val[CONFIG_MAX_VAL_LEN + 1];
	DIR *dir;
	struct dirent *dp;
	struct fcoe_port_config *curr;
	struct fcoe_port_config *next;
	int rc;

	memset(&fcoe_config, 0, sizeof(fcoe_config));

	strncpy(file, CONFIG_DIR "/" "config", sizeof(file));
	fp = fopen(file, "r");
	if (!fp) {
		SA_LOG_ERR(errno, "Failed reading %s\n", file);
		exit(1);
	}

	rc = fcm_read_config_variable(file, val,
				      sizeof(val), fp, "DEBUG");
	if (rc < 0) {
		fclose(fp);
		return -1;
	}
	/* if not found, default to "yes" */
	if (!strncasecmp(val, "yes", 3) || !rc) {
		fcoe_config.debug = 1;
		fcm_dcbd_debug = 1;
		fcm_link_debug = 1;
	}

	rc = fcm_read_config_variable(file, val,
				      sizeof(val), fp, "USE_SYSLOG");
	if (rc < 0) {
		fclose(fp);
		return -1;
	}
	/* if not found, default to "yes" */
	if (!strncasecmp(val, "yes", 3) || !rc) {
		fcoe_config.use_syslog = 1;
		fcm_use_syslog = 1;
	}

	fclose(fp);

	dir = opendir(CONFIG_DIR);
	if (dir == NULL) {
		SA_LOG_ERR(errno,
			   "Failed reading directory %s\n", CONFIG_DIR);
		return -1;
	}
	for (;;) {
		dp = readdir(dir);
		if (dp == NULL)
			break;
		if (dp->d_name[0] == '.' &&
		    (dp->d_name[1] == '\0' ||
		     (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
			continue;
		rc = strncmp(dp->d_name, "cfg-eth", strlen("cfg-eth"));
		if (rc)
			continue;
		next = (struct fcoe_port_config *)
			calloc(1, sizeof(struct fcoe_port_config));
		if (!fcoe_config.port) {
			fcoe_config.port = next;
			curr = next;
		} else {
			curr->next = next;
			curr = next;
		}
		strncpy(curr->ifname, dp->d_name + 4, sizeof(curr->ifname));
		strncpy(file, CONFIG_DIR "/", sizeof(file));
		strncat(file, dp->d_name, sizeof(file) - strlen(file));
		fp = fopen(file, "r");
		if (!fp) {
			SA_LOG_ERR(errno, "Failed reading %s\n", file);
			exit(1);
		}

		/* FCOE_ENABLE */
		rc = fcm_read_config_variable(file, val, sizeof(val),
					      fp, "FCOE_ENABLE");
		if (rc < 0) {
			fclose(fp);
			return -1;
		}
		/* if not found, default to "no" */
		if (!strncasecmp(val, "yes", 3) && rc == 1)
			curr->fcoe_enable = 1;

		/* DCB_REQUIRED */
		rc = fcm_read_config_variable(file, val, sizeof(val),
					      fp, "DCB_REQUIRED");
		if (rc < 0) {
			fclose(fp);
			return -1;
		}
		/* if not found, default to "no" */
		if (!strncasecmp(val, "yes", 3) && rc == 1) {
			curr->dcb_required = 1;
			curr->dcb_app_0_enable = DCB_APP_0_DEFAULT_ENABLE;
			curr->dcb_app_0_willing = DCB_APP_0_DEFAULT_WILLING;
		}

		/* HAS_FIP */
		rc = fcm_read_config_variable(file, val,
					      sizeof(val), fp, "HAS_FIP");
		if (rc < 0) {
			fclose(fp);
			return -1;
		}
		/* if not found, default to "no" */
		if (!strncasecmp(val, "yes", 3) && rc == 1)
			curr->has_fip = 1;

		fclose(fp);
	}
	closedir(dir);
	return 0;
}

static struct fcoe_port_config *
fcm_find_port_config(char *ifname)
{
	struct fcoe_port_config *p;

	p = fcoe_config.port;
	while (p) {
		if (!strncmp(ifname, p->ifname, IFNAMSIZ) &&
		    p->fcoe_enable && p->dcb_required)
			return p;
		p = p->next;
	}
	return NULL;
}

static int
fcm_link_init(void)
{
	int fd;
	int rc;
	struct sockaddr_nl l_local;

	fcm_link_buf = malloc(fcm_link_buf_size);
	ASSERT(fcm_link_buf);

	fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0) {
		SA_LOG_ERR(errno, "socket error");
		return fd;
	}
	memset(&l_local, 0, sizeof(l_local));
	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = RTMGRP_LINK;
	l_local.nl_pid = 0;
	rc = bind(fd, (struct sockaddr *)&l_local, sizeof(l_local));
	if (rc == -1) {
		SA_LOG_ERR(errno, "bind error");
		return rc;
	}
	fcm_link_socket = fd;

	/* Add a given file descriptor from a readfds set */
	sa_select_add_fd(fd, fcm_link_recv, NULL, NULL, NULL);

	fcm_link_getlink();

	return 0;
}

static void
fcm_link_recv(void *arg)
{
	int rc;
	char *buf;
	struct nlmsghdr *hp;
	struct ifinfomsg *ip;
	struct rtattr *ap;
	struct fcm_fcoe *ff;
	unsigned type;
	int plen;
	int rlen;
	char ifname[IFNAMSIZ];

	buf = fcm_link_buf;
	rc = read(fcm_link_socket, buf, fcm_link_buf_size);
	if (rc <= 0) {
		if (rc < 0)
			SA_LOG_ERR(errno, "read error");
		return;
	}
	hp = (struct nlmsghdr *)buf;
	rlen = rc;
	for (hp = (struct nlmsghdr *)buf; NLMSG_OK(hp, rlen);
	     hp = NLMSG_NEXT(hp, rlen)) {
		type = hp->nlmsg_type;
		if (hp->nlmsg_type == NLMSG_DONE)
			break;
		if (hp->nlmsg_type == NLMSG_ERROR) {
			SA_LOG("nlmsg error");
			break;
		}
		plen = NLMSG_PAYLOAD(hp, 0);
		ip = (struct ifinfomsg *)NLMSG_DATA(hp);
		if (plen < sizeof(*ip)) {
			SA_LOG("too short (%d) to be a LINK message", rc);
			break;
		}
		switch (type) {
		case RTM_NEWLINK:
			if (fcm_link_debug)
				SA_LOG("newlink %d", ip->ifi_index);
			goto rest;
		case RTM_DELLINK:
			if (fcm_link_debug)
				SA_LOG("dellink %d", ip->ifi_index);
			goto rest;
		case RTM_GETLINK:
			if (fcm_link_debug)
				SA_LOG("getlink %d", ip->ifi_index);
rest:
			if (fcm_link_buf_check(rc)) {
				fcm_link_getlink();
				return;
			}
			if (ip->ifi_type != ARPHRD_ETHER)
				break;

			ff = fcm_fcoe_lookup_create_ifindex(ip->ifi_index);
			if (ff == NULL)
				break;
			ff->ff_flags = ip->ifi_flags;

			plen -= sizeof(*ip);
			for (ap = (struct rtattr *)(ip + 1); RTA_OK(ap, plen);
			     ap = RTA_NEXT(ap, plen)) {
				switch (ap->rta_type) {
				case IFLA_ADDRESS:
					if (RTA_PAYLOAD(ap) == 6)
						ff->ff_mac =
							net48_get(RTA_DATA(ap));
					break;
				case IFLA_IFNAME:
					sa_strncpy_safe(ifname, sizeof(ifname),
							RTA_DATA(ap),
							RTA_PAYLOAD(ap));
					if (fcm_link_debug)
						SA_LOG("ifname %s", ifname);
					fcm_fcoe_set_name(ff, ifname);
					break;
				case IFLA_OPERSTATE:
					ff->ff_operstate =
						*(uint8_t *) RTA_DATA(ap);
					break;
				default:
					break;
				}
			}
			break;
		default:
			break;
		}
	}
}

/*
 * Send rt_netlink request for all network interfaces.
 */
static void
fcm_link_getlink(void)
{
	struct {
		struct nlmsghdr nl;
		struct ifinfomsg ifi;	/* link level specific information,
					   not dependent on network protocol */
	} msg;
	int rc;

	memset(&msg, 0, sizeof(msg));
	msg.nl.nlmsg_len = sizeof(msg);
	msg.nl.nlmsg_type = RTM_GETLINK;
	msg.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_ATOMIC;
	msg.nl.nlmsg_seq = ++fcm_link_seq;
	/* msg.nl.nlmsg_pid = getpid(); */
	msg.ifi.ifi_family = AF_UNSPEC;
	msg.ifi.ifi_type = ARPHRD_ETHER;
	rc = write(fcm_link_socket, &msg, sizeof(msg));
	if (rc < 0)
		SA_LOG_ERR(errno, "write error");
}

/*
 * Check for whether buffer needs to grow based on amount read.
 * Free's the old buffer so don't use that after this returns non-zero.
 */
static int
fcm_link_buf_check(size_t read_len)
{
	char *buf;
	size_t len = read_len;

	if (len > fcm_link_buf_size - fcm_link_buf_fuzz) {
		len = fcm_link_buf_size;
		len = len + len / 2;	/* grow by 50% */
		buf = malloc(len);
		if (buf != NULL) {
			free(fcm_link_buf);
			fcm_link_buf = buf;
			fcm_link_buf_size = len;
			return 1;
		}
	}
	return 0;
}

static void
fcm_fcoe_init(void)
{
	if (fcm_read_config_files())
		exit(1);
}

/*
 * Allocate an FCoE interface state structure.
 */
static struct fcm_fcoe *
fcm_fcoe_alloc(void)
{
	struct fcm_fcoe *ff;

	ff = calloc(1, sizeof(*ff));
	if (ff) {
		ff->ff_qos_mask = fcm_def_qos_mask;
		ff->ff_ifindex = ~0;
		ff->ff_operstate = IF_OPER_UNKNOWN;
		TAILQ_INSERT_TAIL(&fcm_fcoe_head, ff, ff_list);
	}
	return ff;
}

/*
 * Find an FCoE interface by ifindex.
 */
static struct fcm_fcoe *
fcm_fcoe_lookup_create_ifindex(u_int32_t ifindex)
{
	struct fcm_fcoe *ff;

	TAILQ_FOREACH(ff, &fcm_fcoe_head, ff_list) {
		if (ff->ff_ifindex == ifindex)
			return ff;
	}
	ff = fcm_fcoe_alloc();
	if (ff != NULL) {
		ff->ff_ifindex = ifindex;
		ff->ff_pfc_saved.u.pfcup = 0xffff;
		sa_timer_init(&ff->ff_event_timer, fcm_event_timeout, ff);
	}
	return ff;
}

/*
 * Find an FCoE interface by name.
 * What about VLAN instances?  They can't use DCB, perhaps.
 */
static struct fcm_fcoe *
fcm_fcoe_lookup_name(char *name)
{
	struct fcm_fcoe *ff;

	TAILQ_FOREACH(ff, &fcm_fcoe_head, ff_list) {
		if (strcmp(ff->ff_name, name) == 0)
			break;
	}
	return ff;
}

#ifdef NOT_YET
/*
 * Find an FCoE interface by MAC address.
 */
static struct fcm_fcoe *
fcm_fcoe_lookup_mac(u_int64_t mac, int vlan)
{
	struct fcm_fcoe *ff;

	TAILQ_FOREACH(ff, &fcm_fcoe_head, ff_list) {
		if (ff->ff_mac == mac && ff->ff_vlan == vlan)
			break;
	}
	return ff;
}

/*
 * Find or create an FCoE interface by MAC address and VLAN ID.
 * If vlan is -1, find the base interface.
 */
static struct fcm_fcoe *
fcm_fcoe_lookup_create_mac(u_int64_t mac, int vlan)
{
	struct fcm_fcoe *ff;

	ff = fcm_fcoe_lookup_mac(mac, vlan);
	if (ff == NULL) {
		ff = fcm_fcoe_alloc();
		if (ff != NULL) {
			ff->ff_mac = mac;
			ff->ff_vlan = vlan;
		}
	}
	return ff;
}
#endif

static void
fcm_fcoe_get_dcb_settings(struct fcm_fcoe *ff)
{
	fc_wwn_t wwpn;
	int vlan = ff->ff_vlan;
	struct fcoe_port_config *p;

	if (ff->ff_mac == 0)
		return;		/* loopback or other non-eligible interface */

	/*
	 * Get DCB config from file if possible.
	 */
	wwpn = fc_wwn_from_mac(ff->ff_mac, 2, vlan >= 0 ? vlan : 0);

	p = fcoe_config.port;
	while (p) {
		if (!strncmp(ff->ff_name, p->ifname, IFNAMSIZ)) {
			ff->ff_app_info.enable = p->dcb_app_0_enable;
			ff->ff_app_info.willing = p->dcb_app_0_willing;
			ff->ff_has_fip = p->has_fip;
			break;
		}
		p = p->next;
	}
}

static void
fcm_fcoe_set_name(struct fcm_fcoe *ff, char *ifname)
{
	char *cp;
	int vlan;

	snprintf(ff->ff_name, sizeof(ff->ff_name), "%s", ifname);
	vlan = -1;
	cp = strchr(ff->ff_name, '.');
	if (cp != NULL) {
		vlan = atoi(cp + 1);
		if (vlan < 0 || vlan > 4095)
			vlan = 0;
	}
	ff->ff_vlan = vlan;
}

static int
fcm_fcoe_port_ready(struct fcm_fcoe *ff)
{
	int rc;

	rc = (ff->ff_flags & (IFF_UP|IFF_RUNNING)) == (IFF_UP|IFF_RUNNING) &&
		ff->ff_operstate == IF_OPER_UP;

	return rc;
}

static void
fcm_dcbd_init()
{
	fcm_clif->cl_fd = -1;	/* not connected */
	fcm_clif->cl_ping_pending = 0;
	sa_timer_init(&fcm_dcbd_timer, fcm_dcbd_timeout, NULL);
	fcm_dcbd_timeout(NULL);
}

static int
fcm_dcbd_connect(void)
{
	int rc;
	int fd;
	struct sockaddr_un dest;
	struct sockaddr_un *lp;

	ASSERT(fcm_clif->cl_fd < 0);
	fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		SA_LOG_ERR(errno, "clif socket open failed");	/* XXX */
		return 0;
	}

	lp = &fcm_clif->cl_local;
	lp->sun_family = PF_UNIX;
	snprintf(lp->sun_path, sizeof(lp->sun_path),
		 CLIF_LOCAL_SUN_PATH, getpid());
	rc = bind(fd, (struct sockaddr *)lp, sizeof(*lp));
	if (rc < 0) {
		SA_LOG_ERR(errno, "clif bind failed");
		close(fd);
		return 0;
	}

	memset(&dest, 0, sizeof(dest));
	dest.sun_family = PF_UNIX;
	snprintf(dest.sun_path, sizeof(dest.sun_path),
		 CLIF_NAME_PATH);
	rc = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
	if (rc < 0) {
		SA_LOG_ERR(errno, "clif connect failed");
		unlink(lp->sun_path);
		close(fd);
		return 0;
	}
	fcm_clif->cl_fd = fd;
	sa_select_add_fd(fd, fcm_dcbd_rx, NULL, fcm_dcbd_ex, fcm_clif);
	if (fcm_dcbd_debug)
		SA_LOG("connected to dcbd");
	return 1;
}

static int
is_query_in_progress(void)
{
	struct fcm_fcoe *ff;

	TAILQ_FOREACH(ff, &fcm_fcoe_head, ff_list) {
		if (ff->ff_dcbd_state >= FCD_GET_DCB_STATE &&
		    ff->ff_dcbd_state < FCD_DONE)
			return 1;
	}
	return 0;
}

static void
fcm_fcoe_config_reset(void)
{
	struct fcoe_port_config *p;
	struct fcm_fcoe *ff;

	p = fcoe_config.port;
	while (p) {
		if (p->fcoe_enable && p->dcb_required) {
			ff = fcm_fcoe_lookup_name(p->ifname);
			if (ff) {
				fcm_dcbd_setup(ff, ADM_DESTROY);
				ff->ff_qos_mask = fcm_def_qos_mask;
				ff->ff_pfc_saved.u.pfcup = 0xffff;
			}
			if (fcm_dcbd_debug)
				SA_LOG("Port %s config reset\n", p->ifname);
		}
		p = p->next;
	}
}

static void
fcm_dcbd_timeout(void *arg)
{
	if (fcm_clif->cl_ping_pending > 0) {
		fcm_dcbd_request("D");	/* DETACH_CMD */
		fcm_dcbd_disconnect();
	}
	if (fcm_clif->cl_fd < 0) {
		if (fcm_dcbd_connect())
			fcm_dcbd_request("A");	/* ATTACH_CMD: for events */
	} else {
		if (!is_query_in_progress()) {
			fcm_clif->cl_ping_pending++;
			fcm_dcbd_request("P");	/* ping to verify connection */
		}
	}
	sa_timer_set(&fcm_dcbd_timer, FCM_DCBD_TIMEOUT_USEC);
}

static void
fcm_dcbd_disconnect(void)
{
	if (fcm_clif != NULL && fcm_clif->cl_local.sun_path[0] != '\0') {
		if (fcm_clif->cl_fd >= 0)
			sa_select_rem_fd(fcm_clif->cl_fd);
		unlink(fcm_clif->cl_local.sun_path);
		fcm_clif->cl_local.sun_path[0] = '\0';
		fcm_clif->cl_fd = -1;	/* mark as disconnected */
		fcm_clif->cl_busy = 0;
		fcm_clif->cl_ping_pending = 0;
		fcm_fcoe_config_reset();
		if (fcm_dcbd_debug)
			SA_LOG("disconnected from dcbd");
	}
}

static void
fcm_dcbd_shutdown(void)
{
	if (fcm_dcbd_debug)
		SA_LOG("Shut down dcbd connection\n");
	fcm_dcbd_request("D");	/* DETACH_CMD */
	fcm_dcbd_disconnect();
	unlink(fcm_pidfile);
	closelog();
}

static u_int32_t
fcm_get_hex(char *cp, u_int32_t len, char **endptr)
{
	u_int32_t hex = 0;

	while (len > 0) {
		len--;
		if (*cp >= '0' && *cp <= '9')
			hex = (hex << 4) | (*cp - '0');
		else if (*cp >= 'A' && *cp <= 'F')
			hex = (hex << 4) | (*cp - 'A' + 10);
		else if (*cp >= 'a' && *cp <= 'f')
			hex = (hex << 4) | (*cp - 'a' + 10);
		else
			break;
		cp++;
	}
	*endptr = (len == 0) ? NULL : cp;
	return hex;
}

static struct sa_nameval fcm_dcbd_states[] = FCM_DCBD_STATES;

static void
fcm_dcbd_state_set(struct fcm_fcoe *ff, enum fcm_dcbd_state new_state)
{
	if (fcm_dcbd_debug) {
		char old[32];
		char new[32];

		SA_LOG("%s: %s -> %s",
		       ff->ff_name,
		       sa_enum_decode(old, sizeof(old),
				      fcm_dcbd_states, ff->ff_dcbd_state),
		       sa_enum_decode(new, sizeof(new),
				      fcm_dcbd_states, new_state));
	}
	ff->ff_dcbd_state = new_state;
}

static void
fcm_dcbd_rx(void *arg)
{
	struct fcm_clif *clif = arg;
	cmd_status st;
	char buf[128];
	size_t len;
	int rc;
	char *ep;

	len = sizeof(buf);
	rc = read(clif->cl_fd, buf, sizeof(buf) - 1);
	if (rc < 0)
		SA_LOG_ERR(errno, "read");
	else if ((rc > 0) && (rc < sizeof(buf))) {
		ASSERT(rc < sizeof(buf));
		buf[rc] = '\0';
		len = strlen(buf);
		ASSERT(len <= rc);
		if (fcm_dcbd_debug && len > FCM_PING_RSP_LEN)
			SA_LOG("received len %d buf '%s'", len, buf);

		switch (buf[CLIF_RSP_MSG_OFF]) {
		case CMD_RESPONSE:
			st = fcm_get_hex(buf + CLIF_STAT_OFF, CLIF_STAT_LEN,
					 &ep);
			if (ep != NULL)
				SA_LOG("unexpected response code from dcbd: "
				       "len %d buf %s rc %d", len, buf, rc);
			else if (st != cmd_success &&
				 st != cmd_device_not_found) {
				SA_LOG("error response from dcbd: "
				       "error %d len %d %s",
				       st, len, buf);
			}
			fcm_clif->cl_busy = 0;

			switch (buf[3]) {
			case DCB_CMD:
				fcm_dcbd_cmd_resp(buf, st);
				break;
			case ATTACH_CMD:
				break;
			case DETACH_CMD:
				break;
			case PING_CMD:
				if (clif->cl_ping_pending > 0)
					--clif->cl_ping_pending;
				break;
			case LEVEL_CMD:
				break;
			default:
				SA_LOG("Unexpected cmd in response "
				       "from dcbd: len %d %s",
				       len, buf);
				break;
			}
			fcm_dcbd_next();	/* advance ports if possible */
			break;

		case EVENT_MSG:
			fcm_dcbd_event(buf, len);
			break;
		default:
			SA_LOG("Unexpected message from dcbd: len %d buf %s",
			       len, buf);
			break;
		}
	}
}

static void
fcm_dcbd_ex(void *arg)
{
	if (fcm_dcbd_debug)
		SA_LOG("called");
}

static void
fcm_dcbd_request(char *req)
{
	size_t len;
	int rc;

	if (fcm_clif->cl_fd < 0)
		return;
	len = strlen(req);
	ASSERT(fcm_clif->cl_busy == 0);
	fcm_clif->cl_busy = 1;
	rc = write(fcm_clif->cl_fd, req, len);
	if (rc < 0) {
		SA_LOG_ERR(errno, "Failed write req %s len %d", req, len);
		fcm_clif->cl_busy = 0;
		fcm_dcbd_disconnect();
		fcm_dcbd_connect();
		return;
	}

	if (fcm_dcbd_debug && rc > FCM_PING_REQ_LEN)
		SA_LOG("sent '%s', rc=%d bytes succeeded", req, rc);
	return;
}

/*
 * Find port for message.
 * The port name length starts at len_off for len_len bytes.
 * The entire message length is len.
 * The pointer to the message pointer is passed in, and updated to point
 * past the interface name.
 */
static struct fcm_fcoe *
fcm_dcbd_get_port(char **msgp, size_t len_off, size_t len_len, size_t len)
{
	struct fcm_fcoe *ff;
	u_int32_t if_len;
	char *ep;
	char *msg;
	char ifname[IFNAMSIZ];

	msg = *msgp;
	if (len_off + len_len >= len)
		return NULL;

	if_len = fcm_get_hex(msg + len_off, len_len, &ep);
	if (ep != NULL) {
		SA_LOG("Parse error on port len: msg %s", msg);
		return NULL;
	}

	if (len_off + len_len + if_len > len) {
		SA_LOG("Invalid port len %d msg %s", if_len, msg);
		return NULL;
	}
	msg += len_off + len_len;
	sa_strncpy_safe(ifname, sizeof(ifname), msg, if_len);
	*msgp = msg + if_len;
	ff = fcm_fcoe_lookup_name(ifname);
	if (ff == NULL) {
		SA_LOG("ifname '%s' not found", ifname);
		exit(1);	/* XXX */
	}
	return ff;
}

/*
 * (XXX) Notes:
 * This routine is here to help fcm_dcbd_cmd_resp() to pick up
 * information of the response packet from the DCBD. In the
 * future, it should be merged into fcm_dcbd_cmd_resp().
 */
static int
dcb_rsp_parser(struct fcm_fcoe *ff, char *rsp, cmd_status st)
{
	int version;
	int dcb_cmd;
	int feature;
	int subtype;
	int plen;
	int doff;
	int i;
	int n;
	struct feature_info *f_info = NULL;
	char buf[20];

	if (st != cmd_success)	/* log msg already issued */
		return -1;

	feature = hex2int(rsp+DCB_FEATURE_OFF);
	if (feature != FEATURE_DCB &&
	    feature != FEATURE_PFC &&
	    feature != FEATURE_APP &&
	    feature != FEATURE_LLINK) {
		SA_LOG("WARNING: Unexpected DCB feature %d\n", feature);
		return -1;
	}

	dcb_cmd = hex2int(rsp+DCB_CMD_OFF);
	if (dcb_cmd != CMD_GET_CONFIG &&
	    dcb_cmd != CMD_GET_OPER &&
	    dcb_cmd != CMD_GET_PEER) {
		SA_LOG("WARNING: Unexpected DCB cmd %d\n", dcb_cmd);
		return -1;
	}

	version = rsp[DCB_VER_OFF] & 0x0f;
	if (version != CLIF_MSG_VERSION) {
		SA_LOG("WARNING: Unexpected rsp version %d\n", version);
		return -1;
	}

	subtype = hex2int(rsp+DCB_SUBTYPE_OFF);
	plen = hex2int(rsp+DCB_PORTLEN_OFF);
	doff = DCB_PORT_OFF + plen;

	switch (feature) {
	case FEATURE_DCB:
		ff->ff_dcb_state = (*(rsp+doff+CFG_ENABLE) == '1');
		if (!ff->ff_dcb_state) {
			SA_LOG("WARNING: DCB state is off\n");
			return -1;
		}
		return 0;
	case FEATURE_PFC:
		f_info = &ff->ff_pfc_info;
		break;
	case FEATURE_APP:
		f_info = &ff->ff_app_info;
		f_info->subtype = subtype;
		break;

	case FEATURE_LLINK:
		f_info = &ff->ff_llink_info;
		f_info->subtype = subtype;
		break;
	}

	switch (dcb_cmd) {
	case CMD_GET_CONFIG:
		f_info->enable = (*(rsp+doff+CFG_ENABLE) == '1');
		f_info->advertise = (*(rsp+doff+CFG_ADVERTISE) == '1');
		f_info->willing = (*(rsp+doff+CFG_WILLING) == '1');
		doff += CFG_LEN;
		break;

	case CMD_GET_OPER:
		f_info->op_vers = hex2int(rsp+doff+OPER_OPER_VER);
		f_info->op_error = hex2int(rsp+doff+OPER_ERROR);
		f_info->op_mode = (*(rsp+doff+OPER_OPER_MODE) == '1');
		f_info->syncd = (*(rsp+doff+OPER_SYNCD) == '1');
		doff += OPER_LEN;
		if (feature == FEATURE_PFC) {
			f_info->u.pfcup = 0;
			for (i = 0; i < MAX_USER_PRIORITIES; i++) {
				if (*(rsp+doff+PFC_UP(i)) == '1')
					f_info->u.pfcup |= 1<<i;
			}
		}
		if (feature == FEATURE_APP && subtype == APP_FCOE_STYPE) {
			n = hex2int(rsp+doff+APP_LEN);
			snprintf(buf, sizeof(buf), "%*.*s\n",
				 n, n, rsp+doff+APP_DATA);
			f_info->u.appcfg = hex2int(buf);
		}
		break;
	case CMD_GET_PEER:
		doff += PEER_LEN;
		if (feature == FEATURE_LLINK && subtype == LLINK_FCOE_STYPE)
			ff->ff_llink_status = (*(rsp+doff+LLINK_STATUS) == '1');
		break;
	}

	return 0;
}

/*
 * validating_dcb_app_pfc - Validating App:FCoE and PFC requirements
 *
 * DCB is configured correctly when
 * 1) The local configuration of the App:FCoE feature is
 *    configured to Enable=TRUE, Advertise=TRUE, Willing=TRUE.
 * 2) App:FCoE feature is in Opertional Mode = TRUE,
 * 3) PFC feasture is in Opertional Mode = TRUE,
 * 4) The priority indicated by the App:FCoE Operational Configuration
 *    is also enabled in the PFC Operational Configuration.
 * 5) DCB State is on.
 *
 * Returns:  1 if succeeded
 *           0 if failed
 */
static int
validating_dcb_app_pfc(struct fcm_fcoe *ff)
{
	int error = 0;

	if (!ff->ff_dcb_state) {
		SA_LOG("WARNING: DCB state is off\n");
		error++;
	}
	if (!ff->ff_app_info.willing) {
		SA_LOG("WARNING: APP:0 willing mode is false\n");
		error++;
	}
	if (!ff->ff_app_info.advertise) {
		SA_LOG("WARNING: APP:0 advertise mode is false\n");
		error++;
	}
	if (!ff->ff_app_info.enable) {
		SA_LOG("WARNING: APP:0 enable mode is false\n");
		error++;
	}
	if (!ff->ff_app_info.op_mode) {
		SA_LOG("WARNING: APP:0 operational mode is false\n");
		error++;
	}
	if (!ff->ff_pfc_info.op_mode) {
		SA_LOG("WARNING: PFC operational mode is false\n");
		error++;
	}
	if ((ff->ff_pfc_info.u.pfcup & ff->ff_app_info.u.appcfg) \
	    != ff->ff_app_info.u.appcfg) {
		SA_LOG("WARNING: APP:0 priority (0x%02x) doesn't "
		       "match PFC priority (0x%02x)\n",
		       ff->ff_app_info.u.appcfg,
		       ff->ff_pfc_info.u.pfcup);
		error++;
	}
	if (error) {
		SA_LOG("WARNING: DCB is configured incorrectly\n");
		return 0;
	}
	if (fcm_dcbd_debug)
		SA_LOG("DCB is configured correctly\n");

	return 1;
}

/*
 * validating_llink_tlv - Validating Logical Link TLV requirements
 *
 * Logical Link TLV feature is configured correctly when
 * 1) The local configuration of the Logical Link TLV feature is
 *    configured to Enable=TRUE, Advertise=TRUE, Willing=TRUE.
 * 2) The Opertional Mode of the Logical Link TLV feature must be TRUE,
 * 3) The Link Status of the Logical Link TLV feature must be TRUE (UP).
 *
 * Returns:  1 if succeeded
 *           0 if failed
 */
static int
validating_llink_tlv(struct fcm_fcoe *ff)
{
	int error = 0;

	if (!ff->ff_llink_info.enable) {
		SA_LOG("WARNING: LLINK:0 enable mode is false\n");
		error++;
	}
	if (!ff->ff_llink_info.advertise) {
		SA_LOG("WARNING: LLINK:0 advertise mode is false\n");
		error++;
	}
	if (!ff->ff_llink_info.willing) {
		SA_LOG("WARNING: LLINK:0 willing mode is false\n");
		error++;
	}
	if (!ff->ff_llink_info.op_mode) {
		SA_LOG("WARNING: LLINK:0 operational mode is false\n");
		error++;
	}
	if (error) {
		SA_LOG("WARNING: FCoE LLINK is configured incorrectly\n");
		return 0;
	}
	if (fcm_dcbd_debug)
		SA_LOG("FCoE LLINK is configured correctly\n");

	/*
	 * At this point, this should be the link status
	 * reported by the switch.
	 */
	if (!ff->ff_llink_status) {
		SA_LOG("WARNING: Switch reports FCoE LLINK is DOWN\n");
		return 0;
	}
	if (fcm_dcbd_debug)
		SA_LOG("Switch reports FCoE LLINK is UP\n");

	return 1;
}

/*
 * validating_dcbd_info - Validating DCBD configuration and status
 *
 * Returns:  1 if succeeded
 *           0 if failed
 */
static int
validating_dcbd_info(struct fcm_fcoe *ff)
{
	int rc;

	rc = validating_dcb_app_pfc(ff);
	if (!rc)
		return rc;
	rc = validating_llink_tlv(ff);

	return rc;
}

/*
 * is_pfcup_changed - Check to see if PFC priority is changed
 *
 * Returns:  0 if no
 *           1 if yes, but it is the first time, or was destroyed.
 *           2 if yes
 */
static int
is_pfcup_changed(struct fcm_fcoe *ff)
{
	if (ff->ff_pfc_info.u.pfcup != ff->ff_pfc_saved.u.pfcup) {
		if (ff->ff_pfc_saved.u.pfcup == 0xffff)
			return 1;	/* first time */
		else
			return 2;
	}
	return 0;
}

/*
 * update_saved_pfcup - Update the saved PFC priority with
 *                      the current priority.
 *
 * Returns:  None
 */
static void
update_saved_pfcup(struct fcm_fcoe *ff)
{
	ff->ff_pfc_saved.u.pfcup = ff->ff_pfc_info.u.pfcup;
}

/*
 * clear_dcbd_info - lear dcbd info to unknown values
 *
 */
static void
clear_dcbd_info(struct fcm_fcoe *ff)
{
	ff->ff_dcb_state = 0;
	ff->ff_app_info.advertise = 0;
	ff->ff_app_info.enable = 0;
	ff->ff_app_info.op_mode = 0;
	ff->ff_app_info.u.appcfg = 0;
	ff->ff_app_info.willing = 0;
	ff->ff_llink_info.advertise = 0;
	ff->ff_llink_info.enable = 0;
	ff->ff_llink_info.op_mode = 0;
	ff->ff_llink_info.willing = 0;
	ff->ff_llink_status = 0;
	ff->ff_pfc_info.op_mode = 0;
	ff->ff_pfc_info.u.pfcup = 0xffff;
}

/*
 * Handle command response.
 * Response buffer points past command code character in response.
 */
static void
fcm_dcbd_cmd_resp(char *resp, cmd_status st)
{
	struct fcm_fcoe *ff;
	u_int32_t ver;
	u_int32_t cmd;
	u_int32_t val;
	u_int32_t feature;
	u_int32_t subtype;
	char *ep;
	char *cp;
	size_t len;
	char *orig_resp;
	u_int32_t enable;
	u_int32_t parm_len;
	u_int32_t parm;
	int rc;

	orig_resp = resp;
	resp += CLIF_RSP_OFF;
	len = strlen(resp);
	ver = fcm_get_hex(resp + DCB_VER_OFF, DCB_VER_LEN, &ep);
	if (ep != NULL) {
		SA_LOG("parse error: resp %s", orig_resp);
		return;
	} else if (ver != CLIF_RSP_VERSION) {
		SA_LOG("unexpected version %d resp %s", ver, orig_resp);
		return;
	}
	cmd = fcm_get_hex(resp + DCB_CMD_OFF, DCB_CMD_LEN, &ep);
	if (ep != NULL) {
		SA_LOG("parse error on resp cmd: resp %s", orig_resp);
		return;
	}
	feature = fcm_get_hex(resp + DCB_FEATURE_OFF, DCB_FEATURE_LEN, &ep);
	if (ep != NULL) {
		SA_LOG("parse error on resp feature: resp %s", orig_resp);
		return;
	}
	subtype = fcm_get_hex(resp + DCB_SUBTYPE_OFF, DCB_SUBTYPE_LEN, &ep);
	if (ep != NULL) {
		SA_LOG("parse error on resp subtype: resp %s", orig_resp);
		return;
	}
	cp = resp;
	ff = fcm_dcbd_get_port(&cp, DCB_PORTLEN_OFF, DCB_PORTLEN_LEN, len);
	if (ff == NULL) {
		SA_LOG("port not found. resp %s", orig_resp);
		return;
	}

	switch (cmd) {
	case CMD_SET_CONFIG:
		if (ff->ff_dcbd_state == FCD_SEND_CONF) {
			if (st != cmd_success) {
				fcm_dcbd_state_set(ff, FCD_ERROR);
				break;
			}
			fcm_dcbd_state_set(ff, FCD_GET_PFC_CONFIG);
		}
		break;

	case CMD_GET_CONFIG:
		switch (ff->ff_dcbd_state) {
		case FCD_GET_DCB_STATE:
			if (st != cmd_success) {
				fcm_dcbd_state_set(ff, FCD_ERROR);
				break;
			}
			rc = dcb_rsp_parser(ff, resp, st);
			if (!rc)
				fcm_dcbd_state_set(ff, FCD_SEND_CONF);
			else
				fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		case FCD_GET_PFC_CONFIG:
			if (st != cmd_success) {
				fcm_dcbd_state_set(ff, FCD_ERROR);
				break;
			}
			rc = dcb_rsp_parser(ff, resp, st);
			if (!rc)
				fcm_dcbd_state_set(ff, FCD_GET_LLINK_CONFIG);
			else
				fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		case FCD_GET_LLINK_CONFIG:
			if (st != cmd_success) {
				fcm_dcbd_state_set(ff, FCD_ERROR);
				break;
			}
			rc = dcb_rsp_parser(ff, resp, st);
			if (!rc)
				fcm_dcbd_state_set(ff, FCD_GET_APP_CONFIG);
			else
				fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		case FCD_GET_APP_CONFIG:
			if (st != cmd_success) {
				fcm_dcbd_state_set(ff, FCD_ERROR);
				break;
			}
			rc = dcb_rsp_parser(ff, resp, st);
			if (!rc)
				fcm_dcbd_state_set(ff, FCD_GET_PFC_OPER);
			else
				fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		default:
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		break;

	case CMD_GET_OPER:
		/*
		 * Sample msg: R00C103050004eth8010100100208
		 *                  opppssll    vvmmeemsllpp
		 * cp points past the interface name.
		 */
		val = fcm_get_hex(cp + OPER_ERROR, 2, &ep);
		if (ep != NULL) {
			SA_LOG("invalid get oper response parse error byte %d."
			       "  resp %s", ep - cp, cp);
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		if (val != 0) {
			if (fcm_dcbd_debug) {
				SA_LOG("val=0x%x resp:%s\n", val, orig_resp);
				print_errors("", val);
			}
			fcm_dcbd_setup(ff, ADM_DESTROY);
			fcm_dcbd_state_set(ff, FCD_DONE);
			return;
		}
		if (st != cmd_success) {
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		enable = (cp[OPER_OPER_MODE] == '1');
		switch (ff->ff_dcbd_state) {
		case FCD_GET_PFC_OPER:
			if (fcm_dcbd_debug) {
				SA_LOG("%s PFC feature is %ssynced",
				       ff->ff_name,
				       cp[OPER_SYNCD] == '1' ? "" : "not ");
				SA_LOG("%s PFC operating mode is %s",
				       ff->ff_name, cp[OPER_OPER_MODE] == '1'
				       ? "on" : "off ");
			}
			ff->ff_pfc_info.enable = enable;
			rc = dcb_rsp_parser(ff, resp, st);
			if (!rc)
				fcm_dcbd_state_set(ff, FCD_GET_LLINK_OPER);
			else
				fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		case FCD_GET_LLINK_OPER:
			if (fcm_dcbd_debug) {
				SA_LOG("%s LLINK feature is %ssynced",
				       ff->ff_name,
				       cp[OPER_SYNCD] == '1' ? "" : "not ");
				SA_LOG("%s LLINK operating mode is %s",
				       ff->ff_name, cp[OPER_OPER_MODE] == '1'
				       ? "on" : "off ");
			}
			ff->ff_llink_info.enable = enable;
			rc = dcb_rsp_parser(ff, resp, st);
			if (!rc)
				fcm_dcbd_state_set(ff, FCD_GET_LLINK_PEER);
			else
				fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		case FCD_GET_APP_OPER:
			if (fcm_dcbd_debug) {
				SA_LOG("%s FCoE feature is %ssynced",
				       ff->ff_name,
				       cp[OPER_SYNCD] == '1' ? "" : "not ");
				SA_LOG("%s FCoE operating mode is %s",
				       ff->ff_name,
				       cp[OPER_OPER_MODE] == '1' ?
				       "on" : "off ");
			}
			rc = dcb_rsp_parser(ff, resp, st);
			if (rc) {
				fcm_dcbd_state_set(ff, FCD_ERROR);
				break;
			}

			parm_len = fcm_get_hex(cp + OPER_LEN, 2, &ep);
			cp += OPER_LEN + 2;
			if (ep != NULL || parm_len > strlen(cp)) {
				SA_LOG("invalid peer parm_len %d", parm_len);
				fcm_dcbd_state_set(ff, FCD_ERROR);
				break;
			}
			parm = 0;
			if (parm_len > 0) {
				parm = fcm_get_hex(cp, parm_len, &ep);
				if (ep != NULL) {
					SA_LOG("invalid parameter %s", cp);
					fcm_dcbd_state_set(ff, FCD_ERROR);
					break;
				}
			}
			ff->ff_qos_mask = parm;
			if (validating_dcbd_info(ff)) {
				if (fcm_dcbd_debug)
					SA_LOG("DCB settings of %s "
					       "qualified for creating "
					       "FCoE interface\n",
					       ff->ff_name);
				rc = is_pfcup_changed(ff);
				if (rc == 1) {
					if (fcm_dcbd_debug)
						SA_LOG("%s: Initial "
						       "QOS = 0x%x\n",
						       ff->ff_name,
						       ff->ff_qos_mask);
					fcm_dcbd_setup(ff, ADM_CREATE);
				} else if (rc == 2) {
					if (fcm_dcbd_debug)
						SA_LOG("%s: QOS changed"
						       " to 0x%x\n",
						       ff->ff_name,
						       ff->ff_qos_mask);
					fcm_dcbd_setup(ff, ADM_RESET);
				} else if (!ff->ff_enabled) {
					if (fcm_dcbd_debug)
						SA_LOG("%s: Re-create "
						       "QOS = 0x%x\n",
						       ff->ff_name,
						       ff->ff_qos_mask);
					fcm_dcbd_setup(ff, ADM_CREATE);
				} else {
					if (fcm_dcbd_debug)
						SA_LOG("%s: No action will "
						       "be taken\n",
						       ff->ff_name);
				}
			} else {
				if (fcm_dcbd_debug)
					SA_LOG("DCB settings of %s not "
					       "qualified for FCoE "
					       "operations.",
					       ff->ff_name);
				fcm_dcbd_setup(ff, ADM_DESTROY);
				clear_dcbd_info(ff);
			}

			update_saved_pfcup(ff);
			fcm_dcbd_state_set(ff, FCD_DONE);
			return;
		default:
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		break;

	case CMD_GET_PEER:
		val = fcm_get_hex(cp + OPER_ERROR, 2, &ep);
		if (ep != NULL) {
			SA_LOG("invalid get oper response parse error byte %d."
			       "  resp %s", ep - cp, cp);
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		if (val != 0) {
			if (fcm_dcbd_debug) {
				SA_LOG("val=0x%x resp:%s\n", val, orig_resp);
				print_errors("", val);
			}
			fcm_dcbd_setup(ff, ADM_DESTROY);
			fcm_dcbd_state_set(ff, FCD_DONE);
			return;
		}
		if (st != cmd_success) {
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		switch (ff->ff_dcbd_state) {
		case FCD_GET_LLINK_PEER:
			rc = dcb_rsp_parser(ff, resp, st);
			if (!rc) {
				if (fcm_dcbd_debug) {
					SA_LOG("%s Peer LLINK link status"
					       " is %s", ff->ff_name,
					       ff->ff_llink_status ?
					       "up" : "down");
				}
				fcm_dcbd_state_set(ff, FCD_GET_APP_OPER);
			} else
				fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		default:
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		break;

	default:
		SA_LOG("Unknown cmd 0x%x in response: resp %s",
		       cmd, orig_resp);
		break;
	}
}

static void
fcm_event_timeout(void *arg)
{
	struct fcm_fcoe *ff = (struct fcm_fcoe *)arg;

	if (fcm_dcbd_debug)
		SA_LOG("%s: %d milliseconds timeout!\n",
		       ff->ff_name, FCM_EVENT_TIMEOUT_USEC/1000);

	if (!is_query_in_progress()) {
		fcm_clif->cl_ping_pending++;
		fcm_dcbd_request("P");
	}
	fcm_dcbd_state_set(ff, FCD_GET_DCB_STATE);
}

/*
 * Handle incoming DCB event message.
 * Example message: E5104eth8050001
 */
static void
fcm_dcbd_event(char *msg, size_t len)
{
	struct fcm_fcoe *ff;
	u_int32_t feature;
	u_int32_t subtype;
	char *cp;
	char *ep;

	if (msg[EV_LEVEL_OFF] != MSG_DCB + '0' || len <= EV_PORT_ID_OFF)
		return;
	if (msg[EV_VERSION_OFF] != CLIF_EV_VERSION + '0') {
		SA_LOG("Unexpected version in event msg %s", msg);
		return;
	}
	cp = msg;
	ff = fcm_dcbd_get_port(&cp, EV_PORT_LEN_OFF, EV_PORT_LEN_LEN, len);
	if (ff == NULL)
		return;
	feature = fcm_get_hex(cp + EV_FEATURE_OFF, 2, &ep);
	if (ep != NULL) {
		SA_LOG("%s: Invalid feature code in event msg %s",
		       ff->ff_name, msg);
		return;
	}

	switch (feature) {
	case FEATURE_DCB:
		if (fcm_dcbd_debug)
			SA_LOG("<%s: Got DCB Event>\n", ff->ff_name);
		goto ignore_event;
	case FEATURE_PG:     /* 'E5204eth2020001' */
		if (fcm_dcbd_debug)
			SA_LOG("<%s: Got PG Event>\n", ff->ff_name);
		goto ignore_event;
	case FEATURE_BCN:    /* 'E5204eth2040001' */
		if (fcm_dcbd_debug)
			SA_LOG("<%s: Got BCN Event>\n", ff->ff_name);
		goto ignore_event;
	case FEATURE_PG_DESC:
		if (fcm_dcbd_debug)
			SA_LOG("<%s: Got PG_DESC Event>\n", ff->ff_name);
		goto ignore_event;
	case FEATURE_PFC:    /* 'E5204eth2030011' */
		if (fcm_dcbd_debug)
			SA_LOG("<%s: Got PFC Event>\n", ff->ff_name);
		goto handle_event;
	case FEATURE_APP:    /* 'E5204eth2050011' */
		if (fcm_dcbd_debug)
			SA_LOG("<%s: Got APP Event>\n", ff->ff_name);
		goto handle_event;
	case FEATURE_LLINK:
		if (fcm_dcbd_debug)
			SA_LOG("<%s: Got LLINK Event>\n", ff->ff_name);
handle_event:
		subtype = fcm_get_hex(cp + EV_SUBTYPE_OFF, 2, &ep);
		if (ep != NULL || subtype != APP_FCOE_STYPE) {
			SA_LOG("%s: Unknown application subtype in msg %s",
			       ff->ff_name, msg);
			break;
		}
		if (fcm_dcbd_debug) {
			if (cp[EV_OP_MODE_CHG_OFF] == '1')
				SA_LOG("%s: operational mode changed",
				       ff->ff_name);
			if (cp[EV_OP_CFG_CHG_OFF] == '1')
				SA_LOG("%s: operational config changed",
				       ff->ff_name);
		}
		if (ff->ff_dcbd_state == FCD_DONE ||
		    ff->ff_dcbd_state == FCD_ERROR) {
			if (cp[EV_OP_MODE_CHG_OFF] == '1' ||
			    cp[EV_OP_CFG_CHG_OFF] == '1') {
				/* Cancel timer if it is active */
				sa_timer_cancel(&ff->ff_event_timer);
				/* Reset the timer */
				sa_timer_set(&ff->ff_event_timer,
					     FCM_EVENT_TIMEOUT_USEC);
			}
			if (fcm_clif->cl_busy == 0)
				fcm_dcbd_port_advance(ff);
		}
		break;
	default:
		SA_LOG("%s: Unknown feature 0x%x in msg %s",
		       ff->ff_name, feature, msg);
ignore_event:
		break;
	}
}

/*
 * Run script to enable or disable the interface or print a message.
 *
 * Input:  enable = 0      Destroy the FCoE interface
 *         enable = 1      Create the FCoE interface
 *         enable = 2      Reset the interface
 */
static void
fcm_dcbd_setup(struct fcm_fcoe *ff, enum fcoeadm_action action)
{
	char *op;
	char *qos_arg;
	char qos[64];
	u_int32_t mask;
	int rc;
	int fd;

	if (action == 0)
		op = "--disable";
	else if (action == 1)
		op = "--enable";
	else
		op = "--reset";
	if (action && !ff->ff_qos_mask)
		return;
	if (fcm_dcbd_cmd == NULL) {
		SA_LOG("Should %s %s per op state", op, ff->ff_name);
		return;
	}
	/*
	 * XXX should wait for child status
	 */
	ff->ff_enabled = action;

	rc = fork();
	if (rc < 0) {
		SA_LOG_ERR(errno, "fork error");
	} else if (rc == 0) {	/* child process */
		for (fd = ulimit(4 /* __UL_GETOPENMAX */ , 0); fd > 2; fd--)
			close(fd);
		qos_arg = NULL;
		if (action) {
			mask = ff->ff_qos_mask;
			if (mask) {
				int off = 0;
				char *sep = "";
				u_int32_t bit;

				while (mask != 0 && off < sizeof(qos) - 1) {
					bit = ffs(mask) - 1;
					off +=
						snprintf(qos + off,
							 sizeof(qos) - off,
							 "%s%u",
							 sep, bit);
					mask &= ~(1 << bit);
					sep = ",";
				}
				qos_arg = "--qos";
			}
		}
		if (fcm_dcbd_debug) {
			if (!action)
				SA_LOG("%s %s %s\n",
				       fcm_dcbd_cmd, ff->ff_name, op);
			else
				SA_LOG("%s %s %s %s %s\n",
				       fcm_dcbd_cmd, ff->ff_name, op,
				       qos_arg, qos);
		}
		execlp(fcm_dcbd_cmd, fcm_dcbd_cmd, ff->ff_name,
		       op, qos_arg, qos, (char *)NULL);
		SA_LOG_ERR(errno, "exec '%s' failed", fcm_dcbd_cmd);
		exit(1);
	}
}

/*
 * Called for all ports.  For FCoE ports and candidates,
 * get information and send to dcbd.
 */
static void
fcm_dcbd_port_advance(struct fcm_fcoe *ff)
{
	char buf[80], params[30];
	struct fcoe_port_config *p;

	ASSERT(ff);
	ASSERT(fcm_clif);

	p = fcm_find_port_config(ff->ff_name);
	if (!p)
		return;

	if (ff->ff_dcbd_state != FCD_INIT && !fcm_fcoe_port_ready(ff))
		fcm_dcbd_state_set(ff, FCD_INIT);
	if (fcm_clif->cl_busy)
		return;

	switch (ff->ff_dcbd_state) {
	case FCD_INIT:
		if (!fcm_fcoe_port_ready(ff)) {
			if (fcm_dcbd_debug)
				SA_LOG("FCoE port %s not ready\n", ff->ff_name);
			fcm_dcbd_state_set(ff, FCD_ERROR);
			break;
		}
		fcm_dcbd_state_set(ff, FCD_GET_DCB_STATE);
		/* Fall through */
	case FCD_GET_DCB_STATE:
		fcm_fcoe_get_dcb_settings(ff);
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_CONFIG, FEATURE_DCB, 0,
			 (u_int) strlen(ff->ff_name), ff->ff_name);
		fcm_dcbd_request(buf);
		break;
	case FCD_SEND_CONF:
		snprintf(params, sizeof(params), "%x1%x02%2.2x",
			 ff->ff_app_info.enable,
			 ff->ff_app_info.willing,
			 ff->ff_qos_mask);
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_SET_CONFIG, FEATURE_APP, APP_FCOE_STYPE,
			 (u_int) strlen(ff->ff_name), ff->ff_name, params);
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_PFC_CONFIG:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_CONFIG, FEATURE_PFC, 0,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_LLINK_CONFIG:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_CONFIG, FEATURE_LLINK, LLINK_FCOE_STYPE,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_APP_CONFIG:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_CONFIG, FEATURE_APP, APP_FCOE_STYPE,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_PFC_OPER:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_OPER, FEATURE_PFC, 0,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_LLINK_OPER:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_OPER, FEATURE_LLINK, LLINK_FCOE_STYPE,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_LLINK_PEER:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_PEER, FEATURE_LLINK, LLINK_FCOE_STYPE,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_APP_OPER:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_OPER, FEATURE_APP, APP_FCOE_STYPE,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_GET_PEER:
		snprintf(buf, sizeof(buf), "%c%x%2.2x%2.2x%2.2x%2.2x%s%s",
			 DCB_CMD, CLIF_RSP_VERSION,
			 CMD_GET_PEER, FEATURE_APP, APP_FCOE_STYPE,
			 (u_int) strlen(ff->ff_name), ff->ff_name, "");
		fcm_dcbd_request(buf);
		break;
	case FCD_DONE:
		break;
	case FCD_ERROR:
		break;
	default:
		break;
	}
}

static void
fcm_dcbd_next(void)
{
	struct fcm_fcoe *ff;

	TAILQ_FOREACH(ff, &fcm_fcoe_head, ff_list) {
		if (fcm_clif->cl_busy)
			break;
		fcm_dcbd_port_advance(ff);
	}
}

static void
fcm_usage(void)
{
	printf("%s\n", fcoemon_version);
	printf("Usage: %s\n"
	       "\t [-e|--exec <exec>]\n"
	       "\t [-f|--foreground]\n"
	       "\t [-d|--debug]\n"
	       "\t [-v|--version]\n"
	       "\t [-h|--help]\n\n", progname);
	exit(1);
}

static void
fcm_sig(int sig)
{
	fcm_dcbd_shutdown();
	sa_select_exit();
}

static void
fcm_pidfile_create(void)
{
	FILE *fp;
	char buf[100];
	char *sp;
	int pid;
	int rc;

	fp = fopen(fcm_pidfile, "r+");
	if (fp) {
		sp = fgets(buf, sizeof(buf), fp);
		pid = atoi(sp);
		rc = kill(pid, 0);
		if (sp && (pid > 0) && !rc) {
			SA_LOG("Another instance"
			       " (pid %d) is running - exiting\n",
			       pid);
			exit(1);
		}
		fclose(fp);
	}
	fp = fopen(fcm_pidfile, "w+");
	if (fp) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}
}

int main(int argc, char **argv)
{
	struct sigaction sig;
	int fcm_fg = 0;
	int rc;
	int c;

	strncpy(progname, basename(argv[0]), sizeof(progname));
	sa_log_prefix = progname;
	sa_log_flags = 0;
	openlog(sa_log_prefix, LOG_CONS, LOG_DAEMON);

	while ((c = getopt_long(argc, argv, "fde:hv",
				fcm_options, NULL)) != -1) {
		switch (c) {
		case 'f':
			fcm_fg = 1;
		case 'd':
			fcm_dcbd_debug = 1;
			break;
		case 'e':
			fcm_dcbd_cmd = optarg;
			break;
		case 'v':
			printf("%s\n", fcoemon_version);
			return 0;
		case 'h':
		default:
			fcm_usage();
			break;
		}
	}
	if (argc != optind)
		fcm_usage();

	if (!fcm_fg) {
		pid_t pid, sid;

		pid = fork();
		if (pid < 0) {
			SA_LOG("Starting daemon failed");
			exit(EXIT_FAILURE);
		} else if (pid)
			exit(EXIT_SUCCESS);

		/* Create a new SID for the child process */
		sid = setsid();
		if (sid < 0)
			exit(EXIT_FAILURE);
	}

	umask(0);

	/* Change the current working directory */
	if ((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	/*
	 * Set up for signals.
	 */
	memset(&sig, 0, sizeof(sig));
	sig.sa_handler = fcm_sig;
	rc = sigaction(SIGINT, &sig, NULL);
	if (rc < 0)
		SA_LOG_ERR_EXIT(errno, "sigaction failed");
	rc = sigaction(SIGTERM, &sig, NULL);
	if (rc < 0)
		SA_LOG_ERR_EXIT(errno, "sigaction failed");
	rc = sigaction(SIGHUP, &sig, NULL);
	if (rc < 0)
		SA_LOG_ERR_EXIT(errno, "sigaction failed");
	fcm_pidfile_create();
	fcm_fcoe_init();
	fcm_link_init();	/* NETLINK_ROUTE protocol */
	fcm_dcbd_init();

	sa_select_loop();
	fcm_dcbd_shutdown();
	return 0;
}

/*******************************************************
 *         The following are debug routines            *
 *******************************************************/

static void
print_errors(char *buf, int errors)
{
	char msg[80];
	int len, j;
	int flag = 0;

	memset(msg, 0, sizeof(msg));
	len = sprintf(msg, "0x%02x - ", errors);

	if (!errors) {
		j = sprintf(msg + len, "none\n");
		SA_LOG("%s %s", buf, msg);
		return;
	}

	if (errors & 0x01) {
		flag++;
		j = sprintf(msg + len, "mismatch with peer");
	}

	if (errors & 0x02) {
		j = len;
		if (flag++)
			j = sprintf(msg + len, ", ");
		sprintf(msg + j, "local configuration error");
	}

	if (errors & 0x04) {
		j = len;
		if (flag++)
			j = sprintf(msg + len, ", ");
		sprintf(msg + j, "multiple TLV's received");
	}

	if (errors & 0x08) {
		j = len;
		if (flag++)
			j = sprintf(msg + len, ", ");
		sprintf(msg + j, "peer error");
	}

	if (errors & 0x10) {
		j = len;
		if (flag++)
			j = sprintf(msg + len, ", ");
		sprintf(msg + j, "multiple LLDP neighbors");
	}

	if (errors & 0x20) {
		j = len;
		if (flag++)
			j = sprintf(msg + len, ", ");
		sprintf(msg + j, "peer feature not present");
	}

	SA_LOG("%s %s\n", buf, msg);
}

