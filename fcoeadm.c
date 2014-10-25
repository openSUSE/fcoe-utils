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

#include <libgen.h>
#include <paths.h>
#include <net/if.h>
#include <sys/un.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "fcoe_utils.h"
#include "fcoe_utils_version.h"
#include "fcoe_clif.h"
#include "fcoeadm_display.h"

static const char optstring[] = "cdrSiftlm:sbhpv";
static const struct option fcoeadm_opts[] = {
	{"create", no_argument, 0, 'c'},
	{"destroy", no_argument, 0, 'd'},
	{"reset", no_argument, 0, 'r'},
	{"interface", no_argument, 0, 'i'},
	{"Scan", no_argument, 0, 'S'},
	{"fcf", no_argument, 0, 'f'},
	{"target", no_argument, 0, 't'},
	{"lun", no_argument, 0, 'l'},
	{"mode", required_argument, 0, 'm'},
	{"pid", no_argument, 0, 'p'},
	{"stats", no_argument, 0, 's'},
	{"lesb", no_argument, 0, 'b'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{0, 0, 0, 0}
};

char progname[20];

static void fcoeadm_help(void)
{
	printf("Version %s\n", FCOE_UTILS_VERSION);
	printf("Usage: %s\n"
	       "\t [-m|--mode fabric|vn2vn] [-c|--create] <ethX>\n"
	       "\t [-d|--destroy] <ethX>\n"
	       "\t [-r|--reset] <ethX>\n"
	       "\t [-S|--Scan] <ethX>\n"
	       "\t [-i|--interface] [<ethX>]\n"
	       "\t [-f]--fcf] [<ethX>]\n"
	       "\t [-t|--target] [<ethX>]\n"
	       "\t [-l|--lun] [<ethX>]\n"
	       "\t [-s|--stats] <ethX> [<interval>]\n"
	       "\t [-b|--lesb] <ethX> [<interval>]\n"
	       "\t [-p|--pid]\n"
	       "\t [-v|--version]\n"
	       "\t [-h|--help]\n\n", progname);
}

static enum fcoe_status fcoeadm_clif_request(struct clif_sock_info *clif_info,
					     const struct clif_data *cmd,
					     size_t cmd_len, char *reply,
					     size_t *reply_len)
{
	struct timeval tv;
	int ret;
	fd_set rfds;

	if (send(clif_info->socket_fd, cmd, cmd_len, 0) < 0)
		return ENOMONCONN;

	tv.tv_sec = CLIF_CMD_RESPONSE_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(clif_info->socket_fd, &rfds);
	ret = select(clif_info->socket_fd + 1, &rfds, NULL, NULL, &tv);
	if (FD_ISSET(clif_info->socket_fd, &rfds)) {
		ret = recv(clif_info->socket_fd, reply, *reply_len, 0);
		if (ret < 0)
			return EINTERR;
		*reply_len = ret;
		return SUCCESS;
	} else {
		return EINTERR;
	}
}

static int fcoeadm_request(struct clif_sock_info *clif_info,
					struct clif_data *data)
{
	char rbuf[MAX_MSGBUF];
	size_t len;
	int rc = SUCCESS;

	/*
	 * TODO: This is odd that we read the response code back as a
	 * string. We should just write the error code into a member
	 * of clif_data and then just read it directly.
	 */

	len = MAX_MSGBUF - 1;
	rc = fcoeadm_clif_request(clif_info, data, sizeof(struct clif_data),
				  rbuf, &len);

	if (!rc) {
		rbuf[len] = '\0';
		rc = atoi(rbuf);
	}

	return rc;
}

static inline void fcoeadm_close_cli(struct clif_sock_info *clif_info)
{
	close(clif_info->socket_fd);
}

/*
 * Create fcoeadm client interface
 */
static enum fcoe_status fcoeadm_open_cli(struct clif_sock_info *clif_info)
{
	enum fcoe_status rc = SUCCESS;
	struct sockaddr_un *lp;
	socklen_t addrlen;

	clif_info->socket_fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (clif_info->socket_fd < 0)
		return ENOMONCONN;

	lp = &clif_info->local;
	memset(lp, 0, sizeof(*lp));
	lp->sun_family = AF_LOCAL;
	lp->sun_path[0] = '\0';
	snprintf(&lp->sun_path[1], sizeof(lp->sun_path) - 1,
		 "%s/%lu", CLIF_IFNAME, (unsigned long int)getpid);
	addrlen = sizeof(sa_family_t) + strlen(lp->sun_path + 1) + 1;
	if (bind(clif_info->socket_fd, (struct sockaddr *)lp, addrlen) < 0) {
		rc = ENOMONCONN;
		goto err_close;
	}

	clif_info->dest.sun_family = AF_LOCAL;
	clif_info->dest.sun_path[0] = '\0';
	snprintf(&clif_info->dest.sun_path[1],
		 sizeof(clif_info->dest.sun_path) - 1,
		 "%s", CLIF_IFNAME);
	addrlen = sizeof(sa_family_t) + strlen(clif_info->dest.sun_path + 1) + 1;
	if (connect(clif_info->socket_fd, (struct sockaddr *)&clif_info->dest,
		    addrlen) < 0) {
		rc = ENOMONCONN;
		goto err_close;
	}

	return rc;

err_close:
	close(clif_info->socket_fd);
	return rc;
}

/*
 * Send request to fcoemon
 */
static enum fcoe_status
fcoeadm_action(enum clif_action cmd, char *ifname, enum clif_flags flags)
{
	struct clif_data data;
	struct clif_sock_info clif_info;
	int rc;

	if (ifname)
		strncpy(data.ifname, ifname, sizeof(data.ifname));
	else
		data.ifname[0] = '\0';
	data.cmd = cmd;
	data.flags = flags;

	rc = fcoeadm_open_cli(&clif_info);
	if (!rc) {
		rc = fcoeadm_request(&clif_info, &data);
		if (rc > 0 && cmd == CLIF_PID_CMD) {
			printf("%d\n", rc);
			rc = 0;
		}
		fcoeadm_close_cli(&clif_info);
	}

	return rc;
}

#define MAX_ARG_LEN 32

/*
 * getopts_long(3) does not handle optional arguments
 * correctly. It will not allow a ' ' between the option
 * and its argument. For required arguments the user can
 * specify, '-i X' or '-iX' but with optional arguments
 * only the first style is valid.
 *
 * This is being worked around by making '-i/-t/-l' have
 * no arguments, but then process any following argv
 * elements.
 */
int main(int argc, char *argv[])
{
	enum clif_action cmd = CLIF_NONE;
	enum fcoe_status rc = SUCCESS;
	enum clif_flags flags = CLIF_FLAGS_NONE;
	int opt, stat_interval;
	int op = -1;
	char *ifname = NULL;

	/*
	 * This has to be first because the error print macro
	 * expects progname to be valid.
	 */
	strncpy(progname, basename(argv[0]), sizeof(progname));

	/* check if we have sysfs */
	if (fcoe_checkdir(SYSFS_MOUNT)) {
		rc = ENOSYSFS;
		goto err;
	}

	for (;;) {
		opt = getopt_long(argc, argv, optstring, fcoeadm_opts, NULL);
		if (opt < 0)
			break;
		switch (opt) {
		case 'm':
			if (strcasecmp(optarg, "vn2vn") == 0) {
				flags &= ~CLIF_FLAGS_MODE_MASK;
				flags |= CLIF_FLAGS_VN2VN;
			} else if (strcasecmp(optarg, "fabric") == 0) {
				flags &= ~CLIF_FLAGS_MODE_MASK;
			} else {
				rc = EINVALARG;
			}
			break;

		default:
			if (op == -1)
				op = opt;
			else
				rc = EINVALARG;
			break;

		case '?':
			rc = EIGNORE;
			break;
		}
	}

	if (op == -1)
		fcoeadm_help();
	else if (rc == SUCCESS) {
		switch (op) {
		case 'd':
			cmd = CLIF_DESTROY_CMD;
			flags = 0;	/* No flags allowed on destroy yet */
			/* fall through */
		case 'c':
			if (cmd == CLIF_NONE)
				cmd = CLIF_CREATE_CMD;

			if (argc - optind != 1) {
				rc = EBADNUMARGS;
				break;
			}

			ifname = argv[optind];
			rc = fcoeadm_action(cmd, ifname, flags);
			break;
		case 'r':
			cmd = CLIF_RESET_CMD;
			/* fall through */
		case 'S':
			if (cmd == CLIF_NONE)
				cmd = CLIF_SCAN_CMD;

			if (argc - optind != 1) {
				rc = EBADNUMARGS;
				break;
			}

			ifname = argv[optind];
			rc = fcoe_validate_fcoe_conn(ifname);
			if (!rc)
				rc = fcoeadm_action(cmd, ifname, flags);
			break;

		case 'i':
			if (argc - optind > 1) {
				rc = EBADNUMARGS;
				break;
			}

			/*
			 * If there's an additional argument
			 * treat it as the interface name.
			 */
			if (optind != argc) {
				ifname = argv[optind];
				rc = fcoe_validate_fcoe_conn(ifname);
			}

			if (!rc)
				rc = display_adapter_info(ifname);
			break;

		case 'f':
			if (argc - optind > 1) {
				rc = EBADNUMARGS;
				break;
			}

			/*
			 * If there's an aditional argument
			 * treat it as the interface name.
			 */
			if (optind != argc) {
				ifname = argv[optind];
				rc = fcoe_validate_fcoe_conn(ifname);
			}

			if (!rc)
				rc = display_fcf_info(ifname);
			break;

		case 't':
			if (argc - optind > 1) {
				rc = EBADNUMARGS;
				break;
			}

			/*
			 * If there's an aditional argument
			 * treat it as the interface name.
			 */
			if (optind != argc) {
				ifname = argv[optind];
				rc = fcoe_validate_fcoe_conn(ifname);
			}

			if (!rc)
				rc = display_target_info(ifname, DISP_TARG);
			break;

		case 'l':
			if (argc - optind > 1) {
				rc = EBADNUMARGS;
				break;
			}

			/*
			 * If there's an aditional argument
			 * treat it as the interface name.
			 */
			if (optind != argc) {
				ifname = argv[optind];
				rc = fcoe_validate_fcoe_conn(ifname);
			}

			if (!rc)
				rc = display_target_info(ifname, DISP_LUN);
			break;

		case 's':
			if (argc - optind > 2) {
				rc = EBADNUMARGS;
				break;
			}

			if (optind != argc) {
				ifname = argv[optind];
				rc = fcoe_validate_fcoe_conn(ifname);
			}

			if (!rc && ++optind != argc) {
				stat_interval = atoi(argv[optind]);
				if (stat_interval <= 0)
					rc = EINVALARG;
			} else if (!rc && optind == argc)
				stat_interval = DEFAULT_STATS_INTERVAL;

			if (!rc)
				rc = display_port_stats(ifname, stat_interval);
			break;
		case 'p':
			rc = fcoeadm_action(CLIF_PID_CMD, NULL, flags);
			break;

		case 'b':
			if (argc - optind > 2) {
				rc = EBADNUMARGS;
				break;
			}

			if (optind != argc) {
				ifname = argv[optind];
				rc = fcoe_validate_fcoe_conn(ifname);
			}

			if (!rc && ++optind != argc) {
				stat_interval = atoi(argv[optind]);
				if (stat_interval <= 0)
					rc = EINVALARG;
			} else if (!rc && optind == argc)
				stat_interval = DEFAULT_STATS_INTERVAL;

			if (!rc)
				rc = display_port_lesb_stats(ifname,
							     stat_interval);
			break;

		case 'v':
			if (argc - optind != 0) {
				rc = EBADNUMARGS;
				break;
			}

			printf("%s\n", FCOE_UTILS_VERSION);
			break;

		case 'h':
			if (argc - optind != 0) {
				rc = EBADNUMARGS;
				break;
			}

			fcoeadm_help();
			break;

		case '?':
			rc = EIGNORE;
			break;
		}
	}

err:
	if (rc) {
		switch (rc) {
		case EFAIL:
			FCOE_LOG_ERR("Command failed\n");
			break;

		case ENOACTION:
			FCOE_LOG_ERR("No action was taken\n");
			break;

		case EFCOECONN:
			FCOE_LOG_ERR("Connection already created on "
				     "interface %s\n", ifname);
			break;

		case ENOFCOECONN:
		case ENOFCHOST:
			FCOE_LOG_ERR("No connection created on "
				     "interface %s\n", ifname);
			break;

		case EINVALARG:
			FCOE_LOG_ERR("Invalid argument\n");
			break;

		case EBADNUMARGS:
			/*
			 * Overloading E2BIG for too many argumets
			 * and too few arguments.
			 */
			FCOE_LOG_ERR("Incorrect number of arguments\n");
			break;

		case EIGNORE:
			/*
			 * getopt_long will print the initial error, just break
			 * through to get the --help suggestion.
			 */
			break;

		case ENOETHDEV:
			FCOE_LOG_ERR("Invalid interface name %s\n", ifname);
			break;

		case ENOSYSFS:
			FCOE_LOG_ERR("sysfs not mounted\n");
			break;

		case ENOMONCONN:
			FCOE_LOG_ERR("Could not connect to fcoemon\n");
			break;

		case ECONNTMOUT:
			FCOE_LOG_ERR("Connection to fcoemon timed out\n");
			break;

		case EHBAAPIERR:
			FCOE_LOG_ERR("libHBAAPI or libhbalinux error\n");
			break;

		case EINTERR:
			FCOE_LOG_ERR("Internal error\n");
			break;

		case EBADCLIFMSG:
			FCOE_LOG_ERR("Messaging error\n");
			break;

		default:
			/*
			 * This will catch EOPNOTSUPP which should never happen
			 */
			FCOE_LOG_ERR("Unknown error code %d\n", rc);
			break;
		}

		fprintf(stderr, "Try \'%s --help\' for more information.\n",
			progname);
	}

	return rc;
}
