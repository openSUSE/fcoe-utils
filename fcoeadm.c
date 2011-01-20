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

static const char *optstring = "c:d:r:S:itlshv";
static struct option fcoeadm_opts[] = {
	{"create", required_argument, 0, 'c'},
	{"destroy", required_argument, 0, 'd'},
	{"reset", required_argument, 0, 'r'},
	{"interface", no_argument, 0, 'i'},
	{"target", no_argument, 0, 't'},
	{"lun", no_argument, 0, 'l'},
	{"stats", no_argument, 0, 's'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{0, 0, 0, 0}
};

char progname[20];

static void fcoeadm_help(void)
{
	printf("Version %s\n", FCOE_UTILS_VERSION);
	printf("Usage: %s\n"
	       "\t [-c|--create] <ethX>\n"
	       "\t [-d|--destroy] <ethX>\n"
	       "\t [-r|--reset] <ethX>\n"
	       "\t [-S|--Scan] <ethX>\n"
	       "\t [-i|--interface] [<ethX>]\n"
	       "\t [-t|--target] [<ethX>]\n"
	       "\t [-l|--lun] [<ethX>]\n"
	       "\t [-s|--stats] <ethX> [<interval>]\n"
	       "\t [-v|--version]\n"
	       "\t [-h|--help]\n\n", progname);
}

static enum fcoe_err fcoeadm_clif_request(struct clif_sock_info *clif_info,
					  const struct clif_data *cmd,
					  size_t cmd_len, char *reply,
					  size_t *reply_len)
{
	struct timeval tv;
	int ret;
	fd_set rfds;

	if (send(clif_info->socket_fd, cmd, cmd_len, 0) < 0)
		return ENOMONCONN;

	for (;;) {
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
			break;
		} else {
			return EINTERR;
		}
	}

	return NOERR;
}

static enum fcoe_err fcoeadm_request(struct clif_sock_info *clif_info,
				     struct clif_data *data)
{
	char rbuf[MAX_MSGBUF];
	size_t len;
	int rc = NOERR;

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
static enum fcoe_err fcoeadm_open_cli(struct clif_sock_info *clif_info)
{
	enum fcoe_err rc = NOERR;

	clif_info->socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (clif_info->socket_fd < 0)
		return ENOMONCONN;

	clif_info->local.sun_family = AF_UNIX;
	if (bind(clif_info->socket_fd, (struct sockaddr *)&clif_info->local,
		 sizeof(clif_info->local.sun_family)) < 0) {
		rc = ENOMONCONN;
		goto err_close;
	}

	clif_info->dest.sun_family = AF_UNIX;
	strncpy(clif_info->dest.sun_path, CLIF_SOCK_FILE,
		sizeof(clif_info->dest.sun_path));

	if (connect(clif_info->socket_fd, (struct sockaddr *)&clif_info->dest,
		     sizeof(clif_info->dest)) < 0) {
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
static enum fcoe_err fcoeadm_action(enum clif_action cmd, char *ifname)
{
	struct clif_data data;
	struct clif_sock_info clif_info;
	enum fcoe_err rc;

	strncpy(data.ifname, ifname, sizeof(data.ifname));
	data.cmd = cmd;

	rc = fcoeadm_open_cli(&clif_info);
	if (!rc) {
		rc = fcoeadm_request(&clif_info, &data);
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
	enum fcoe_err rc = NOERR;
	int opt, stat_interval;
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

	opt = getopt_long(argc, argv, optstring, fcoeadm_opts, NULL);
	if (opt != -1) {
		switch (opt) {
		case 'c':
			cmd = CLIF_CREATE_CMD;
		case 'd':
			if (cmd == CLIF_NONE)
				cmd = CLIF_DESTROY_CMD;
		case 'r':
			if (cmd == CLIF_NONE)
				cmd = CLIF_RESET_CMD;
		case 'S':
			if (cmd == CLIF_NONE)
				cmd = CLIF_SCAN_CMD;

			if (argc > 3) {
				rc = EBADNUMARGS;
				break;
			}

			ifname = optarg;
			rc = fcoeadm_action(cmd, ifname);
			break;

		case 'i':
			if (argc > 3) {
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
				rc = display_adapter_info(ifname);

			break;

		case 't':
			if (argc > 3) {
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
			if (argc > 3) {
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
			if (argc > 4) {
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

		case 'v':
			if (argc > 2) {
				rc = EBADNUMARGS;
				break;
			}

			printf("%s\n", FCOE_UTILS_VERSION);
			break;

		case 'h':
			if (argc > 2) {
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
		case EFCOECONN:
			FCOE_LOG_ERR("Connection already created on "
				     "interface %s\n", ifname);
			break;

		case ENOFCOECONN:
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

		default:
			/*
			 * This will catch EOPNOTSUPP which should never happen
			 */
			FCOE_LOG_ERR("Unknown error\n");
			break;
		}

		fprintf(stderr, "Try \'%s --help\' for more information.\n",
			progname);
	}

	return rc;
}
