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

#include "fcoe_utils_version.h"
#include "fcoeadm.h"
#include "fcoe_clif.h"

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

struct opt_info _opt_info, *opt_info = &_opt_info;
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

/*
 * TODO - check this ifname before performing any action
 */
static enum fcoe_err fcoeadm_check(char *ifname)
{
	char path[256];
	int fd;
	enum fcoe_err rc = NOERR;

	/* check if we have sysfs */
	if (fcoe_checkdir(SYSFS_MOUNT))
		rc = ENOSYSFS;

	if (!rc && valid_ifname(ifname))
		rc = ENOETHDEV;

	sprintf(path, "%s/%s", SYSFS_NET, ifname);

	if (!rc && fcoe_checkdir(path))
		rc = ENOETHDEV;

	fd = open(CLIF_PID_FILE, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0)
		rc = ENOMONCONN;

	return rc;
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

static void fcoeadm_close_cli(struct clif_sock_info *clif_info)
{
	unlink(clif_info->local.sun_path);
	close(clif_info->socket_fd);
}

/*
 * Create fcoeadm client interface
 */
static enum fcoe_err fcoeadm_open_cli(struct clif_sock_info *clif_info)
{
	int counter;
	enum fcoe_err rc = NOERR;

	clif_info->socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (clif_info->socket_fd < 0) {
		rc = ENOMONCONN;
		goto err;
	}

	clif_info->local.sun_family = AF_UNIX;
	snprintf(clif_info->local.sun_path, sizeof(clif_info->local.sun_path),
		 "/tmp/fcadm_clif_%d-%d", getpid(), counter++);

	if (bind(clif_info->socket_fd, (struct sockaddr *)&clif_info->local,
		 sizeof(clif_info->local)) < 0) {
		rc = ENOMONCONN;
		goto err_close;
	}

	clif_info->dest.sun_family = AF_UNIX;
	strncpy(clif_info->dest.sun_path, CLIF_SOCK_FILE,
		sizeof(clif_info->dest.sun_path));

	if (!connect(clif_info->socket_fd, (struct sockaddr *)&clif_info->dest,
		     sizeof(clif_info->dest)) < 0) {
		rc = ENOMONCONN;
		unlink(clif_info->local.sun_path);
		goto err_close;
	}

	return rc;

err_close:
	close(clif_info->socket_fd);
err:
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

static enum fcoe_err fcoeadm_loadhba()
{
	if (HBA_STATUS_OK != HBA_LoadLibrary())
		return EHBAAPIERR;

	return NOERR;
}

/*
 * Display adapter information
 */
static enum fcoe_err fcoeadm_display_adapter_info(struct opt_info *opt_info)
{
	if (fcoeadm_loadhba())
		return EHBAAPIERR;

	display_adapter_info(opt_info);

	HBA_FreeLibrary();
	return NOERR;
}

/*
 * Display target information
 */
static enum fcoe_err fcoeadm_display_target_info(struct opt_info *opt_info)
{
	if (fcoeadm_loadhba())
		return EHBAAPIERR;

	display_target_info(opt_info);

	HBA_FreeLibrary();
	return NOERR;
}

/*
 * Display port statistics
 */
static int fcoeadm_display_port_stats(struct opt_info *opt_info)
{
	if (!opt_info->s_flag)
		return -EINVAL;

	if (!opt_info->n_flag)
		opt_info->n_interval = DEFAULT_STATS_INTERVAL;

	if (fcoeadm_loadhba())
		return -EINVAL;

	display_port_stats(opt_info);

	HBA_FreeLibrary();
	return 0;
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
	int opt;
	enum clif_action cmd = CLIF_NONE;
	enum fcoe_err rc = NOERR;

	strncpy(progname, basename(argv[0]), sizeof(progname));
	memset(opt_info, 0, sizeof(*opt_info));

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

			strncpy(opt_info->ifname, optarg,
				sizeof(opt_info->ifname));

			if (fcoeadm_check(opt_info->ifname)) {
				rc = -EINVAL;
				break;
			}

			if (opt != 'c')
				rc = fcoe_validate_interface(opt_info->ifname);

			if (!rc)
				rc = fcoeadm_action(cmd, opt_info->ifname);
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
				strncpy(opt_info->ifname, argv[optind],
					sizeof(opt_info->ifname));

				rc = fcoe_validate_interface(opt_info->ifname);
			}

			if (!rc)
				rc = fcoeadm_display_adapter_info(opt_info);

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
				strncpy(opt_info->ifname, argv[optind],
					sizeof(opt_info->ifname));

				rc = fcoe_validate_interface(opt_info->ifname);
			}

			if (!rc) {
				opt_info->t_flag = 1;
				rc = fcoeadm_display_target_info(opt_info);
			}

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
				strncpy(opt_info->ifname, argv[optind],
					sizeof(opt_info->ifname));

				rc = fcoe_validate_interface(opt_info->ifname);
			}

			if (!rc) {
				opt_info->l_flag = 1;
				rc = fcoeadm_display_target_info(opt_info);
			}

			break;

		case 's':
			if (argc > 4) {
				rc = EBADNUMARGS;
				break;
			}

			if (optind != argc) {
				strncpy(opt_info->ifname, argv[optind],
					sizeof(opt_info->ifname));

				rc = fcoe_validate_interface(opt_info->ifname);
			}

			if (!rc && ++optind != argc) {
				opt_info->n_interval = atoi(argv[optind]);
				if (opt_info->n_interval <= 0)
					rc = EINVALARG;
				else
					opt_info->n_flag = 1;
			}

			if (!rc) {
				opt_info->s_flag = 1;
				rc = fcoeadm_display_port_stats(opt_info);
			}

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

	if (rc) {
		switch (rc) {
		case ENOFCOECONN:
			FCOE_LOG_ERR("No connection created on "
				     "interface %s\n", opt_info->ifname);
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
			FCOE_LOG_ERR("Invalid interface name %s\n",
				     opt_info->ifname);
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
