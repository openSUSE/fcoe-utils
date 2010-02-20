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

static const char *optstring = "c:d:r:itlshv";
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
static int fcoeadm_check(char *ifname)
{
	char path[256];
	int fd;
	int status = 0;

	/* check if we have sysfs */
	if (fcoe_checkdir(SYSFS_MOUNT)) {
		fprintf(stderr,
			"%s: Sysfs mount point %s not found\n",
			progname, SYSFS_MOUNT);
		status = -EINVAL;
	}

	/* check target interface */
	if (valid_ifname(ifname)) {
		fprintf(stderr, "%s: Invalid interface name\n", progname);
		status = -EINVAL;
	}
	sprintf(path, "%s/%s", SYSFS_NET, ifname);
	if (fcoe_checkdir(path)) {
		fprintf(stderr,
			"%s: Interface %s not found\n", progname, ifname);
		status = -EINVAL;
	}

	fd = open(CLIF_PID_FILE, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr,
			"%s: fcoemon was not running\n", progname);
		status = -EINVAL;
	}

	return status;
}

static int fcoeadm_clif_request(struct clif_sock_info *clif_info,
				const struct clif_data *cmd, size_t cmd_len,
				char *reply, size_t *reply_len)
{
	struct timeval tv;
	int ret;
	fd_set rfds;

	if (send(clif_info->socket_fd, cmd, cmd_len, 0) < 0)
		return -1;

	for (;;) {
		tv.tv_sec = CLIF_CMD_RESPONSE_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(clif_info->socket_fd, &rfds);
		ret = select(clif_info->socket_fd + 1, &rfds, NULL, NULL, &tv);
		if (FD_ISSET(clif_info->socket_fd, &rfds)) {
			ret = recv(clif_info->socket_fd, reply, *reply_len, 0);
			if (ret < 0)
				return ret;
			*reply_len = ret;
			break;
		} else {
			return -2;
		}
	}

	return 0;
}

/*
 * TODO: What is this returning? A 'enum clif_status'?
 */
static int fcoeadm_request(struct clif_sock_info *clif_info,
			   struct clif_data *data)
{
	char rbuf[MAX_MSGBUF];
	size_t len;
	int ret;

	len = sizeof(rbuf)-1;

	ret = fcoeadm_clif_request(clif_info, data, sizeof(struct clif_data),
				   rbuf, &len);
	if (ret == -2) {
		fprintf(stderr, "Command timed out\n");
		goto fail;
	} else if (ret < 0) {
		fprintf(stderr, "Command failed\n");
		goto fail;
	}

	rbuf[len] = '\0';
	ret = atoi(rbuf);
	return ret;

fail:
	return -EINVAL;
}

static void fcoeadm_close_cli(struct clif_sock_info *clif_info)
{
	unlink(clif_info->local.sun_path);
	close(clif_info->socket_fd);
}

/*
 * Create fcoeadm client interface
 */
static int fcoeadm_open_cli(struct clif_sock_info *clif_info)
{
	int counter;
	int rc = 0;

	clif_info->socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (clif_info->socket_fd < 0) {
		/* Error code is returned through errno */
		rc = errno;
		goto err;
	}

	clif_info->local.sun_family = AF_UNIX;
	snprintf(clif_info->local.sun_path, sizeof(clif_info->local.sun_path),
		 "/tmp/fcadm_clif_%d-%d", getpid(), counter++);

	if (bind(clif_info->socket_fd, (struct sockaddr *)&clif_info->local,
		 sizeof(clif_info->local)) < 0) {
		/* Error code is returned through errno */
		rc = errno;
		goto err_close;
	}

	clif_info->dest.sun_family = AF_UNIX;
	strncpy(clif_info->dest.sun_path, CLIF_SOCK_FILE,
		sizeof(clif_info->dest.sun_path));

	if (!connect(clif_info->socket_fd, (struct sockaddr *)&clif_info->dest,
		     sizeof(clif_info->dest)) < 0) {
		/* Error code is returned through errno */
		rc = errno;
		unlink(clif_info->local.sun_path);
		goto err_close;
	}

err:
	return rc;

err_close:
	close(clif_info->socket_fd);
	return rc;
}

/*
 * Send request to fcoemon
 */
/*
 * TODO: This is wrong. Which is this routine returning
 * 'enum clif_status' or an -ERROR?
 */
static int fcoeadm_action(enum clif_action cmd, char *ifname)
{
	struct clif_data data;
	struct clif_sock_info clif_info;
	int rc;

	strncpy(data.ifname, ifname, sizeof(data.ifname));
	data.cmd = cmd;

	rc = fcoeadm_open_cli(&clif_info);
	if (!rc) {
		rc = fcoeadm_request(&clif_info, &data);
		fcoeadm_close_cli(&clif_info);
	}

	return rc;
}

static int fcoeadm_loadhba()
{
	if (HBA_STATUS_OK != HBA_LoadLibrary()) {
		fprintf(stderr, "Failed to load Linux HBAAPI library! Please "
			"verify the hba.conf file is set up correctly.\n");
		return -EINVAL;
	}
	return 0;
}


/*
 * Display adapter information
 */
static int fcoeadm_display_adapter_info(struct opt_info *opt_info)
{
	if (fcoeadm_loadhba())
		return -EINVAL;

	display_adapter_info(opt_info);

	HBA_FreeLibrary();
	return 0;
}

/*
 * Display target information
 */
static int fcoeadm_display_target_info(struct opt_info *opt_info)
{
	if (fcoeadm_loadhba())
		return -EINVAL;

	display_target_info(opt_info);

	HBA_FreeLibrary();
	return 0;
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
	int opt, rc = 0;
	enum clif_action cmd = CLIF_NONE;

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

			if (argc > 3) {
				rc = -E2BIG;
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
				rc = -E2BIG;
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
				rc = -E2BIG;
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
				rc = -E2BIG;
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
				rc = -E2BIG;
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
					rc = -EINVAL;
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
				rc = -E2BIG;
				break;
			}

			printf("%s\n", FCOE_UTILS_VERSION);
			break;

		case 'h':
			if (argc > 2) {
				rc = -E2BIG;
				break;
			}

			fcoeadm_help();
			break;

		case '?':
			rc = -ENOSYS;
			break;
		}
	}

	if (rc) {
		switch (rc) {
		case -ENOENT:
		case -ENODEV:
			fprintf(stderr, "%s: No connection created on "
				"interface %s\n", progname, opt_info->ifname);
			break;

		case -EINVAL:
			fprintf(stderr, "%s: Invalid argument\n", progname);
			break;

		case -E2BIG:
			/*
			 * Overloading E2BIG for too many argumets
			 * and too few arguments.
			 */
			fprintf(stderr, "%s: Incorrect number of arguments\n",
				progname);
			break;

		case -ENOSYS:
			/*
			 * getopt_long will print the initial error, just break
			 * through to get the --help suggestion.
			 */
			break;

		default:
			/*
			 * This will catch EOPNOTSUPP which should never happen
			 */
			fprintf(stderr, "%s: Unknown error\n",
				progname);
			break;
		}

		fprintf(stderr, "Try \'%s --help\' for more information.\n",
			progname);
	}

	return rc;
}
