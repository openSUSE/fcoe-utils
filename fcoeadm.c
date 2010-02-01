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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <libgen.h>
#include <paths.h>
#include "fcoe_utils.h"
#include "fcoeadm.h"
#include "fcoe_clif.h"

static char *fcoeadm_version =
"fcoeadm v" FCOE_UTILS_VERSION "\n Copyright (c) 2009, Intel Corporation.\n";

#define CMD_RESPONSE_TIMEOUT 5

static struct option fcoeadm_opts[] = {
	{"create", 1, 0, 'c'},
	{"destroy", 1, 0, 'd'},
	{"reset", 1, 0, 'r'},
	{"interface", 1, 0, 'i'},
	{"target", 1, 0, 't'},
	{"lun", 2, 0, 'l'},
	{"stats", 1, 0, 's'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

struct opt_info _opt_info, *opt_info = &_opt_info;
char progname[20];

struct clif *clif_conn;

static void fcoeadm_help(void)
{
	printf("%s\n", fcoeadm_version);
	printf("Usage: %s\n"
	       "\t [-c|--create] <ethX>\n"
	       "\t [-d|--destroy] <ethX>\n"
	       "\t [-r|--reset] <ethX>\n"
	       "\t [-i|--interface] [<ethX>]\n"
	       "\t [-t|--target] [<ethX>]\n"
	       "\t [-l|--lun] [<target port_id> [<lun_id>]]\n"
	       "\t [-s|--stats] <ethX> [-n <interval>]\n"
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
	if (fcoeclif_checkdir(SYSFS_MOUNT)) {
		fprintf(stderr,
			"%s: Sysfs mount point %s not found\n",
			progname, SYSFS_MOUNT);
		status = -EINVAL;
	}

	/* check target interface */
	if (!ifname) {
		fprintf(stderr, "%s: Invalid interface name\n", progname);
		status = -EINVAL;
	}
	sprintf(path, "%s/%s", SYSFS_NET, ifname);
	if (fcoeclif_checkdir(path)) {
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

static int fcoeadm_clif_request(const struct clif_data *cmd, size_t cmd_len,
				char *reply, size_t *reply_len)
{
	struct timeval tv;
	int ret;
	fd_set rfds;

	if (send(clif_conn->s, cmd, cmd_len, 0) < 0)
		return -1;

	for (;;) {
		tv.tv_sec = CMD_RESPONSE_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(clif_conn->s, &rfds);
		ret = select(clif_conn->s + 1, &rfds, NULL, NULL, &tv);
		if (FD_ISSET(clif_conn->s, &rfds)) {
			ret = recv(clif_conn->s, reply, *reply_len, 0);
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

static int fcoeadm_request(int cmd, char *s)
{
	struct clif_data *data = NULL;
	char rbuf[MAX_MSGBUF];
	size_t len;
	int ret;

	if (clif_conn == NULL) {
		fprintf(stderr, "Not connected to fcoemon\n");
		return -EINVAL;
	}

	data = (struct clif_data *)malloc(sizeof(struct clif_data));
	if (data == NULL)
		return -EINVAL;

	memset(data, 0, sizeof(data));
	data->cmd = cmd;
	strcpy(data->ifname, s);

	len = sizeof(rbuf)-1;

	ret = fcoeadm_clif_request(data, sizeof(struct clif_data), rbuf, &len);
	if (ret == -2) {
		fprintf(stderr, "Command timed out\n");
		goto fail;
	} else if (ret < 0) {
		fprintf(stderr, "Command failed\n");
		goto fail;
	}

	rbuf[len] = '\0';
	ret = atoi(rbuf);
	free(data);
	return ret;

fail:
	free(data);
	return -EINVAL;
}

static void fcoeadm_close_cli(void)
{
	if (clif_conn == NULL)
		return;

	unlink(clif_conn->local.sun_path);
	close(clif_conn->s);
	free(clif_conn);
	clif_conn = NULL;
}

/*
 * Create fcoeadm client interface
 */
static struct clif *fcoeadm_open_cli(const char *ifname)
{
	char *fcmon_file = NULL;
	int flen;
	static int counter;

	flen = strlen(FCM_SRV_DIR) + strlen(ifname) + 2;
	fcmon_file = malloc(flen);
	if (fcmon_file == NULL)
		goto fail;
	snprintf(fcmon_file, flen, "%s/%s", FCM_SRV_DIR, ifname);

	clif_conn = malloc(sizeof(*clif_conn));
	if (clif_conn == NULL)
		goto fail;
	memset(clif_conn, 0, sizeof(*clif_conn));

	clif_conn->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (clif_conn->s < 0)
		goto fail;

	clif_conn->local.sun_family = AF_UNIX;
	snprintf(clif_conn->local.sun_path, sizeof(clif_conn->local.sun_path),
		    "/tmp/fcadm_clif_%d-%d", getpid(), counter++);
	if (bind(clif_conn->s, (struct sockaddr *) &clif_conn->local,
		    sizeof(clif_conn->local)) < 0) {
		close(clif_conn->s);
		goto fail;
	}

	clif_conn->dest.sun_family = AF_UNIX;
	snprintf(clif_conn->dest.sun_path, sizeof(clif_conn->dest.sun_path),
			"%s", fcmon_file);
	if (connect(clif_conn->s, (struct sockaddr *) &clif_conn->dest,
		    sizeof(clif_conn->dest)) < 0) {
		close(clif_conn->s);
		unlink(clif_conn->local.sun_path);
		goto fail;
	}

	free(fcmon_file);
	return clif_conn;

fail:
	free(fcmon_file);
	free(clif_conn);
	return NULL;
}

/*
 * Send request to fcoemon
 */
static int fcoeadm_action(int cmd, char *device_name)
{
	char *clif_ifname = NULL;
	int ret = 0;

	if (!device_name)
		return -EINVAL;

	for (;;) {
		if (clif_ifname == NULL) {
			struct dirent *dent;
			DIR *dir = opendir(FCM_SRV_DIR);
			if (dir) {
				while ((dent = readdir(dir))) {
					if (strcmp(dent->d_name, ".") == 0 ||
						strcmp(dent->d_name, "..") == 0)
						continue;
					clif_ifname = strdup(dent->d_name);
					break;
				}
			closedir(dir);
			}
		}

		clif_conn = fcoeadm_open_cli(clif_ifname);
		if (clif_conn) {
			break;
		} else {
			fprintf(stderr, "Failed to connect to fcoemon\n");
			free(clif_ifname);
			return -1;
		}
	}

	ret = fcoeadm_request(cmd, device_name);

	free(clif_ifname);
	fcoeadm_close_cli();

	return ret;
}

/*
 * Create FCoE instance for this ifname
 */
static int fcoeadm_create(char *ifname)
{
	if (fcoeadm_check(ifname)) {
		fprintf(stderr,
			"%s: Failed to create FCoE instance on %s\n",
			progname, ifname);
		return -EINVAL;
	}
	return fcoeadm_action(FCOE_CREATE_CMD, ifname);
}

/*
 * Remove FCoE instance for this ifname
 */
static int fcoeadm_destroy(char *ifname)
{
	if (fcoeadm_check(ifname)) {
		fprintf(stderr,
			"%s: Failed to destroy FCoE instance on %s\n",
			progname, ifname);
		return -EINVAL;
	}
	return fcoeadm_action(FCOE_DESTROY_CMD, ifname);
}

/*
 * Reset the fc_host that is associated w/ this ifname
 */
static int fcoeadm_reset(char *ifname)
{
	return fcoeadm_action(FCOE_RESET_CMD, ifname);
}

/*
 * Parse a user-entered hex field.
 * Format may be xx-xx-xx OR xxxxxx OR xx:xx:xx for len bytes (up to 8).
 * Leading zeros may be omitted.
 */
static int parse_hex_ll(unsigned long long *hexp, const char *input, u_int len)
{
	int i;
	unsigned long long hex = 0;
	unsigned long long byte;
	char *endptr = "";
	int error = EINVAL;
	char sep = 0;

	for (i = 0; i < len; i++) {
		byte = strtoull(input, &endptr, 16);
		if (i == 0 && *endptr == '\0') {
			hex = byte;
			if (len == 8 || hex < (1ULL << (8 * len)))
				error = 0;
			break;
		}
		if (sep == 0 && (*endptr == ':' || *endptr == '-'))
			sep = *endptr;
		if ((*endptr == '\0' || *endptr == sep) && byte < 256)
			hex = (hex << 8) | byte;
		else
			break;
		input = endptr + 1;
	}
	if (i == len && *endptr == '\0')
		error = 0;
	if (error == 0)
		*hexp = hex;
	return error;
}

static int parse_fcid(HBA_UINT32 *fcid, const char *input)
{
	int rc;
	unsigned long long hex;

	rc = parse_hex_ll(&hex, input, 3);
	if (rc == 0)
		*fcid = (HBA_UINT32) hex;
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

int main(int argc, char *argv[])
{
	char fchost[FCHOSTBUFLEN], *s;
	int opt, rc = -1;

	strncpy(progname, basename(argv[0]), sizeof(progname));
	memset(opt_info, 0, sizeof(*opt_info));

	while ((opt = getopt_long(argc, argv, "c:d:r:itls:n:hv",
				  fcoeadm_opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			if ((argc < 2 || argc > 3) ||
			    strnlen(optarg, MAX_ARG_LEN) > (IFNAMSIZ - 1) ||
			    ((argc == 3) && strnlen(argv[1], MAX_ARG_LEN) > 2 &&
			     argv[1][1] != '-'))
				goto error;
			rc = fcoeadm_create(optarg);
			goto done;
		case 'd':
			if ((argc < 2 || argc > 3) ||
			    strnlen(optarg, MAX_ARG_LEN) > (IFNAMSIZ - 1) ||
			    ((argc == 3) && strnlen(argv[1], MAX_ARG_LEN) > 2 &&
			     argv[1][1] != '-'))
				goto error;
			rc = fcoeadm_destroy(optarg);
			goto done;
		case 'r':
			if ((argc < 2 || argc > 3) ||
			    strnlen(optarg, MAX_ARG_LEN) > (IFNAMSIZ - 1) ||
			    ((argc == 3) && strnlen(argv[1], MAX_ARG_LEN) > 2 &&
			     argv[1][1] != '-'))
				goto error;
			rc = fcoeadm_reset(optarg);
			goto done;
		case 'i':
			if (argc < 2 || argc > 3 ||
			    (argc == 3 && strnlen(argv[1], MAX_ARG_LEN) > 2 &&
			     (argv[1][1] != '-' || strchr(argv[1], '=')
			      != NULL)))
				goto error;
			s = NULL;
			if (argc == 2) {
				if (argv[1][1] == '-')
					s = strchr(argv[1], '=')+1;
				else
					s = argv[1]+2;
			} else
				s = argv[2];

			if (s) {
				if (strnlen(s, MAX_ARG_LEN) > (IFNAMSIZ - 1))
					goto error;
				strncpy(opt_info->ifname, s,
					sizeof(opt_info->ifname));
			}
			if (strnlen(opt_info->ifname, IFNAMSIZ - 1)) {
				if (fcoeclif_validate_interface(
					    opt_info->ifname,
					    fchost, FCHOSTBUFLEN))
					goto done;
			}
			opt_info->a_flag = 1;
			rc = fcoeadm_display_adapter_info(opt_info);
			goto done;
		case 't':
			if (argc < 2 || argc > 3 ||
			    (argc == 3 && strnlen(argv[1], MAX_ARG_LEN) > 2 &&
			     (argv[1][1] != '-' || strchr(argv[1], '=')
			      != NULL)))
				goto error;
			s = NULL;
			if (argc == 2) {
				if (argv[1][1] == '-')
					s = strchr(argv[1], '=')+1;
				else
					s = argv[1]+2;
			} else {
				s = argv[2];
			}
			if (s) {
				if (strnlen(s, MAX_ARG_LEN) > (IFNAMSIZ - 1))
					goto error;
				strncpy(opt_info->ifname, s,
					sizeof(opt_info->ifname));
			}
			if (strnlen(opt_info->ifname, IFNAMSIZ - 1)) {
				if (fcoeclif_validate_interface(
					    opt_info->ifname,
					    fchost, FCHOSTBUFLEN))
					goto done;
			}
			opt_info->t_flag = 1;
			rc = fcoeadm_display_target_info(opt_info);
			goto done;
		case 'l':
			if (argc < 2 || argc > 4)
				goto error;
			if (optarg) {
				if (parse_fcid(&opt_info->l_fcid, optarg))
					goto error;
				opt_info->l_fcid_present = 1;
				if (argv[optind]) {
					opt_info->l_lun_id = atoi(argv[optind]);
					opt_info->l_lun_id_present = 1;
				}
			}
			opt_info->l_flag = 1;
			rc = fcoeadm_display_target_info(opt_info);
			goto done;
		case 's':
			if ((argc < 2 || argc > 5) ||
			    strnlen(optarg, MAX_ARG_LEN) > (IFNAMSIZ - 1))
				goto error;
			if (optarg)
				strncpy(opt_info->ifname, optarg,
					sizeof(opt_info->ifname));
			if (strnlen(opt_info->ifname, IFNAMSIZ - 1)) {
				if (fcoeclif_validate_interface(
					    opt_info->ifname,
					    fchost, FCHOSTBUFLEN))
					goto done;
			}
			opt_info->s_flag = 1;
			if (argv[optind] && !strncmp(argv[optind], "-n", 2))
				break;
			goto stats;
		case 'n':
			if (!opt_info->s_flag)
				goto error;
			opt_info->n_interval = atoi(optarg);
			if (opt_info->n_interval <= 0)
				goto error;
			if (argv[optind] &&
			    strnlen(argv[optind], MAX_ARG_LEN<<1) > MAX_ARG_LEN)
				goto error;
			opt_info->n_flag = 1;
			goto stats;
		case 'v':
			if (argc != 2)
				goto error;
			printf("%s\n", fcoeadm_version);
			goto done;
		case 'h':
		default:
			if (argc != 2)
				goto error;
			fcoeadm_help();
			exit(-EINVAL);
		}
	}
	goto error;

stats:
	if (!fcoeadm_display_port_stats(opt_info))
		goto done;

error:
	fprintf(stderr, "%s: Invalid command options\n", progname);
	fcoeadm_help();
	exit(-EINVAL);

done:
	return rc;
}
