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

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <getopt.h>
#include <dirent.h>
#include "fcoeadm.h"

static char *fcoeadm_version = "\
fcoeadm v1.0.7\n\
Copyright (c) 2009, Intel Corporation.\n\
";

#define SYSFS_MOUNT	"/sys"
#define SYSFS_NET	SYSFS_MOUNT "/class/net"
#define SYSFS_FCHOST	SYSFS_MOUNT "/class/fc_host"
#define SYSFS_FCOE	SYSFS_MOUNT "/module/fcoe/parameters"
#define FCOE_CREATE	SYSFS_FCOE "/create"
#define FCOE_DESTROY	SYSFS_FCOE "/destroy"

#define FCHOSTBUFLEN		64

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

static void
fcoeadm_help(void)
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
 * Open and close to check if directory exists
 */
static int
fcoeadm_checkdir(char *dir)
{
	DIR *d = NULL;

	if (!dir)
		return -EINVAL;
	/* check if we have sysfs */
	d = opendir(dir);
	if (!d)
		return -EINVAL;
	closedir(d);
	return 0;
}

/*
 * TODO - check this ifname before performing any action
 */
static int
fcoeadm_check(char *ifname)
{
	char path[256];

	/* check if we have sysfs */
	if (fcoeadm_checkdir(SYSFS_MOUNT)) {
		fprintf(stderr,
			"%s: Sysfs mount point %s not found!\n",
			progname, SYSFS_MOUNT);
		return -EINVAL;
	}
	/* check fcoe module */
	if (fcoeadm_checkdir(SYSFS_FCOE)) {
		fprintf(stderr,
			"%s: Please make sure FCoE driver module is loaded!\n",
			progname);
		return -EINVAL;
	}
	/* check target interface */
	if (!ifname) {
		fprintf(stderr, "%s: Invalid interface name!\n", progname);
		return -EINVAL;
	}
	sprintf(path, "%s/%s", SYSFS_NET, ifname);
	if (fcoeadm_checkdir(path)) {
		fprintf(stderr,
			"%s: Interface %s not found!\n", progname, ifname);
		return -EINVAL;
	}

	return 0;
}

/*
 * TODO - for now, this just writes to path
 */
static int
fcoeadm_action(char *path, char *s)
{
	FILE *fp = NULL;

	if (!path)
		return -EINVAL;

	if (!s)
		return -EINVAL;

	fp = fopen(path, "w");
	if (!fp) {
		fprintf(stderr,
			"%s: Failed to open %s\n", progname, path);
		return -ENOENT;
	}
	if (EOF == fputs(s, fp))
		fprintf(stderr,
			"%s: Failed to write %s to %s\n", progname, s, path);

	fclose(fp);

	return 0;
}

static char *
fcoeadm_read(const char *path)
{
	FILE *fp;
	char *buf;
	int size = 512;

	if (!path)
		return NULL;

	buf = malloc(size);
	if (!buf)
		return NULL;
	memset(buf, 0, size);

	fp = fopen(path, "r");
	if (fp) {
		if (fgets(buf, size, fp)) {
			fclose(fp);
			return buf;
		}
	}
	fclose(fp);
	free(buf);
	return NULL;
}

static int
fcoeadm_check_fchost(const char *ifname, const char *dname)
{
	char *buf;
	char path[512];

	if (!ifname)
		return -EINVAL;

	if (!dname)
		return -EINVAL;

	if (dname[0] == '.')
		return -EINVAL;

	sprintf(path, "%s/%s/symbolic_name", SYSFS_FCHOST, dname);
	buf = fcoeadm_read(path);
	if (!buf)
		return -EINVAL;

	if (!strstr(buf, ifname)) {
		free(buf);
		return -EINVAL;
	}
	free(buf);
	return 0;
}

static int
fcoeadm_find_fchost(char *ifname, char *fchost, int len)
{
	int n, dname_len;
	int found = 0;
	struct dirent **namelist;

	if (!ifname)
		return -EINVAL;

	if ((!fchost) || (len <= 0))
		return -EINVAL;

	memset(fchost, 0, len);
	n = scandir(SYSFS_FCHOST, &namelist, 0, alphasort);
	if (n > 0) {
		while (n--) {
			/* check symbolic name */
			if (!fcoeadm_check_fchost(ifname,
						  namelist[n]->d_name)) {
				dname_len = strnlen(namelist[n]->d_name, len);
				if (dname_len != len) {
					/*
					 * This assumes that d_name is always
					 * NULL terminated.
					 */
					strncpy(fchost, namelist[n]->d_name,
						dname_len + 1);
					found = 1;
				} else {
					fprintf(stderr, "scsi_host (%s) is "
						"too large for a buffer that "
						"is only %d bytes large\n",
						namelist[n]->d_name, dname_len);
					free(namelist[n]);
				}
			}
			free(namelist[n]);
		}
		free(namelist);
	}

	return found;
}


/*
 * Create FCoE instance for this ifname
 */
static int
fcoeadm_create(char *ifname)
{
	if (fcoeadm_check(ifname)) {
		fprintf(stderr,
			"%s: Failed to create FCoE instance on %s!\n",
			progname, ifname);
		return -EINVAL;
	}
	return fcoeadm_action(FCOE_CREATE, ifname);
}

/*
 * Remove FCoE instance for this ifname
 */
static int
fcoeadm_destroy(char *ifname)
{
	if (fcoeadm_check(ifname)) {
		fprintf(stderr,
			"%s: Failed to destroy FCoE instance on %s!\n",
			progname, ifname);
		return -EINVAL;
	}
	return fcoeadm_action(FCOE_DESTROY, ifname);
}

/*
 * Validate an existing instance for an FC interface
 */
static int
fcoeadm_validate_interface(char *ifname, char *fchost, int len)
{
	if (!fcoeadm_find_fchost(ifname, fchost, len)) {
		fprintf(stderr, "%s: No fc_host found for %s\n",
			progname, ifname);
		return -EINVAL;
	}

	return 0;
}

/*
 * Reset the fc_host that is associated w/ this ifname
 */
static int
fcoeadm_reset(char *ifname)
{
	char fchost[FCHOSTBUFLEN];
	char path[256];

	if (fcoeadm_validate_interface(ifname, fchost, FCHOSTBUFLEN))
		return -EINVAL;

	sprintf(path, "%s/%s/issue_lip", SYSFS_FCHOST, fchost);
	return fcoeadm_action(path, "1");
}

/*
 * Parse a user-entered hex field.
 * Format may be xx-xx-xx OR xxxxxx OR xx:xx:xx for len bytes (up to 8).
 * Leading zeros may be omitted.
 */
static int
parse_hex_ll(unsigned long long *hexp, const char *input, u_int len)
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

static int
parse_fcid(HBA_UINT32 *fcid, const char *input)
{
	int rc;
	unsigned long long hex;

	rc = parse_hex_ll(&hex, input, 3);
	if (rc == 0)
		*fcid = (HBA_UINT32) hex;
	return rc;
}

/*
 * Display adapter information
 */
static int fcoeadm_display_adapter_info(struct opt_info *opt_info)
{
	HBA_STATUS retval;

	retval = HBA_LoadLibrary();
	if (retval != HBA_STATUS_OK) {
		perror("HBA_LoadLibrary");
		return -EINVAL;
	}

	display_adapter_info(opt_info);

	HBA_FreeLibrary();
	return 0;
}

/*
 * Display target information
 */
static int
fcoeadm_display_target_info(struct opt_info *opt_info)
{
	HBA_STATUS retval;

	retval = HBA_LoadLibrary();
	if (retval != HBA_STATUS_OK) {
		perror("HBA_LoadLibrary");
		return -EINVAL;
	}

	display_target_info(opt_info);

	HBA_FreeLibrary();
	return 0;
}

/*
 * Display port statistics
 */
static int
fcoeadm_display_port_stats(struct opt_info *opt_info)
{
	HBA_STATUS retval;

	if (!opt_info->s_flag)
		return -EINVAL;

	if (!opt_info->n_flag)
		opt_info->n_interval = DEFAULT_STATS_INTERVAL;

	retval = HBA_LoadLibrary();
	if (retval != HBA_STATUS_OK) {
		perror("HBA_LoadLibrary");
		return -EINVAL;
	}

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
				if (fcoeadm_validate_interface(
					    opt_info->ifname,
					    fchost, FCHOSTBUFLEN))
				goto error;
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
				if (fcoeadm_validate_interface(
					    opt_info->ifname,
					    fchost, FCHOSTBUFLEN))
					goto error;
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
				if (fcoeadm_validate_interface(
					    opt_info->ifname,
					    fchost, FCHOSTBUFLEN))
					goto error;
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
	fprintf(stderr, "%s: Invalid command options!\n", progname);
	fcoeadm_help();
	exit(-EINVAL);

done:
	return rc;
}
