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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <dirent.h>
#include <net/if.h>
#include <errno.h>
#include "fcoe_clif.h"

static char *fcoeclif_read(const char *path)
{
	FILE *fp;
	char *buf;
	int size = 512;

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

static int fcoeclif_check_fchost(const char *ifname, const char *dname)
{
	char *buf;
	char path[512];

	if (dname[0] == '.')
		return -EINVAL;

	sprintf(path, "%s/%s/symbolic_name", SYSFS_FCHOST, dname);
	buf = fcoeclif_read(path);
	if (!buf)
		return -EINVAL;

	if (!strstr(buf, ifname)) {
		free(buf);
		return -EINVAL;
	}
	free(buf);
	return 0;
}

static int fcoeclif_find_fchost(char *ifname, char *fchost, int len)
{
	int n, dname_len;
	int found = 0;
	struct dirent **namelist;

	memset(fchost, 0, len);
	n = scandir(SYSFS_FCHOST, &namelist, 0, alphasort);
	if (n > 0) {
		while (n--) {
			/* check symbolic name */
			if (!fcoeclif_check_fchost(ifname,
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
 * Validate an existing instance for an FC interface
 */
int fcoeclif_validate_interface(char *ifname, char *fchost, int len)
{
	if ((!ifname) || (!fchost) || (len <= 0))
		return -EINVAL;

	if (!fcoeclif_find_fchost(ifname, fchost, len)) {
		fprintf(stderr, "No fc_host found for %s\n", ifname);
		return -EINVAL;
	}

	return 0;
}


/*
 * Open and close to check if directory exists
 */
int fcoeclif_checkdir(char *dir)
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
