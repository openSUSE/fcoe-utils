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

#include "fcoe_utils.h"

static int fcoe_sysfs_read(char *buf, int size, const char *path)
{
	FILE *fp;
	int rc = 0;

	fp = fopen(path, "r");
	if (fp) {
		if (!fgets(buf, size, fp))
			rc = -EINVAL;
	}

	fclose(fp);

	return rc;
}

static int fcoe_check_fchost(const char *ifname, const char *dname)
{
	char buf[MAX_STR_LEN];
	char path[MAX_PATH_LEN];
	char *substr;
	int rc = -EINVAL;

	sprintf(path, "%s/%s/symbolic_name", SYSFS_FCHOST, dname);

	if (!fcoe_sysfs_read(buf, MAX_STR_LEN, path)) {
		substr = strstr(buf, ifname);
		if (substr && strlen(substr) == strlen(ifname))
			rc = 0;
	}

	return rc;
}

static int fcoe_find_fchost(char *ifname, char *fchost, int len)
{
	int n, dname_len;
	int found = 0;
	struct dirent **namelist;

	memset(fchost, 0, len);
	n = scandir(SYSFS_FCHOST, &namelist, 0, alphasort);
	if (n > 0) {
		while (n--) {
			/* check symbolic name */
			if (!fcoe_check_fchost(ifname, namelist[n]->d_name)) {
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
int fcoe_validate_interface(char *ifname, char *fchost, int len)
{
	return fcoe_find_fchost(ifname, fchost, len);
}

/*
 * Open and close to check if directory exists
 */
int fcoe_checkdir(char *dir)
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
