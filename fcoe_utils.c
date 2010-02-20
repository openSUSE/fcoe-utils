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

#include "fcoe_utils.h"

static int fcoe_sysfs_read(char *buf, int size, const char *path)
{
	FILE *fp;
	int i, rc = -EINVAL;

	fp = fopen(path, "r");
	if (fp) {
		if (fgets(buf, size, fp)) {
			/*
			 * Strip trailing newline by replacing
			 * any '\r' or '\n' instances with '\0'.
			 * It's not as elegant as it could be, but
			 * we know that the symbolic name won't
			 * have either of those characters until
			 * the end of the line.
			 */
			for (i = 0; i < strlen(buf); i++) {
				if (buf[i] == '\n' ||
				    buf[i] == '\r') {
					buf[i] = '\0';
					break;
				}
			}
			rc = 0;
		}

		fclose(fp);
	}

	return rc;
}

static int fcoe_check_fchost(const char *ifname, const char *dname)
{
	char buf[MAX_STR_LEN];
	char path[MAX_PATH_LEN];
	int rc = -EINVAL;

	sprintf(path, "%s/%s/symbolic_name", SYSFS_FCHOST, dname);

	if (!fcoe_sysfs_read(buf, MAX_STR_LEN, path))
		rc = check_symbolic_name_for_interface(buf, ifname);

	return rc;
}

int fcoe_find_fchost(char *ifname, char *fchost, int len)
{
	int n, dname_len;
	struct dirent **namelist;
	int rc = -ENOENT;

	n = scandir(SYSFS_FCHOST, &namelist, 0, alphasort);

	for (n-- ; n >= 0 ; n--) {
		if (rc) {
			/* check symbolic name */
			if (!fcoe_check_fchost(ifname, namelist[n]->d_name)) {
				dname_len = strnlen(namelist[n]->d_name, len);

				if (len > dname_len) {
					strncpy(fchost, namelist[n]->d_name,
						dname_len + 1);
					/* rc = 0 indicates found */
					rc = 0;
				} else {
					/*
					 * The fc_host is too large
					 * for the buffer.
					 */
					rc = -ENOMEM;
				}
			}
		}
		free(namelist[n]);

	}
	free(namelist);

	return rc;
}

/*
 * Validate an existing instance for an FC interface
 */
int fcoe_validate_interface(char *ifname)
{
	char fchost[FCHOSTBUFLEN];
	return fcoe_find_fchost(ifname, fchost, FCHOSTBUFLEN);
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

char *get_ifname_from_symbolic_name(const char *symbolic_name)
{
	int symbolic_name_len = strlen(symbolic_name);
	int lead_len = strlen(SYMB_NAME_LEAD);

	if (lead_len < symbolic_name_len)
		return (char *)(symbolic_name + lead_len);

       return NULL;
}

int check_symbolic_name_for_interface(const char *symbolic_name,
				      const char *ifname)
{
	int rc = -EINVAL;
	char *symb;

	symb = get_ifname_from_symbolic_name(symbolic_name);

	/*
	 * It's important to use the length of the ifname
	 * from the symbolic_name here. If the ifname length
	 * were used then if the user passed in a substring
	 * of the the interface name it would match because
	 * we'd only be looking for the first few characters,
	 * not the whole string.
	 */
	if (symb && !strncmp(ifname, symb, strlen(symb)))
		rc = 0;

	return rc;
}

int valid_ifname(const char *ifname)
{
	if (strlen(ifname) > 0)
		return 0;
	return -EINVAL;
}
