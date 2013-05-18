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

int fcoe_sysfs_read(char *buf, int size, const char *path)
{
	FILE *fp;
	unsigned int i;
	int rc = -EINVAL;

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

enum fcoe_status fcoe_find_fchost(const char *ifname, char *fchost, int len)
{
	int n, dname_len, status;
	struct dirent **namelist;
	int rc = ENOFCOECONN;

	status = n = scandir(SYSFS_FCHOST, &namelist, 0, alphasort);

	for (n-- ; n >= 0 ; n--) {
		if (rc) {
			/* check symbolic name */
			if (!fcoe_check_fchost(ifname, namelist[n]->d_name)) {
				dname_len = strnlen(namelist[n]->d_name, len);

				if (len > dname_len) {
					strncpy(fchost, namelist[n]->d_name,
						dname_len + 1);
					/* rc = 0 indicates found */
					rc = SUCCESS;
				} else {
					/*
					 * The fc_host is too large
					 * for the buffer.
					 */
					rc = EINTERR;
				}
			}
		}
		free(namelist[n]);
	}
	if (status >= 0)
		free(namelist);

	return rc;
}

enum fcoe_status fcoe_validate_interface(char *ifname)
{
	enum fcoe_status rc = SUCCESS;
	char path[MAX_PATH_LEN];


	if (!strlen(ifname))
		rc = ENOETHDEV;

	/*
	 * TODO: Is there a better way to check if the
	 * interface name is correct?
	 */
	sprintf(path, "%s/%s", SYSFS_NET, ifname);
	if (!rc && fcoe_checkdir(path))
		rc = ENOETHDEV;

	return rc;
}

/*
 * Validate an existing instance for an FC interface
 */
enum fcoe_status fcoe_validate_fcoe_conn(char *ifname)
{
	char fchost[FCHOSTBUFLEN];
	enum fcoe_status rc = SUCCESS;

	rc = fcoe_validate_interface(ifname);

	if (!rc)
		rc = fcoe_find_fchost(ifname, fchost, FCHOSTBUFLEN);

	return rc;
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

/*
 * Parse the interface name from the symbolic name string.
 * Assumption: Symbolic name is of the type "<DRIVER> <VERSION> over <IFACE>"
 *             Specifically there is a space before the <IFACE>
 */
char *get_ifname_from_symbolic_name(const char *symbolic_name)
{
	char *last_space = strrchr(symbolic_name, ' ');

	if (!last_space || strlen(last_space) == 1)
		return NULL;

	return (char *)(last_space + 1);
}

int check_symbolic_name_for_interface(const char *symbolic_name,
				      const char *ifname)
{
	int rc = -EINVAL;
	char *symb;

	if (!ifname)
		return rc;

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

enum fcoe_status fcm_write_str_to_sysfs_file(const char *path, const char *str)
{
	FILE *fp = NULL;
	enum fcoe_status ret = EFAIL;

	fp = fopen(path, "w");
	if (!fp)
		goto err_out;

	if (EOF == fputs(str, fp))
		goto out;

	ret = SUCCESS;
out:
	fclose(fp);
err_out:
	return ret;
}

static int fchost_filter(const struct dirent *dent)
{
	return !strncmp(dent->d_name, "host", 4);
}

static int fcoe_check_ctlr(const char *fchost, const char *dname)
{
	int n, status;
	struct dirent **namelist;
	char path[MAX_PATH_LEN];
	int rc = -EINVAL;

	sprintf(path, "%s/%s", SYSFS_FCOE_BUS_DEVICES, dname);
	status = n = scandir(path, &namelist, fchost_filter, alphasort);
	for (n-- ; n >= 0 ; n--) {
		if (rc) {
			if (!strncmp(namelist[n]->d_name, fchost, 20))
				rc = SUCCESS;
			else
				rc = EINTERR;
		}
		free(namelist[n]);
	}
	if (status >= 0)
		free(namelist);

	return rc;
}

static int ctlr_filter(const struct dirent *dent)
{
	return !strncmp(dent->d_name, "ctlr_", 5);
}

enum fcoe_status fcoe_find_ctlr(const char *fchost, char *ctlr, int len)
{
	int n, dname_len, status;
	struct dirent **namelist;
	int rc = ENOFCOECONN;

	status = n = scandir(SYSFS_FCOE_BUS_DEVICES, &namelist,
			     ctlr_filter, alphasort);
	for (n-- ; n >= 0 ; n--) {
		if (rc) {
			/* check ctlr against known host */
			if (!fcoe_check_ctlr(fchost,
					     namelist[n]->d_name)) {

				dname_len = strnlen(namelist[n]->d_name, len);

				if (len > dname_len) {
					strncpy(ctlr, namelist[n]->d_name,
						dname_len + 1);
					/* rc = 0 indicates found */
					rc = SUCCESS;
				} else {
					/*
					 * The fc_host is too large
					 * for the buffer.
					 */
					rc = EINTERR;
				}
			}
		}
		free(namelist[n]);
	}
	if (status >= 0)
		free(namelist);

	return rc;
}

enum fcoe_status fcm_write_str_to_ctlr_attr(const char *ctlr,
					    const char *attr,
					    const char *str)
{
	char path[MAX_PATH_LEN];

	sprintf(path, "%s/%s/%s", SYSFS_FCOE_BUS_DEVICES, ctlr, attr);
	return fcm_write_str_to_sysfs_file(path, str);
}
