/*
 * Copyright(c) 2012-2013 Intel Corporation. All rights reserved.
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

#include "libopenfcoe.h"

#define SYSFS_HOST_DIR	   "/sys/class/fc_host"
#define SYSFS_HBA_DIR	   "/sys/class/net"

int mac2str(const u_int8_t *mac, char *dst, size_t size)
{
	if (dst && size > MAC_ADDR_STRLEN) {
		snprintf(dst, size, "%02X:%02X:%02X:%02X:%02X:%02X",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		return 0;
	}
	return -1;
}

int str2mac(const char *src, u_int8_t *mac, size_t size)
{
	int i = 0;
	int rc = -1;

	if (size < 6)
		goto out_err;

	if (!src)
		goto out_err;

	if (strlen(src) != MAC_ADDR_STRLEN)
		goto out_err;

	memset(mac, 0, size);
	for (i = 0; i < 6; i++, mac++)
		if (1 != sscanf(&src[i * 3], "%02hhX", mac))
			goto out_err;
	rc = 0;
out_err:
	return rc;
}

static char *safe_makepath(char *path, size_t path_sz,
		char *dname, char *fname)
{
	size_t dsz = sizeof(dname);
	size_t fsz = strlen(fname);
	char *cp = path;

	if ((dsz + fsz + 2) > path_sz) {
		fprintf(stderr,
			"error: no room to expand pathname (%d+%d > %d)\n",
			(int)dsz, (int)fsz, (int)path_sz);
		return NULL;
	}

	memcpy(cp, dname, dsz);
	cp += dsz;

	*cp++ = '/';

	memcpy(cp, fname, fsz);
	cp += fsz;

	*cp = '\0';

	return path;
}

static int add_fcoe_fcf_device(struct dirent *dp, void *arg)
{
	struct fcoe_ctlr_device *ctlr = (struct fcoe_ctlr_device *)arg;
	struct fcoe_fcf_device *fcf;

	if (!strstr(dp->d_name, "fcf") ||
	    (!strcmp(dp->d_name, "fcf_dev_loss_tmo")))
		return 0;

	fcf = malloc(sizeof(struct fcoe_fcf_device));
	if (!fcf)
		return -ENOMEM;

	memset(fcf, 0, sizeof(struct fcoe_fcf_device));

	/* Save the path */
	if (safe_makepath(fcf->path, sizeof(fcf->path),
				ctlr->path, dp->d_name) == NULL)
		goto fail;

	/* Use the index from the logical enumeration */
	fcf->index = atoi(dp->d_name + sizeof("fcf_") - 1);

	/* Save the fcf in the fcport's table */
	if (sa_table_insert(&ctlr->fcfs, fcf->index,
			    fcf) < 0) {
		fprintf(stderr, "%s: insert of fcf %d failed\n",
			__func__, fcf->index);
		goto fail;
	}

	return 0;

fail:
	free(fcf);
	return -ENOENT;
}

static void read_fcoe_fcf_device(void *ep, UNUSED void *arg)
{
	struct fcoe_fcf_device *fcf = (struct fcoe_fcf_device *)ep;
	char buf[MAX_STR_LEN];

	sa_sys_read_line(fcf->path, "state", buf, sizeof(buf));
	sa_enum_encode(fcf_state_table, buf, &fcf->state);
	sa_sys_read_u32(fcf->path, "dev_loss_tmo", &fcf->dev_loss_tmo);
	sa_sys_read_u64(fcf->path, "fabric_name", &fcf->fabric_name);
	sa_sys_read_u64(fcf->path, "switch_name", &fcf->switch_name);
	sa_sys_read_u32(fcf->path, "fc_map", &fcf->fc_map);
	sa_sys_read_u32(fcf->path, "vfid", &fcf->vfid);

	sa_sys_read_line(fcf->path, "mac", buf, MAX_STR_LEN);
	str2mac(buf, &fcf->mac[0], MAC_ADDR_LEN);

	sa_sys_read_u32(fcf->path, "priority", &fcf->priority);
	sa_sys_read_u32(fcf->path, "fka_period", &fcf->fka_period);
	sa_sys_read_u32(fcf->path, "selected", &fcf->selected);
	sa_sys_read_u32(fcf->path, "vlan_id", &fcf->vlan_id);
}

static void read_fcoe_fcf(void *ep, UNUSED void *arg)
{
	struct fcoe_ctlr_device *ctlr = (struct fcoe_ctlr_device *)ep;

	/* Iterate through the ctlr and add any fcfs */
	sa_dir_read(ctlr->path, add_fcoe_fcf_device, ctlr);

	/* Populate each fabric */
	sa_table_iterate(&ctlr->fcfs, read_fcoe_fcf_device, NULL);
}

static void free_fcoe_fcf_device(void *ep, UNUSED void *arg)
{
	struct fcoe_fcf_device *fcf = (struct fcoe_fcf_device *)ep;

	free(fcf);
}

#define SYSFS_MOUNT "/sys"
#define FCOE_CTLR_DEVICE_DIR SYSFS_MOUNT "/bus/fcoe/devices/"

static int find_fchost(struct dirent *dp, void *arg)
{
	char *fchost = arg;

	if (strstr(dp->d_name, "host")) {
		strncpy(fchost, dp->d_name, MAX_STR_LEN);
		return 1;
	}

	return 0;
}

static int read_fcoe_ctlr_device(struct dirent *dp, void *arg)
{
	struct sa_table *ctlrs = arg;
	struct fcoe_ctlr_device *ctlr;
	char buf[MAX_STR_LEN];
	char lesb_path[MAX_STR_LEN];
	char hpath[MAX_STR_LEN];
	char fchost[MAX_STR_LEN];
	char *cp, *ifname;
	int rc;

	if (strncmp(dp->d_name, "ctlr_", 5))
		return 0;

	ctlr = malloc(sizeof(struct fcoe_ctlr_device));
	if (!ctlr)
		return 0; /* Must return 0 or loop will break */

	memset(ctlr, 0, sizeof(struct fcoe_ctlr_device));
	sa_table_init(&ctlr->fcfs);

	/* Save the path */
	snprintf(ctlr->path, sizeof(ctlr->path),
		 FCOE_CTLR_DEVICE_DIR "%s", dp->d_name);

	/* Use the index from the logical enumeration */
	ctlr->index = atoi(dp->d_name + sizeof("ctlr_") - 1);

	rc = sa_dir_read(ctlr->path, find_fchost, fchost);
	if (!rc)
		goto fail;

	sprintf(hpath, "%s/%s/", SYSFS_FCHOST, fchost);

	rc = sa_sys_read_line(hpath, "symbolic_name", buf, sizeof(buf));

	/* Skip the HBA if it isn't Open-FCoE */
	cp = strstr(buf, " over ");
	if (!cp)
		goto fail;

	ifname = get_ifname_from_symbolic_name(buf);
	strncpy(ctlr->ifname, ifname, IFNAMSIZ-1);

	/* Get fcf device loss timeout */
	sa_sys_read_u32(ctlr->path, "fcf_dev_loss_tmo",
			&ctlr->fcf_dev_loss_tmo);

	sa_sys_read_line(ctlr->path, "mode", buf, sizeof(buf));
	sa_enum_encode(fip_conn_type_table, buf, &ctlr->mode);

	if (safe_makepath(lesb_path, sizeof(lesb_path),
				ctlr->path, "lesb") == NULL)
		goto fail;

	/* Get LESB statistics */
	sa_sys_read_u32(lesb_path, "link_fail",
			&ctlr->lesb_link_fail);
	sa_sys_read_u32(lesb_path, "vlink_fail",
			&ctlr->lesb_vlink_fail);
	sa_sys_read_u32(lesb_path, "miss_fka",
			&ctlr->lesb_miss_fka);
	sa_sys_read_u32(lesb_path, "symb_err",
			&ctlr->lesb_symb_err);
	sa_sys_read_u32(lesb_path, "err_block",
			&ctlr->lesb_err_block);
	sa_sys_read_u32(lesb_path, "fcs_error",
			&ctlr->lesb_fcs_error);

	/* Save the ctlr in the supplied table */
	if (sa_table_insert(ctlrs, ctlr->index, ctlr) < 0) {
		fprintf(stderr, "%s: insert of ctlr %d failed\n",
			__func__, ctlr->index);
		goto fail;
	}

	return 0;

fail:
	free(ctlr);
	return -ENOENT;
}

void read_fcoe_ctlr(struct sa_table *ctlrs)
{
	sa_dir_read(FCOE_CTLR_DEVICE_DIR, read_fcoe_ctlr_device, ctlrs);
	sa_table_iterate(ctlrs, read_fcoe_fcf, NULL);
}

void free_fcoe_ctlr_device(void *ep, UNUSED void *arg)
{
	struct fcoe_ctlr_device *ctlr = (struct fcoe_ctlr_device *)ep;

	sa_table_iterate(&ctlr->fcfs, free_fcoe_fcf_device, NULL);

	free(ctlr);
}
