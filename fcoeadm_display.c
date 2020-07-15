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

#define _GNU_SOURCE

#include <sys/param.h>
#include <linux/types.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <limits.h>
#include <unistd.h>
#include <inttypes.h>
#include <dirent.h>

#include "net_types.h"
#include "fc_types.h"
#include "fc_scsi.h"
#include "fcoeadm_display.h"
#include "fcoe_utils.h"
#include "fcoemon_utils.h"
#include "libopenfcoe.h"
#include "sysfs_hba.h"

/* Define FC4 Type */
#define FC_TYPE_FCP        0x08 /* SCSI FCP */

/* Constant defined in fcoe_def.h of fcoe driver */
#define FCOE_WORD_TO_BYTE  4

/* Minimum byte size of the received inquiry data */
#define MIN_INQ_DATA_SIZE       36

#define FCP_TARG_STR "FCP Target"

#define SYSFS_HOST_DIR     "/sys/class/fc_host"

/*
 * Options for displaying target/LUN info.
 */
struct target_info_arguments {
	char *ifname;
	enum disp_style style;
};

struct sa_nameval port_states[] = {
	{ "Not Present",    HBA_PORTSTATE_UNKNOWN },
	{ "Online",         HBA_PORTSTATE_ONLINE },
	{ "Offline",        HBA_PORTSTATE_OFFLINE },
	{ "Blocked",        HBA_PORTSTATE_UNKNOWN },
	{ "Bypassed",       HBA_PORTSTATE_BYPASSED },
	{ "Diagnostics",    HBA_PORTSTATE_DIAGNOSTICS },
	{ "Linkdown",       HBA_PORTSTATE_LINKDOWN },
	{ "Error",          HBA_PORTSTATE_ERROR },
	{ "Loopback",       HBA_PORTSTATE_LOOPBACK },
	{ "Deleted",        HBA_PORTSTATE_UNKNOWN },
	{ NULL, 0 }
};


/*
 * table of /sys port speed strings to HBA-API values.
 */
struct sa_nameval port_speeds[] = {
	{ "Unknown",        HBA_PORTSPEED_UNKNOWN },
	{ "1 Gbit",         HBA_PORTSPEED_1GBIT },
	{ "2 Gbit",         HBA_PORTSPEED_2GBIT },
	{ "4 Gbit",         HBA_PORTSPEED_4GBIT },
	{ "10 Gbit",        HBA_PORTSPEED_10GBIT },
	{ "8 Gbit",         HBA_PORTSPEED_8GBIT },
	{ "16 Gbit",        HBA_PORTSPEED_16GBIT },
	{ "32 Gbit",        HBA_PORTSPEED_32GBIT },
	{ "20 Gbit",        HBA_PORTSPEED_20GBIT },
	{ "40 Gbit",        HBA_PORTSPEED_40GBIT },
	{ "Not Negotiated", HBA_PORTSPEED_NOT_NEGOTIATED },
	{ NULL, 0 }
};

static int is_fcp_target(struct port_attributes *rp_info)
{
	if (!strncmp(rp_info->roles, FCP_TARG_STR, strlen(FCP_TARG_STR)))
		return 0;

	return -EINVAL;
}

static void show_hba_info(struct hba_info *hba_info)
{
	printf("    Description:      %s\n", hba_info->model_description);
	printf("    Revision:         %s\n", hba_info->hardware_version);
	printf("    Manufacturer:     %s\n", hba_info->manufacturer);
	printf("    Serial Number:    %s\n", hba_info->serial_number);
	printf("    Driver:           %s %s\n", hba_info->driver_name,
	       hba_info->driver_version);
	printf("    Number of Ports:  %d\n", hba_info->nports);
	printf("\n");
}

static void show_port_info(struct port_attributes *lp_info)
{
	printf("        Symbolic Name:     %s\n",
	       lp_info->symbolic_name);

	printf("        OS Device Name:    %s\n",
	       lp_info->device_name);

	printf("        Node Name:         %s\n",
		lp_info->node_name);

	printf("        Port Name:         %s\n",
		lp_info->port_name);

	printf("        Fabric Name:        %s\n",
		lp_info->fabric_name);

	printf("        Speed:             %s\n",
		lp_info->speed);

	printf("        Supported Speed:   %s\n",
		lp_info->supported_speeds);

	printf("        MaxFrameSize:      %s\n",
	       lp_info->maxframe_size);

	printf("        FC-ID (Port ID):   %s\n",
	       lp_info->port_id);

	printf("        State:             %s\n",
		lp_info->port_state);
	/* TODO: Display PortSupportedFc4Types and PortActiveFc4Types */
}

static void show_target_info(const char *symbolic_name,
			     struct port_attributes *rp_info)
{
	char *ifname;

	ifname = get_ifname_from_symbolic_name(symbolic_name);

	printf("    Interface:        %s\n", ifname);
	printf("    Roles:            %s\n", rp_info->roles);
	printf("    Node Name:        %s\n", rp_info->node_name);
	printf("    Port Name:        %s\n", rp_info->port_name);
	printf("    Target ID:        %s\n", rp_info->scsi_target_id);
	printf("    MaxFrameSize:     %s\n", rp_info->maxframe_size);
	printf("    OS Device Name:   %s\n", rp_info->device_name);
	printf("    FC-ID (Port ID):  %s\n", rp_info->port_id);
	printf("    State:            %s\n", rp_info->port_state);
	printf("\n");
}

static void
show_short_lun_info_header(void)
{
	printf("    LUN ID  Device Name   Capacity   "
	       "Block Size  Description\n");
	printf("    ------  -----------  ----------  ----------  "
	       "----------------------------\n");
}

static void sa_dir_crawl(char *dir_name,
			 void (*func)(char *dirname, enum disp_style style),
			 enum disp_style style)
{
	DIR *dir;
	struct dirent *dp;
	void (*f)(char *dirname, enum disp_style style);
	char path[1024];

	f = func;

	dir = opendir(dir_name);
	if (!dir)
		return;

	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.' && (dp->d_name[1] == '\0' ||
		   (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir_name, dp->d_name);

		f(path, style);
	}
	closedir(dir);
}

static char *format_capstr(uint64_t size, unsigned int blksize)
{
	double cap_abbr;
	char *capstr;
	uint64_t cap;
	char *abbr;
	int ret;

	cap = size * blksize;

	cap_abbr = cap / (1024.0 * 1024.0);
	abbr = "MiB";
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "GiB";
	}
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "TiB";
	}
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "PiB";
	}

	ret = asprintf(&capstr, "%0.2f %s", cap_abbr, abbr);
	if (ret == -1)
		return "Unknown";

	return capstr;
}

static void show_full_lun_info(unsigned int hba, unsigned int port,
				unsigned int tgt, unsigned int lun)
{
	char vendor[256];
	char model[256];
	char rev[256];
	char *osname;
	char *capstr;
	uint64_t lba = 0;
	uint32_t blksize = 0;
	char path[1024];
	char npath[1024];
	DIR *dir;
	struct dirent *dp;
	struct port_attributes *rport_attrs;
	struct port_attributes *port_attrs;

	snprintf(path, sizeof(path),
		"/sys/class/scsi_device/%u:%u:%u:%u",
		hba, port, tgt, lun);

	rport_attrs = get_rport_attribs_by_device(path);
	if (!rport_attrs)
		return;

	port_attrs = get_port_attribs_by_device(path);
	if (!port_attrs)
		goto free_rport;

	strncat(path, "/device/", sizeof(path) - strlen(path) - 1);

	sa_sys_read_line(path, "rev", rev, sizeof(rev));
	sa_sys_read_line(path, "model", model, sizeof(model));
	sa_sys_read_line(path, "vendor", vendor, sizeof(vendor));

	strncat(path, "block", sizeof(path) - strlen(path) - 1);

	dir = opendir(path);
	if (!dir)
		goto free_port;

	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.' && (dp->d_name[1] == '\0' ||
		   (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
			continue;


		osname = dp->d_name;

		snprintf(npath, sizeof(npath), "%s/%s/", path, osname);
		sa_sys_read_u64(npath, "size", &lba);

		snprintf(npath, sizeof(npath), "%s/%s/queue/", path, osname);
		sa_sys_read_u32(npath, "hw_sector_size", &blksize);
	}

	closedir(dir);

	/* Show lun info */
	printf("    LUN #%d Information:\n", lun);
	printf("        OS Device Name:     %s\n",
	       osname);
	printf("        Description:        %s %s (rev %s)\n",
	       vendor, model, rev);
	printf("        Ethernet Port FCID: %s\n",
	       port_attrs->port_id);
	printf("        Target FCID:        %s\n",
		rport_attrs->port_id);
	if (tgt == 0xFFFFFFFFU)
		printf("        Target ID:          (None)\n");
	else
		printf("        Target ID:          %u\n", tgt);
	printf("        LUN ID:             %d\n", lun);

	capstr = format_capstr(lba, blksize);
	printf("        Capacity:           %s\n", capstr);
	printf("        Capacity in Blocks: %" PRIu64 "\n", lba);
	printf("        Block Size:         %" PRIu32 " bytes\n", blksize);
	printf("        Status:             Attached\n");

	printf("\n");

free_rport:
	free(rport_attrs);
free_port:
	free(port_attrs);
}

static void show_short_lun_info(unsigned int hba, unsigned int port,
				unsigned int tgt, unsigned int lun)
{
	struct dirent *dp;
	char vendor[256];
	char path[1024];
	char npath[1024];
	char model[256];
	char rev[256];
	DIR *dir;
	uint32_t blksize = 0;
	char *capstr = "Unknown";
	char *osname = "Unknown";
	uint64_t size;

	snprintf(path, sizeof(path),
		"/sys/class/scsi_device/%u:%u:%u:%u/device/",
		hba, port, tgt, lun);

	sa_sys_read_line(path, "rev", rev, sizeof(rev));
	sa_sys_read_line(path, "model", model, sizeof(model));
	sa_sys_read_line(path, "vendor", vendor, sizeof(vendor));

	strncat(path, "block", sizeof(path) - strlen(path) - 1);

	dir = opendir(path);
	if (!dir)
		return;

	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.' && (dp->d_name[1] == '\0' ||
		   (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
			continue;


		osname = dp->d_name;

		snprintf(npath, sizeof(npath), "%s/%s/", path, osname);
		sa_sys_read_u64(npath, "size", &size);

		snprintf(npath, sizeof(npath), "%s/%s/queue/", path, osname);
		sa_sys_read_u32(npath, "hw_sector_size", &blksize);
	}

	closedir(dir);

	capstr = format_capstr(size, blksize);

	/* Show the LUN info */
	printf("%10d  %-11s  %10s  %7d     %s %s (rev %s)\n",
	       lun, osname,
	       capstr, blksize,
	       vendor, model, rev);

	free(capstr);
	return;
}

static void list_scsi_device(char *d_name, enum disp_style style)
{
	unsigned int port;
	unsigned int hba;
	unsigned int tgt;
	unsigned int lun;
	char *last;

	last = strrchr(d_name, '/');

	if (sscanf(last, "/%u:%u:%u:%u", &hba, &port, &tgt, &lun) != 4)
		return;


	if (style == DISP_TARG)
		show_short_lun_info(hba, port, tgt, lun);
	else
		show_full_lun_info(hba, port, tgt, lun);
}

static void search_rport_targets(char *d_name, enum disp_style style)
{
	if (!strstr(d_name, "target"))
		return;

	sa_dir_crawl(d_name, list_scsi_device, style);
}

static void list_luns_by_rport(char *rport, enum disp_style style)
{
	char path[1024];
	char link[1024];
	char *substr;
	int len;
	int ret;

	snprintf(path, sizeof(path), "/sys/class/fc_remote_ports/%s", rport);

	ret = readlink(path, link, sizeof(link));
	if (ret == -1)
		return;

	if (link[ret] != '\0')
		link[ret] = '\0';

	substr = strstr(link, "net");
	snprintf(path, sizeof(path), "/sys/class/%s", substr);

	substr = strstr(path, "fc_remote_ports");

	len = strlen(path) - strlen(substr);
	path[len] = '\0';

	sa_dir_crawl(path, search_rport_targets, style);
}

static void scan_device_map(char *rport, enum disp_style style)
{
	if (style == DISP_TARG)
		show_short_lun_info_header();

	list_luns_by_rport(rport, style);

	/* Newline at the end of the short lun report */
	if (style == DISP_TARG)
		printf("\n");
}

static void show_port_stats_header(const char *ifname, int interval)
{
	printf("\n");
	printf("%-15s interval: %-2d                            Err  Inv  "
	       "IvTx Link Cntl Input     Input     Output    Output\n",
	       ifname, interval);
	printf("Seconds TxFrames  TxBytes      RxFrames  RxBytes        "
	       "Frms CRC  Byte Fail Reqs Requests  MBytes    "
	       "Requests  MBytes\n");
	printf("------- --------- ------------ --------- -------------- "
	       "---- ---- ---- ---- ---- --------- --------- "
	       "--------- ---------\n");
}

static void
show_port_stats_in_row(uint64_t start_time,
		       struct port_statistics *port_stats)

{
	printf("%-7"PRIu64" ",
		port_stats->seconds_since_last_reset - start_time);
	printf("%-9"PRIu64" ", port_stats->tx_frames);
	printf("%-12"PRIu64" ", port_stats->tx_words * FCOE_WORD_TO_BYTE);
	printf("%-9"PRIu64" ", port_stats->rx_frames);
	printf("%-14"PRIu64" ", port_stats->rx_words * FCOE_WORD_TO_BYTE);
	printf("%-4"PRIu64" ", port_stats->error_frames);
	printf("%-4"PRIu64" ", port_stats->invalid_crc_count);
	printf("%-4"PRIu64" ",
		port_stats->invalid_tx_word_count * FCOE_WORD_TO_BYTE);
	printf("%-4"PRIu64" ", port_stats->link_failure_count);
	printf("%-4"PRIu64" ", port_stats->fcp_control_requests);
	printf("%-9"PRIu64" ", port_stats->fcp_input_requests);
	printf("%-9"PRIu64" ", port_stats->fcp_input_megabytes);
	printf("%-9"PRIu64" ", port_stats->fcp_output_requests);
	printf("%-9"PRIu64" ", port_stats->fcp_output_megabytes);
	printf("\n");
}

enum fcoe_status display_port_stats(const char *ifname, int interval)
{
	struct port_statistics *port_stats;
	enum fcoe_status rc = EINTERR;
	uint64_t start_time = 0;
	char *host;
	int i, num_hbas;

	num_hbas = get_number_of_adapters();
	if (num_hbas < 0)
		return rc;

	host = get_host_from_netdev(ifname);
	if (!host)
		return rc;

	i = 0;
	while (1) {
		unsigned int secs_left;

		port_stats = get_port_statistics(host);
		if (!port_stats)
			goto free_host;


		if (!start_time)
			start_time = port_stats->seconds_since_last_reset;

		if (!(i % 52))
			show_port_stats_header(ifname, interval);

		show_port_stats_in_row(start_time, port_stats);
		i++;

		/* wait for the requested time interval in seconds */
		secs_left = interval;
		do {
			secs_left = sleep(secs_left);
		} while (secs_left);
	}

	rc = SUCCESS;
	free(port_stats);

free_host:
	free(host);

	return rc;
}

static int get_host_from_vport(struct dirent *dp,
			void *arg __attribute__ ((unused)))
{
	if (!strncmp(dp->d_name, "host", strlen("host"))) {
		struct port_attributes *port_attrs;

		port_attrs = get_port_attribs(dp->d_name);
		if (!port_attrs)
			return 0;
		printf("\n");
		show_port_info(port_attrs);
		free(port_attrs);
	}

	return 0;
}

static int crawl_vports(struct dirent *dp, void *arg)
{
	char *oldpath = arg;

	if (!strncmp(dp->d_name, "vport", strlen("vport"))) {
		char path[1024];

		snprintf(path, sizeof(path), "%s/%s", oldpath, dp->d_name);
		sa_dir_read(path, get_host_from_vport, NULL);
	}
	return 0;
}

static void show_host_vports(const char *host)
{
	char path[1024];

	snprintf(path, sizeof(path), "%s/%s/device/", SYSFS_HOST_DIR, host);
	sa_dir_read(path, crawl_vports, path);

}

static enum fcoe_status display_one_adapter_info(char *ifname)
{
	struct port_attributes *port_attrs;
	struct hba_info *hba_info;
	enum fcoe_status rc = EINTERR;
	char *pcidev;
	char *host;

	pcidev = get_pci_dev_from_netdev(ifname);
	if (!pcidev)
		return rc;

	host = get_host_from_netdev(ifname);
	if (!host)
		goto free_pcidev;

	hba_info = get_hbainfo_by_pcidev(pcidev);
	if (!hba_info)
		goto free_host;

	port_attrs = get_port_attribs(host);
	if (!port_attrs)
		goto free_hba_info;

	/*
	 * Display the adapter header.
	 */
	show_hba_info(hba_info);
	show_port_info(port_attrs);
	show_host_vports(host);

	rc = SUCCESS;

	free(port_attrs);
free_hba_info:
	free(hba_info);
free_host:
	free(host);
free_pcidev:
	free(pcidev);
	return rc;
}

static int search_fc_adapter(struct dirent *dp,
			void *arg __attribute__ ((unused)))
{
	display_one_adapter_info(dp->d_name);
	return 0;
}

enum fcoe_status display_adapter_info(char *ifname)
{
	enum fcoe_status rc = SUCCESS;
	int num_hbas;
	int err;

	if (ifname)
		return display_one_adapter_info(ifname);

	num_hbas = get_number_of_adapters();
	if (!num_hbas)
		return ENOACTION;

	err = sa_dir_read("/sys/class/net/", search_fc_adapter, NULL);
	if (err)
		return EINTERR;

	return rc;
}


static char *get_ifname_from_rport(char *rport)
{
	char link[1024];
	char ifname[32];
	ssize_t ret;
	char *path;
	char *offs;
	int err;
	int i = 0;

	err = asprintf(&path, "%s/%s", "/sys/class/fc_remote_ports", rport);
	if (err == -1)
		return NULL;

	ret = readlink(path, link, sizeof(link));
	free(path);
	if (ret == -1)
		return NULL;

	if (link[ret] != '\0')
		link[ret] = '\0';

	offs = strstr(link, "/net/");
	if (!offs)
		return NULL;

	offs = offs + 5;

	for (i = 0; offs[i] != '\0'; i++)
		if (offs[i] == '/')
			break;

	strncpy(ifname, offs, i);
	if (ifname[i] != '\0')
		ifname[i] = '\0';

	return strdup(ifname);
}

static enum fcoe_status display_one_target_info(char *ifname, char *rport,
						enum disp_style style)
{
	struct port_attributes *rport_attrs;
	struct port_attributes *port_attrs;
	enum fcoe_status rc = SUCCESS;
	char *host;

	rport_attrs = get_rport_attribs(rport);
	if (!rport_attrs)
		return EINTERR;

	/*
	 * Skip any targets that are not FCP targets
	 */
	if (is_fcp_target(rport_attrs))
		goto free_rport_attribs;

	rc = EINTERR;
	host = get_host_from_netdev(ifname);
	if (!host)
		goto free_rport_attribs;

	port_attrs = get_port_attribs(host);
	if (!port_attrs)
		goto free_host;

	show_target_info(port_attrs->symbolic_name,
		rport_attrs);

	if (strncmp(port_attrs->port_state, "Online", 6))
		goto free_port_attribs;

	/*
	 * This will print the LUN table
	 * under the target.
	 */
	scan_device_map(rport, style);

free_port_attribs:
	free(port_attrs);
free_host:
	free(host);
free_rport_attribs:
	free(rport_attrs);

	return rc;
}

static bool rport_is_child(const char *rport, const char *ifname)
{

	char link[1024];
	ssize_t ret;
	char *path;
	char *offs;
	int err;

	err = asprintf(&path, "%s/%s", "/sys/class/fc_remote_ports", rport);
	if (err == -1)
		return false;

	ret = readlink(path, link, sizeof(link));
	free(path);
	if (ret == -1)
		return false;

	offs = strstr(link, ifname);

	return offs ? true : false;
}

static int search_rports(struct dirent *dp, void *arg)
{
	struct target_info_arguments *ta;
	bool allocated = false; /* ifname is malloc()ed? */
	char *ifname;
	char *rport;


	ta = arg;
	rport = dp->d_name;
	ifname = ta->ifname;

	if (ifname) {
		bool child;

		child = rport_is_child(rport, ifname);
		if (!child)
			return 0;
	} else {
		ifname = get_ifname_from_rport(rport);
		if (!ifname)
			return 0;
		allocated = true;
	}

	display_one_target_info(ifname, rport, ta->style);

	if (allocated)
		free(ifname);

	return 0;
}

enum fcoe_status display_target_info(char *ifname,
				     enum disp_style style)
{
	struct target_info_arguments args;

	args.ifname = ifname;
	args.style = style;

	sa_dir_read("/sys/class/fc_remote_ports/", search_rports, (void *) &args);

	return SUCCESS;

}

static struct sa_table fcoe_ctlr_table;

static void print_fcoe_fcf_device(void *ep, UNUSED void *arg)
{
	struct fcoe_fcf_device *fcf = (struct fcoe_fcf_device *)ep;
	char temp[MAX_STR_LEN];
	char mac[MAX_STR_LEN];
	int len = sizeof(temp);
	const char *buf;

	printf("\n");
	printf("    FCF #%u Information\n", fcf->index);
	buf = sa_enum_decode(temp, len, fcf_state_table, fcf->state);
	if (!buf)
		buf = temp;
	printf("        Connection Mode:  %s\n", buf);
	printf("        Fabric Name:      0x%016" PRIx64 "\n", fcf->fabric_name);
	printf("        Switch Name       0x%016" PRIx64 "\n", fcf->switch_name);
	mac2str(fcf->mac, mac, MAX_STR_LEN);
	printf("        MAC Address:      %s\n", mac);
	printf("        FCF Priority:     %u\n", fcf->priority);
	printf("        FKA Period:       %u seconds\n", fcf->fka_period);
	printf("        Selected:         ");
	(fcf->selected == 1) ? printf("Yes\n") : printf("No\n");
	printf("        VLAN ID:          %u\n", fcf->vlan_id);
	printf("\n");
}

static void print_interface_fcoe_fcf_device(void *ep, void *arg)
{
	struct fcoe_ctlr_device *ctlr = (struct fcoe_ctlr_device *)ep;
	const char *ifname = arg;
	const char *buf;
	char temp[MAX_STR_LEN];
	int len = sizeof(temp);

	if (!ifname || !strncmp(ifname, ctlr->ifname, IFNAMSIZ)) {
		printf("    Interface:        %s\n", ctlr->ifname);
		buf = sa_enum_decode(temp, len, fip_conn_type_table,
				     ctlr->mode);
		if (!buf)
			buf = temp;
		printf("    Connection Type:  %s\n", buf);

		sa_table_iterate(&ctlr->fcfs, print_fcoe_fcf_device, NULL);
	}
}

/*
 * NULL ifname indicates to dispaly all fcfs
 */
enum fcoe_status display_fcf_info(const char *ifname)
{
	enum fcoe_status rc = SUCCESS;

	sa_table_init(&fcoe_ctlr_table);
	read_fcoe_ctlr(&fcoe_ctlr_table);

	sa_table_iterate(&fcoe_ctlr_table, print_interface_fcoe_fcf_device,
			 (void *)ifname);
	sa_table_iterate(&fcoe_ctlr_table, free_fcoe_ctlr_device, NULL);

	return rc;
}

static void print_interface_fcoe_lesb_stats(void *ep, void *arg)
{
	struct fcoe_ctlr_device *ctlr = (struct fcoe_ctlr_device *)ep;
	const char *ifname = arg;

	if (!ifname || !strncmp(ifname, ctlr->ifname, IFNAMSIZ)) {
		printf("%-8u ", ctlr->lesb_link_fail);
		printf("%-9u ", ctlr->lesb_vlink_fail);
		printf("%-7u ", ctlr->lesb_miss_fka);
		printf("%-7u ", ctlr->lesb_symb_err);
		printf("%-9u ", ctlr->lesb_err_block);
		printf("%-9u ", ctlr->lesb_fcs_error);
		printf("\n");
	}
}

static void
print_interface_fcoe_lesb_stats_header(const char *ifname, int interval)
{
	printf("\n");
	printf("%-15s interval: %-2d\n", ifname, interval);
	printf("LinkFail VLinkFail MissFKA SymbErr ErrBlkCnt FCSErrCnt\n");
	printf("-------- --------- ------- ------- --------- ---------\n");
}

enum fcoe_status display_port_lesb_stats(const char *ifname,
					 int interval)
{
	enum fcoe_status rc = SUCCESS;
	int i = 0;

	while (1) {
		unsigned int secs_left;

		sa_table_init(&fcoe_ctlr_table);
		read_fcoe_ctlr(&fcoe_ctlr_table);

		if (!(i % 52))
			print_interface_fcoe_lesb_stats_header(ifname,
							       interval);

		sa_table_iterate(&fcoe_ctlr_table,
				 print_interface_fcoe_lesb_stats,
				 (void *)ifname);

		sa_table_iterate(&fcoe_ctlr_table,
				 free_fcoe_ctlr_device, NULL);

		i++;

		secs_left = interval;
		do {
			secs_left = sleep(secs_left);
		} while (secs_left);
	}

	return rc;
}
