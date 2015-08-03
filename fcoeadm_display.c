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
#include <sys/ioctl.h>
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
#include <scsi/sg.h>
#include <byteswap.h>
#include <net/if.h>
#include <unistd.h>
#include <inttypes.h>
#include <dirent.h>

#include "net_types.h"
#include "fc_types.h"
#include "fc_scsi.h"
#include "hbaapi.h"
#include "fcoeadm_display.h"
#include "fcoe_utils.h"
#include "fcoemon_utils.h"
#include "libopenfcoe.h"
#include "sysfs_hba.h"

/* #define TEST_HBAAPI_V1 */
#ifdef TEST_HBAAPI_V1
#define HBA_FCP_SCSI_ENTRY	 HBA_FCPSCSIENTRY
#define HBA_FCP_TARGET_MAPPING HBA_FCPTARGETMAPPING
#else
#define HBA_FCP_SCSI_ENTRY	 HBA_FCPSCSIENTRYV2
#define HBA_FCP_TARGET_MAPPING HBA_FCPTARGETMAPPINGV2
#endif
/* #define TEST_REPORT_LUNS */
/* #define TEST_READ_CAP_V1 */
/* #define TEST_DEV_SERIAL_NO */

/* Define FC4 Type */
#define FC_TYPE_FCP        0x08 /* SCSI FCP */

/* Constant defined in fcoe_def.h of fcoe driver */
#define FCOE_WORD_TO_BYTE  4

/* Minimum byte size of the received inquiry data */
#define MIN_INQ_DATA_SIZE       36

#define FCP_TARG_STR "FCP Target"

#define SYSFS_HOST_DIR     "/sys/class/fc_host"

/*
 * HBA and port objects are one-to-one since there
 * is one host created per Ethernet port (vlan).
 */
struct hba_name_table {
	HBA_HANDLE            hba_handle;
	HBA_ADAPTERATTRIBUTES hba_attrs;
	HBA_PORTATTRIBUTES    port_attrs;
	int                   failed;
	int                   displayed;
};

/*
 * List of HBA objects.
 */
struct hba_name_table_list {
	int			hba_count;
	struct hba_name_table	hba_table[1];
};

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

#define HBA_PORTSPEED_4GBIT		0x0008  /* 4 GBit/sec */
#define HBA_PORTSPEED_8GBIT		0x0010  /* 8 GBit/sec */
#define HBA_PORTSPEED_16GBIT		0x0020  /* 16 GBit/sec */
#define HBA_PORTSPEED_32GBIT		0x0040  /* 32 GBit/sec */
#define HBA_PORTSPEED_20GBIT		0x0080  /* 20 GBit/sec */
#define HBA_PORTSPEED_40GBIT		0x0100  /* 40 GBit/sec */
#define HBA_PORTSPEED_NOT_NEGOTIATED	(1 << 15) /* Speed not established */


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

	printf("        FabricName:        %s\n",
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

	strncat(path, "/device/", sizeof(path));

	sa_sys_read_line(path, "rev", rev, sizeof(rev));
	sa_sys_read_line(path, "model", model, sizeof(model));
	sa_sys_read_line(path, "vendor", vendor, sizeof(vendor));

	strncat(path, "block", sizeof(path));

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

	strncat(path, "block", sizeof(path));

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
	if (ret== -1)
		return;

	if (link[ret] != '\0')
		link[ret] = '\0';

	substr = strstr(link, "net");
	snprintf(path, sizeof(path), "/sys/class/%s", substr);

	substr = strstr(path, "fc_remote_ports");

	len = strlen(path) - strlen(substr);
	path[len] = '\0';

	sa_dir_crawl(path, search_rport_targets, style);

	return;
}

static void scan_device_map(char *port, char *rport, enum disp_style style)
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
	printf("%-7s interval: %-2d                                    Err  Inv  "
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
show_port_stats_in_row(HBA_INT64 start_time,
		       HBA_PORTSTATISTICS *port_stats,
		       HBA_FC4STATISTICS *port_fc4stats)
{
	printf("%-7lld ", port_stats->SecondsSinceLastReset - start_time);
	printf("%-9lld ", port_stats->TxFrames);
	printf("%-12lld ", port_stats->TxWords * FCOE_WORD_TO_BYTE);
	printf("%-9lld ", port_stats->RxFrames);
	printf("%-14lld ", port_stats->RxWords * FCOE_WORD_TO_BYTE);
	printf("%-4lld ", port_stats->ErrorFrames);
	printf("%-4lld ", port_stats->InvalidCRCCount);
	printf("%-4lld ", port_stats->InvalidTxWordCount * FCOE_WORD_TO_BYTE);
	printf("%-4lld ", port_stats->LinkFailureCount);
	printf("%-4lld ", port_fc4stats->ControlRequests);
	printf("%-9lld ", port_fc4stats->InputRequests);
	printf("%-9lld ", port_fc4stats->InputMegabytes);
	printf("%-9lld ", port_fc4stats->OutputRequests);
	printf("%-9lld ", port_fc4stats->OutputMegabytes);
	printf("\n");
}

static void hba_table_list_destroy(struct hba_name_table_list *hba_table_list)
{
	int i;

	if (!hba_table_list)
		return;

	for (i = 0 ; i < hba_table_list->hba_count ; i++)
		HBA_CloseAdapter(hba_table_list->hba_table[i].hba_handle);

	free(hba_table_list);
	hba_table_list = NULL;
}

static enum fcoe_status fcoeadm_loadhba(void)
{
	if (HBA_STATUS_OK != HBA_LoadLibrary())
		return EHBAAPIERR;

	return SUCCESS;
}

/*
 * This routine leaves all adapters fd's open.
 */
static int hba_table_list_init(struct hba_name_table_list **hba_table_list)
{
	HBA_STATUS retval;
	char namebuf[1024];
	int i, num_hbas = 0;
	struct hba_name_table_list *hba_table_list_temp = NULL;
	struct hba_name_table *hba_table = NULL;
	int size = 0;

	num_hbas = HBA_GetNumberOfAdapters();
	if (!num_hbas) {
		fprintf(stderr, "No FCoE interfaces created.\n");
		return num_hbas;
	}

	size = sizeof(struct hba_name_table_list) + \
			(num_hbas - 1)*sizeof(struct hba_name_table);

	hba_table_list_temp = (struct hba_name_table_list *)calloc(1, size);
	if (!hba_table_list_temp) {
		fprintf(stderr,
			"Failure allocating memory.\n");
		return -1;
	}

	hba_table_list_temp->hba_count = num_hbas;

	/*
	 * Fill out the HBA table.
	 */
	for (i = 0; i < num_hbas ; i++) {
		retval = HBA_GetAdapterName(i, namebuf);
		if (retval != HBA_STATUS_OK) {
			fprintf(stderr,
				"Failure of HBA_GetAdapterName: %d\n", retval);
			continue;
		}

		hba_table = &hba_table_list_temp->hba_table[i];
		hba_table->hba_handle = HBA_OpenAdapter(namebuf);
		if (!hba_table->hba_handle) {
			hba_table->failed = 1;
			fprintf(stderr, "HBA_OpenAdapter failed\n");
			perror("HBA_OpenAdapter");
			continue;
		}

		retval = HBA_GetAdapterAttributes(hba_table->hba_handle,
						  &hba_table->hba_attrs);
		if (retval != HBA_STATUS_OK) {
			HBA_CloseAdapter(hba_table->hba_handle);
			hba_table->failed = 1;
			fprintf(stderr,
				"HBA_GetAdapterAttributes failed, retval=%d\n",
				retval);
			perror("HBA_GetAdapterAttributes");
			continue;
		}

		retval = HBA_GetAdapterPortAttributes(hba_table->hba_handle,
						      0,
						      &hba_table->port_attrs);
		if (retval != HBA_STATUS_OK) {
			HBA_CloseAdapter(hba_table->hba_handle);
			hba_table->failed = 1;
			fprintf(stderr,
				"HBA_GetAdapterPortAttributes failed, "
				"retval=%d\n", retval);
			continue;
		}
	}

	*hba_table_list = hba_table_list_temp;

	return num_hbas;
}

/*
 * This routine expects a valid interface name.
 */
static int get_index_for_ifname(struct hba_name_table_list *hba_table_list,
				const char *ifname)
{
	HBA_PORTATTRIBUTES *port_attrs;
	int i;

	for (i = 0 ; i < hba_table_list->hba_count ; i++) {

		port_attrs = &hba_table_list->hba_table[i].port_attrs;

		if (!check_symbolic_name_for_interface(
			    port_attrs->PortSymbolicName,
			    ifname))
			return i;
	}

	return -EINVAL;
}

enum fcoe_status display_port_stats(const char *ifname, int interval)
{
	HBA_STATUS retval;
	HBA_HANDLE hba_handle;
	HBA_PORTATTRIBUTES *port_attrs;
	HBA_PORTSTATISTICS port_stats;
	HBA_FC4STATISTICS port_fc4stats;
	HBA_INT64 start_time = 0;
	struct hba_name_table_list *hba_table_list = NULL;
	enum fcoe_status rc = SUCCESS;
	int i, num_hbas;

	if (fcoeadm_loadhba())
		return EHBAAPIERR;

	num_hbas = hba_table_list_init(&hba_table_list);
	if (!num_hbas)
		goto out;

	if (num_hbas < 0) {
		rc = EINTERR;
		goto out;
	}

	i = get_index_for_ifname(hba_table_list, ifname);

	/*
	 * Return error code if a valid index wasn't returned.
	 */
	if (i < 0) {
		hba_table_list_destroy(hba_table_list);
		HBA_FreeLibrary();
		return EHBAAPIERR;
	}

	hba_handle = hba_table_list->hba_table[i].hba_handle;
	port_attrs = &hba_table_list->hba_table[i].port_attrs;

	i = 0;
	while (1) {
		unsigned int secs_left;

		retval = HBA_GetPortStatistics(hba_handle,
					       0, &port_stats);
		if (retval != HBA_STATUS_OK &&
		    retval != HBA_STATUS_ERROR_NOT_SUPPORTED) {
			fprintf(stderr,
				"HBA_GetPortStatistics failed, status=%d\n",
				retval);
			break;
		}
		if (retval == HBA_STATUS_ERROR_NOT_SUPPORTED) {
			fprintf(stderr,
				"Port Statistics not supported by %s\n",
				ifname);
			break;
		}

		if (!start_time)
			start_time = port_stats.SecondsSinceLastReset;

		retval = HBA_GetFC4Statistics(hba_handle,
					      port_attrs->PortWWN,
					      FC_TYPE_FCP,
					      &port_fc4stats);
		if (retval != HBA_STATUS_OK &&
		    retval != HBA_STATUS_ERROR_NOT_SUPPORTED) {
			fprintf(stderr, "HBA_GetFC4Statistics failed, "
				"status=%d\n", retval);
			break;
		}
		if (retval == HBA_STATUS_ERROR_NOT_SUPPORTED) {
			fprintf(stderr,
				"Port FC4 Statistics not supported by %s\n",
				ifname);
			break;
		}
		if (!(i % 52))
			show_port_stats_header(ifname, interval);
		show_port_stats_in_row(start_time, &port_stats, &port_fc4stats);
		i++;

		/* wait for the requested time interval in seconds */
		secs_left = interval;
		do {
			secs_left = sleep(secs_left);
		} while (secs_left);
	}

	hba_table_list_destroy(hba_table_list);
out:
	HBA_FreeLibrary();
	return rc;
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

static int search_fc_adapter(struct dirent *dp, void *arg)
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
		return false;

	ret = readlink(path, link, sizeof(link));
	free(path);
	if (ret == -1)
		return false;

	if (link[ret] != '\0')
		link[ret] = '\0';

	offs = strstr(link, "/net/");

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
	scan_device_map(ifname,	rport, style);

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
			return -ENOMEM;
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
	printf("%-7s interval: %-2d\n", ifname, interval);
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
