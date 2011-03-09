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

#include <sys/param.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <limits.h>
#include <scsi/sg.h>
#include <byteswap.h>
#include <net/if.h>
#include <unistd.h>

#include "net_types.h"
#include "fc_types.h"
#include "fc_scsi.h"
#include "hbaapi.h"
#include "fcoeadm_display.h"
#include "fcoe_utils.h"

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

struct sa_nameval {
	char        *nv_name;
	u_int32_t   nv_val;
};

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
	{ "10 Gbit",        HBA_PORTSPEED_10GBIT },
	{ "2 Gbit",         HBA_PORTSPEED_2GBIT },
	{ "1 Gbit",         HBA_PORTSPEED_1GBIT },
	{ "Not Negotiated", HBA_PORTSPEED_NOT_NEGOTIATED },
	{ "Unknown",        HBA_PORTSPEED_UNKNOWN },
	{ NULL, 0 }
};

/** sa_enum_decode(buf, len, tp, val)
 *
 * @param buf buffer for result (may be used or not).
 * @param len size of buffer (at least 32 bytes recommended).
 * @param tp pointer to table of names and values, struct sa_nameval.
 * @param val value to be decoded into a name.
 * @returns pointer to name string.  Unknown values are put into buffer in hex.
 */
static const char *
sa_enum_decode(char *buf, size_t len,
	       const struct sa_nameval *tp, u_int32_t val)
{
	snprintf(buf, len, "Unknown");
	for (; tp->nv_name != NULL; tp++) {
		if (tp->nv_val == val) {
			strncpy(buf, tp->nv_name, len);
			break;
		}
	}
	return buf;
}

static void
sa_dump_wwn(void *Data, int Length, int Break)
{
	unsigned char *pc = (unsigned char *)Data;
	int i;

	for (i = 1; i <= Length; i++) {
		printf("%02X", (int)*pc++);
		if ((Break != 0) && (!(i % Break)))
			printf("     ");
	}
}

/*
 * Make a printable NUL-terminated copy of the string.
 * The source buffer might not be NUL-terminated.
 */
static char *
sa_strncpy_safe(char *dest, size_t len, const char *src, size_t src_len)
{
	char *dp = dest;
	const char *sp = src;

	while (len-- > 1 && src_len-- > 0 && *sp != '\0') {
		*dp++ = isprint(*sp) ? *sp : (isspace(*sp) ? ' ' : '.');
		sp++;
	}
	*dp = '\0';

	/*
	 * Take off trailing blanks.
	 */
	while (--dp >= dest && isspace(*dp))
		*dp = '\0';

	return dest;
}

/*
 * Read a line from the specified file in the specified directory
 * into the buffer.  The file is opened and closed.
 * Any trailing white space is trimmed off.
 * This is useful for accessing /sys files.
 * Returns 0 or an error number.
 */
static int
sa_sys_read_line(const char *dir, const char *file, char *buf, size_t len)
{
	FILE *fp;
	char file_name[256];
	char *cp;
	int rc = 0;

	snprintf(file_name, sizeof(file_name), "%s/%s", dir, file);
	fp = fopen(file_name, "r");
	if (fp == NULL)
		rc = -1;
	else {
		cp = fgets(buf, len, fp);
		if (cp == NULL) {
			fprintf(stderr, "read error or empty file %s,"
				" errno=0x%x\n", file_name, errno);
			rc = -1;
		} else {

			/*
			 * Trim off trailing newline or other white space.
			 */
			cp = buf + strlen(buf);
			while (--cp >= buf && isspace(*cp))
				*cp = '\0';
		}
		fclose(fp);
	}
	return rc;
}

static int
sa_sys_read_u32(const char *dir, const char *file, u_int32_t *vp)
{
	char buf[256];
	int rc;
	u_int32_t val;
	char *endptr;

	rc = sa_sys_read_line(dir, file, buf, sizeof(buf));
	if (rc == 0) {
		val = strtoul(buf, &endptr, 0);
		if (*endptr != '\0') {
			fprintf(stderr,
				"parse error. file %s/%s line '%s'\n",
				dir, file, buf);
			rc = -1;
		} else
			*vp = val;
	}
	return rc;
}

static int is_fcp_target(HBA_PORTATTRIBUTES *rp_info)
{
	char buf[MAX_STR_LEN];

	if (sa_sys_read_line(rp_info->OSDeviceName, "roles", buf, sizeof(buf)))
		return -EINVAL;

	if (!strncmp(buf, FCP_TARG_STR, strlen(FCP_TARG_STR)))
		return 0;

	return -EINVAL;
}

static void show_wwn(unsigned char *pWwn)
{
	sa_dump_wwn(pWwn, 8, 0);
}

static void show_hba_info(HBA_ADAPTERATTRIBUTES *hba_info)
{
	printf("    Description:      %s\n", hba_info->ModelDescription);
	printf("    Revision:         %s\n", hba_info->HardwareVersion);
	printf("    Manufacturer:     %s\n", hba_info->Manufacturer);
	printf("    Serial Number:    %s\n", hba_info->SerialNumber);
	printf("    Driver:           %s %s\n", hba_info->DriverName,
	       hba_info->DriverVersion);
	printf("    Number of Ports:  %d\n", hba_info->NumberOfPorts);
	printf("\n");
}

static void show_port_info(HBA_ADAPTERATTRIBUTES *hba_info,
			   HBA_PORTATTRIBUTES *lp_info)
{
	char buf[256];
	int len = sizeof(buf);

	printf("        Symbolic Name:     %s\n",
	       lp_info->PortSymbolicName);

	printf("        OS Device Name:    %s\n",
	       lp_info->OSDeviceName);

	printf("        Node Name:         0x");
	show_wwn(lp_info->NodeWWN.wwn);
	printf("\n");

	printf("        Port Name:         0x");
	show_wwn(lp_info->PortWWN.wwn);
	printf("\n");

	printf("        FabricName:        0x");
	show_wwn(lp_info->FabricName.wwn);
	printf("\n");

	sa_enum_decode(buf, len, port_speeds, lp_info->PortSpeed);
	printf("        Speed:             %s\n", buf);

	sa_enum_decode(buf, len, port_speeds, lp_info->PortSupportedSpeed);
	printf("        Supported Speed:   %s\n", buf);

	printf("        MaxFrameSize:      %d\n",
	       lp_info->PortMaxFrameSize);

	printf("        FC-ID (Port ID):   0x%06X\n",
	       lp_info->PortFcId);

	sa_enum_decode(buf, sizeof(buf), port_states, lp_info->PortState);
	printf("        State:             %s\n", buf);
	printf("\n");
	/* TODO: Display PortSupportedFc4Types and PortActiveFc4Types */
}

static void show_target_info(const char *symbolic_name,
			     HBA_ADAPTERATTRIBUTES *hba_info,
			     HBA_PORTATTRIBUTES *rp_info)
{
	char buf[256];
	u_int32_t tgt_id;
	int rc;
	char *ifname;

	ifname = get_ifname_from_symbolic_name(symbolic_name);

	rc = sa_sys_read_line(rp_info->OSDeviceName, "roles", buf, sizeof(buf));
	printf("    Interface:        %s\n", ifname);
	printf("    Roles:            %s\n", buf);

	printf("    Node Name:        0x");
	show_wwn(rp_info->NodeWWN.wwn);
	printf("\n");

	printf("    Port Name:        0x");
	show_wwn(rp_info->PortWWN.wwn);
	printf("\n");

	rc = sa_sys_read_u32(rp_info->OSDeviceName, "scsi_target_id", &tgt_id);
	if (tgt_id != -1)
		printf("    Target ID:        %d\n", tgt_id);

	printf("    MaxFrameSize:     %d\n", rp_info->PortMaxFrameSize);

	printf("    OS Device Name:   %s\n",
	       strrchr(rp_info->OSDeviceName, '/') + 1);

	printf("    FC-ID (Port ID):  0x%06X\n", rp_info->PortFcId);

	sa_enum_decode(buf, sizeof(buf), port_states, rp_info->PortState);
	printf("    State:            %s\n", buf);
	printf("\n");
}

static void
show_sense_data(char *dev, char *sense, int slen)
{
	printf("%s", dev);
	if (slen >= 3)
		printf("    Sense Key=0x%02x", sense[2]);
	if (slen >= 13)
		printf(" ASC=0x%02x", sense[12]);
	if (slen >= 14)
		printf(" ASCQ=0x%02x\n", sense[13]);
	printf("\n");
}

#ifdef TEST_HBAAPI_V1
static HBA_STATUS
get_inquiry_data_v1(HBA_HANDLE hba_handle,
		    HBA_FCPSCSIENTRY *ep,
		    char *inqbuf, size_t inqlen)
{
	char sense[128];
	HBA_UINT32 rlen;
	HBA_UINT32 slen;
	HBA_STATUS status;

	memset(inqbuf, 0, inqlen);
	memset(sense, 0, sizeof(sense));
	rlen = (HBA_UINT32) inqlen;
	slen = (HBA_UINT32) sizeof(sense);
	status = HBA_SendScsiInquiry(hba_handle,
				     ep->FcpId.PortWWN,
				     ep->FcpId.FcpLun,
				     0,
				     0,
				     inqbuf,
				     rlen,
				     sense,
				     slen);
	if ((status != HBA_STATUS_OK) ||
	    (rlen < MIN_INQ_DATA_SIZE)) {
		fprintf(stderr,
			"%s: HBA_SendScsiInquiry failed, "
			"status=0x%x, rlen=%d\n",
			__func__, status, rlen);
		show_sense_data(ep->ScsiId.OSDeviceName, sense, slen);
		return HBA_STATUS_ERROR;
	}
	return HBA_STATUS_OK;
}
#else
static HBA_STATUS
get_inquiry_data_v2(HBA_HANDLE hba_handle,
		    HBA_PORTATTRIBUTES *lp_info,
		    HBA_FCPSCSIENTRYV2 *ep,
		    char *inqbuf, size_t inqlen)
{
	char sense[128];
	HBA_UINT32 rlen;
	HBA_UINT32 slen;
	HBA_STATUS status;
	HBA_UINT8 sstat;

	memset(inqbuf, 0, inqlen);
	memset(sense, 0, sizeof(sense));
	rlen = (HBA_UINT32) inqlen;
	slen = (HBA_UINT32) sizeof(sense);
	sstat = SCSI_ST_GOOD;
	status = HBA_ScsiInquiryV2(hba_handle,
				   lp_info->PortWWN,
				   ep->FcpId.PortWWN,
				   ep->FcpId.FcpLun,
				   0,
				   0,
				   inqbuf,
				   &rlen,
				   &sstat,
				   sense,
				   &slen);
	if ((status != HBA_STATUS_OK) ||
	    (sstat != SCSI_ST_GOOD) ||
	    (rlen < MIN_INQ_DATA_SIZE)) {
		fprintf(stderr,
			"%s: HBA_ScsiInquiryV2 failed, "
			"status=0x%x, sstat=0x%x, rlen=%d\n",
			__func__, status, sstat, rlen);
		if (sstat != SCSI_ST_GOOD)
			show_sense_data(ep->ScsiId.OSDeviceName, sense, slen);
		return HBA_STATUS_ERROR;
	}
	return HBA_STATUS_OK;
}
#endif

#ifdef TEST_HBAAPI_V1
static HBA_STATUS
get_device_capacity_v1(HBA_HANDLE hba_handle,
		       HBA_FCPSCSIENTRY *ep,
		       char *buf, size_t len)
{
	char sense[128];
	HBA_UINT32 rlen;
	HBA_UINT32 slen;
	HBA_STATUS status;
	int retry_count = 10;

	while (retry_count--) {
		memset(buf, 0, len);
		memset(sense, 0, sizeof(sense));
		rlen = (HBA_UINT32)len;
		slen = (HBA_UINT32)sizeof(sense);
		status = HBA_SendReadCapacity(hba_handle,
					      ep->FcpId.PortWWN,
					      ep->FcpId.FcpLun,
					      buf,
					      rlen,
					      sense,
					      slen);
		if (status == HBA_STATUS_OK)
			return HBA_STATUS_OK;
		if (sense[2] == 0x06)
			continue;
		fprintf(stderr,
			"%s: HBA_SendReadCapacity failed, "
			"status=0x%x, slen=%d\n",
			__func__, status, slen);
		show_sense_data(ep->ScsiId.OSDeviceName, sense, slen);
		return HBA_STATUS_ERROR;
	}
	/* retry count exhausted */
	return HBA_STATUS_ERROR;
}
#else
static HBA_STATUS
get_device_capacity_v2(HBA_HANDLE hba_handle,
		       HBA_PORTATTRIBUTES *lp_info,
		       HBA_FCPSCSIENTRYV2 *ep,
		       char *buf, size_t len)
{
	char sense[128];
	HBA_UINT32 rlen;
	HBA_UINT32 slen;
	HBA_STATUS status;
	HBA_UINT8 sstat;
	int retry_count = 10;

	while (retry_count--) {
		memset(buf, 0, len);
		memset(sense, 0, sizeof(sense));
		rlen = (HBA_UINT32)len;
		slen = (HBA_UINT32)sizeof(sense);
		sstat = SCSI_ST_GOOD;
		status = HBA_ScsiReadCapacityV2(hba_handle,
						lp_info->PortWWN,
						ep->FcpId.PortWWN,
						ep->FcpId.FcpLun,
						buf,
						&rlen,
						&sstat,
						sense,
						&slen);
		if ((status == HBA_STATUS_OK) && (sstat == SCSI_ST_GOOD))
			return HBA_STATUS_OK;
		if (sstat == SCSI_ST_CHECK)
			continue;
		fprintf(stderr,
			"%s: HBA_ScsiReadCapacityV2 failed, "
			"status=0x%x, sstat=0x%x, slen=%d\n",
			__func__, status, sstat, slen);
		if (sstat != SCSI_ST_GOOD)
			show_sense_data(ep->ScsiId.OSDeviceName, sense, slen);
		return HBA_STATUS_ERROR;
	}
	/* retry count exhausted */
	return HBA_STATUS_ERROR;
}
#endif

#ifdef TEST_DEV_SERIAL_NO
static HBA_STATUS
get_device_serial_number(HBA_HANDLE hba_handle,
			 HBA_FCPSCSIENTRYV2 *ep,
			 char *buf, size_t buflen)
{
	struct scsi_inquiry_unit_sn *unit_sn;
	char rspbuf[256];
	char sense[128];
	HBA_UINT32 rlen;
	HBA_UINT32 slen;
	HBA_STATUS status;

	memset(rspbuf, 0, sizeof(rspbuf));
	memset(sense, 0, sizeof(sense));
	rlen = (HBA_UINT32) sizeof(rspbuf);
	slen = (HBA_UINT32) sizeof(sense);
	status = HBA_SendScsiInquiry(hba_handle,
				     ep->FcpId.PortWWN,
				     ep->FcpId.FcpLun,
				     SCSI_INQF_EVPD,
				     SCSI_INQP_UNIT_SN,
				     rspbuf,
				     rlen,
				     sense,
				     slen);
	if (status != HBA_STATUS_OK) {
		fprintf(stderr,
			"%s: inquiry page 0x80 failed, status=0x%x\n",
			__func__, status);
		show_sense_data(ep->ScsiId.OSDeviceName, sense, slen);
		return HBA_STATUS_ERROR;
	}
	unit_sn = (struct scsi_inquiry_unit_sn *)rspbuf;
	unit_sn->is_serial[unit_sn->is_page_len] = '\0';
	sa_strncpy_safe(buf, buflen, (char *)unit_sn->is_serial,
			(size_t)unit_sn->is_page_len);
	return HBA_STATUS_OK;
}
#endif

#ifdef TEST_REPORT_LUNS
static void
show_report_luns_data(char *rspbuf)
{
	struct scsi_report_luns_resp *rp;
	int list_len;
	net64_t *lp;
	u_int64_t lun_id;

	rp = (struct scsi_report_luns_resp *)rspbuf;
	list_len = net32_get(&rp->rl_len);
	printf("\tTotal Number of LUNs=%lu\n", list_len/sizeof(u_int64_t));

	for (lp = rp->rl_lun; list_len > 0; lp++, list_len -= sizeof(*lp)) {
		lun_id = net64_get(lp);
		if (!(lun_id & ((0xfc01ULL << 48) - 1)))
			printf("\tLUN %u\n", (u_int32_t)(lun_id >> 48));
		else
			printf("\tLUN %lx\n", (u_int64_t)lun_id);
	}
}

static HBA_STATUS
get_report_luns_data_v1(HBA_HANDLE hba_handle, HBA_FCPSCSIENTRYV2 *ep)
{
	HBA_STATUS status;
	char rspbuf[512 * sizeof(u_int64_t)]; /* max 512 luns */
	char sense[128];
	HBA_UINT32 rlen;
	HBA_UINT32 slen;
	int retry_count = 10;

	while (retry_count--) {
		memset(rspbuf, 0, sizeof(rspbuf));
		memset(sense, 0, sizeof(sense));
		rlen = (HBA_UINT32) sizeof(rspbuf);
		slen = (HBA_UINT32) sizeof(sense);
		status = HBA_SendReportLUNs(hba_handle,
					    ep->FcpId.PortWWN,
					    rspbuf,
					    rlen,
					    sense,
					    slen);
		if (status == HBA_STATUS_OK) {
			show_report_luns_data(rspbuf);
			return HBA_STATUS_OK;
		}
		if (sense[2] == 0x06)
			continue;
		fprintf(stderr,
			"%s: HBA_SendReportLUNs failed, "
			"status=0x%x, slen=%d\n",
			__func__, status, slen);
		show_sense_data(ep->ScsiId.OSDeviceName, sense, slen);
		return HBA_STATUS_ERROR;
	}
	/* retry count exhausted */
	return HBA_STATUS_ERROR;
}

static HBA_STATUS
get_report_luns_data_v2(HBA_HANDLE hba_handle,
			HBA_PORTATTRIBUTES *lp_info,
			HBA_FCPSCSIENTRYV2 *ep)
{
	HBA_STATUS status;
	char rspbuf[512 * sizeof(u_int64_t)]; /* max 512 luns */
	char sense[128];
	HBA_UINT32 rlen;
	HBA_UINT32 slen;
	HBA_UINT8 sstat;
	int retry_count = 10;

	while (retry_count--) {
		memset(rspbuf, 0, sizeof(rspbuf));
		memset(sense, 0, sizeof(sense));
		rlen = (HBA_UINT32) sizeof(rspbuf);
		slen = (HBA_UINT32) sizeof(sense);
		sstat = SCSI_ST_GOOD;
		status = HBA_ScsiReportLUNsV2(hba_handle,
					      lp_info->PortWWN,
					      ep->FcpId.PortWWN,
					      rspbuf,
					      &rlen,
					      &sstat,
					      sense,
					      &slen);
		if ((status == HBA_STATUS_OK) && (sstat == SCSI_ST_GOOD)) {
			show_report_luns_data(rspbuf);
			return HBA_STATUS_OK;
		}
		if ((sstat == SCSI_ST_CHECK) && (sense[2] == 0x06))
			continue;
		fprintf(stderr,
			"%s: HBA_ScsiReportLUNsV2 failed, "
			"status=0x%x, sstat=0x%x, slen=%d\n",
			__func__, status, sstat, slen);
		if (sstat != SCSI_ST_GOOD)
			show_sense_data(ep->ScsiId.OSDeviceName, sense, slen);
		return HBA_STATUS_ERROR;
	}
	/* retry count exhausted */
	return HBA_STATUS_ERROR;
}
#endif

static void
show_short_lun_info_header(void)
{
	printf("    LUN ID  Device Name   Capacity   "
	       "Block Size  Description\n");
	printf("    ------  -----------  ----------  ----------  "
	       "----------------------------\n");
}

static void
show_short_lun_info(HBA_FCP_SCSI_ENTRY *ep, char *inqbuf,
		    struct scsi_rcap10_resp *rcap_resp)
{
	struct scsi_inquiry_std *inq = (struct scsi_inquiry_std *)inqbuf;
	char vendor[10];
	char model[20];
	char capstr[32];
	char rev[16];
	u_int64_t cap;
	double cap_abbr;
	char *abbr;

	memset(vendor, 0, sizeof(vendor));
	memset(model, 0, sizeof(model));
	memset(capstr, 0, sizeof(capstr));
	memset(rev, 0, sizeof(rev));

	/* Get device capacity */
	cap = (u_int64_t) net32_get(&rcap_resp->rc_block_len) *
		net32_get(&rcap_resp->rc_lba);
	cap_abbr = cap / (1024.0 * 1024.0);
	abbr = "MB";
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "GB";
	}
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "TB";
	}
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "PB";
	}
	snprintf(capstr, sizeof(capstr), "%0.2f %s", cap_abbr, abbr);

	/* Get the device description */
	sa_strncpy_safe(vendor, sizeof(vendor),
			inq->is_vendor_id, sizeof(inq->is_vendor_id));
	sa_strncpy_safe(model, sizeof(model),
			inq->is_product, sizeof(inq->is_product));
	sa_strncpy_safe(rev, sizeof(rev), inq->is_rev_level,
			sizeof(inq->is_rev_level));

	/* Show the LUN info */
	printf("%10d  %-11s  %10s  %7d     %s %s (rev %s)\n",
	       ep->ScsiId.ScsiOSLun, ep->ScsiId.OSDeviceName,
	       capstr, net32_get(&rcap_resp->rc_block_len),
	       vendor, model, rev);
}

static void
show_full_lun_info(HBA_HANDLE hba_handle,
		   HBA_ADAPTERATTRIBUTES *hba_info,
		   HBA_PORTATTRIBUTES *lp_info,
		   HBA_PORTATTRIBUTES *rp_info,
		   HBA_FCP_SCSI_ENTRY *ep,
		   char *inqbuf,
		   struct scsi_rcap10_resp *rcap_resp)
{
	struct scsi_inquiry_std *inq = (struct scsi_inquiry_std *)inqbuf;
	char vendor[10];
	char model[20];
	char capstr[32];
	char rev[16];
	double cap_abbr;
	char *abbr;
	u_int64_t cap;
	u_int32_t tgt_id;
	u_int8_t pqual;
#ifdef TEST_DEV_SERIAL_NO
	HBA_STATUS status;
	char serial_number[32];
#endif

	memset(vendor, 0, sizeof(vendor));
	memset(model, 0, sizeof(model));
	memset(capstr, 0, sizeof(capstr));
	memset(rev, 0, sizeof(rev));

	/* Get device description */
	sa_strncpy_safe(vendor, sizeof(vendor),
			inq->is_vendor_id, sizeof(inq->is_vendor_id));
	sa_strncpy_safe(model, sizeof(model),
			inq->is_product, sizeof(inq->is_product));
	sa_strncpy_safe(rev, sizeof(rev), inq->is_rev_level,
			sizeof(inq->is_rev_level));

	/* Get device capacity */
	cap = (u_int64_t) net32_get(&rcap_resp->rc_block_len) *
		net32_get(&rcap_resp->rc_lba);
	cap_abbr = cap / (1024.0 * 1024.0);
	abbr = "MB";
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "GB";
	}
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "TB";
	}
	if (cap_abbr >= 1024) {
		cap_abbr /= 1024.0;
		abbr = "PB";
	}
	snprintf(capstr, sizeof(capstr), "%0.2f %s", cap_abbr, abbr);

	/* Get SCSI target ID */
	sa_sys_read_u32(rp_info->OSDeviceName,
			"scsi_target_id", &tgt_id);

	/* Show lun info */
	printf("    LUN #%d Information:\n", ep->ScsiId.ScsiOSLun);
	printf("        OS Device Name:     %s\n",
	       ep->ScsiId.OSDeviceName);
	printf("        Description:        %s %s (rev %s)\n",
	       vendor, model, rev);
	printf("        Ethernet Port FCID: 0x%06X\n",
	       lp_info->PortFcId);
	printf("        Target FCID:        0x%06X\n",
	       rp_info->PortFcId);
	if (tgt_id == -1)
		printf("        Target ID:          (None)\n");
	else
		printf("        Target ID:          %u\n", tgt_id);
	printf("        LUN ID:             %d\n",
	       ep->ScsiId.ScsiOSLun);

	printf("        Capacity:           %s\n", capstr);
	printf("        Capacity in Blocks: %d\n",
	       net32_get(&rcap_resp->rc_lba));
	printf("        Block Size:         %d bytes\n",
	       net32_get(&rcap_resp->rc_block_len));
	pqual = inq->is_periph & SCSI_INQ_PQUAL_MASK;
	if (pqual == SCSI_PQUAL_ATT)
		printf("        Status:             Attached\n");
	else if (pqual == SCSI_PQUAL_DET)
		printf("        Status:             Detached\n");
	else if (pqual == SCSI_PQUAL_NC)
		printf("        Status:             "
		       "Not capable of attachment\n");

#ifdef TEST_DEV_SERIAL_NO
	/* Show the serial number of the device */
	status = get_device_serial_number(hba_handle, ep,
					  serial_number, sizeof(serial_number));
	if (status == HBA_STATUS_OK)
		printf("        Serial Number:      %s\n", serial_number);
#endif

	printf("\n");
}

/* Compare two LUN mappings for qsort */
static int
lun_compare(const void *arg1, const void *arg2)
{
	const HBA_FCP_SCSI_ENTRY *e1 = arg1;
	const HBA_FCP_SCSI_ENTRY *e2 = arg2;
	int diff;

	diff = e2->FcpId.FcId - e1->FcpId.FcId;
	if (diff == 0)
		diff = e1->ScsiId.ScsiOSLun - e2->ScsiId.ScsiOSLun;

	return diff;
}

static HBA_STATUS
get_device_map(HBA_HANDLE hba_handle, HBA_PORTATTRIBUTES *lp_info,
	       HBA_FCP_TARGET_MAPPING **tgtmap, u_int32_t *lun_count)
{
	HBA_STATUS status;
	HBA_FCP_TARGET_MAPPING *map = NULL;
	HBA_FCP_SCSI_ENTRY *ep;
	u_int32_t limit;
	u_int32_t i;

#define LUN_COUNT_START     8       /* number of LUNs to start with */
#define LUN_COUNT_INCR      4       /* excess to allocate */

	/*
	 * Get buffer large enough to retrieve all the mappings.
	 * If they don't fit, increase the size of the buffer and retry.
	 */
	*lun_count = 0;
	limit = LUN_COUNT_START;
	for (;;) {
		i = (limit - 1) * sizeof(*ep) +  sizeof(*map);
		map = malloc(i);
		if (map == NULL) {
			fprintf(stderr, "%s: malloc failed\n", __func__);
			return HBA_STATUS_ERROR;
		}
		memset((char *)map, 0, i);
		map->NumberOfEntries = limit;
#ifdef TEST_HBAAPI_V1
		status = HBA_GetFcpTargetMapping(hba_handle, map);
#else
		status = HBA_GetFcpTargetMappingV2(
			hba_handle, lp_info->PortWWN, map);
#endif
		if (map->NumberOfEntries > limit) {
			limit = map->NumberOfEntries + LUN_COUNT_INCR;
			free(map);
			continue;
		}
		if (status != HBA_STATUS_OK) {
			fprintf(stderr,
				"%s: HBA_GetFcpTargetMappingV2 failed\n",
				__func__);
			free(map);
			return HBA_STATUS_ERROR;
		}
		break;
	}

	if (map == NULL) {
		fprintf(stderr, "%s: map == NULL\n", __func__);
		return HBA_STATUS_ERROR;
	}

	if (map->NumberOfEntries > limit) {
		fprintf(stderr, "%s: map->NumberOfEntries=%d too big\n",
			__func__, map->NumberOfEntries);
		return HBA_STATUS_ERROR;
	}

	ep = map->entry;
	limit = map->NumberOfEntries;

	/* Sort the response by LUN number */
	qsort(ep, limit, sizeof(*ep), lun_compare);

	*lun_count = limit;
	*tgtmap = map;
	return HBA_STATUS_OK;
}

static void
scan_device_map(HBA_HANDLE hba_handle,
		HBA_ADAPTERATTRIBUTES *hba_info,
		HBA_PORTATTRIBUTES *lp_info,
		HBA_PORTATTRIBUTES *rp_info,
		const char *ifname,
		enum disp_style style)
{
	HBA_STATUS status;
	HBA_FCP_TARGET_MAPPING *map = NULL;
	u_int32_t limit;
	HBA_FCP_SCSI_ENTRY *ep;
	u_int32_t i;
	char *dev;
	char inqbuf[256];
	struct scsi_rcap10_resp rcap_resp;
	int lun_count = 0;
	int print_header = 0;

	status = get_device_map(hba_handle, lp_info, &map, &limit);
	if (status != HBA_STATUS_OK) {
		fprintf(stderr, "%s: get_device_map() failed\n", __func__);
		return;
	}

	ep = map->entry;
	for (i = 0; i < limit; i++, ep++) {
		if (ep->FcpId.FcId != rp_info->PortFcId)
			continue;

		dev = ep->ScsiId.OSDeviceName;
		if (strstr(dev, "/dev/") == dev)
			dev += 5;

		/* Issue standard inquiry */
#ifdef TEST_HBAAPI_V1
		status = get_inquiry_data_v1(hba_handle, ep,
					     inqbuf, sizeof(inqbuf));
#else
		status = get_inquiry_data_v2(hba_handle, lp_info,
					     ep, inqbuf, sizeof(inqbuf));
#endif
		if (status != HBA_STATUS_OK)
			continue;
		lun_count++;

		/* Issue read capacity */
#ifdef TEST_HBAAPI_V1
		status = get_device_capacity_v1(hba_handle, ep,
						(char *)&rcap_resp,
						sizeof(rcap_resp));
#else
		status = get_device_capacity_v2(hba_handle, lp_info,
						ep, (char *)&rcap_resp,
						sizeof(rcap_resp));
#endif
		if (status != HBA_STATUS_OK)
			continue;
		switch (style) {
		case DISP_TARG:
			if (!print_header) {
				show_short_lun_info_header();
				print_header = 1;
			}
			show_short_lun_info(ep, inqbuf, &rcap_resp);
			break;
		case DISP_LUN:
			show_full_lun_info(hba_handle, hba_info, lp_info,
					   rp_info, ep, inqbuf, &rcap_resp);
			break;
		}

#ifdef TEST_REPORT_LUNS
		if (i == 0) {	/* only issue report luns to the first LUN */
#ifdef TEST_HBAAPI_V1
			get_report_luns_data_v1(hba_handle, ep);
#else
			get_report_luns_data_v2(hba_handle, lp_info, ep);
#endif
		}
#endif
	}

	/* Newline at the end of the short lun report */
	if (style == DISP_TARG)
		printf("\n");

	free(map);
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

static enum fcoe_status fcoeadm_loadhba()
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

enum fcoe_status display_adapter_info(const char *ifname)
{
	struct hba_name_table_list *hba_table_list = NULL;
	enum fcoe_status rc = SUCCESS;
	int i, j, num_hbas = 0;
	HBA_HANDLE hba_handle;
	HBA_PORTATTRIBUTES *port_attrs;
	HBA_PORTATTRIBUTES *sport_attrs;
	HBA_ADAPTERATTRIBUTES *hba_attrs;
	HBA_ADAPTERATTRIBUTES *shba_attrs;

	if (fcoeadm_loadhba())
		return EHBAAPIERR;

	num_hbas = hba_table_list_init(&hba_table_list);
	if (!num_hbas)
		goto out;

	if (num_hbas < 0) {
		rc = EINTERR;
		goto out;
	}

	/*
	 * Loop through each HBA entry and for each serial number
	 * not already printed print the header and each sub-port
	 * on that adapter.
	 */
	for (i = 0 ; i < num_hbas ; i++) {
		if (hba_table_list->hba_table[i].failed ||
		    hba_table_list->hba_table[i].displayed)
			continue;

		hba_handle = hba_table_list->hba_table[i].hba_handle;
		port_attrs = &hba_table_list->hba_table[i].port_attrs;
		hba_attrs = &hba_table_list->hba_table[i].hba_attrs;

		if (ifname && check_symbolic_name_for_interface(
			    port_attrs->PortSymbolicName,
			    ifname)) {
			/*
			 * Overloading 'displayed' to indicate
			 * that the HBA/Port should be skipped.
			 */
			hba_table_list->hba_table[i].displayed = 1;
			continue;
		}

		/*
		 * Display the adapter header.
		 */
		show_hba_info(hba_attrs);

		/*
		 * Loop through HBAs again to print sub-ports.
		 */
		for (j = 0; j < num_hbas ; j++) {
			sport_attrs = &hba_table_list->hba_table[j].port_attrs;
			shba_attrs = &hba_table_list->hba_table[j].hba_attrs;
			if (ifname && check_symbolic_name_for_interface(
				    sport_attrs->PortSymbolicName,
				    ifname)) {
				/*
				 * Overloading 'displayed' to indicate
				 * that the HBA/Port should be skipped.
				 */
				hba_table_list->hba_table[i].displayed = 1;
				continue;
			}

			if (!strncmp(hba_attrs->SerialNumber,
				     shba_attrs->SerialNumber,
				     strlen(hba_attrs->SerialNumber))) {
				show_port_info(shba_attrs,
					       sport_attrs);
				hba_table_list->hba_table[j].displayed = 1;
			}
		}
	}

	hba_table_list_destroy(hba_table_list);
out:
	HBA_FreeLibrary();

	return rc;
}

enum fcoe_status display_target_info(const char *ifname,
				     enum disp_style style)
{
	HBA_STATUS retval;
	HBA_PORTATTRIBUTES rport_attrs;
	struct hba_name_table_list *hba_table_list = NULL;
	int i, target_index, num_hbas = 0;
	enum fcoe_status rc = SUCCESS;
	HBA_HANDLE hba_handle;
	HBA_PORTATTRIBUTES *port_attrs;
	HBA_ADAPTERATTRIBUTES *hba_attrs;

	if (fcoeadm_loadhba())
		return EHBAAPIERR;

	num_hbas = hba_table_list_init(&hba_table_list);
	if (!num_hbas)
		goto out;

	if (num_hbas < 0) {
		rc = EINTERR;
		goto out;
	}

	/*
	 * Loop through each HBA entry and for each serial number
	 * not already printed print the header and each sub-port
	 * on that adapter.
	 */
	for (i = 0 ; i < num_hbas ; i++) {
		if (hba_table_list->hba_table[i].failed ||
		    hba_table_list->hba_table[i].displayed)
			continue;

		hba_handle = hba_table_list->hba_table[i].hba_handle;
		port_attrs = &hba_table_list->hba_table[i].port_attrs;
		hba_attrs = &hba_table_list->hba_table[i].hba_attrs;

		if (ifname && check_symbolic_name_for_interface(
			    port_attrs->PortSymbolicName,
			    ifname)) {
			/*
			 * Overloading 'displayed' to indicate
			 * that the HBA/Port should be skipped.
			 */
			hba_table_list->hba_table[i].displayed = 1;
			continue;
		}

		for (target_index = 0;
		     target_index < port_attrs->NumberofDiscoveredPorts;
		     target_index++) {

			/* TODO: Second arg might be incorrect */
			retval = HBA_GetDiscoveredPortAttributes(
				hba_handle,
				0, target_index,
				&rport_attrs);

			if (retval != HBA_STATUS_OK) {
				fprintf(stderr,
					"HBA_GetDiscoveredPortAttributes "
					"failed for target_index=%d, "
					"status=%d\n", target_index, retval);
				hba_table_list->hba_table[i].failed = 1;
				continue;
			}

			/*
			 * Skip any targets that are not FCP targets
			 */
			if (is_fcp_target(&rport_attrs))
				continue;

			show_target_info(
				port_attrs->PortSymbolicName,
				hba_attrs,
				&rport_attrs);

			if (port_attrs->PortState != HBA_PORTSTATE_ONLINE)
				continue;

			/*
			 * This will print the LUN table
			 * under the target.
			 */
			scan_device_map(hba_handle,
					hba_attrs,
					port_attrs,
					&rport_attrs, ifname, style);
		}
	}

	hba_table_list_destroy(hba_table_list);
out:
	HBA_FreeLibrary();

	return rc;
}
