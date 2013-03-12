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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
#include <linux/bsg.h>
#include <scsi/sg.h>
#include "fc_gs.h"
#include "fc_ns.h"
#include "scsi_bsg_fc.h"

static bool quiet = false;

__attribute__((__format__(__printf__, 2, 3)))
static int print_result(const char *prefix, const char *format, ...)
{
	va_list ap;
	int rc;

	va_start(ap, format);
	if (!quiet)
		printf("%s: ", prefix);
	rc = vprintf(format, ap);
	va_end(ap);
	return rc;
}

__attribute__((__format__(__printf__, 1, 2)))
static int print_err(const char *format, ...)
{
	va_list ap;
	int rc;

	if (quiet)
		return 0;
	va_start(ap, format);
	rc = vprintf(format, ap);
	va_end(ap);
	return rc;
}

#define ntoh24(n) (u32) ((n)[0] << 16 | (n)[1] << 8  | (n)[2])
#define hton24(h) { (h) >> 16 & 0xff, (h) >> 8 & 0xff, (h) & 0xff }

static u64 ntohll(u64 netll)
{
	u8 *_netll = (u8 *)&netll;
	return	(u64) _netll[0] << (7 * 8) |
		(u64) _netll[1] << (6 * 8) |
		(u64) _netll[2] << (5 * 8) |
		(u64) _netll[3] << (4 * 8) |
		(u64) _netll[4] << (3 * 8) |
		(u64) _netll[5] << (2 * 8) |
		(u64) _netll[6] << (1 * 8) |
		(u64) _netll[7];
}

static u64 htonll(u64 hostll)
{
	u64 netll;
	u8 *_netll = (u8 *)&netll;
	_netll[0] = hostll >> (7 * 8) & 0xff;
	_netll[1] = hostll >> (6 * 8) & 0xff;
	_netll[2] = hostll >> (5 * 8) & 0xff;
	_netll[3] = hostll >> (4 * 8) & 0xff;
	_netll[4] = hostll >> (3 * 8) & 0xff;
	_netll[5] = hostll >> (2 * 8) & 0xff;
	_netll[6] = hostll >> (1 * 8) & 0xff;
	_netll[7] = hostll & 0xff;
	return netll;
}

static char* rjt_reason[] = {
	[1] = "Invalid command code",
	[2] = "Invalid version level",
	[3] = "Logical error",
	[4] = "Invalid CT_IU size",
	[5] = "Logical busy",
	[7] = "Protocol error",
	[9] = "Unable to perform command request",
	[0xB] = "Command not supported",
	[0xD] = "Server not available",
	[0xE] = "Session could not be established",
};

static char* rjt_explan[] = {
	[0] = "No additional explanation",
	[1] = "Port Identifier not registered",
	[2] = "Port Name not registered",
	[3] = "Node Name not registered",
	[4] = "Class of Service not registered",
	[6] = "Initial Process Associator not registered",
	[7] = "FC-4 Types not registered",
	[8] = "Symbolic Port Name not registered",
	[9] = "Symbolic Node Name not registered",
	[0xA] = "Port Type not registered",
	[0xC] = "Fabric Port Name not registered",
	[0xD] = "Hard Address not registered",
	[0xF] = "FC-4 Features not registered",
	[0x10] = "Access denied",
	[0x11] = "Unacceptable Port Identifier",
	[0x12] = "Data base empty",
	[0x13] = "No object registered in the specified scope",
	[0x14] = "Domain ID not present",
	[0x15] = "Port number not present",
	[0x16] = "No device attached",
	[0xf0] = "Authorization Exception",
	[0xf1] = "Authentication Exception",
	[0xf2] = "Data base full",
	[0xf3] = "Data base empty",
	[0xf4] = "Processing request",
	[0xf5] = "Unable to verify connection",
	[0xf6] = "Devices not in a common zone",
};

static u16 ct_rjt(u8 reason, u8 explan) {
	return (u16) reason << 8 | explan;
}

static u8 ct_rjt_reason(u16 rjt) {
	return (u8)(rjt >> 8);
}

static u8 ct_rjt_explan(u16 rjt) {
	return (u8) rjt & 0xff;
}

static int ns_query(int bsg, void *req, int req_len, void *resp, int resp_len)
{
	char sense[96];

	struct fc_bsg_request cdb = {
		.msgcode 	= FC_BSG_HST_CT,
		.rqst_data.h_ct	= {
			.port_id = hton24(0xfffffc),
		}
	};

	struct sg_io_v4 sgio = {
		.guard			= 'Q',
		.protocol		= BSG_PROTOCOL_SCSI,
		.subprotocol		= BSG_SUB_PROTOCOL_SCSI_TRANSPORT,
		.request_len		= sizeof(cdb),
		.request		= (uintptr_t) &cdb,
		.dout_xfer_len		= req_len,
		.dout_xferp		= (uintptr_t) req,
		.din_xfer_len		= resp_len,
		.din_xferp		= (uintptr_t) resp,
		.max_response_len	= sizeof(sense),
		.response		= (uintptr_t) &sense,
		.timeout		= 1000,
	};

	return ioctl(bsg, SG_IO, &sgio);
}

static u16 gn_id(int bsg, u32 fcid, u16 cmd, u64 *wwn)
{
	struct {
		struct fc_ct_hdr hdr;
		u64 wwn;
	} __attribute__((__packed__)) gn_resp;

	struct {
		struct fc_ct_hdr hdr;
		u8 resv;
		u8 port_id[3];
	} __attribute__((__packed__)) gn = {
		.hdr = {
			.ct_rev		= FC_CT_REV,
			.ct_fs_type	= FC_FST_DIR,
			.ct_fs_subtype	= FC_NS_SUBTYPE,
			.ct_cmd		= htons(cmd),
			.ct_mr_size	= htons(sizeof(gn_resp)),
		},
		.port_id = hton24(fcid),
	};

	if (ns_query(bsg, &gn, sizeof(gn), &gn_resp, sizeof(gn_resp)) < 0)
		return ~0;
	if (gn_resp.hdr.ct_cmd != htons(FC_FS_ACC))
		return ct_rjt(gn_resp.hdr.ct_reason, gn_resp.hdr.ct_explan);
	*wwn = ntohll(gn_resp.wwn);
	return 0;
}

#define FC_NS_GPN_ID	0x0112
static int gpn_id(int bsg, u32 fcid)
{
	u64 wwpn;
	u16 rjt;

	rjt = gn_id(bsg, fcid, FC_NS_GPN_ID, &wwpn);
	if (rjt)
		goto fail;
	print_result("Port Name", "%16.16llx\n", wwpn);
	return 0;
fail:
	if (rjt == (u16) ~0)
		print_err("%s ioctl failed: %s\n", __func__, strerror(errno));
	else
		print_err("%s command failed: %s, %s\n", __func__,
			  rjt_reason[ct_rjt_reason(rjt)],
			  rjt_explan[ct_rjt_explan(rjt)]);
	return rjt;
}

#define FC_NS_GNN_ID	0x0113
static int gnn_id(int bsg, u32 fcid)
{
	u64 wwnn;
	u16 rjt;

	rjt = gn_id(bsg, fcid, FC_NS_GNN_ID, &wwnn);
	if (rjt)
		goto fail;
	print_result("Node Name", "%16.16llx\n", wwnn);
	return 0;
fail:
	if (rjt == (u16) ~0)
		print_err("%s ioctl failed: %s\n", __func__, strerror(errno));
	else
		print_err("%s command failed: %s, %s\n", __func__,
			  rjt_reason[ct_rjt_reason(rjt)],
			  rjt_explan[ct_rjt_explan(rjt)]);
	return rjt;
}

#define FC_NS_GSPN_ID	0x0118
static int gspn_id(int bsg, u32 fcid)
{
	struct {
		struct fc_ct_hdr hdr;
		u8 len;
		char name[255];
	} __attribute__((__packed__)) gspn_resp;

	struct {
		struct fc_ct_hdr hdr;
		u8 resv;
		u8 port_id[3];
	} __attribute__((__packed__)) gspn = {
		.hdr = {
			.ct_rev		= FC_CT_REV,
			.ct_fs_type	= FC_FST_DIR,
			.ct_fs_subtype	= FC_NS_SUBTYPE,
			.ct_cmd		= htons(FC_NS_GSPN_ID),
			.ct_mr_size	= htons(sizeof(gspn_resp)),
		},
		.port_id = hton24(fcid),
	};

	if (ns_query(bsg, &gspn, sizeof(gspn), &gspn_resp, sizeof(gspn_resp)) < 0) {
		print_err("%s ioctl failed: %s\n", __func__, strerror(errno));
		return ~0;
	}
	if (gspn_resp.hdr.ct_cmd != htons(FC_FS_ACC)) {
		print_err("%s command failed: %s, %s\n", __func__,
			  rjt_reason[gspn_resp.hdr.ct_reason],
			  rjt_explan[gspn_resp.hdr.ct_explan]);
		return ct_rjt(gspn_resp.hdr.ct_reason, gspn_resp.hdr.ct_explan);
	}
	print_result("Symbolic Port Name", "%s\n", gspn_resp.name);
	return 0;
}

#define FC_NS_GSNN_NN	0x0139
static int gsnn_nn(int bsg, u64 wwnn)
{
	struct {
		struct fc_ct_hdr hdr;
		u8 len;
		char name[255];
	} __attribute__((__packed__)) gsnn_resp;

	struct {
		struct fc_ct_hdr hdr;
		u64 wwnn;
	} __attribute__((__packed__)) gsnn = {
		.hdr = {
			.ct_rev		= FC_CT_REV,
			.ct_fs_type	= FC_FST_DIR,
			.ct_fs_subtype	= FC_NS_SUBTYPE,
			.ct_cmd		= htons(FC_NS_GSNN_NN),
			.ct_mr_size	= htons(sizeof(gsnn_resp)),
		},
		.wwnn = htonll(wwnn),
	};

	if (ns_query(bsg, &gsnn, sizeof(gsnn), &gsnn_resp, sizeof(gsnn_resp)) < 0) {
		print_err("%s ioctl failed: %s\n", __func__, strerror(errno));
		return ~0;
	}
	if (gsnn_resp.hdr.ct_cmd != htons(FC_FS_ACC)) {
		print_err("%s command failed: %s, %s\n", __func__,
			  rjt_reason[gsnn_resp.hdr.ct_reason],
			  rjt_explan[gsnn_resp.hdr.ct_explan]);
		return ct_rjt(gsnn_resp.hdr.ct_reason, gsnn_resp.hdr.ct_explan);
	}
	print_result("Symbolic Node Name", "%s\n", gsnn_resp.name);
	return 0;
}

enum commands {
	NONE = 0,
	GPN_ID,
	GNN_ID,
	GSPN_ID,
	GSNN_NN,
};

static const struct option options[] = {
	{ "gpn", required_argument, NULL, GPN_ID },
	{ "gnn", required_argument, NULL, GNN_ID },
	{ "gspn", required_argument, NULL, GSPN_ID },
	{ "gsnn", required_argument, NULL, GSNN_NN },
	{ "quiet", no_argument, NULL, 'q' },
	{ NULL, 0, NULL, 0 },
};

static void help(int status)
{
	printf(
		"Usage: fcnsq <host#> <command> [options]\n"
		"Commands:\n"
		"  --gpn  <port id>\n"
		"  --gnn  <port id>\n"
		"  --gspn <port id>\n"
		"  --gsnn <world wide node name>\n"
		"Options:\n"
		"  --quiet	print minimal results on success, and no error messages\n"
		"\n"
		"Port IDs and World Wide Names must be specified in hexadecimal.\n"
		);
	exit(status);
}

int main(int argc, char *argv[])
{
	char *bsg;
	int bsg_dev;
	u32 port_id;
	u64 wwnn;
	int rc = 0;
	enum commands cmd = 0;
	char c;

	while(1) {
		c = getopt_long_only(argc, argv, "", options, NULL);
		if (c < 0)
			break;
		switch(c) {
		case '?':
			help(-1);
			break;
		case 'q':
			quiet = true;
			break;
		case GPN_ID:
		case GNN_ID:
		case GSPN_ID:
			if (cmd)
				help(-1);
			cmd = c;
			sscanf(optarg, "%x", &port_id);
			break;
		case GSNN_NN:
			if (cmd)
				help(-1);
			cmd = c;
			sscanf(optarg, "%llx", &wwnn);
			break;
		}
	}

	if (cmd == NONE)
		help(-1);

	if (asprintf(&bsg, "/dev/bsg/fc_%s", argv[optind]) < 0) {
		if (!quiet)
			perror(NULL);
		return -1;
	}
	bsg_dev = open(bsg, O_RDWR);
	if (bsg_dev < 0) {
		if (!quiet)
			perror(bsg);
		return -1;
	}
	switch (cmd) {
	case GPN_ID:
		rc = gpn_id(bsg_dev, port_id);
		break;
	case GNN_ID:
		rc = gnn_id(bsg_dev, port_id);
		break;
	case GSPN_ID:
		rc = gspn_id(bsg_dev, port_id);
		break;
	case GSNN_NN:
		rc = gsnn_nn(bsg_dev, wwnn);
		break;
	default:
		help(-1);
		break;
	};
	close(bsg_dev);
	free(bsg);
	return rc;
}

