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
#include <dirent.h>
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
#include <scsi/fc/fc_els.h>
#include <scsi/scsi_bsg_fc.h>

#define ntoh24(n) (u32) ((n)[0] << 16 | (n)[1] << 8  | (n)[2])
#define hton24(h) { (h) >> 16 & 0xff, (h) >> 8 & 0xff, (h) & 0xff }

#define SYSFS_FC_RPORTS "/sys/class/fc_remote_ports"

struct rport_info {
	int host_no;
	int channel;
	u32 number;
	u32 port_id;
	bool found;
	bool online;
};

struct fcoe_fc_els_lesb {
	__be32 lesb_link_fail;	/* link failure count */
	__be32 lesb_vlink_fail; /* virtual link failure count */
	__be32 lesb_miss_fka;	/* missing FIP keep-alive count */
	__be32 lesb_symb_err;	/* symbol error during carrier count */
	__be32 lesb_err_block;	/* errored block count */
	__be32 lesb_fcs_error; /* frame check sequence error count */
} __attribute__((__packed__));

union rls_acc {
	struct fc_els_lesb fs3;
	struct fcoe_fc_els_lesb bb5;
} __attribute__((__packed__));

struct rls_rjt {
	u8 er_resv;
	u8 er_reason;
	u8 er_explan;
	u8 er_vendor;
} __attribute__((__packed__));

struct rls_rsp {
	u8 rls_cmd;
	u8 rls_resv[3];
	union rls_acc acc;
	struct rls_rjt rjt;
} __attribute__((__packed__));

static char *rjt_reason[] = {
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
	[0xFF] = "Vendor specific",
	[0x100] = "N/A",
};

static char *rjt_explan[] = {
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
	[0x17] = "invalid OX_ID-RX_ID combination",
	[0x19] = "Request already in progress",
	[0x1e] = "N_Port login required",
	[0x29] = "insufficient resources",
	[0x2a] = "unable to supply requested data",
	[0x2c] = "Request not supported",
	[0x2d] = "Invalid payload length",
	[0x44] = "Invalid Port/Node_Name",
	[0x46] = "Login Extension not supported",
	[0x48] = "Authentication required",
	[0x50] = "Periodic Scan Value not allowed",
	[0x51] = "Periodic Scanning not supported",
	[0x60] = "MAC addressing mode not supported",
	[0x61] = "Proposed MAC address incorrectly formed",
	[0xf0] = "Authorization Exception",
	[0xf1] = "Authentication Exception",
	[0xf2] = "Data base full",
	[0xf3] = "Data base empty",
	[0xf4] = "Processing request",
	[0xf5] = "Unable to verify connection",
	[0xf6] = "Devices not in a common zone",
	[0x100] = "N/A",

};

enum commands {
	NONE = 0,
	RLS_PORT,
	RLS_FCID,
	RLS_QUIET,
	RLS_HELP,
};

/* RLS_QUIET */
static bool quiet;

/* : - has arg
 * :: - has optional arg
 * ;  - arg is long opt
 */
static const struct option lopt[] = {
	{ "port", required_argument, NULL, RLS_PORT },
	{ "fcid", required_argument, NULL, RLS_FCID },
	{ "quiet", no_argument, NULL, RLS_QUIET },
	{ "help", no_argument, NULL, RLS_HELP },
	{ NULL, 0, NULL, 0 },
};

static const char *lopt_usage[] = {
	"rport bsg name, e.g., rport-7:0-1.",
	"rport port FC_ID, e.g., 0xce000d.",
	"disable verbose output.",
	"print useage information.",
	NULL,
};

#define bsg_error(format...)		\
({					\
	fprintf(stderr, "ERROR: " format);	\
})

#define bsg_debug(format...)		\
({					\
	if (!quiet)			\
		printf("DEBUG: " format);		\
})

static char *els_rjt2str(int type, int code)
{
	char **str;

	str = (type == 0) ? rjt_reason : rjt_explan;

	if (code > 0xff)
		code = 0x100;

	if (!str[code])
		code = 0x100;

	return str[code];
}

static int els_print_lesb(struct fcoe_fc_els_lesb *lesb)
{
	printf("RLS request accepted (LS_ACC), dumping status counters:\n"
		"\tLink Failure Count                   = %u\n"
		"\tVirtual Link Failure Count           = %u\n"
		"\tMissed Discovery Advertisement Count = %u\n"
		"\tSymbol Error During Carrier Count    = %u\n"
		"\tErrored Block Count                  = %u\n"
		"\tFrame Check Sequence Error Count     = %u\n",
		ntohl(lesb->lesb_link_fail),
		ntohl(lesb->lesb_vlink_fail),
		ntohl(lesb->lesb_miss_fka),
		ntohl(lesb->lesb_symb_err),
		ntohl(lesb->lesb_err_block),
		ntohl(lesb->lesb_fcs_error));

	return 0;
}

static int els_print_rjt(struct rls_rjt *rjt)
{
	printf("RLS request rejected (LS_RJT), check reason code below:\n"
		"\tReason Code  = 0x%02x, %s.\n"
		"\tExplain Code = 0x%02x, %s.\n",
		rjt->er_reason, els_rjt2str(0, rjt->er_reason),
		rjt->er_explan, els_rjt2str(1, rjt->er_explan));
	if (rjt->er_reason == ELS_RJT_VENDOR)
		printf("\tVendor Code  = 0x%02x (check with your vendor).\n",
		       rjt->er_vendor);
	return 0;
}

static int bsg_rport_els(int bsg, u8 els_code, void *req, int req_len,
			 void *rsp, int rsp_len)
{
	int rc;
	char sense[96];
	struct fc_bsg_reply *reply = (struct fc_bsg_reply *)sense;
	struct fc_bsg_request cdb = {
		.msgcode 	= FC_BSG_RPT_ELS,
		.rqst_data.r_els = {
			.els_code = els_code,
		}
	};

	struct sg_io_v4 sgio = {
		.guard			= 'Q',
		.protocol		= BSG_PROTOCOL_SCSI,
		.subprotocol		= BSG_SUB_PROTOCOL_SCSI_TRANSPORT,
		.request_len		= sizeof(cdb),
		.request		= (uintptr_t)&cdb,
		.dout_xfer_len		= req_len,
		.dout_xferp		= (uintptr_t)req,
		.din_xfer_len		= rsp_len,
		.din_xferp		= (uintptr_t)rsp,
		.max_response_len	= sizeof(sense),
		.response		= (uintptr_t)&sense,
		.timeout		= 1000,
	};
	memset(sense, 0, sizeof(sense));
	rc = ioctl(bsg, SG_IO, &sgio);
	bsg_debug("ioctl returned %d: bsg_reply result=%d\n",
		 rc, reply->result);
	return rc;
}

static int bsg_rport_els_rls(int bsg, struct rport_info *rpi)
{
	int rc = EOPNOTSUPP;
	struct fc_els_rls rls = {
		.rls_cmd = ELS_RLS,
		.rls_port_id = hton24(rpi->port_id),
	};
	struct rls_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rc = bsg_rport_els(bsg, ELS_RLS, &rls, sizeof(rls), &rsp, sizeof(rsp));
	if (rc) {
		bsg_error("bsg_rport_els(ELS_RLS) failed\n");
		return rc;
	}
	if (rsp.rls_cmd == ELS_LS_ACC)
		return	els_print_lesb(&rsp.acc.bb5);

	if (rsp.rls_cmd == ELS_LS_RJT)
		return els_print_rjt(&rsp.rjt);

	bsg_error("Unknow response!\n");
	return EIO;
}

static int rport_getid(struct rport_info *rpi)
{
	FILE *f;
	char rp_sysfs[256];

	if (rpi->found)
		return 0;
	snprintf(rp_sysfs, sizeof(rp_sysfs), "%s/rport-%d:%d-%d/port_id",
		SYSFS_FC_RPORTS, rpi->host_no, rpi->channel, rpi->number);
	f = fopen(rp_sysfs, "ro");
	if (!f) {
		bsg_error("failed to fopen(%s)!\n", rp_sysfs);
		return ENODEV;
	}
	if (1 != fscanf(f, "0x%6x", &rpi->port_id)) {
		bsg_error("failed to fscanf(%s)\n", rp_sysfs);
		fclose(f);
		return ENODEV;
	}
	if (rpi->port_id & 0xff000000) {
		bsg_error("rport %s:invalid fcid 0x%x\n", rp_sysfs,
			  rpi->port_id);
		rpi->port_id = 0;
		fclose(f);
		return ENODEV;
	}
	fclose(f);
	return 0;
}

/*
 * parse a string in format of rport-%d:%d-%d, and get the
 * corresponding rport info.
 * rport-%d:%d-%d
 */
static int rport_parse(const char *s, struct rport_info *rpi)
{
	if (!s)
		return EINVAL;
	memset(rpi, 0, sizeof(*rpi));
	if (3 != sscanf(s, "rport-%d:%d-%d", &rpi->host_no, &rpi->channel,
			&rpi->number))
		return ENODEV;
	if (rport_getid(rpi))
		return ENODEV;
	return 0;
}

#define RPORT_ONLINE	"Online"
static int rport_check_state(struct rport_info *rpi)
{
	FILE *f;
	char rp_sysfs[256];
	char rp_state[256];

	rpi->online = false;
	if (!rpi->found)
		return EINVAL;

	snprintf(rp_sysfs, sizeof(rp_sysfs), "%s/rport-%d:%d-%d/port_state",
		SYSFS_FC_RPORTS, rpi->host_no, rpi->channel, rpi->number);

	f = fopen(rp_sysfs, "ro");
	if (!f) {
		bsg_error("failed to fopen(%s)!\n", rp_sysfs);
		return ENODEV;
	}
	if (!fgets(rp_state, sizeof(rp_state), f)) {
		bsg_error("failed to fgets(%s)!\n", rp_sysfs);
		fclose(f);
		return ENODEV;
	}
	if (strncmp(rp_state, RPORT_ONLINE, strlen(RPORT_ONLINE))) {
		bsg_error("rport 0x%x %s:must be %s\n", rpi->port_id,
			rp_state, RPORT_ONLINE);
		fclose(f);
		return ENODEV;
	}
	rpi->online = true;
	fclose(f);
	return 0;
}
/* locate rport by fcid */
static int rport_find(struct rport_info *rpi)
{
	int n;
	struct dirent **namelist;
	struct rport_info rpii;

	if (rpi->found)
		return 0;

	if (!rpi->port_id)
		return ENODEV;

	n = scandir(SYSFS_FC_RPORTS, &namelist, 0, alphasort);
	if (n < 0) {
		bsg_error("failed to scandir %s\n", SYSFS_FC_RPORTS);
		return ENODEV;
	}
	while (n--) {
		if ((namelist[n]->d_type != DT_DIR) &&
		    (namelist[n]->d_type != DT_LNK))
			goto free_name;
		if (rport_parse(namelist[n]->d_name, &rpii))
			goto free_name;
		if (rpi->port_id != rpii.port_id)
			goto free_name;
		rpii.found = true;
		memcpy(rpi, &rpii, sizeof(rpii));
		bsg_debug("found rport 0x%06x as rport-%d:%d-%d\n",
			  rpi->port_id, rpi->host_no, rpi->channel,
			  rpi->number);
free_name:
		free(namelist[n]);
	}
	free(namelist);
	return 0;
}

static void bsg_usage(int status)
{
	int i, n;

	if (status)
		bsg_error("Failed! %s (Errno %d)!\n", strerror(status), status);

	n = sizeof(lopt)/sizeof(struct option) - 1;
	printf("Usage: fcrls\n");
	for (i = 0; i < n; i++)
		printf("\t--%s: %s\n", lopt[i].name, lopt_usage[i]);
	exit(status);
}


int main(int argc, char *argv[])
{
	int rc = ENODEV;
	int opt;
	int bsg_dev;
	char *endptr;
	char *bsg_name = NULL;
	struct rport_info rpi;

	rpi.found = false;
	while ((opt = getopt_long(argc, argv, "", lopt, NULL)) != -1) {
		switch (opt) {
		case RLS_PORT:
			if (rport_parse(optarg, &rpi)) {
				bsg_error("%s format incorrect, must be:"
					"rport-host:channel-number\n", optarg);
				bsg_usage(EINVAL);
			}
			rpi.found = true;
			goto out_rls;
		case RLS_FCID:
			rpi.found = false;
			rpi.port_id = strtoull(optarg, &endptr, 16);
			if (*endptr != '\0') {
				bsg_error("%s has no valid FCID\n", optarg);
				bsg_usage(EINVAL);
			}
			if (rport_find(&rpi)) {
				bsg_error("%s is not a rport\n", optarg);
				bsg_usage(ENODEV);
			}
			goto out_rls;
		case RLS_QUIET:
			quiet = true;
			break;
		case RLS_HELP:
			bsg_usage(0);
			break;
		}
	}
out_rls:
	/* bsg device name */
	if (!rpi.found)
		bsg_usage(ENODEV);

	if (asprintf(&bsg_name, "/dev/bsg/rport-%d:%d-%d",
		     rpi.host_no, rpi.channel, rpi.number) < 0) {
		rc = ENOMEM;
		bsg_error("not enough memory!\n");
		goto out_error;
	}
	/* open bsg device */
	bsg_dev = open(bsg_name, O_RDWR);
	if (bsg_dev < 0) {
		bsg_error("failed to open %s!\n", bsg_name);
		goto out_free;
	}
	/* check port state */
	if (rport_check_state(&rpi) || (!rpi.online)) {
		bsg_error("rport 0x%x is not online!\n", rpi.port_id);
		goto out_close;
	}
	/* send rls */
	rc = bsg_rport_els_rls(bsg_dev, &rpi);
	if (rc) {
		bsg_error("Faild to bsg_rport_els_rls\n");
		goto out_close;
	}
	rc = 0;

out_close:
	close(bsg_dev);
out_free:
	free(bsg_name);
out_error:
	return rc;
}
