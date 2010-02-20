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

/*
 * FCPing - FC fabric diagnostic.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <malloc.h>
#include <limits.h>
#include <signal.h>
#include <libgen.h>
#include <assert.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <hbaapi.h>
#include <vendorhbaapi.h>
#include <linux/types.h>
#include <linux/bsg.h>
#include "net_types.h"
#include "fc_types.h"
typedef uint8_t u8;
#include <scsi/sg.h>
#include <scsi/fc/fc_ns.h>
#include <scsi/fc/fc_gs.h>
#include <scsi/fc/fc_els.h>
#include <scsi/scsi_bsg_fc.h>

#include "fcoe_utils.h"

static const char *cmdname;

#define FC_MAX_PAYLOAD  (2112U - sizeof(net32_t))
#define MAX_SENSE_LEN	96	/* SCSI_SENSE_BUFFERSIZE */
#define MAX_HBA_COUNT	128
#define FP_LEN_DEF	32	/* default ping payload length */
#define FP_LEN_PAD	32	/* extra length for response */
#define FP_MIN_INTVL	0.001	/* minimum interval in seconds */
#define FP_DEF_INTVL	1.000	/* default sending interval in seconds */
#define SYSFS_HBA_DIR   "/sys/class/net"

static void
fp_usage()
{
	fprintf(stderr,
	"Usage: %s [-fqx] -i <interval> -c <count> -h <hba> -s <size> \\\n"
	"                [ -F <FC-ID> | -P <WWPN> | -N <WWNN>]\n"
	"  flags: \n"
	"     -f:            Flood ping\n"
	"     -q:            Quiet! just print summary\n"
	"     -x:            Hex dump of responses\n"
	"     -i <interval>: Wait <interval> seconds between each ping\n"
	"     -c <count>:    Stop after sending <count> pings\n"
	"     -h <hba>:      eth<n>, MAC address, WWPN, or FC-ID of the HBA\n"
	"     -s <size>:     Byte-length of ping request payload (max %ld)\n"
	"     -F <FC-ID>:    Destination port ID\n"
	"     -P <WWPN>:     Destination world-wide port name\n"
	"     -N <WWNN>:     Destination world-wide node name\n",
	cmdname, FC_MAX_PAYLOAD);
	exit(1);
}

static fc_fid_t fp_did;
static fc_wwn_t fp_port_wwn;
static fc_wwn_t fp_node_wwn;
static int fp_count = -1;	/* send indefinitely by default */
static uint32_t fp_len = FP_LEN_DEF;
static int fp_flood;			/* send as fast as possible */
static uint32_t fp_interval = FP_DEF_INTVL * 1000; /* in milliseconds */
static int fp_quiet;
static int fp_hex;
static char *fp_hba;	/* name of interface to be used */
static int fp_hba_type;
#define FP_HBA_FCID_TYPE	1
#define FP_HBA_WWPN_TYPE	2
#define FP_HBA_HOST_TYPE	3
#define FP_HBA_ETH_TYPE		4
static char fp_dev[64];
static int fp_fd;	/* file descriptor for openfc ioctls */
static void *fp_buf;	/* sending buffer */
static int fp_debug;

struct fp_stats {
	uint32_t fp_tx_frames;
	uint32_t fp_rx_frames;
	uint32_t fp_rx_errors;
	uint64_t fp_transit_time_us; /* total transit time in microseconds */
	uint32_t fp_rx_times;        /* valid times on receive */
};
static struct fp_stats fp_stats;

#define hton24(p, v) \
do { \
	p[0] = (((v) >> 16) & 0xFF);	\
	p[1] = (((v) >> 8) & 0xFF);	\
	p[2] = ((v) & 0xFF);		\
} while (0)

#define hton64(p, v) \
do { \
	p[0] = (u_char) ((v) >> 56) & 0xFF;	\
	p[1] = (u_char) ((v) >> 48) & 0xFF;	\
	p[2] = (u_char) ((v) >> 40) & 0xFF;	\
	p[3] = (u_char) ((v) >> 32) & 0xFF;	\
	p[4] = (u_char) ((v) >> 24) & 0xFF;	\
	p[5] = (u_char) ((v) >> 16) & 0xFF;	\
	p[6] = (u_char) ((v) >> 8) & 0xFF;	\
	p[7] = (u_char) (v) & 0xFF;		\
} while (0)

static void sa_log_func(const char *func, const char *format, ...);
static void sa_log_err(int, const char *func, const char *format, ...);
static void sa_log_output(const char *buf);

/*
 * Log message.
 */
#define SA_LOG(...) \
	do { sa_log_func(__func__, __VA_ARGS__); } while (0)

#define SA_LOG_ERR(error, ...) \
	do { sa_log_err(error, NULL, __VA_ARGS__); } while (0)

/*
 * Logging exits.
 */
#define SA_LOG_EXIT(...) \
	do {	sa_log_func(__func__, __VA_ARGS__); \
		if (fp_debug) \
			sa_log_func(__func__, \
			"Exiting at %s:%d", __FILE__, __LINE__); \
		exit(1); \
	} while (0)

#define SA_LOG_ERR_EXIT(error, ...) \
	do {	sa_log_func(__func__, __VA_ARGS__); \
		if (fp_debug) \
			sa_log_err(error, __func__, \
			"Exiting at %s:%d", __FILE__, __LINE__); \
		else \
			sa_log_err(error, NULL, NULL); \
		exit(1); \
	} while (0)

#define SA_LOG_BUF_LEN  200     /* on-stack line buffer size */

/*
 * log with a variable argument list.
 */
static void
sa_log_va(const char *func, const char *format, va_list arg)
{
	size_t len;
	size_t flen;
	int add_newline;
	char sa_buf[SA_LOG_BUF_LEN];
	char *bp;

	/*
	 * If the caller didn't provide a newline at the end, we will.
	 */
	len = strlen(format);
	add_newline = 0;
	if (!len || format[len - 1] != '\n')
		add_newline = 1;
	bp = sa_buf;
	len = sizeof(sa_buf);
	if (func) {
		flen = snprintf(bp, len, "%s: ", func);
		len -= flen;
		bp += flen;
	}
	flen = vsnprintf(bp, len, format, arg);
	if (add_newline && flen < len) {
		bp += flen;
		*bp++ = '\n';
		*bp = '\0';
	}
	sa_log_output(sa_buf);
}

/*
 * log with function name.
 */
static void
sa_log_func(const char *func, const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	if (fp_debug)
		sa_log_va(func, format, arg);
	else
		sa_log_va(NULL, format, arg);
	va_end(arg);
}

/*
 * log with error number.
 */
static void
sa_log_err(int error, const char *func, const char *format, ...)
{
	va_list arg;
	char buf[SA_LOG_BUF_LEN];

	strerror_r(error, buf, sizeof(buf));
	sa_log_func(func, "errno=%d %s", error, buf);
	if (format) {
		va_start(arg, format);
		sa_log_va(func, format, arg);
		va_end(arg);
	}
}

static void
sa_log_output(const char *buf)
{
	fprintf(stderr, "%s", buf);
	fflush(stderr);
}

static char *
sa_hex_format(char *buf, size_t buflen,
		const unsigned char *data, size_t data_len,
		unsigned int group_len, char *inter_group_sep)
{
	size_t rlen, tlen;
	char *bp, *sep;
	unsigned int i;

	rlen = buflen;
	bp = buf;
	sep = "";
	for (i = 0; rlen > 0 && i < data_len; ) {
		tlen = snprintf(bp, rlen, "%s%2.2x", sep, data[i]);
		rlen -= tlen;
		bp += tlen;
		i++;
		sep = (i % group_len) ? "" : inter_group_sep;
	}
	return buf;
}

/*
 * Hex dump buffer to file.
 */
static void sa_hex_dump(unsigned char *bp, size_t len, FILE *fp)
{
	char lbuf[120];
	size_t tlen;
	uint32_t offset = 0;

	while (len > 0) {
		tlen = 16;  /* bytes per line */
		if (tlen > len)
			tlen = len;
		sa_hex_format(lbuf, sizeof(lbuf), bp, tlen, 4, " ");
		fprintf(fp, "%6x %s\n", offset, lbuf);
		offset += tlen;
		len -= tlen;
		bp += tlen;
	}
}

/*
 * Convert 48-bit IEEE MAC address to 64-bit FC WWN.
 */
fc_wwn_t
fc_wwn_from_mac(uint64_t mac, uint32_t scheme, uint32_t port)
{
	fc_wwn_t wwn;

	assert(mac < (1ULL << 48));
	wwn = mac | ((fc_wwn_t) scheme << 60);
	switch (scheme) {
	case 1:
		assert(port == 0);
		break;
	case 2:
		assert(port < 0xfff);
		wwn |= (fc_wwn_t) port << 48;
		break;
	default:
		assert(1);
		break;
	}
	return wwn;
}

/*
 * Handle WWN/MAC arguments
 */
static fc_wwn_t
fp_parse_wwn(const char *arg, char *msg, uint32_t scheme, uint32_t port)
{
	char *endptr;
	fc_wwn_t wwn;
	fc_wwn_t oui;
	struct ether_addr mac;

	wwn = strtoull(arg, &endptr, 16);
	if (*endptr != '\0') {
		if (ether_aton_r(arg, &mac) == NULL &&
		    ether_hostton(arg, &mac) != 0) {
			SA_LOG_EXIT("invalid %s WWN or MAC addr %s", msg, arg);
		}
		oui = net48_get((net48_t *)mac.ether_addr_octet);
		wwn = fc_wwn_from_mac(oui, scheme, port);
	}
	return wwn;
}

/*
 * Handle options.
 */
static void
fp_options(int argc, char *argv[])
{
	int opt;
	char *endptr;
	float sec;
	int targ_spec = 0;

	cmdname = basename(argv[0]);
	if (argc <= 1)
		fp_usage();

	while ((opt = getopt(argc, argv, "c:fi:h:qs:xF:P:N:")) != -1) {
		switch (opt) {
		case 'c':
			fp_count = (int) strtoul(optarg, &endptr, 10);
			if (*endptr != '\0')
				SA_LOG_EXIT("bad count %s\n", optarg);
			break;
		case 'f':
			fp_flood = 1;
			break;
		case 'i':
			if (sscanf(optarg, "%f", &sec) != 1 ||
					sec < FP_MIN_INTVL)
				SA_LOG_EXIT("bad interval %s\n", optarg);
			fp_interval = sec * 1000;
			break;
		case 'h':
			fp_hba = optarg;
			break;
		case 'q':
			fp_quiet = 1;
			break;
		case 's':
			fp_len = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0' || fp_len > FC_MAX_PAYLOAD)
				SA_LOG_EXIT("bad size %s max %d\n",
					optarg, FC_MAX_PAYLOAD);
			if (fp_len < 4)
				SA_LOG_EXIT("bad size %s min %d\n",
					optarg, 4);
			break;
		case 'x':
			fp_hex = 1;
			break;

		/*
		 * -F specifies the target FC_ID.
		 */
		case 'F':
			fp_did = strtoull(optarg, &endptr, 16);
			if (*endptr != '\0')
				SA_LOG_EXIT("bad target FC_ID %s\n", optarg);
			targ_spec++;
			break;

		/*
		 * The -P and -N flags take a world-wide name in hex,
		 * or an ethernet addr, or an etherhost entry from /etc/ethers.
		 */
		case 'N':
			fp_node_wwn = fp_parse_wwn(optarg, "Node", 1, 0);
			targ_spec++;
			break;

		case 'P':
			fp_port_wwn = fp_parse_wwn(optarg, "Port", 2, 0);
			targ_spec++;
			break;

		case '?':
		default:
			fprintf(stderr, "FC_MAX_PAYLOAD=%lu\n", FC_MAX_PAYLOAD);
			fp_usage();	/* exits */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (fp_hba == NULL)
		SA_LOG_EXIT("FCoE interface not specified");

	if (targ_spec == 0)
		SA_LOG_EXIT("no target specified");

	if (targ_spec > 1)
		SA_LOG_EXIT("too many targets specified;"
			    " only one is allowed.");

	return;
}

/*
 * Lookup specified adapter using HBAAPI.
 */
static int
fp_find_hba(void)
{
	HBA_STATUS retval;
	HBA_UINT32 hba_cnt;
	HBA_HANDLE hba_handle = 0;
	HBA_ADAPTERATTRIBUTES hba_attrs;
	HBA_PORTATTRIBUTES port_attrs;
	HBA_UINT32 fcid = 0;
	struct stat statbuf;
	char namebuf[1028];
	char hba_dir[256];
	fc_wwn_t wwn = 0;
	HBA_WWN wwpn;
	char *endptr;
	int i, found = 0;

	/*
	 * Parse HBA spec. if there is one.
	 * These formats are tried:
	 *    If pass in an interface name, it does not need
	 *    to be validated here. The interface name can be
	 *    anything. It will have to be found via HBAAPI
	 *    library. It fails if not found.
	 *    host<n> = match the index <n>.
	 *    mac address xx:xx:xx:xx:xx:xx
	 *    otherwise, try parsing as a wwn and match that.
	 */

	snprintf(hba_dir, sizeof(hba_dir), SYSFS_HBA_DIR "/%s", fp_hba);
	if (!stat(hba_dir, &statbuf)) {
		fp_hba_type = FP_HBA_ETH_TYPE;
	} else if (strstr(fp_hba, "host") == fp_hba) {
		i = strtoul(fp_hba + 4, &endptr, 10);
		if (*endptr != '\0')
			SA_LOG_EXIT("invalid hba name %s", fp_hba);
		fp_hba_type = FP_HBA_HOST_TYPE;
	} else if (strstr(fp_hba, ":")) {
		wwn = fp_parse_wwn(fp_hba, "HBA", 2, 0);
		hton64(wwpn.wwn, wwn);
		fp_hba_type = FP_HBA_WWPN_TYPE;
	} else {
		wwn = strtoull(fp_hba, &endptr, 16);
		if (wwn < 0x1000000) {
			fcid = wwn;
			fp_hba_type = FP_HBA_FCID_TYPE;
		} else {
			if (*endptr != '\0')
				SA_LOG_EXIT("unsupported hba name");
			wwn = fp_parse_wwn(fp_hba, "HBA", 2, 0);
			hton64(wwpn.wwn, wwn);
			fp_hba_type = FP_HBA_WWPN_TYPE;
		}
	}

	hba_cnt = HBA_GetNumberOfAdapters();
	if (!hba_cnt)
		SA_LOG_EXIT("No FCoE interfaces created");

	for (i = 0; i < hba_cnt; i++) {
		retval = HBA_GetAdapterName(i, namebuf);
		if (retval != HBA_STATUS_OK) {
			SA_LOG("HBA_GetAdapterName"
				" failed, retval=%d", retval);
			continue;
		}

		hba_handle = HBA_OpenAdapter(namebuf);
		if (!hba_handle) {
			SA_LOG("HBA_OpenAdapter failed");
			continue;
		}

		retval = HBA_GetAdapterAttributes(hba_handle, &hba_attrs);
		if (retval != HBA_STATUS_OK) {
			SA_LOG("HBA_GetAdapterAttributes"
				" failed, retval=%d", retval);
			HBA_CloseAdapter(hba_handle);
			continue;
		}

		retval = HBA_GetAdapterPortAttributes(
				hba_handle, 0, &port_attrs);
		if (retval != HBA_STATUS_OK) {
			SA_LOG("HBA_GetAdapterPortAttributes"
				" failed, retval=%d", retval);
			HBA_CloseAdapter(hba_handle);
			continue;
		}

		switch (fp_hba_type) {
		case FP_HBA_FCID_TYPE:
			if (port_attrs.PortFcId != fcid) {
				HBA_CloseAdapter(hba_handle);
				continue;
			}
			break;
		case FP_HBA_WWPN_TYPE:
			if (memcmp(&port_attrs.PortWWN, &wwpn, sizeof(wwpn))) {
				HBA_CloseAdapter(hba_handle);
				continue;
			}
			break;
		case FP_HBA_HOST_TYPE:
			if (!strstr(port_attrs.OSDeviceName, fp_hba)) {
				HBA_CloseAdapter(hba_handle);
				continue;
			}
			break;
		default:
			if (check_symbolic_name_for_interface(
				    port_attrs.PortSymbolicName,
				    fp_hba)) {
				HBA_CloseAdapter(hba_handle);
				continue;
			}
			break;
		}

		snprintf(fp_dev, sizeof(fp_dev),
			"fc_%s", port_attrs.OSDeviceName);
		found = 1;
		break;
	}
	if (!found)
		SA_LOG("FCoE interface %s not found", fp_hba);

	return found;
}

static void
fp_report(void)
{
	double loss;
	struct fp_stats *sp = &fp_stats;

	loss = 100.0 * (sp->fp_tx_frames - sp->fp_rx_frames) / sp->fp_tx_frames;
	printf("%d frames sent, %d received %d errors, %.3f%% loss, "
		"avg. rt time %.3f ms\n",
		sp->fp_tx_frames, sp->fp_rx_frames, sp->fp_rx_errors, loss,
		sp->fp_rx_times ?  sp->fp_transit_time_us * 1.0 /
		(1000.0 * sp->fp_rx_times) : 0.0);
}

/*
 * Lookup ID from port name or node name.
 */
static int
fp_ns_get_id(uint32_t op, fc_wwn_t wwn, char *response, size_t *resp_len)
{
	struct ct_get_id {
		struct fc_ct_hdr hdr;
		net64_t	 wwn;
	} ct;
	struct fc_bsg_request cdb;
	struct fc_bsg_reply reply;
	struct sg_io_v4 sg_io;
	size_t actual_len;
	int cmd, rc = 0;

	memset((char *)&cdb, 0, sizeof(cdb));
	memset(&ct, 0, sizeof(ct));
	ct.hdr.ct_rev = FC_CT_REV;
	hton24(ct.hdr.ct_in_id, 0xfffffc);
	ct.hdr.ct_fs_type = FC_FST_DIR;
	ct.hdr.ct_fs_subtype = FC_NS_SUBTYPE;
	ct.hdr.ct_options = 0;
	ct.hdr.ct_cmd = htons(op);
	ct.hdr.ct_mr_size = *resp_len;
	net64_put(&ct.wwn, wwn);

	cdb.msgcode = FC_BSG_HST_CT;
	hton24(cdb.rqst_data.h_ct.port_id, 0xfffffc);
	memcpy(&cdb.rqst_data.h_ct.preamble_word0, &ct.hdr,
	       3 * sizeof(uint32_t));

	sg_io.guard = 'Q';
	sg_io.protocol = BSG_PROTOCOL_SCSI;
	sg_io.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	sg_io.request_len = sizeof(cdb);
	sg_io.request = (__u64)&cdb;
	sg_io.dout_xfer_len = sizeof(ct);
	sg_io.dout_xferp = (unsigned long)&ct;
	sg_io.din_xfer_len = *resp_len;
	sg_io.din_xferp = (__u64)response;
	sg_io.max_response_len = sizeof(reply);
	sg_io.response = (__u64)&reply;
	sg_io.timeout = 1000;	/* millisecond */
	memset(&reply, 0, sizeof(reply));
	memset(response, 0, *resp_len);

	rc = ioctl(fp_fd, SG_IO, &sg_io);
	if (rc < 0) {
		if (op == FC_NS_GID_PN)
			printf("GID_PN error: %s\n", strerror(errno));
		if (op == FC_NS_GID_NN)
			printf("GID_NN error: %s\n", strerror(errno));
		return rc;
	}

	cmd = ((response[8]<<8) | response[9]) & 0xffff;
	if (cmd != FC_FS_ACC)
		return -1;

	actual_len = reply.reply_payload_rcv_len;
	if (actual_len < *resp_len)
		*resp_len = actual_len;

	return 0;
}

static int
fp_lookup_target()
{
	char response[32];
	size_t resp_len;
	int rc;

	if (fp_did != 0)
		return 0;

	if (fp_port_wwn != 0) {
		resp_len = sizeof(response);
		memset(&response, 0, sizeof(response));
		rc = fp_ns_get_id(FC_NS_GID_PN, fp_port_wwn,
				response, &resp_len);
		if (rc == 0) {
			fp_did = ((response[17] << 16) & 0xff0000) |
				 ((response[18] << 8) & 0x00ff00) |
				 (response[19] & 0x0000ff);
			return 0;
		}
		SA_LOG("cannot find fcid of destination @ wwpn 0x%llX",
			fp_port_wwn);
	}
	if (fp_node_wwn != 0) {
		resp_len = sizeof(response);
		memset(&response, 0, sizeof(response));
		rc = fp_ns_get_id(FC_NS_GID_NN, fp_node_wwn,
				response, &resp_len);
		if (rc == 0) {
			fp_did = ((response[17] << 16) & 0xff0000) |
				 ((response[18] << 8) & 0x00ff00) |
				 (response[19] & 0x0000ff);
			return 0;
		}
		SA_LOG("cannot find fcid of destination @ wwnn 0x%llX",
			fp_node_wwn);
	}
	return 1;
}

/*
 * ELS_ECHO request format being used.
 * Put a sequence number in the payload, followed by the pattern.
 */
struct fcping_echo {
	net8_t      fe_op;              /* opcode */
	net24_t     fe_resvd;           /* reserved, must be zero */
	net32_t     fe_seq;             /* sequence number */
};

/*
 * Setup buffer to be sent.
 */
static void
fp_buf_setup(void)
{
	struct fcping_echo *ep;
	net8_t *pp;
	int len;
	int i;

	/*
	 * Alloc extra in case of odd len or shorter than minimum.
	 */
	len = fp_len + sizeof(*ep) + sizeof(net32_t);
	ep = calloc(1, len);
	if (ep == NULL)
		SA_LOG_ERR_EXIT(errno, "calloc %d bytes failed", len);
	ep->fe_op = ELS_ECHO;
	net32_put(&ep->fe_seq, 1);      /* starting sequence number */
	i = 0;
	for (pp = (net8_t *) (ep + 1); pp < (net8_t *) ep + fp_len; pp++)
		*pp = i++;
	fp_buf = ep;
}

static unsigned long long
fp_get_time_usec(void)
{
#ifdef _POSIX_TIMERS
	struct timespec ts;
	int rc;

	rc = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (rc)
		SA_LOG_ERR_EXIT(errno, "clock_gettime error");
	return ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
#else
#warning no _POSIX_TIMERS
	struct timeval ts;

	gettimeofday(&ts, NULL);
	return ts.tv_sec * 1000000ULL + ts.tv_usec;
#endif /* _POSIX_TIMERS */
}

static int
send_els_echo(int fp_fd, void *fp_buf, uint32_t fp_len,
		unsigned char *resp, uint32_t *resp_len, fc_fid_t fp_did)
{
	struct fc_bsg_request cdb;
	char sense[MAX_SENSE_LEN];
	struct sg_io_v4 sg_io;
	int rc;

	cdb.msgcode = FC_BSG_HST_ELS_NOLOGIN;
	cdb.rqst_data.h_els.command_code = ELS_ECHO;
	hton24(cdb.rqst_data.h_els.port_id, fp_did);

	sg_io.guard = 'Q';
	sg_io.protocol = BSG_PROTOCOL_SCSI;
	sg_io.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	sg_io.request_len = sizeof(cdb);
	sg_io.request = (unsigned long)&cdb;
	sg_io.dout_xfer_len = fp_len;
	sg_io.dout_xferp = (unsigned long)fp_buf;
	sg_io.din_xfer_len = *resp_len;
	sg_io.din_xferp = (unsigned long)resp;
	sg_io.max_response_len = sizeof(sense);
	sg_io.response = (unsigned long)sense;
	sg_io.timeout = 20000;
	memset(sense, 0, sizeof(sense));

	rc = ioctl(fp_fd, SG_IO, &sg_io);
	if (rc < 0)
		return 1;

	*resp_len = sg_io.din_xfer_len - sg_io.din_resid;
	return 0;
}

/*
 * Send ELS ECHO.
 */
static int fp_send_ping(void)
{
	struct fp_stats *sp = &fp_stats;
	struct fcping_echo *ep;
	int rc;
	uint32_t resp_len;
	unsigned char *resp;
	unsigned long long tx_time;
	unsigned long long usec;
	char msg[80];
	char time_msg[80];

	resp_len = fp_len + FP_LEN_PAD; /* for odd-byte padding and then some */
	resp = calloc(1, resp_len);
	if (resp == NULL)
		SA_LOG_EXIT("calloc %d bytes failed", resp_len);

	sp->fp_tx_frames++;
	if (fp_len >= sizeof(*ep)) {
		ep = (struct fcping_echo *) fp_buf;
		net32_put(&ep->fe_seq, sp->fp_tx_frames);
	}
	tx_time = fp_get_time_usec();

	/* send ELS ECHO frame and receive */
	rc = send_els_echo(fp_fd, fp_buf, fp_len, resp, &resp_len, fp_did);
	if (rc) {
		sp->fp_rx_errors++;
		printf("echo %4d error: %s\n",
			sp->fp_tx_frames, strerror(errno));
	} else {
		usec = fp_get_time_usec();
		sp->fp_rx_frames++;
		ep = (struct fcping_echo *) resp;
		if (usec < tx_time) {
			snprintf(time_msg, sizeof(time_msg),
				"time unknown now %llx old %llx",
				usec, tx_time);
			usec = 0;	/* as if time went backwards */
		} else {
			usec = usec - tx_time;
			snprintf(time_msg, sizeof(time_msg),
				"%6.3f ms", usec / 1000.0);
			sp->fp_transit_time_us += usec;
			sp->fp_rx_times++;
		}
		if (ep->fe_op == ELS_LS_ACC) {
			if (memcmp((char *) ep + 1,
					(char *) fp_buf + 1, fp_len - 1) == 0)
				snprintf(msg, sizeof(msg), "accepted");
			else {
				sp->fp_rx_errors++;
				snprintf(msg, sizeof(msg),
					"accept data mismatches");
			}
		} else if (ep->fe_op == ELS_LS_RJT) {
			sp->fp_rx_errors++;
			snprintf(msg, sizeof(msg), "REJECT received");
		} else {
			sp->fp_rx_errors++;
			snprintf(msg, sizeof(msg),
				"op %x received", ep->fe_op);
		}
		if (fp_quiet == 0)
			printf("echo %4d %-30s %s\n",
				sp->fp_tx_frames, msg, time_msg);
	}
	if (fp_hex) {
		printf("response length %u\n", resp_len);
		sa_hex_dump(resp, resp_len, stdout);
		printf("\n");
	}
	free(resp);
	return rc;
}

static void
fp_signal_handler(int sig)
{
	/*
	 * Allow graceful termination of the
	 * for loop in fp_start.
	 */
	fp_count = 0;
}

/*
 * Main loop.
 */
static void fp_start(void)
{
	struct sigaction act;
	int i;
	int rc;

	memset(&act, 0, sizeof(act));
	act.sa_handler = fp_signal_handler;
	act.sa_flags = 0;

	sigaction(SIGTERM, &act, NULL);		/* Signal 15: kill <pid> */
	sigaction(SIGQUIT, &act, NULL);		/* Signal 3: Ctrl-\ */
	sigaction(SIGINT,  &act, NULL);		/* Signal 2: Ctrl-C */

	printf("sending echo to 0x%X\n", fp_did);
	for (i = 0; fp_count == -1 || i < fp_count; i++) {
		rc = fp_send_ping();
		if (rc != 0 && errno == EMSGSIZE)
			break;
		if (rc != 0 && errno == ECONNABORTED)
			break;
		if (fp_flood == 0)
			usleep(fp_interval * 1000);
		if (!fp_count)
			break;
	}
}

/*
 * Main.
 */
int main(int argc, char *argv[])
{
	char bsg_dev[80];
	int rc = 1;

	fp_options(argc, argv);

	if (HBA_LoadLibrary() != HBA_STATUS_OK)
		SA_LOG_ERR_EXIT(errno, "HBA_LoadLibrary failed");

	if (fp_find_hba()) {
		sprintf(bsg_dev, "/dev/bsg/%s", fp_dev);
		fp_fd = open(bsg_dev, O_RDWR);
		if (fp_fd < 0)
			SA_LOG_ERR_EXIT(errno,
				"open of %s failed", bsg_dev);

		if (!fp_lookup_target()) {
			fp_buf_setup();
			fp_start();
			fp_report();
			rc = 0;
		}
		close(fp_fd);
	}

	HBA_FreeLibrary();
	return rc;
}
