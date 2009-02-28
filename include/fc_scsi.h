/*
 * Copyright (c) 2008, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef _FC_SCSI_H_
#define	_FC_SCSI_H_

/*
 * SCSI definitions.
 * From T10 SBC-3.
 */

/*
 * Block size.
 */
#define	SCSI_BSIZE	512

/*
 * Operation codes.
 */
enum scsi_op {
	SCSI_OP_TEST_UNIT_READY = 0,	/* test unit ready */
	SCSI_OP_REQ_SENSE =	0x03,	/* request sense */
	SCSI_OP_INQUIRY =	0x12,	/* inquiry */
	SCSI_OP_START_STOP =	0x1b,	/* start/stop unit command */
	SCSI_OP_READ_CAP10 =	0x25,	/* read capacity (32-bit blk address) */
	SCSI_OP_READ10 =	0x28,	/* read (32-bit block address) */
	SCSI_OP_WRITE10 =	0x2a,	/* write (32-bit block address) */
	SCSI_OP_READ16 =	0x88,	/* read (64-bit block address) */
	SCSI_OP_SA_IN_16 =	0x9e,	/* serivice action in (16) */
	SCSI_OP_SA_OUT_16 =	0x9f,	/* serivice action out (16) */
	SCSI_OP_REPORT_LUNS =	0xa0,	/* report LUNs */
};

/*
 * Name table initializer for SCSI opcodes.
 * Please keep this in sync with the enum above.
 */
#define	SCSI_OP_NAME_INIT {					\
	[SCSI_OP_TEST_UNIT_READY] = "test unit ready",		\
	[SCSI_OP_REQ_SENSE] =	"request sense",		\
	[SCSI_OP_INQUIRY] =	"inquiry",			\
	[SCSI_OP_START_STOP] =	"start/stop unit",		\
	[SCSI_OP_READ_CAP10] =	"read_cap(10)",			\
	[SCSI_OP_READ10] =	"read(10)",			\
	[SCSI_OP_WRITE10] =	"write(10)",			\
	[SCSI_OP_READ16] =	"read(16)",			\
	[SCSI_OP_SA_IN_16] =	"sa_in(16)",			\
	[SCSI_OP_SA_OUT_16] =	"sa_out(16)",			\
	[SCSI_OP_REPORT_LUNS] =	"report LUNs",			\
}

/*
 * Service action codes.
 * Codes for SCSI_OP_SA_IN_16 and SCSI_OP_SA_OUT_16.
 */
enum scsi_sa_in_16 {
	SCSI_SA_READ_CAP16 =	0x10,	/* read capacity (16) (IN only) */
	SCSI_SA_RW_LONG =	0x11,	/* read/write long (16) */
};

/*
 * Status codes.
 */
enum scsi_status {
	SCSI_ST_GOOD =		0x00,	/* good */
	SCSI_ST_CHECK =		0x02,	/* check condition */
	SCSI_ST_COND_MET =	0x04,	/* condition met */
	SCSI_ST_BUSY =		0x08,	/* busy */
	SCSI_ST_INTMED =	0x10,	/* intermediate */
	SCSI_ST_INTMED_MET =	0x14,	/* intermediate, condition met */
	SCSI_ST_RESERVED =	0x18,	/* reservation conflict */
	SCSI_ST_TS_FULL =	0x28,	/* task set full */
	SCSI_ST_ACA_ACTV =	0x30,	/* ACA active */
	SCSI_ST_ABORTED =	0x40,	/* task aborted */
};

/*
 * Control byte.
 */
#define	SCSI_CTL_LINK (1 << 0)	/* Task is linked accross multiple commands */
#define	SCSI_CTL_NACA (1 << 2)	/* Normal auto contingent allegiance (ACA)  */

/*
 * Test Unit Ready command.
 */
struct scsi_test_unit_ready {
	net8_t		tr_op;		/* opcode (0) */
	net8_t		_tr_resvd[4];	/* reserved */
	net8_t		tr_control;	/* control bits */
};

/*
 * Request Sense command.
 */
struct scsi_req_sense {
	net8_t		rs_op;		/* opcode (0x88) */
	net8_t		rs_flags;	/* LSB is descriptor sense bit */
	net8_t		_rs_resvd[2];
	net8_t		rs_alloc_len;	/* allocated reply length */
	net8_t		rs_control;	/* control bits */
};

#define	SCSI_REQ_SENSE_LEN	6	/* expected length of struct */

#define	SCSI_SENSE_LEN_MAX	252	/* maximum rs_alloc_len */

/*
 * Start / stop command.
 */
struct scsi_start {
	net8_t		ss_op;		/* opcode (0x88) */
	net8_t		ss_immed;	/* LSB is respond-immediately bit */
	net8_t		_ss_resvd[2];
	net8_t		ss_flags;	/* power condition, flags */
	net8_t		ss_control;	/* control bits */
};

#define	SCSI_START_LEN		6	/* expected length of struct */

/*
 * ss_flags:
 */
#define	SCSI_SSF_START	    0x01	/* start */
#define	SCSI_SSF_LOEJ	    0x02	/* load or eject depending on start */

#define	SCSI_SSF_ACTIVE     0x10	/* set active power condition */
#define	SCSI_SSF_IDLE	    0x20	/* set idle power condition */
#define	SCSI_SSF_STANDBY    0x30	/* set idle power condition */
#define	SCSI_SSF_LU_CONTROL 0x70	/* set local control of power */
#define	SCSI_SSF_IDLE_0     0xa0	/* force idle timer to zero */
#define	SCSI_SSF_STDBY_0    0xb0	/* force standby timer to zero */

/*
 * Read Capacity (10) command.
 */
struct scsi_rcap10 {
	net8_t		rc_op;		/* opcode */
	net8_t		_rc_resvd;
	ua_net32_t	rc_lba;		/* logical block address */
	net8_t		_rc_resvd1[2];
	net8_t		rc_flags;	/* flags (see below) */
	net8_t		rc_control;	/* control */
};

#define	SCSI_RCAP10_LEN	10		/* expected length of struct */

#define	SCSI_RCAPF_PMI	(1 << 0)	/* rc_flags: partial medium indicator */

struct scsi_rcap10_resp {
	net32_t		rc_lba;		/* logical block address (size) */
	net32_t		rc_block_len;	/* block length in bytes */
};

/*
 * Read Capacity (16) command.
 */
struct scsi_rcap16 {
	net8_t		rc_op;		/* opcode (0x9e) */
	net8_t		rc_sa;		/* serivce action sub-opcode (0x10) */
	ua_net64_t	rc_lba;		/* logical block address */
	ua_net32_t	rc_alloc_len;	/* allocation length */
	net8_t		rc_flags;	/* flags (see scsi_rcap10 rc_flags) */
	net8_t		rc_control;	/* control */
};

#define	SCSI_RCAP16_LEN	16		/* expected length of struct */

struct scsi_rcap16_resp {
	net64_t		rc_lba;		/* logical block address (size) */
	net32_t		rc_block_len;	/* block length in bytes */
};

/*
 * Read(10) or write(10) command.
 */
struct scsi_rw10 {
	net8_t		rd_op;		/* opcode */
	net8_t		rd_flags;
	ua_net32_t	rd_lba;		/* logical block address */
	net8_t		rd_group;	/* group number */
	ua_net16_t	rd_len;		/* transfer length */
	net8_t		rd_control;	/* control */
};

#define	SCSI_RW10_LEN	10		/* expected length of struct */

/*
 * Read(16) or write(16) command.
 */
struct scsi_rw16 {
	net8_t		rd_op;		/* opcode */
	net8_t		rd_flags;
	ua_net64_t	rd_lba;		/* logical block address */
	ua_net32_t	rd_len;		/* transfer length */
	net8_t		rd_group;	/* group number */
	net8_t		rd_control;	/* control */
};

#define	SCSI_RW16_LEN	16		/* expected length of struct */

/*
 * Flags:
 */
#define	RDF_RWPROT_BIT	5		/* shift for RD/WRPROTECT field */
#define	RDF_DPO		0x10		/* disable page out - cache advisory */
#define	RDF_FUA		0x08		/* force unit access */
#define	RDF_FUA_NV	0x02		/* force unit access non-volatile */

/*
 * REPORT LUNS.
 */
struct scsi_report_luns {
	net8_t		rl_op;		/* opcode (0x88) */
	net8_t		_rl_resvd1;
	net8_t		rl_sel_report;	/* select report field */
	net8_t		_rl_resvd2[3];
	ua_net32_t	rl_alloc_len;	/* allocated length for reply */
	net8_t		_rl_resvd3;
	net8_t		rl_control;	/* control */
};

#define	SCSI_REPORT_LUNS_LEN 12	/* expected length of struct */

/*
 * rl_sel_report.
 */
#define	SCSI_RLS_WKL	1		/* req. well known LUNs only */
#define	SCSI_RLS_ITL	2		/* req. LUNs accessible to I_T nexus */

/*
 * REPORT LUNS repsonse.
 */
struct scsi_report_luns_resp {
	net32_t		rl_len;		/* list length in bytes */
	net8_t		_rl_resvd[4];
	net64_t		rl_lun[1];	/* list of LUNs */
};

/*
 * Inquiry.
 */
struct scsi_inquiry {
	net8_t		in_op;		/* opcode (0x12) */
	net8_t		in_flags;	/* LSB is EVPD */
	net8_t		in_page_code;	/* page code */

	/*
	 * Note that the in_alloc_len field was widened to 16-bits between
	 * SPC-2 and SPC-3, but some devices will ignore the upper 8 bits.
	 * It makes sense to use lengths less than 256 where possible.
	 */
	ua_net16_t	in_alloc_len;	/* allocated length for reply */
	net8_t		in_control;	/* control */
};

#define	SCSI_INQUIRY_LEN	6	/* expected length of struct */

/*
 * Inquiry in_flags.
 */
#define	SCSI_INQF_EVPD	(1 << 0)	/* request vital product data (VPD) page */

/*
 * SCSI Inquiry VPD Page Codes.
 */
enum scsi_inq_page {
	SCSI_INQP_SUPP_VPD =	0,	/* supported VPD list */
	SCSI_INQP_UNIT_SN =	0x80,	/* Unit serial number */
	SCSI_INQP_DEV_ID =	0x83,	/* Device Identification */
	SCSI_INQP_SW_IF_ID =	0x84,	/* Software Interface Identification */
	SCSI_INQP_MGMT_ADDR =	0x85,	/* management network addresses */
	SCSI_INQP_EXT_DATA =	0x86,	/* Extended Inquiry Data */
	SCSI_INQP_MD_PAGE_POL =	0x87,	/* Mode Page Policy */
	SCSI_INQP_SCSI_PORTS =	0x88,	/* SCSI Ports */
};

/*
 * Inquiry - standard data format.
 */
struct scsi_inquiry_std {
	net8_t		is_periph;	/* peripheral qualifier and type */
	net8_t		is_flags1;	/* flags (see below) */
	net8_t		is_version;
	net8_t		is_flags2;	/* flags / response data format */

	net8_t		is_addl_len;	/* additional length */
	net8_t		is_flags3;	/* flags (see below) */
	net8_t		is_flags4;
	net8_t		is_flags5;

	char		is_vendor_id[8]; /* ASCII T10 vendor identification */
	char		is_product[16];	/* ASCII product identification */
	char		is_rev_level[4]; /* ASCII revision level */
	char		is_vendor_spec[56 - 36]; /* vendor specific data */

	net8_t		is_clock_flags;	/* clocking, QAS, IUS flags */
	net8_t		is_resvd;
	net16_t		is_vers_desc[8]; /* version descriptors */

	/* followed by vendor-specific fields */
};

#define	SCSI_INQUIRY_STD_LEN	74	/* expected length of structure */

/*
 * Peripheral qualifier in is_periph field.
 */
#define	SCSI_INQ_PQUAL_MASK	0xe0	/* mask for peripheral qualifier */
#define	SCSI_INQ_PTYPE_MASK	0x1f	/* mask for peripheral type */

enum scsi_inq_pqual {
	SCSI_PQUAL_ATT =	0,		/* peripheral attached */
	SCSI_PQUAL_DET =	(1 << 5),	/* peripheral detached */
	SCSI_PQUAL_NC =		(3 << 5),	/* not capable of attachment */
};

enum scsi_inq_ptype {
	SCSI_PTYPE_DIR =	0x00,	/* direct acccess block device */
	SCSI_PTYPE_SEQ =	0x01,	/* sequential acccess block device */
	SCSI_PTYPE_PRINT =	0x02,	/* printer device (obsolete) */
	SCSI_PTYPE_PROC =	0x03,	/* processor device */
	SCSI_PTYPE_WORM =	0x04,	/* write-once device */
	SCSI_PTYPE_CDDVD =	0x05,	/* CD/DVD device */
	SCSI_PTYPE_SCANNER =	0x06,	/* scanner device (obsolete) */
	SCSI_PTYPE_OPTMEM =	0x07,	/* optical memory device */
	SCSI_PTYPE_CHANGER =	0x08,	/* medium changer device */
	SCSI_PTYPE_RAID =	0x0c,	/* storage array controoler (RAID) */
	SCSI_PTYPE_SES =	0x0d,	/* enclosure services device */
	SCSI_PTYPE_SDIR =	0x0e,	/* simplified direct acccess */
	SCSI_PTYPE_OCRW =	0x0f,	/* optical card reader/writer */
	SCSI_PTYPE_BCC =	0x10,	/* bridge controller commands */
	SCSI_PTYPE_OSD =	0x11,	/* object-based storage device */
	SCSI_PTYPE_ADC =	0x12,	/* automation/drive interface */
	SCSI_PTYPE_UNK =	0x1f,	/* unknown or no device type */
};

/*
 * is_flags[1-5] in the standard inquiry response.
 */
#define	SCSI_INQF1_RMB		(1 << 7) /* removable medium */

#define	SCSI_INQF2_NACA		(1 << 5) /* normal ACA */
#define	SCSI_INQF2_HISUP	(1 << 4) /* hierarchical LUN support */
#define	SCSI_INQF2_RDF_MASK	0xf	/* response data format mask */
#define	SCSI_INQF2_RDF		2	/* this response data format */

#define	SCSI_INQF3_PROTECT	(1 << 0) /* supports protection information */
#define	SCSI_INQF3_3PC		(1 << 3) /* supports third-party copy */
#define	SCSI_INQF3_TPGS_IMPL	(1 << 4) /* supports REPORT TARGET PORT GRPS */
#define	SCSI_INQF3_TPGS_EXPL	(1 << 5) /* supports SET TARGET PORT GROUPS */
#define	SCSI_INQF3_ACC		(1 << 6) /* access controls coordinator */
#define	SCSI_INQF3_SCCS	(1 << 7)	/* SCC supported (see SCC-2) */

#define	SCSI_INQF4_ADDR16	(1 << 0) /* parallel-SCSI only  */
#define	SCSI_INQF4_MULTIP	(1 << 4) /* multiport compliant */
#define	SCSI_INQF4_ENCSERV	(1 << 6) /* embedded enclosure services */
#define	SCSI_INQF4_BQUE		(1 << 7) /* basic task management model */

#define	SCSI_INQF5_CMDQUE	(1 << 1) /* full task management model */
#define	SCSI_INQF5_LINKED	(1 << 3) /* linked commands supported */
#define	SCSI_INQF5_SYNC		(1 << 4)	/* parallel-SCSI only  */
#define	SCSI_INQF5_WBUS16	(1 << 5)	/* parallel-SCSI only  */

/*
 * Inquiry - page 0 - supported VPD pages.
 */
struct scsi_inquiry_supp_vpd {
	net8_t		is_periph;	/* peripheral qualifier and type */
	net8_t		is_page_code;	/* page code (0x00) */
	net8_t		_is_resvd;	/* reserved */
	net8_t		is_list_len;	/* length of page list */
	net8_t		is_page_list[1]; /* supported page list - var. length */
};

/*
 * Inquiry - page 0x80 - unit serial number VPD page.
 */
struct scsi_inquiry_unit_sn {
	net8_t		is_periph;	/* peripheral qualifier and type */
	net8_t		is_page_code;	/* page code (0x80) */
	net8_t		_is_resvd;	/* reserved */
	net8_t		is_page_len;	/* length of serial number */
	net8_t		is_serial[1];	/* ASCII serial number - var. length */
};

/*
 * Inquiry - page 0x83 - device identification.
 */
struct scsi_inquiry_dev_id {
	net8_t		is_periph;	/* peripheral qualifier and type */
	net8_t		is_page_code;	/* page code (0x83) */
	net16_t		is_page_len;	/* len of designation descriptor list */

	/* descriptor list follows */
};

/*
 * Inquiry - page 0x83 designation descriptor list entry.
 */
struct scsi_inquiry_desc {
	net8_t		id_proto_code;	/* protocol identifier and code set */
	net8_t		id_type_flags;	/* designator type and flags */
	net8_t		_id_resvd;	/* reserved */
	net8_t		id_designator_len; /* designator length */
	net8_t		id_designator[1]; /* designator - variable length */
};

/*
 * id_proto_code field.
 */
#define	SCSI_INQ_CODE_MASK  0xf	/* mask for code set in id_proto_code */

enum scsi_inq_code_set {
	SCSI_CS_BIN =	1,	/* designator contains binary values */
	SCSI_CS_ASCII =	2,	/* designator contains printable ASCII */
	SCSI_CS_UTF8 =	3,	/* designator contains UTF-8 codes */
};

/*
 * id_type_flags field.
 */
#define	SCSI_INQT_PIV		(1 << 7) /* protocol identifier field valid */
#define	SCSI_INQT_ASSOC_BIT	4	/* shift count for association */
#define	SCSI_INQT_ASSOC_MASK	0x3	/* mask for association */
#define	SCSI_INQT_TYPE_MASK	0xf	/* mask for designator type */

enum scsi_inq_assoc {
	SCSI_ASSOC_LUN =	0,	/* designator is for the LUN */
	SCSI_ASSOC_PORT =	1,	/* designator is for the target port */
	SCSI_ASSOC_TARG =	2,	/* designator is for the target dev */
};

/*
 * Designator type field values.
 */
enum scsi_inq_dtype {
	SCSI_DTYPE_VENDOR =	0,	/* vendor specific */
	SCSI_DTYPE_T10_VENDOR =	1,	/* T10 vendor-ID based */
	SCSI_DTYPE_EUI_64 =	2,	/* EUI-64 based */
	SCSI_DTYPE_NAA =	3,	/* network address authority (WWN) */
	SCSI_DTYPE_RTPI =	4,	/* relative target port id */
	SCSI_DTYPE_TPORTG =	5,	/* target port group */
	SCSI_DTYPE_LPORTG =	6,	/* logical port group */
	SCSI_DTYPE_MD5_LUN =	7,	/* MD5 LU identifier */
	SCSI_DTYPE_SCSI_NAME =	8,	/* SCSI name string */
};

#endif /* _FC_SCSI_H_ */
