/*
 * Copyright(c) 2015 SUSE GmbH. All rights reserved.
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
 * Maintained at www.Open-FCoE.org
 */

#ifndef _SYSFS_HBA_H
#define _SYSFS_HBA_H

#include <stdint.h>

#define SYSFS_HOST_DIR	"/sys/class/fc_host"
#define SYSFS_NET_DIR	"/sys/class/net"
#define SYSFS_RPORT_DIR	"/sys/class/fc_remote_ports"

#define HBA_PORTSTATE_UNKNOWN		1   /* Unknown */
#define HBA_PORTSTATE_ONLINE		2   /* Operational */
#define HBA_PORTSTATE_OFFLINE		3   /* User Offline */
#define HBA_PORTSTATE_BYPASSED		4   /* Bypassed */
#define HBA_PORTSTATE_DIAGNOSTICS	5   /* In diagnostics mode */
#define HBA_PORTSTATE_LINKDOWN		6   /* Link Down */
#define HBA_PORTSTATE_ERROR		7   /* Port Error */
#define HBA_PORTSTATE_LOOPBACK		8   /* Loopback */

#define HBA_PORTSPEED_UNKNOWN		0x0000  /* Unknown - transceiver incable
						 * of reporting */
#define HBA_PORTSPEED_1GBIT		0x0001  /* 1 GBit/sec */
#define HBA_PORTSPEED_2GBIT		0x0002  /* 2 GBit/sec */
#define HBA_PORTSPEED_10GBIT		0x0004  /* 10 GBit/sec */
#define HBA_PORTSPEED_4GBIT		0x0008  /* 4 GBit/sec */
#define HBA_PORTSPEED_8GBIT		0x0010  /* 8 GBit/sec */
#define HBA_PORTSPEED_16GBIT		0x0020  /* 16 GBit/sec */
#define HBA_PORTSPEED_32GBIT		0x0040  /* 32 GBit/sec */
#define HBA_PORTSPEED_20GBIT		0x0080  /* 20 GBit/sec */
#define HBA_PORTSPEED_40GBIT		0x0100  /* 40 GBit/sec */
#define HBA_PORTSPEED_NOT_NEGOTIATED	(1 << 15) /* Speed not established */

/* Event Codes */
#define HBA_EVENT_LIP_OCCURRED		1
#define HBA_EVENT_LINK_UP		2
#define HBA_EVENT_LINK_DOWN		3
#define HBA_EVENT_LIP_RESET_OCCURRED	4
#define HBA_EVENT_RSCN			5
#define HBA_EVENT_PROPRIETARY		0xFFFF

struct port_attributes {
	char device_name[256];
	char symbolic_name[256];
	char node_name[256];
	char port_name[256];
	char fabric_name[256];
	char speed[256];
	char supported_speeds[256];
	char maxframe_size[256];
	char port_id[256];
	char port_state[256];
	char scsi_target_id[256];
	char supported_classes[256];
	char roles[256];
};

struct hba_info {
	char manufacturer[64];
	char serial_number[64];
	char model_description[256];
	char hardware_version[256];
	char driver_name[256];
	char driver_version[256];
	uint32_t nports;
};

struct port_statistics {
	uint64_t seconds_since_last_reset;
	uint64_t tx_frames;
	uint64_t tx_words;
	uint64_t rx_frames;
	uint64_t rx_words;
	uint64_t error_frames;
	uint64_t invalid_crc_count;
	uint64_t invalid_tx_word_count;
	uint64_t link_failure_count;
	uint64_t fcp_control_requests;
	uint64_t fcp_input_requests;
	uint64_t fcp_input_megabytes;
	uint64_t fcp_output_requests;
	uint64_t fcp_output_megabytes;
};

struct hba_wwn {
	union {
		uint8_t wwn[8];
		uint64_t wwn64;
	};
};

int get_number_of_adapters(void);
struct hba_info *get_hbainfo_by_pcidev(const char *pcidev);
struct port_statistics *get_port_statistics(const char *host);
struct port_attributes *get_port_attribs(const char *host);
struct port_attributes *get_port_attribs_by_device(char *path);
struct port_attributes *get_rport_attribs(const char *rport);
struct port_attributes *get_rport_attribs_by_device(char *path);
char *get_pci_dev_from_netdev(const char *netdev);
char *get_host_from_netdev(const char *netdev);
char *get_host_by_wwpn(struct hba_wwn wwn);
char *get_host_by_fcid(uint32_t fcid);
char *get_rport_by_fcid(uint32_t fcid);

#endif /* _SYSFS_HBA_H */
