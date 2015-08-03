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
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Maintained at www.Open-FCoE.org
 */

#ifndef _SYSFS_HBA_H
#define _SYSFS_HBA_H

#include <stdint.h>


#define HBA_PORTSPEED_4GBIT		0x0008  /* 4 GBit/sec */
#define HBA_PORTSPEED_8GBIT		0x0010  /* 8 GBit/sec */
#define HBA_PORTSPEED_16GBIT		0x0020  /* 16 GBit/sec */
#define HBA_PORTSPEED_32GBIT		0x0040  /* 32 GBit/sec */
#define HBA_PORTSPEED_20GBIT		0x0080  /* 20 GBit/sec */
#define HBA_PORTSPEED_40GBIT		0x0100  /* 40 GBit/sec */
#define HBA_PORTSPEED_NOT_NEGOTIATED	(1 << 15) /* Speed not established */

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


int get_number_of_adapters(void);
struct hba_info *get_hbainfo_by_pcidev(const char *pcidev);
struct port_attributes *get_port_attribs(const char *host);
struct port_attributes *get_port_attribs_by_device(char *path);
struct port_attributes *get_rport_attribs(const char *rport);
struct port_attributes *get_rport_attribs_by_device(char *path);
char *get_pci_dev_from_netdev(const char *netdev);
char *get_host_from_netdev(const char *netdev);

#endif /* _SYSFS_HBA_H */
