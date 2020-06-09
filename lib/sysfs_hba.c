/*
 * Copyright (c) 2008, Intel Corporation.
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

#define _GNU_SOURCE

#include <linux/pci_regs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <pciaccess.h>

#include "sysfs_hba.h"
#include "fcoemon_utils.h"
#include "net_types.h"

#define hton64(p, v)					\
	do {						\
		p[0] = (u_char) ((v) >> 56) & 0xFF;	\
		p[1] = (u_char) ((v) >> 48) & 0xFF;	\
		p[2] = (u_char) ((v) >> 40) & 0xFF;	\
		p[3] = (u_char) ((v) >> 32) & 0xFF;	\
		p[4] = (u_char) ((v) >> 24) & 0xFF;	\
		p[5] = (u_char) ((v) >> 16) & 0xFF;	\
		p[6] = (u_char) ((v) >> 8) & 0xFF;	\
		p[7] = (u_char) (v) & 0xFF;		\
	} while (0)

struct port_attributes *get_port_attribs_by_device(char *path)
{
	char link[1024];
	char *host;
	char *rport;
	int ret;

	ret = readlink(path, link, sizeof(link));
	if (ret == -1)
		return NULL;

	host = strstr(link, "host");
	rport = strstr(link, "rport");

	host[strlen(host) - strlen(rport) - 1] = '\0';

	return get_port_attribs(host);
}

struct port_attributes *get_rport_attribs_by_device(char *path)
{
	char link[1024];
	char *target;
	char *rport;
	int ret;

	ret = readlink(path, link, sizeof(link));
	if (ret == -1)
		return NULL;

	target = strstr(link, "target");
	rport = strstr(link, "rport");

	rport[strlen(rport) - strlen(target) - 1] = '\0';

	return get_rport_attribs(rport);
}

static void get_device_serial_number(struct pci_device *dev,
				     struct hba_info *info)
{
	uint32_t pcie_cap_header;
	uint32_t dword_high = 0;
	uint32_t dword_low = 0;
	uint16_t pcie_cap_id;
	pciaddr_t offset;
	uint16_t status;
	uint8_t cap_ptr;
	int rc;

	/* Default */
	snprintf(info->serial_number, sizeof(info->serial_number), "Unknown");

	/*
	 * Read the Status Regiser in the PCIe configuration
	 * header space to see if the PCI Capability List is
	 * supported by this device.
	 */
	rc = pci_device_cfg_read_u16(dev, &status, PCI_STATUS);
	if (rc) {
		fprintf(stderr, "Failed reading PCI status register\n");
		return;
	}

	if (!(status & PCI_STATUS_CAP_LIST)) {
		fprintf(stderr, "PCI capabilities are not supported\n");
		return;
	}

	/*
	 * Read the offset (cap_ptr) of first entry in the capability list in
	 * the PCI configuration space.
	 */
	rc = pci_device_cfg_read_u8(dev, &cap_ptr,  PCI_CAPABILITY_LIST);
	if (rc) {
		fprintf(stderr,
			"Failed reading PCI Capability List Register\n");
		return;
	}
	offset = cap_ptr;

	/* Search for the PCIe capability */
	while (offset) {
		uint8_t next_cap;
		uint8_t cap_id;

		rc = pci_device_cfg_read_u8(dev, &cap_id,
					    offset + PCI_CAP_LIST_ID);
		if (rc) {
			fprintf(stderr,
				"Failed reading capability ID at 0x%"PRIx64"\n",
				offset + PCI_CAP_LIST_ID);
			return;
		}

		if (cap_id != PCI_CAP_ID_EXP) {
			rc = pci_device_cfg_read_u8(dev, &next_cap,
						offset + PCI_CAP_LIST_NEXT);
			if (rc) {
				fprintf(stderr,
					"Failed reading next capability ID at 0x%"PRIx64"\n",
					offset + PCI_CAP_LIST_NEXT);
				return;
			}

			offset = (pciaddr_t) next_cap;
			continue;
		}

		/*
		 * PCIe Capability Structure exists!
		 */

		/*
		 * The first PCIe extended capability is located at
		 * offset 0x100 in the device configuration space.
		 */
		offset = 0x100;
		do {
			rc = pci_device_cfg_read_u32(dev, &pcie_cap_header,
						     offset);
			if (rc) {
				fprintf(stderr,
					"Failed reading PCIe config header\n");
				return;
			}

			/* Get the PCIe Extended Capability ID */
			pcie_cap_id = pcie_cap_header & 0xffff;

			if (pcie_cap_id != PCI_EXT_CAP_ID_DSN) {
				/* Get the offset of the next capability */
				offset = (pciaddr_t) pcie_cap_header >> 20;
				continue;
			}

			/*
			 * Found the serial number register!
			 */

			(void) pci_device_cfg_read_u32(dev, &dword_low,
						       offset + 4);
			(void) pci_device_cfg_read_u32(dev, &dword_high,
						       offset + 8);
			snprintf(info->serial_number,
				sizeof(info->serial_number),
				"%02X%02X%02X%02X%02X%02X\n",
				dword_high >> 24, (dword_high >> 16) & 0xff,
				(dword_high >> 8) & 0xff,
				(dword_low >> 16) & 0xff,
				(dword_low >> 8) & 0xff, dword_low & 0xff);
			break;
		} while (offset);

		break;
	}
}

static void get_pci_device_info(struct pci_device *dev, struct hba_info *info)
{
	char *unknown = "unknown";
	const char *vname;
	const char *dname;
	uint8_t revision;

	vname = pci_device_get_vendor_name(dev);
	if (!vname)
		vname = unknown;

	strncpy(info->manufacturer, vname, sizeof(info->manufacturer));

	dname = pci_device_get_device_name(dev);
	if (!dname)
		dname = unknown;

	strncpy(info->model_description, dname,
		sizeof(info->model_description));

	pci_device_cfg_read_u8(dev, &revision, PCI_REVISION_ID);
	snprintf(info->hardware_version, sizeof(info->hardware_version),
		"%02x", revision);

	info->nports = 1;

	get_device_serial_number(dev, info);
}

static void get_module_info(const char *pcidev, struct hba_info *info)
{
	char buf[1024];
	char *path;
	int err;

	strncpy(info->driver_name, "Unknown", sizeof(info->driver_name));
	strncpy(info->driver_version, "Unknown", sizeof(info->driver_version));

	err = asprintf(&path, "/sys/bus/pci/devices/%s/driver/module", pcidev);
	if (err == -1)
		return;

	sa_sys_read_line(path, "version",
			 info->driver_version, sizeof(info->driver_version));

	err = readlink(path, buf, sizeof(buf) - 1);
	free(path);
	if (err == -1)
		return;

	buf[err] = '\0';

	if (strstr(buf, "module"))
		strncpy(info->driver_name,
			strstr(buf, "module") + strlen("module") + 1,
			sizeof(info->driver_name));

}

struct hba_info *get_hbainfo_by_pcidev(const char *pcidev)
{
	struct pci_device_iterator *iterator;
	struct pci_slot_match match;
	struct pci_device *dev;
	struct hba_info *info;
	int rc;

	rc = pci_system_init();
	if (rc)
		return NULL;

	info = calloc(1, sizeof(struct hba_info));
	if (!info)
		return NULL;

	sscanf(pcidev, "%x:%x:%x.%x", &match.domain, &match.bus, &match.dev,
	       &match.func);

	iterator = pci_slot_match_iterator_create(&match);
	if (!iterator) {
		free(info);
		return NULL;
	}

	for (;;) {
		dev = pci_device_next(iterator);
		if (!dev)
			break;
		get_pci_device_info(dev, info);
		get_module_info(pcidev, info);
	}

	free(iterator);
	pci_system_cleanup();

	return info;
}

struct port_attributes *get_rport_attribs(const char *rport)
{
	struct port_attributes *pa;
	char *path;
	int err;

	err = asprintf(&path, "%s/%s", SYSFS_RPORT_DIR, rport);
	if (err == -1)
		return NULL;

	pa = calloc(1, sizeof(*pa));
	if (!pa)
		goto free_path;

	strncpy(pa->device_name, rport, sizeof(pa->device_name));
	sa_sys_read_line(path, "node_name", pa->node_name,
			 sizeof(pa->node_name));
	sa_sys_read_line(path, "port_name", pa->port_name,
			 sizeof(pa->port_name));
	sa_sys_read_line(path, "port_id", pa->port_id, sizeof(pa->port_id));
	sa_sys_read_line(path, "scsi_target_id", pa->scsi_target_id,
			 sizeof(pa->scsi_target_id));
	sa_sys_read_line(path, "maxframe_size", pa->maxframe_size,
			 sizeof(pa->maxframe_size));
	sa_sys_read_line(path, "port_state", pa->port_state,
			 sizeof(pa->port_state));
	sa_sys_read_line(path, "supported_classes", pa->supported_classes,
			 sizeof(pa->supported_classes));
	sa_sys_read_line(path, "roles", pa->roles, sizeof(pa->roles));

free_path:
	free(path);

	return pa;
}

struct port_statistics *get_port_statistics(const char *host)
{
	struct port_statistics *ps;
	char *path;
	int err;

	err = asprintf(&path, "%s/%s/statistics/", SYSFS_HOST_DIR, host);
	if (err == -1)
		return NULL;

	ps = calloc(1, sizeof(*ps));
	if (!ps)
		goto free_path;

	sa_sys_read_u64(path, "seconds_since_last_reset",
			&ps->seconds_since_last_reset);
	sa_sys_read_u64(path, "tx_frames", &ps->tx_frames);
	sa_sys_read_u64(path, "tx_words", &ps->tx_words);
	sa_sys_read_u64(path, "rx_frames", &ps->rx_frames);
	sa_sys_read_u64(path, "rx_words", &ps->rx_words);
	sa_sys_read_u64(path, "error_frames", &ps->error_frames);
	sa_sys_read_u64(path, "invalid_crc_count", &ps->invalid_crc_count);
	sa_sys_read_u64(path, "invalid_tx_word_count",
			&ps->invalid_tx_word_count);
	sa_sys_read_u64(path, "link_failure_count", &ps->link_failure_count);
	sa_sys_read_u64(path, "fcp_control_requests",
			&ps->fcp_control_requests);
	sa_sys_read_u64(path, "fcp_input_requests", &ps->fcp_input_requests);
	sa_sys_read_u64(path, "fcp_input_megabytes", &ps->fcp_input_megabytes);
	sa_sys_read_u64(path, "fcp_output_requests", &ps->fcp_output_requests);
	sa_sys_read_u64(path, "fcp_output_megabytes",
			&ps->fcp_output_megabytes);

free_path:
	free(path);

	return ps;
}

struct port_attributes *get_port_attribs(const char *host)
{
	struct port_attributes *pa;
	char *path;
	int err;

	err = asprintf(&path, "%s/%s/", SYSFS_HOST_DIR, host);
	if (err == -1)
		return NULL;

	pa = calloc(1, sizeof(*pa));
	if (!pa)
		goto free_path;

	strncpy(pa->device_name, host, sizeof(pa->device_name));

	sa_sys_read_line(path, "symbolic_name", pa->symbolic_name,
			 sizeof(pa->symbolic_name));
	sa_sys_read_line(path, "node_name", pa->node_name,
			 sizeof(pa->node_name));
	sa_sys_read_line(path, "port_name", pa->port_name,
			 sizeof(pa->port_name));
	sa_sys_read_line(path, "fabric_name", pa->fabric_name,
			 sizeof(pa->fabric_name));
	sa_sys_read_line(path, "speed", pa->speed, sizeof(pa->speed));
	sa_sys_read_line(path, "supported_speeds", pa->supported_speeds,
			 sizeof(pa->supported_speeds));
	sa_sys_read_line(path, "maxframe_size", pa->maxframe_size,
			 sizeof(pa->maxframe_size));
	sa_sys_read_line(path, "port_id", pa->port_id, sizeof(pa->port_id));
	sa_sys_read_line(path, "port_state", pa->port_state,
			 sizeof(pa->port_state));

free_path:
	free(path);

	return pa;
}

char *get_pci_dev_from_netdev(const char *netdev)
{
	char buf[1024];
	char *pcidev;
	char *path;
	char *cp;
	int func;
	int dom;
	int bus;
	int dev;
	int ret;

	ret = asprintf(&path, "%s/%s/device", SYSFS_NET_DIR, netdev);
	if (ret == -1)
		return NULL;

	ret = readlink(path, buf, sizeof(buf) - 1);
	free(path);
	if (ret == -1) {
		char realdev[256];
		char *subif;
		size_t len;

		subif = strchr(netdev, '.');
		if (!subif)
			return NULL;

		len = strlen(netdev) - strlen(subif);
		if (len > (sizeof(realdev) - 1))
			return NULL;
		strncpy(realdev, netdev, sizeof(realdev)-1);
		if (realdev[len] != '\0')
			realdev[len] = '\0';

		ret = asprintf(&path, "%s/%s/lower_%s", SYSFS_NET_DIR,
			       netdev, realdev);
		if (ret == -1)
			return NULL;

		ret = readlink(path, buf, sizeof(buf) - 1);
		free(path);

		if (ret == -1)
			return NULL;
	}

	do {
		cp = strrchr(buf, '/');
		if (!cp)
			break;

		ret = sscanf(cp + 1, "%x:%x:%x.%x", &dom, &bus, &dev, &func);
		if (ret == 4)
			break;

		*cp = '\0';
	} while (cp && cp > buf);

	ret = asprintf(&pcidev, "%04x:%02x:%02x.%x", dom, bus, dev, func);
	if (ret == -1)
		return NULL;

	return pcidev;
}

char *get_host_by_wwpn(struct hba_wwn wwn)
{
	struct dirent *dp;
	DIR *dir;
	char *host = NULL;
	char path[1024];
	uint64_t port_name = 0;
	struct hba_wwn port_wwn;

	dir = opendir(SYSFS_HOST_DIR);
	if (!dir)
		return NULL;

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		if (dp->d_name[0] == '.' && dp->d_name[1] == '\0')
			continue;
		if (dp->d_name[1] == '.' && dp->d_name[2] == '\0')
			continue;

		snprintf(path, sizeof(path), "%s/%s", SYSFS_HOST_DIR,
			 dp->d_name);

		sa_sys_read_u64(path, "port_name", &port_name);
		hton64(port_wwn.wwn, port_name);
		if (memcmp((void *)&port_wwn, &wwn, sizeof(struct hba_wwn)))
			continue;

		host = strdup(dp->d_name);
		break;
	}

	closedir(dir);

	return host;
}

char *get_host_by_fcid(uint32_t fcid)
{
	struct dirent *dp;
	DIR *dir;
	char *host = NULL;
	char path[1024];
	uint32_t port_id;

	dir = opendir(SYSFS_HOST_DIR);
	if (!dir)
		return NULL;

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		if (dp->d_name[0] == '.' && dp->d_name[1] == '\0')
			continue;
		if (dp->d_name[1] == '.' && dp->d_name[2] == '\0')
			continue;

		snprintf(path, sizeof(path), "%s/%s", SYSFS_HOST_DIR,
			dp->d_name);

		sa_sys_read_u32(path, "port_id", &port_id);
		if (port_id != fcid)
			continue;

		host = strdup(dp->d_name);
		break;
	}

	closedir(dir);

	return host;
}

char *get_rport_by_fcid(uint32_t fcid)
{
	struct dirent *dp;
	DIR *dir;
	char *rport = NULL;
	char path[1024];
	uint32_t port_id;

	dir = opendir(SYSFS_RPORT_DIR);
	if (!dir)
		return NULL;

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		if (dp->d_name[0] == '.' && dp->d_name[1] == '\0')
			continue;
		if (dp->d_name[1] == '.' && dp->d_name[2] == '\0')
			continue;

		snprintf(path, sizeof(path), "%s/%s", SYSFS_RPORT_DIR,
			dp->d_name);

		sa_sys_read_u32(path, "port_id", &port_id);
		if (port_id != fcid)
			continue;

		rport = strdup(dp->d_name);
		break;
	}

	closedir(dir);

	return rport;
}

static int get_ctlr_num(const char *netdev)
{
	struct dirent *dp;
	int ctlr_num = -1;
	char path[1024];
	char *ctlr;
	DIR *dir;

	sprintf(path, "%s/%s", SYSFS_NET_DIR, netdev);

	dir = opendir(path);
	if (!dir)
		return -1;

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		if (dp->d_name[0] == '.' && dp->d_name[1] == '\0')
			continue;
		if (dp->d_name[1] == '.' && dp->d_name[2] == '\0')
			continue;

		ctlr = strstr(dp->d_name, "ctlr_");
		if (!ctlr)
			continue;

		ctlr_num = atoi(&ctlr[sizeof("ctlr_") - 1]);
		break;
	}

	closedir(dir);

	return ctlr_num;
}

char *get_host_from_netdev(const char *netdev)
{
	struct dirent *dp;
	char *host = NULL;
	char *path = NULL;
	DIR *dir;
	int ret;
	int ctlr_num;

	ctlr_num = get_ctlr_num(netdev);
	if (ctlr_num == -1)
		return NULL;

	ret = asprintf(&path, "%s/%s/ctlr_%d/", SYSFS_NET_DIR,
		       netdev, ctlr_num);
	if (ret == -1)
		return NULL;

	dir = opendir(path);
	free(path);
	path = NULL;

	if (!dir)
		return NULL;

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		if (dp->d_name[0] == '.' && dp->d_name[1] == '\0')
			continue;
		if (dp->d_name[1] == '.' && dp->d_name[2] == '\0')
			continue;

		host = strstr(dp->d_name, "host");
		if (host) {
			struct stat sb;

			ret = asprintf(&path, "%s/%s/ctlr_%d/%s/fc_host/%s",
				SYSFS_NET_DIR, netdev, ctlr_num, host, host);
			if (ret == -1)
				goto out_closedir;

			ret = stat(path, &sb);
			free(path);
			path = NULL;

			if (ret == -1)
				host = NULL;
			break;

		}
	}

out_closedir:
	closedir(dir);

	return host ? strdup(host) : NULL;
}

int get_number_of_adapters(void)
{
	struct dirent *dp;
	int num = 0;
	DIR *dir;

	dir = opendir(SYSFS_HOST_DIR);
	if (!dir)
		return errno;

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		if (dp->d_name[0] == '.' && dp->d_name[1] == '\0')
			continue;
		if (dp->d_name[1] == '.' && dp->d_name[2] == '\0')
			continue;

		if (strstr(dp->d_name, "host"))
			num++;

	}

	closedir(dir);

	return num;
}
