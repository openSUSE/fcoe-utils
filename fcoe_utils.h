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

#ifndef _FCOE_UTILS_H_
#define _FCOE_UTILS_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <dirent.h>
#include <errno.h>

#define MAX_STR_LEN 512
#define MAX_PATH_LEN MAX_STR_LEN

#define SYSFS_MOUNT	"/sys"
#define SYSFS_NET	SYSFS_MOUNT "/class/net"
#define SYSFS_FCHOST	SYSFS_MOUNT "/class/fc_host"
#define SYSFS_FCOE	SYSFS_MOUNT "/module/fcoe/parameters"

#define FCHOSTBUFLEN 64

int fcoe_validate_interface(char *ifname, char *fchost, int len);
int fcoe_checkdir(char *dir);

#endif /* _FCOE_UTILS_H_ */
