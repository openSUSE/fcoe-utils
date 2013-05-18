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
#include <strings.h>
#include <libgen.h>
#include <dirent.h>
#include <errno.h>

#define UNUSED __attribute__((__unused__))

#define MAX_STR_LEN 512
#define MAX_PATH_LEN MAX_STR_LEN

#define SYSFS_MOUNT                            "/sys"
#define SYSFS_NET               SYSFS_MOUNT    "/class/net"
#define SYSFS_FCHOST            SYSFS_MOUNT    "/class/fc_host"
#define SYSFS_FCOE_BUS          SYSFS_MOUNT    "/bus/fcoe"
#define SYSFS_FCOE_BUS_DEVICES  SYSFS_FCOE_BUS "/devices"

#define SYSFS_FCOE   SYSFS_MOUNT "/module/libfcoe/parameters" /* legacy */
#define FCOE_CREATE  SYSFS_FCOE  "/create"  /* legacy */
#define FCOE_CREATE_VN2VN  SYSFS_FCOE  "/create_vn2vn"  /* legacy */
#define FCOE_DESTROY SYSFS_FCOE  "/destroy" /* legacy */
#define FCOE_ENABLE  SYSFS_FCOE  "/enable"  /* legacy */
#define FCOE_DISABLE SYSFS_FCOE  "/disable" /* legacy */

#define FCOE_BUS_CREATE        SYSFS_FCOE_BUS "/ctlr_create"
#define FCOE_BUS_DESTROY       SYSFS_FCOE_BUS "/ctlr_destroy"
#define FCOE_CTLR_ATTR_ENABLED "/enabled"
#define FCOE_CTLR_ATTR_MODE    "/mode"

#define FCHOSTBUFLEN 64

/*
 * This macro assumes that progname has been set
 */
#define FCOE_LOG_ERR(fmt, args...)					\
	do {								\
		fprintf(stderr, "%s: " fmt, progname, ##args);		\
	} while (0)


enum fcoe_status {
	SUCCESS = 0,  /* Success */
	EFAIL,        /* Command Failed */
	ENOACTION,    /* No action was taken */
	EFCOECONN,    /* FCoE connection already exists */
	ENOFCOECONN,  /* No FCoE connection on interface */
	ENOFCHOST,    /* FC Host found */
	EINTERR,      /* Internal error */
	EINVALARG,    /* Invalid argument */
	EBADNUMARGS,  /* Invalid number of arguments */
	EIGNORE,      /* Ignore this error value */
	ENOSYSFS,     /* sysfs is not present */
	ENOETHDEV,    /* Not a valid Ethernet interface */
	ENOMONCONN,   /* Not connected to fcoemon */
	ECONNTMOUT,   /* Connection to fcoemon timed out */
	EHBAAPIERR,   /* Error using HBAAPI/libhbalinux */
	EBADCLIFMSG,  /* Messaging error */
};

enum fcoe_status fcoe_validate_interface(char *ifname);
enum fcoe_status fcoe_validate_fcoe_conn(char *ifname);
enum fcoe_status fcoe_find_fchost(const char *ifname, char *fchost, int len);
enum fcoe_status fcoe_find_ctlr(const char *fchost, char *ctlr, int len);
int fcoe_checkdir(char *dir);
int check_symbolic_name_for_interface(const char *symbolic_name,
				      const char *ifname);
char *get_ifname_from_symbolic_name(const char *symbolic_name);
int fcoe_sysfs_read(char *buf, int size, const char *path);
enum fcoe_status fcm_write_str_to_sysfs_file(const char *path, const char *str);
enum fcoe_status fcm_write_str_to_ctlr_attr(const char *ctlr,
					    const char *attr,
					    const char *str);
#endif /* _FCOE_UTILS_H_ */
