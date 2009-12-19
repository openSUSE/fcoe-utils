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

#ifndef _FCOE_CLIF_H_
#define _FCOE_CLIF_H_

#define SYSFS_MOUNT	"/sys"
#define SYSFS_NET	SYSFS_MOUNT "/class/net"
#define SYSFS_FCHOST	SYSFS_MOUNT "/class/fc_host"
#define SYSFS_FCOE	SYSFS_MOUNT "/module/fcoe/parameters"
#define FCM_SRV_DIR "/var/run/fcm"
#define CLIF_IFNAME "fcm_clif"
#define FCHOSTBUFLEN		64
#define MAX_MSGBUF 512
#define CLIF_PID_FILE           _PATH_VARRUN "fcoemon.pid"

enum clif_status {
	CLI_SUCCESS = 0,
	CLI_FAIL,
	CLI_NO_ACTION
};

enum {
	FCOE_CREATE_CMD = 1,
	FCOE_DESTROY_CMD,
	FCOE_RESET_CMD,
};

/*
 * Description of fcoemon and fcoeadm socket data structure interface
 */
struct clif_data {
	int cmd;
	char ifname[IFNAMSIZ];
};

int fcoeclif_validate_interface(char *ifname, char *fchost, int len);
int fcoeclif_checkdir(char *dir);
#endif /* _FCOE_CLIF_H_ */
