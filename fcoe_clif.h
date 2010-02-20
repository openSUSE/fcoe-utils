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

#ifndef _FCOE_CLIF_H_
#define _FCOE_CLIF_H_

/*
 * A DCB file is incorrectly including linux/if.h which is redefining
 * IFF_UP. This makes it so we cannot include net/if.h. We have to
 * redefine IFNAMSIZ to work around this until DCB is corrected.

*/

#define FCM_SRV_DIR "/var/run/fcm"
#define CLIF_IFNAME "fcm_clif"
#define CLIF_PID_FILE           _PATH_VARRUN "fcoemon.pid"

#define CLIF_CMD_RESPONSE_TIMEOUT 5
#define MAX_MSGBUF 512

enum clif_status {
	CLI_SUCCESS = 0,
	CLI_FAIL,
	CLI_NO_ACTION
};

enum clif_action {
	CLIF_CREATE_CMD = 1,
	CLIF_DESTROY_CMD,
	CLIF_RESET_CMD,
};

/**
 * struct clif - Internal structure for client interface library
 *
 * This structure is used by fcoeadm client interface to store internal data.
 */
struct clif_sock_info {
	int socket_fd;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

/*
 * Description of fcoemon and fcoeadm socket data structure interface
 */
struct clif_data {
	enum clif_action cmd;
	char ifname[IFNAMSIZ];
};

#endif /* _FCOE_CLIF_H_ */
