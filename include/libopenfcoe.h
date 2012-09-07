/*
 * Copyright(c) 2012 Intel Corporation. All rights reserved.
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

#ifndef _LIBOPENFCOE_H_
#define _LIBOPENFCOE_H_

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#include "fcoemon_utils.h"
#include "fcoe_utils.h"

#define MAC_ADDR_LEN                6

/* MAC_ADDR_STRLEN = strlen("00:11:22:33:44:55") */
#define MAC_ADDR_STRLEN	17

enum fip_conn_type {
	FIP_CONN_TYPE_UNKNOWN = 0,
	FIP_CONN_TYPE_FABRIC,
	FIP_CONN_TYPE_VN2VN,
};

static const struct sa_nameval fip_conn_type_table[] = {
	{ "Unknown", FIP_CONN_TYPE_UNKNOWN },
	{ "Fabric",  FIP_CONN_TYPE_FABRIC },
	{ "VN2VN",   FIP_CONN_TYPE_VN2VN },
	{ NULL, 0 }
};

struct fcoe_ctlr_device {
	/* Filesystem Information */
	int              index;
	char             path[MAX_STR_LEN];
	char             ifname[IFNAMSIZ];

	/* Associations */
	struct sa_table fcfs;

	/* Attributes */
	u_int32_t       fcf_dev_loss_tmo;
	enum fip_conn_type mode;
	u_int32_t       lesb_link_fail;	/* link failure count */
	u_int32_t	lesb_vlink_fail; /* virtual link failure count */
	u_int32_t	lesb_miss_fka;	/* missing FIP keep-alive count */
	u_int32_t	lesb_symb_err;	/* symbol error during carrier count */
	u_int32_t	lesb_err_block;	/* errored block count */
	u_int32_t	lesb_fcs_error; /* frame check sequence error count */
};

/* fcf states */
enum fcf_state {
	FCOE_FCF_STATE_UNKNOWN = 0,
	FCOE_FCF_STATE_DISCONNECTED,
	FCOE_FCF_STATE_CONNECTED,
	FCOE_FCF_STATE_DELETED,
};

static const struct sa_nameval fcf_state_table[] = {
	{ "Unknown",      FCOE_FCF_STATE_UNKNOWN },
	{ "Disconnected", FCOE_FCF_STATE_DISCONNECTED },
	{ "Connected",    FCOE_FCF_STATE_CONNECTED },
	{ "Deleted",      FCOE_FCF_STATE_DELETED },
	{ NULL, 0 }
};

struct fcoe_fcf_device {
	/* Filesystem Information */
	int              index;
	char             path[MAX_STR_LEN];

	/* Attributes */
	enum fcf_state   state;
	u_int32_t        dev_loss_tmo;
	u_int64_t        fabric_name;
	u_int64_t        switch_name;
	u_int32_t        fc_map;
	u_int32_t        vfid;        /* u16 in kernel */
	u_int8_t         mac[MAC_ADDR_LEN];
	u_int32_t        priority;    /* u8 in kernel  */
	u_int32_t        fka_period;
	u_int32_t        selected;    /* u8 in kernel  */
	u_int32_t        vlan_id;     /* u16 in kernel */
};

void read_fcoe_ctlr(struct sa_table *ctlrs);
void print_fcoe_ctlr_device(void *ep, void *arg);
void free_fcoe_ctlr_device(void *ep, void *arg);

int mac2str(const u_int8_t *mac, char *dst, size_t size);
int str2mac(const char *src, u_int8_t *mac, size_t size);

#endif /* _LIBOPENFCOE_H_ */
