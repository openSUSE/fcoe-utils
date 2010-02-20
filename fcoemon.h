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

#ifndef _FCOEMON_H_
#define _FCOEMON_H_

#include "fcoe_utils.h"

struct fcoe_config {
	int debug;
	int use_syslog;
	struct fcoe_port *port;
} fcoe_config;

/*
 * Log message.
 */
#define FCM_LOG(...)							\
	do {								\
		sa_log(__VA_ARGS__);					\
	} while (0)

#define FCM_LOG_ERR(error, ...) \
	do {								\
		sa_log_err(error, NULL, __VA_ARGS__);			\
	} while (0)

#define FCM_LOG_DBG(fmt, args...)					\
	do {								\
		if (fcoe_config.debug)					\
			sa_log(fmt, ##args);				\
	} while (0)

#define FCM_LOG_DEV_DBG(fcm, fmt, args...)				\
	do {								\
		if (fcoe_config.debug)					\
			sa_log("%s, " fmt, fcm->ifname, ##args);	\
	} while (0)

#define FCM_LOG_DEV(fcm, fmt, args...)				\
	do {							\
		sa_log("%s, " fmt, fcm->ifname, ##args);	\
	} while (0)

/*
 * States for HBAs relative to the DCB daemon.
 * States advance sequentially if conditions are right.
 */
enum fcm_dcbd_state {
   FCD_INIT = 0,        /* starting state */
   FCD_GET_DCB_STATE,   /* getting DCB state */
   FCD_SEND_CONF,       /* set proposed configuration */
   FCD_GET_PFC_CONFIG,  /* getting PFC configuration */
   FCD_GET_APP_CONFIG,  /* getting APP configuration */
   FCD_GET_PFC_OPER,    /* getting PFC operational mode */
   FCD_GET_APP_OPER,    /* getting operational mode */
   FCD_GET_PEER,        /* getting peer configuration */
   FCD_DONE,            /* DCB exchanges complete */
   FCD_ERROR,           /* DCB error or port unknown by DCB */
};

#define MSG_RBUF sizeof(int)
struct sock_info {
	int sock;
	struct sockaddr_un from;
	socklen_t fromlen;
};

/*
 * Action codes for FCoE ports
*/
enum fcp_action {
   FCP_WAIT = 0,        /* waiting for something to happen */
   FCP_CREATE_IF,       /* create FCoE interface */
   FCP_DESTROY_IF,      /* destroy FCoE interface */
   FCP_RESET_IF,        /* reset FCoE interface */
   FCP_ENABLE_IF,       /* enable FCoE interface */
   FCP_DISABLE_IF,      /* disable FCoE interface */
   FCP_ACTIVATE_IF,     /* create or enable FCoE interface */
   FCP_ERROR,           /* error condition */
};

#define FCM_DCBD_STATES {                         \
    { "INIT",             FCD_INIT },             \
    { "GET_DCB_STATE",    FCD_GET_DCB_STATE },    \
    { "SEND_CONF",        FCD_SEND_CONF },        \
    { "GET_PFC_CONFIG",   FCD_GET_PFC_CONFIG },   \
    { "GET_APP_CONFIG",   FCD_GET_APP_CONFIG },   \
    { "GET_PFC_OPER",     FCD_GET_PFC_OPER },     \
    { "GET_APP_OPER",     FCD_GET_APP_OPER },     \
    { "GET_PEER",         FCD_GET_PEER },         \
    { "DONE",             FCD_DONE },             \
    { "ERROR",            FCD_ERROR },            \
    { NULL,               0 }                     \
}

struct feature_info {
   u_int32_t	enable;    /* enable/disable feature */
   u_int32_t	advertise; /* enable/disable advertise */
   u_int32_t	willing;   /* enable/disable willing mode */
   u_int32_t	syncd;     /* synchronized with switch */
   u_int32_t	op_mode;   /* operational mode */
   u_int32_t	op_vers;   /* feature operational version */
   u_int32_t	op_error;  /* operational error */
   u_int32_t	subtype;   /* subtype */
   union {
      u_int32_t pfcup;
      u_int32_t appcfg;
   } u;
};

/*
 * Description of potential FCoE network interface.
 */
struct fcm_netif {
   TAILQ_ENTRY(fcm_netif) ff_list;          /* list linkage */
   u_int32_t             ff_enabled:1;     /* operational status */
   u_int32_t             ff_dcb_state;     /* DCB feature state */
   struct feature_info   ff_pfc_info;      /* PFC feature info */
   struct feature_info   ff_app_info;      /* App feature info */
   u_int8_t              ff_operstate;     /* RFC 2863 operational status */
   enum fcm_dcbd_state   ff_dcbd_state;    /* DCB daemon state */
   char                  ifname[IFNAMSIZ]; /* Ethernet interface name */
   int                   response_pending; /* dcbd query in progress */
   int                   dcbd_retry_cnt;   /* Number of query attempts */
   struct sa_timer       dcbd_retry_timer; /* dcbd retry timer */
};

/*
 * Description of fcoe socket server interface
 */
struct fcm_srv_info {
	int srv_sock;
};

TAILQ_HEAD(fcm_netif_head, fcm_netif);

struct fcm_netif_head fcm_netif_head;

static void fcm_dcbd_init(void);
static void fcm_dcbd_shutdown(void);
static void fcm_fcoe_init(void);
static struct fcm_netif *fcm_netif_lookup(char *);
static struct fcm_netif *fcm_netif_lookup_create(char *);
static int fcm_link_init(void);
static void fcm_dcbd_state_set(struct fcm_netif *, enum fcm_dcbd_state);

#endif /* _FCOEMON_H_ */
