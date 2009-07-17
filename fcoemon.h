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

int fcm_debug;

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
		if (fcm_debug)						\
			sa_log(fmt, ##args);				\
	} while (0)

#define FCM_LOG_DEV_DBG(fcm, fmt, args...)				\
	do {								\
		if (fcm_debug)						\
			sa_log("%s, " fmt, fcm->ff_name, ##args);	\
	} while (0)

#define FCM_LOG_DEV(fcm, fmt, args...)				\
	do {							\
		sa_log("%s, " fmt, fcm->ff_name, ##args);	\
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
   FCD_GET_LLINK_CONFIG,/* getting LLINK configuration */
   FCD_GET_APP_CONFIG,  /* getting APP configuration */
   FCD_GET_PFC_OPER,    /* getting PFC operational mode */
   FCD_GET_LLINK_OPER,  /* getting LLINK operational mode */
   FCD_GET_LLINK_PEER,  /* getting LLINK peer configuration */
   FCD_GET_APP_OPER,    /* getting operational mode */
   FCD_GET_PEER,        /* getting peer configuration */
   FCD_DONE,            /* DCB exchanges complete */
   FCD_ERROR,           /* DCB error or port unknown by DCB */
};

#define FCM_DCBD_STATES {                         \
    { "INIT",             FCD_INIT },             \
    { "GET_DCB_STATE",    FCD_GET_DCB_STATE },    \
    { "SEND_CONF",        FCD_SEND_CONF },        \
    { "GET_PFC_CONFIG",   FCD_GET_PFC_CONFIG },   \
    { "GET_LLINK_CONFIG", FCD_GET_LLINK_CONFIG }, \
    { "GET_APP_CONFIG",   FCD_GET_APP_CONFIG },   \
    { "GET_PFC_OPER",     FCD_GET_PFC_OPER },     \
    { "GET_LLINK_OPER",   FCD_GET_LLINK_OPER },   \
    { "GET_LLINK_PEER",   FCD_GET_LLINK_PEER },   \
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
 * Description of potential FCoE interface.
 */
struct fcm_fcoe {
   TAILQ_ENTRY(fcm_fcoe) ff_list;          /* list linkage */
   u_int32_t             ff_ifindex;       /* kernel interface index */
   u_int32_t             ff_flags;         /* kernel interface flags */
   u_int32_t             ff_last_flags;    /* previously known flags */
   u_int32_t             ff_enabled:1;     /* operational status */
   u_int32_t             ff_dcb_state;     /* DCB feature state */
   struct feature_info   ff_pfc_info;      /* PFC feature info */
   struct feature_info   ff_pfc_saved;     /* saved PFC feature info */
   struct feature_info   ff_app_info;      /* App feature info */
   struct feature_info   ff_llink_info;    /* LLink feature info */
   u_int32_t             ff_llink_status;  /* LLink status */
   u_int64_t             ff_mac;           /* MAC address */
   int                   ff_vlan;          /* VLAN ID or -1 if none */
   u_int8_t              ff_operstate;     /* RFC 2863 operational status */
   u_int8_t              ff_qos_mask;      /* 801.p priority mask */
   enum fcm_dcbd_state   ff_dcbd_state;    /* DCB daemon state */
   struct sa_timer       ff_event_timer;   /* Event timer */
   char                  ff_name[IFNAMSIZ];/* Ethernet interface name */
};

TAILQ_HEAD(fcm_fcoe_head, fcm_fcoe);

struct fcm_fcoe_head fcm_fcoe_head;
extern char build_date[];

static void fcm_dcbd_init(void);
static void fcm_dcbd_shutdown(void);
static void fcm_fcoe_init(void);
#ifdef NOT_YET
static struct fcm_fcoe *fcm_fcoe_lookup_mac(u_int64_t ff_mac, int vlan);
static struct fcm_fcoe *fcm_fcoe_lookup_create_mac(u_int64_t ff_mac, int vlan);
#endif
static struct fcm_fcoe *fcm_fcoe_lookup_name(char *name);
static struct fcm_fcoe *fcm_fcoe_lookup_create_ifindex(u_int32_t ifindex);
static void fcm_fcoe_set_name(struct fcm_fcoe *, char *);
static void fcm_fcoe_get_dcb_settings(struct fcm_fcoe *);
static int fcm_fcoe_port_ready(struct fcm_fcoe *);
static int fcm_link_init(void);

#endif /* _FCOEMON_H_ */
