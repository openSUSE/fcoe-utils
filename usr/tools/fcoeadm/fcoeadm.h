/*
 * Copyright(c) 2008 Intel Corporation. All rights reserved.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <limits.h>
#include <scsi/sg.h>
#include <getopt.h>
#include <byteswap.h>

#include "hbaapi.h"
#include "net_types.h"
#include "fc_types.h"
#include "fc_scsi.h"

struct opt_info {
	char ifname[20];
	char a_flag;
	char t_flag;
	char l_flag;
	char l_fcid_present;
	HBA_UINT32 l_fcid;
	char l_lun_id_present;
	u_int32_t l_lun_id;
	char s_flag;
	char n_flag;
	#define DEFAULT_STATS_INTERVAL	1
	int n_interval;		/* seconds */
};
extern struct opt_info *opt_info;

extern void display_adapter_info(struct opt_info *opt_info);
extern void display_target_info(struct opt_info *opt_info);
extern void display_port_stats(struct opt_info *opt_info);
