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

#ifndef _FCOEADM_DISPLAY_H_
#define _FCOEADM_DISPLAY_H_

#define DEFAULT_STATS_INTERVAL	1

enum disp_style {
	DISP_LUN = 0,
	DISP_TARG,
};

enum fcoe_err display_adapter_info(const char *ifname);
enum fcoe_err display_target_info(const char *ifname,
				  enum disp_style style);
enum fcoe_err display_port_stats(const char *ifname,
				 int stat_interval);

#endif /* _FCOEADM_DISPLAY_H_ */
