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

#include "fcoemon_utils.h"
#include "net_types.h"
#include "fc_types.h"

/*
 * Convert 48-bit IEEE MAC address to 64-bit FC WWN.
 */
fc_wwn_t
fc_wwn_from_mac(u_int64_t mac, u_int scheme, u_int port)
{
	fc_wwn_t wwn;

	ASSERT(mac < (1ULL << 48));
	wwn = mac | ((fc_wwn_t) scheme << 60);
	switch (scheme) {
	case 1:
		ASSERT(port == 0);
		break;
	case 2:
		ASSERT(port < 0xfff);
		wwn |= (fc_wwn_t) port << 48;
		break;
	default:
		ASSERT_NOTREACHED;
		break;
	}
	return wwn;
}

/* assumes input is pointer to two hex digits */
/* returns -1 on error */
int
hex2int(char *b)
{
	int i;
	int n = 0;
	int m;

	for (i = 0, m = 1; i < 2; i++, m--) {
		if (isxdigit(*(b+i))) {
			if (*(b+i) <= '9')
				n |= (*(b+i) & 0x0f) << (4*m);
			else
				n |= ((*(b+i) & 0x0f) + 9) << (4*m);
		} else
			return -1;
	}
	return n;
}

