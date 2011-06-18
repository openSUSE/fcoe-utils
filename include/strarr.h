/*
 * Copyright (c) 2011 Intel Corporation. All rights reserved.
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

#ifndef _STRARR_H_
#define _STRARR_H_

typedef const char * const _strarr[];

struct _str_arr_desc {
	const unsigned limit;
	const _strarr * const str_arr;
	const char * const unknown_str;
	const char * const out_of_range_str;
};

#define GEN_STR_ARR(sc, sz, nm, unk, oor, ...)			\
static const char * const _##nm##_strs[sz] = { __VA_ARGS__ };	\
sc const struct _str_arr_desc nm = {				\
	.limit = sizeof(_##nm##_strs) / sizeof(_##nm##_strs[0]),\
	.str_arr = &_##nm##_strs,				\
	.unknown_str = unk,					\
	.out_of_range_str = oor,				\
}

#define EXT_STR_ARR(nm, unk, oor, ...)		\
		GEN_STR_ARR(, , nm, unk, oor, __VA_ARGS__)
#define EXT_STR_ARR_SZ(nm, sz, unk, oor, ...)	\
		GEN_STR_ARR(, sz, nm, unk, oor, __VA_ARGS__)
#define STR_ARR(nm, unk, oor, ...)		\
		GEN_STR_ARR(static, , nm, unk, oor, __VA_ARGS__)
#define STR_ARR_SZ(nm, sz, unk, oor, ...)	\
		GEN_STR_ARR(static, sz, nm, unk, oor, __VA_ARGS__)

static inline const char *
getstr(const struct _str_arr_desc *desc, unsigned ix)
{
	const char *str;

	if (ix >= desc->limit)
		return desc->out_of_range_str;
	str = (*desc->str_arr)[ix];
	if (!str)
		return desc->unknown_str;

	return str;
}

#endif /* _STRARR_H_ */
