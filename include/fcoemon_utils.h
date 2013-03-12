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

#ifndef _FCOEMON_UTILS_H_
#define _FCOEMON_UTILS_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <dirent.h>

#include "fc_types.h"

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

__attribute__((__format__(__printf__, 1, 2)))
void sa_log(const char *format, ...);
__attribute__((__format__(__printf__, 1, 2)))
void sa_log_debug(const char *format, ...);
__attribute__((__format__(__printf__, 3, 4)))
void sa_log_err(int, const char *func, const char *format, ...);

/*
 * These functions can be provided outside of libsa for those environments
 * that want to redirect them.
 */
void sa_log_output(const char *);	/* log message */
void sa_log_abort(const char *);	/* log message and abort */

#define __SA_STRING(x)  #x

/*
 * Logging options.
 */
#define SA_LOGF_TIME    0x0001      /* include timestamp in message */
#define SA_LOGF_DELTA   0x0002      /* include time since last message */

extern u_int sa_log_flags;          /* timestamp and other option flags */
extern int sa_log_time_delta_min;   /* minimum diff to print in millisec */
extern char *sa_log_prefix;         /* string to print before any message */

__attribute__((__format__(__printf__, 1, 2)))
extern void assert_failed(const char *s, ...);

#ifndef UNLIKELY
#define UNLIKELY(_x) (_x)
#endif /* UNLIKELY */

/*
 * ASSERT macros
 *
 * ASSERT(expr) - this calls assert_failed() if expr is false.  This variant
 * is not present in production code or if DEBUG_ASSERTS is not defined.
 * Be careful not to rely on expr being evaluated.
 */
#if defined(DEBUG_ASSERTS)
#define ASSERT(_x) do {							\
		if (UNLIKELY(!(_x))) {					\
			assert_failed("ASSERT FAILED (%s) @ %s:%d\n",	\
				"" #_x, __FILE__, __LINE__);		\
		}							\
	} while (0)
#else
#define ASSERT(_x)
#endif /* DEBUG_ASSERTS */

/*
 * ASSERT_NOTIMPL(expr) - this calls assert_failed() if expr is false.
 * The implication is that the condition is not handled by the current
 * implementation, and work should be done eventually to handle this.
 */
#define ASSERT_NOTIMPL(_x) do {						\
		if (UNLIKELY(!(_x))) {					\
			assert_failed("ASSERT (NOT IMPL) "		\
				"(%s) @ %s:%d\n",			\
				"" #_x, __FILE__, __LINE__);		\
		}							\
	} while (0)

/*
 * ASSERT_NOTREACHED - this is the same as ASSERT_NOTIMPL(0).
 */
#define ASSERT_NOTREACHED do {						\
		assert_failed("ASSERT (NOT REACHED) @ %s:%d\n",		\
			__FILE__, __LINE__);				\
	} while (0)

/*
 * ASSERT_BUG(bugno, expr).  This variant is used when a bug number has
 * been assigned to any one of the other assertion failures.  It is always
 * present in code.  It gives the bug number which helps locate
 * documentation and helps prevent duplicate bug filings.
 */
#define ASSERT_BUG(_bugNr, _x) do {					\
		if (UNLIKELY(!(_x))) {					\
			assert_failed("ASSERT (BUG %d) (%s) @ %s:%d\n", \
				(_bugNr), #_x, __FILE__, __LINE__);	\
		}                                                       \
	} while (0)

#ifndef LIBSA_USE_DANGEROUS_ROUTINES
#define strcpy DONT_USE_strcpy
#define strcat DONT_USE_strcat
#define gets   DONT_USE_gets
#endif /* LIBSA_USE_DANGEROUS_ROUTINES */

char *sa_strncpy_safe(char *dest, size_t len, const char *src, size_t src_len);
char *sa_hex_format(char *buf, size_t buflen,
			const unsigned char *data, size_t data_len,
			unsigned int group_len, char *inter_group_sep);

/*
 * Structure for tables encoding and decoding name-value pairs such as enums.
 */
struct sa_nameval {
	char      *nv_name;
	u_int32_t nv_val;
};

const char *sa_enum_decode(char *, size_t, const struct sa_nameval *, u_int);
int sa_enum_encode(const struct sa_nameval *tp, const char *, u_int *);
const char *sa_flags_decode(char *, size_t, const struct sa_nameval *, u_int);

/*
 * Timer facility.
 */

struct sa_timer {
	struct sa_timer	*tm_next;
	u_int64_t	tm_nsec;	/* relative time to event (nSec) */
	void		(*tm_handler)(void *arg);
	void		*tm_handler_arg;
	struct sa_timer **timer_head;
};


#define SA_TIMER_UNITS  (1000 * 1000UL)	/* number of timer ticks per second */

/*
 * Initialize a pre-allocated timer structure.
 */
void sa_timer_init(struct sa_timer *, void (*handler)(void *), void *arg);

/*
 * Test whether the timer is active.
 */
static inline int sa_timer_active(struct sa_timer *tm)
{
	return tm->tm_nsec != 0;
}

/*
 * Allocate a timer structure.  Set handler.
 */
struct sa_timer *sa_timer_alloc(void (*)(void *arg), void *arg);

/*
 * Set timer to fire.   Delta is in microseconds from now.
 */
void sa_timer_set(struct sa_timer *, u_long delta);

/*
 * Cancel timer.
 */
void sa_timer_cancel(struct sa_timer *);

/*
 * Free (and cancel) timer.
 */
void sa_timer_free(struct sa_timer *);


/*
 * Handle timer checks.  Called from select loop or other periodic function.
 *
 * The struct timeval passed in indicates how much time has passed since
 * the last call, and is set before returning to the maximum amount of time
 * that should elapse before the next call.
 *
 * Returns 1 if any timer handlers were invoked, 0 otherwise.
 */
int sa_timer_check(struct timeval *);

/*
 * Get time in nanoseconds since some arbitrary time.
 */
u_int64_t sa_timer_get(void);

/*
 * Get time in seconds since some arbitrary time.
 */
u_int sa_timer_get_secs(void);

/*
 * sa_select - Server Array select facility.
 *
 * This is a thin layer to poll files with a select loop.
 */

/*
 * Enter the polling loop which never exits.
 */
int sa_select_loop(void);

/*
 * Set callback for every time through the select loop.
 */
void sa_select_set_callback(void (*)(void));

/*
 * Add a callback to handle files which are ready for receive, transmit,
 * or to handle exceptions.
 */
void sa_select_add_fd(int fd, void (*rx_handler)(void *),
			void (*tx_handler)(void *),
			void (*ex_handler)(void *), void *arg);

/*
 * Change a single callback for a descriptor that's already been added.
 */
void sa_select_set_rx(int fd, void (*handler)(void *));
void sa_select_set_tx(int fd, void (*handler)(void *));
void sa_select_set_ex(int fd, void (*handler)(void *));

/*
 * Remove all callbacks for a file descriptor.
 */
void sa_select_rem_fd(int fd);

/*
 * Cause select loop to return.
 */
void sa_select_exit(int sig);

/*
 * Convert 48-bit IEEE MAC address to 64-bit FC WWN.
 */
extern fc_wwn_t
fc_wwn_from_mac(u_int64_t, u_int32_t scheme, u_int32_t port);

extern int hex2int(char *b);

extern int use_syslog;
void enable_syslog(int);
void enable_debug_log(int);

/*
 * Table and sysfs helpers
 */

/*
 * Structure for integer-indexed tables that can grow.
 */
struct sa_table {
	u_int32_t   st_size;        /* number of entries in table */
	u_int32_t   st_limit;       /* end of valid entries in table (public) */
	void        **st_table;     /* re-allocatable array of pointers */
};

/*
 * Function prototypes
 */
extern int sa_sys_read_line(const char *, const char *, char *, size_t);
extern int sa_sys_write_line(const char *, const char *, const char *);
extern int sa_sys_read_int(const char *, const char *, int *);
extern int sa_sys_read_u32(const char *, const char *, u_int32_t *);
extern int sa_sys_read_u64(const char *, const char *, u_int64_t *);
extern int sa_dir_read(char *, int (*)(struct dirent *, void *), void *);
extern char *sa_strncpy_safe(char *dest, size_t len,
			     const char *src, size_t src_len);
extern const char *sa_enum_decode(char *, size_t,
				  const struct sa_nameval *, u_int32_t);
extern int sa_enum_encode(const struct sa_nameval *tp,
			const char *, u_int32_t *);
extern const char *sa_flags_decode(char *, size_t,
				   const struct sa_nameval *, u_int32_t);
extern int sa_table_grow(struct sa_table *, u_int32_t index);
extern void sa_table_destroy_all(struct sa_table *);
extern void sa_table_destroy(struct sa_table *);
extern void sa_table_iterate(struct sa_table *tp,
			void (*handler)(void *ep, void *arg), void *arg);
extern void *sa_table_search(struct sa_table *tp,
			void *(*match)(void *ep, void *arg), void *arg);

/** sa_table_init(tp) - initialize a table.
 * @param tp table pointer.
 *
 * This just clears a table structure that was allocated by the caller.
 */
static inline void sa_table_init(struct sa_table *tp)
{
	memset(tp, 0, sizeof(*tp));
}

/** sa_table_lookup(tp, index) - lookup an entry in the table.
 * @param tp table pointer.
 * @param index the index in the table to access
 * @returns the entry, or NULL if the index wasn't valid.
 */
static inline void *sa_table_lookup(const struct sa_table *tp, u_int32_t index)
{
	void *ep = NULL;

	if (index < tp->st_limit)
		ep = tp->st_table[index];
	return ep;
}

/** sa_table_lookup_n(tp, n) - find Nth non-empty entry in a table.
 * @param tp table pointer.
 * @param n is the entry number, the first non-empty entry is 0.
 * @returns the entry, or NULL if the end of the table reached first.
 */
static inline void *sa_table_lookup_n(const struct sa_table *tp, u_int32_t n)
{
	void *ep = NULL;
	u_int32_t   i;

	for (i = 0; i < tp->st_limit; i++) {
		ep = tp->st_table[i];
		if (ep != NULL && n-- == 0)
			return ep;
	}
	return NULL;
}

/** sa_table_insert(tp, index, ep) - Replace or insert an entry in the table.
 * @param tp table pointer.
 * @param index the index for the new entry.
 * @param ep entry pointer.
 * @returns index on success, or -1 if the insert failed.
 *
 * Note: if the table has never been used, and is still all zero, this works.
 *
 * Note: perhaps not safe for multithreading.  Caller can lock the table
 * externally, but reallocation can take a while, during which time the
 * caller may not wish to hold the lock.
 */
static inline int sa_table_insert(struct sa_table *tp,
				  u_int32_t index, void *ep)
{
	if (index >= tp->st_limit && sa_table_grow(tp, index) < 0)
		return -1;
	tp->st_table[index] = ep;
	return index;
}

/** sa_table_append(tp, ep) - add entry to table and return index.
 *
 * @param tp pointer to sa_table structure.
 * @param ep pointer to new entry, to be added at the end of the table.
 * @returns new index, or -1 if table couldn't be grown.
 *
 * See notes on sa_table_insert().
 */
static inline int
sa_table_append(struct sa_table *tp, void *ep)
{
	return sa_table_insert(tp, tp->st_limit, ep);
}

/** sa_table_sort(tp, compare) - sort table in place
 *
 * @param tp pointer to sa_table structure.
 * @param compare function to compare two entries.  It is called with pointers
 * to the pointers to the entries to be compared.  See qsort(3).
 */
static inline void
sa_table_sort(struct sa_table *tp, int (*compare)(const void **, const void **))
{
	qsort(tp->st_table, tp->st_limit, sizeof(void *),
		(int (*)(const void *, const void *)) compare);
}

#endif /* _FCOEMON_UTILS_H_ */
