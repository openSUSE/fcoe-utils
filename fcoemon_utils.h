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

#include "fc_types.h"

void sa_log(const char *format, ...);
void sa_log_func(const char *func, const char *format, ...);
void sa_log_err(int, const char *func, const char *format, ...);

/*
 * These functions can be provided outside of libsa for those environments
 * that want to redirect them.
 */
void sa_log_output(const char *);	/* log message */
void sa_log_abort(const char *);	/* log message and abort */

#define __SA_STRING(x)  #x

/*
 * Log message.
 */
#define SA_LOG(...) \
	do {								\
		sa_log_func(__func__, __VA_ARGS__);			\
	} while (0)

#define SA_LOG_ERR(error, ...) \
	do {								\
		sa_log_err(error, NULL, __VA_ARGS__);			\
	} while (0)

/*
 * Logging exits.
 */
#define SA_LOG_EXIT(...) \
	do {								\
		sa_log_func(__func__, __VA_ARGS__);			\
		sa_log_func(__func__, "exiting at %s:%d",		\
			__FILE__, __LINE__);				\
		exit(1);						\
	} while (0)

#define SA_LOG_ERR_EXIT(error, ...) \
	do {								\
		sa_log_func(__func__, __VA_ARGS__);			\
		sa_log_err(error, __func__, "exiting at %s:%d",		\
			__FILE__, __LINE__);				\
		exit(1);						\
	} while (0)

/*
 * Logging options.
 */
#define SA_LOGF_TIME    0x0001      /* include timestamp in message */
#define SA_LOGF_DELTA   0x0002      /* include time since last message */

extern u_int sa_log_flags;          /* timestamp and other option flags */
extern int sa_log_time_delta_min;   /* minimum diff to print in millisec */
extern char *sa_log_prefix;         /* string to print before any message */

extern void assert_failed(const char *s, ...)
    __attribute__ ((format(printf, 1, 2)));

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
    char    *nv_name;
    u_int   nv_val;
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
 * Add a deferred function call.  The function is called at the start
 * of the next select loop cycle.
 * Returns a handle to the deferred call object on success, or NULL on memory
 * allocation failure.
 */
void *sa_select_add_deferred_callback(void (*func)(void *), void *arg);

/*
 * Delete a deferred function call.
 * Takes the handle returned by sa_select_add_deferred_callback as an argument.
 */
void sa_select_del_deferred_callback(void *handle);


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
void sa_select_exit(void);

/*
 * Convert 48-bit IEEE MAC address to 64-bit FC WWN.
 */
extern fc_wwn_t
fc_wwn_from_mac(u_int64_t, u_int32_t scheme, u_int32_t port);

extern int hex2int(char *b);
extern int fcm_use_syslog;

#endif /* _FCOEMON_UTILS_H_ */
