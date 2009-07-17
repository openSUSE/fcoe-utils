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

u_char libsa_lock_hier;		/* for lock debugging non-log related */

/*
 * Size of on-stack line buffers.
 * These shouldn't be to large for a kernel stack frame.
 */
#define SA_LOG_BUF_LEN  200	/* on-stack line buffer size */

/*
 * log with a variable argument list.
 */
static void
sa_log_va(const char *func, const char *format, va_list arg)
{
	size_t len;
	size_t flen;
	int add_newline;
	char sa_buf[SA_LOG_BUF_LEN];
	char *bp;

	/*
	 * If the caller didn't provide a newline at the end, we will.
	 */
	len = strlen(format);
	add_newline = 0;
	if (!len || format[len - 1] != '\n')
		add_newline = 1;
	bp = sa_buf;
	len = sizeof(sa_buf);
	if (func) {
		flen = snprintf(bp, len, "%s: ", func);
		len -= flen;
		bp += flen;
	}
	flen = vsnprintf(bp, len, format, arg);
	if (add_newline && flen < len) {
		bp += flen;
		*bp++ = '\n';
		*bp = '\0';
	}
	sa_log_output(sa_buf);
}

/*
 * log
 */
void
sa_log(const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	sa_log_va(NULL, format, arg);
	va_end(arg);
}

/*
 * log with function name.
 */
void
sa_log_func(const char *func, const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	sa_log_va(func, format, arg);
	va_end(arg);
}

/*
 * log with error number.
 */
void
sa_log_err(int error, const char *func, const char *format, ...)
{
	va_list arg;
	char buf[SA_LOG_BUF_LEN];

	if (func)
		sa_log("%s: error %d %s", func, error,
		       strerror_r(error, buf, sizeof(buf)));
	else
		sa_log("error %d %s", error,
		       strerror_r(error, buf, sizeof(buf)));
	va_start(arg, format);
	sa_log_va(func, format, arg);
	va_end(arg);
}

/*
 * Size of on-stack line buffers.
 * These shouldn't be to large for a kernel stack frame.
 */
#define SA_LOG_BUF_LEN  200	/* on-stack line buffer size */

/*
 * Assert failures.
 */
void
assert_failed(const char *format, ...)
{
	va_list arg;
	char buf[SA_LOG_BUF_LEN];

	va_start(arg, format);
	vsnprintf(buf, sizeof(buf), format, arg);
	va_end(arg);
	sa_log_abort(buf);
}

/*
 * Log options.
 * These may be set directly by callers.
 */
u_int sa_log_flags;                     /* timestamp and other option flags */
int sa_log_time_delta_min = 1;          /* minimum diff to print in millisec */
char *sa_log_prefix;                    /* string to print before any message */

void
sa_log_set_option(u_int flags)
{
	sa_log_flags = flags;
}

/*
 * Put timestamp on front of each log line, as controlled by tunables above.
 */
static void
sa_log_timestamp(void)
{
	static struct timeval tlast;
	char ctime_buf[30];
	struct timeval t;
	struct timeval diff;

	gettimeofday(&t, NULL);
	if (sa_log_flags & SA_LOGF_TIME) {
		ctime_r(&t.tv_sec, ctime_buf);
		ctime_buf[11 + 8] = '\0';   /* trim ctime after seconds */
		fprintf(stderr, "%s.%3.3ld ",
			ctime_buf + 11, t.tv_usec / 1000);
	}
	if (sa_log_flags & SA_LOGF_DELTA) {
		if (tlast.tv_sec == 0)
			tlast = t;
		timersub(&t, &tlast, &diff);
		tlast = t;
		if (diff.tv_sec != 0 ||
		    diff.tv_usec >= sa_log_time_delta_min * 1000)
			fprintf(stderr, "%4ld.%3.3ld ",
				diff.tv_sec, diff.tv_usec / 1000);
		else
			fprintf(stderr, "%8s ", "");
	}
	if (sa_log_prefix)
		fprintf(stderr, "%s: ", sa_log_prefix);
}

void
sa_log_output(const char *buf)
{
	if (fcm_use_syslog) {
		syslog(LOG_INFO, "%s", buf);
		return;
	}
	sa_log_timestamp();
	fprintf(stderr, "%s", buf);
	fflush(stderr);
}

void
sa_log_abort(const char *buf)
{
	sa_log_output(buf);
	abort();
}

void
sa_log_output_exit(const char *buf)
{
	exit(1);
}

/*
 * Make a printable NUL-terminated copy of the string.
 * The source buffer might not be NUL-terminated.
 */
char *
sa_strncpy_safe(char *dest, size_t len, const char *src, size_t src_len)
{
	char *dp = dest;
	const char *sp = src;

	while (len-- > 1 && src_len-- > 0 && *sp != '\0') {
		*dp++ = isprint(*sp) ? *sp : (isspace(*sp) ? ' ' : '.');
		sp++;
	}
	*dp = '\0';

	/*
	 * Take off trailing blanks.
	 */
	while (--dp >= dest && isspace(*dp))
		*dp = '\0';
	return dest;
}

/** sa_enum_decode(buf, len, tp, val)
 *
 * @param buf buffer for result (may be used or not).
 * @param len size of buffer (at least 32 bytes recommended).
 * @param tp pointer to table of names and values, struct sa_nameval.
 * @param val value to be decoded into a name.
 * @returns pointer to name string.  Unknown values are put into buffer in hex.
 */
const char *
sa_enum_decode(char *buf, size_t len, const struct sa_nameval *tp, u_int val)
{
	for (; tp->nv_name != NULL; tp++) {
		if (tp->nv_val == val)
			return tp->nv_name;
	}
	snprintf(buf, len, "Unknown (code 0x%X)", val);
	return buf;
}

#define SA_TIMER_HZ     (1000 * 1000 * 1000ULL)	/* nanoseconds per second */
#define SA_TIMER_FUZZ   (500 * 1000ULL)	/* 500 microseconds is close enough */

static struct sa_timer *sa_timer_head;	/* queue of scheduled events */
static u_int64_t sa_timer_nsec;		/* nanoseconds since start */

/*
 * Initialize a timer structure.  Set handler.
 */
void
sa_timer_init(struct sa_timer *tm, void (*handler)(void *), void *arg)
{
	ASSERT(handler != NULL);
	memset(tm, 0, sizeof(*tm));
	tm->tm_handler = handler;
	tm->tm_handler_arg = arg;
}

/*
 * Allocate a timer structure.  Set handler.
 */
struct sa_timer *
sa_timer_alloc(void (*handler)(void *arg), void *arg)
{
	struct sa_timer *tm;

	tm = malloc(sizeof(*tm));
	if (tm)
		sa_timer_init(tm, handler, arg);
	return tm;
}

u_int64_t
sa_timer_get(void)
{
	u_int64_t nsec;
#ifndef _POSIX_TIMERS
	struct timeval tv;

	gettimeofday(&tv, NULL);	/* XXX want monotonic time, not TOD */
	nsec = tv.tv_sec * SA_TIMER_HZ + tv.tv_usec * 1000;
#else /* _POSIX_TIMERS */
	struct timespec ts;
	int rc;

	rc = clock_gettime(CLOCK_MONOTONIC, &ts);
	ASSERT_NOTIMPL(rc == 0);
	nsec = ts.tv_sec * SA_TIMER_HZ + ts.tv_nsec;
#endif /* _POSIX_TIMERS */

#if 0 /* XXX */
	ASSERT(nsec >= sa_timer_nsec);	/* really must be monotonic */
#else
	if (nsec < sa_timer_nsec)
		sa_log("sa_timer_get: negative time lapse "
			"old %qud new %qud diff %qd nsec\n",
			(long long unsigned int) sa_timer_nsec,
			(long long unsigned int) nsec,
			(long long int) (nsec - sa_timer_nsec));
#endif
	sa_timer_nsec = nsec;
	return nsec;
}

/*
 * Get monotonic time since some arbitrary time in the past.
 * If _POSIX_MONOTONIC_CLOCK isn't available, we'll use time of day.
 */
u_int
sa_timer_get_secs(void)
{
	u_int sec;

#ifndef _POSIX_TIMERS
	struct timeval tv;

	gettimeofday(&tv, NULL); /* XXX want monotonic time, not TOD */
	sec = tv.tv_sec;
#else /* _POSIX_TIMERS */
	struct timespec ts;
	int rc;

	rc = clock_gettime(CLOCK_MONOTONIC, &ts);
	ASSERT_NOTIMPL(rc == 0);
	sec = ts.tv_sec;
#endif /* _POSIX_TIMERS */
	return sec;
}

/*
 * Set timer to fire.   Delta is in microseconds from now.
 */
void
sa_timer_set(struct sa_timer *tm, u_long delta_usec)
{
	struct sa_timer *cur;
	struct sa_timer **prev;

	ASSERT(delta_usec != 0);
	ASSERT(tm->tm_handler != NULL);
	sa_timer_cancel(tm);
	ASSERT(sa_timer_active(tm) == 0);
	tm->tm_nsec =
	    sa_timer_get() + delta_usec * SA_TIMER_HZ / SA_TIMER_UNITS;
	ASSERT(tm->tm_nsec != 0);

	/*
	 * Insert timer into sorted linked list.
	 * Find insertion point, before cur.
	 */
	for (prev = &sa_timer_head;
	     (cur = *prev) != NULL && cur->tm_nsec <= tm->tm_nsec;
	     prev = &cur->tm_next)
		;
	*prev = tm;
	tm->tm_next = cur;
}

/*
 * Cancel timer if it is active.
 */
void
sa_timer_cancel(struct sa_timer *tm)
{
	struct sa_timer *cur;
	struct sa_timer **prev;

	if (sa_timer_active(tm)) {
		for (prev = &sa_timer_head; (cur = *prev) != NULL;
		     prev = &cur->tm_next)
			if (cur == tm) {
				tm->tm_nsec = 0;
				*prev = tm->tm_next;
				break;
			}
		ASSERT(cur == tm);
	}
}

/*
 * Free (and cancel) timer.
 */
void
sa_timer_free(struct sa_timer *tm)
{
	if (sa_timer_active(tm))
		sa_timer_cancel(tm);
	free(tm);
}

/*
 * Handle timer checks.  Called from select loop or other periodic function.
 *
 * The struct timeval is set before returning to the maximum amount of time
 * that should elapse before the next call.
 *
 * Returns 1 if any timer functions were called, 0 otherwise.
 */
int
sa_timer_check(struct timeval *tv)
{
	u_int64_t now = 0;
	u_int64_t next_due = 0;
	struct sa_timer *tm;
	int ret = 0;

	/*
	 * Remember, the list may change during the handler.
	 */
	for (;;) {
		now = sa_timer_get();
		tm = sa_timer_head;
		if (tm == NULL) {
			next_due = now;
			break;
		}

		next_due = tm->tm_nsec;
		if (next_due > now + SA_TIMER_FUZZ)
			break;

		/*
		 * Remove this element from the list.
		 */
		sa_timer_head = tm->tm_next;
		tm->tm_next = NULL;

		/*
		 * Mark cancelled and call handler.
		 */
		tm->tm_nsec = 0;
		ASSERT(tm->tm_handler != NULL);
		(*tm->tm_handler)(tm->tm_handler_arg);
		ret = 1;
	}

	ASSERT(next_due >= now);
	next_due -= now;
	tv->tv_sec = (time_t) (next_due / SA_TIMER_HZ);
	tv->tv_usec = (long) (next_due % SA_TIMER_HZ) / 1000;

	return ret;
}

#define NFC_NFDS        64

/*
 * Deferred procedure call.
 */
struct sa_defer_ent {
	TAILQ_ENTRY(sa_defer_ent) de_next;
	void        (*de_func)(void *arg);
	void        *de_arg;
};

/*
	* Static module state.
	*/
static struct sa_sel_state {
	fd_set      ts_rx_fds;
	fd_set      ts_tx_fds;
	fd_set      ts_ex_fds;
	int         ts_max_fd;
	u_char      ts_exit;
	struct sa_sel_fd {
		void    (*ts_rx_handler)(void *);
		void    (*ts_tx_handler)(void *);
		void    (*ts_ex_handler)(void *);
		void    *ts_handler_arg;
	} ts_fd[NFC_NFDS];
	void        (*ts_callback)(void);
	TAILQ_HEAD(, sa_defer_ent) ts_defer_list;
} sa_sel_state;

static void
sa_select_call_deferred_funcs(void)
{
	struct sa_sel_state *ss = &sa_sel_state;
	struct sa_defer_ent *de, *de_next;

	de = ss->ts_defer_list.tqh_first;
	TAILQ_INIT(&ss->ts_defer_list);

	for (; de != NULL; de = de_next) {
		de_next = de->de_next.tqe_next;
		if (de->de_func != NULL)
			(*de->de_func)(de->de_arg);
		free(de);
	}
}

int sa_select_loop(void)
{
	struct sa_sel_state *ss = &sa_sel_state;
	struct sa_sel_fd *fp;
	fd_set rx_fds;
	fd_set tx_fds;
	fd_set ex_fds;
	struct timeval tval;
	struct timeval *tvp;
	int rv, i;

	ss->ts_exit = 0;
	while (ss->ts_exit == 0) {
		sa_timer_check(&tval);
		if (ss->ts_exit)
			break;
		if (ss->ts_defer_list.tqh_first != NULL) {
			/*
			 * If a timer or deferred function added a new deferred
			 * function, just poll through select (zero-timeout).
			 */
			tval.tv_sec = tval.tv_usec = 0;
			tvp = &tval;
		} else if (tval.tv_sec == 0 && tval.tv_usec == 0)
			tvp = NULL;
		else
			tvp = &tval;
		rx_fds = ss->ts_rx_fds;
		tx_fds = ss->ts_tx_fds;
		ex_fds = ss->ts_ex_fds;
		rv = select(ss->ts_max_fd + 1, &rx_fds, &tx_fds, &ex_fds, tvp);
		if (rv == -1) {
			if (errno == EINTR)
				continue;
			return errno;
		}

		fp = ss->ts_fd;
		for (i = 0; rv > 0 && i <= sa_sel_state.ts_max_fd; i++, fp++) {
			if (FD_ISSET(i, &rx_fds)) {
				if (fp->ts_rx_handler != NULL)
					(*fp->ts_rx_handler)
					(fp->ts_handler_arg);
				else
					ASSERT(!FD_ISSET(i, &ss->ts_rx_fds));
				--rv;
			}
			if (FD_ISSET(i, &tx_fds)) {
				if (fp->ts_tx_handler != NULL)
					(*fp->ts_tx_handler)
					(fp->ts_handler_arg);
				else
					ASSERT(!FD_ISSET(i, &ss->ts_tx_fds));
				--rv;
			}
			if (FD_ISSET(i, &ex_fds)) {
				if (fp->ts_ex_handler != NULL)
					(*fp->ts_ex_handler)
					(fp->ts_handler_arg);
				else
					ASSERT(!FD_ISSET(i, &ss->ts_ex_fds));
				--rv;
			}
		}
		if (ss->ts_callback != NULL)
			(*ss->ts_callback)();
		if (ss->ts_defer_list.tqh_first != NULL)
			sa_select_call_deferred_funcs();
	}
	return 0;
}

void
sa_select_add_fd(int fd,
		 void (*rx_handler)(void *),
		 void (*tx_handler)(void *),
		 void (*ex_handler)(void *),
		 void *arg)
{
	struct sa_sel_state *ss = &sa_sel_state;
	struct sa_sel_fd *fp;

	ASSERT_NOTIMPL(fd < NFC_NFDS);
	ASSERT(rx_handler != NULL || tx_handler != NULL || ex_handler != NULL);
	if (ss->ts_max_fd < fd)
		ss->ts_max_fd = fd;
	fp = &ss->ts_fd[fd];
	fp->ts_handler_arg = arg;
	if (rx_handler != NULL) {
		fp->ts_rx_handler = rx_handler;
		FD_SET(fd, &ss->ts_rx_fds);
	}
	if (tx_handler != NULL) {
		fp->ts_tx_handler = tx_handler;
		FD_SET(fd, &ss->ts_tx_fds);
	}
	if (ex_handler != NULL) {
		fp->ts_ex_handler = ex_handler;
		FD_SET(fd, &ss->ts_ex_fds);
	}
}

void
sa_select_set_rx(int fd, void (*handler)(void *))
{
	struct sa_sel_state *ss = &sa_sel_state;

	ASSERT(fd <= ss->ts_max_fd);
	ss->ts_fd[fd].ts_rx_handler = handler;
	if (handler != NULL)
		FD_SET(fd, &ss->ts_rx_fds);
	else
		FD_CLR(fd, &ss->ts_rx_fds);
}

void
sa_select_set_tx(int fd, void (*handler)(void *))
{
	struct sa_sel_state *ss = &sa_sel_state;

	ASSERT(fd <= ss->ts_max_fd);
	ss->ts_fd[fd].ts_tx_handler = handler;
	if (handler != NULL)
		FD_SET(fd, &ss->ts_tx_fds);
	else
		FD_CLR(fd, &ss->ts_tx_fds);
}

void
sa_select_set_ex(int fd, void (*handler)(void *))
{
	struct sa_sel_state *ss = &sa_sel_state;

	ASSERT(fd <= ss->ts_max_fd);
	ss->ts_fd[fd].ts_ex_handler = handler;
	if (handler != NULL)
		FD_SET(fd, &ss->ts_ex_fds);
	else
		FD_CLR(fd, &ss->ts_ex_fds);
}

void
sa_select_rem_fd(int fd)
{
	struct sa_sel_state *ss = &sa_sel_state;
	struct sa_sel_fd *fp;

	ASSERT_NOTIMPL(fd < NFC_NFDS);
	FD_CLR(fd, &ss->ts_rx_fds);
	FD_CLR(fd, &ss->ts_tx_fds);
	FD_CLR(fd, &ss->ts_ex_fds);
	fp = &ss->ts_fd[fd];
	fp->ts_rx_handler = NULL;
	fp->ts_tx_handler = NULL;
	fp->ts_ex_handler = NULL;
	fp->ts_handler_arg = NULL;
}

/*
 * Set callback for every time through the select loop.
 */
void
sa_select_set_callback(void (*cb)(void))
{
	sa_sel_state.ts_callback = cb;
}

/*
 * Add a deferred function call.
 */
void *
sa_select_add_deferred_callback(void (*func)(void *), void *arg)
{
	struct sa_sel_state *ss = &sa_sel_state;
	struct sa_defer_ent *de;

	ASSERT(func != NULL);

	de = malloc(sizeof(*de));
	if (de != NULL) {
		de->de_func = func;
		de->de_arg = arg;
		if (ss->ts_defer_list.tqh_first == NULL)
			TAILQ_INIT(&ss->ts_defer_list);
		TAILQ_INSERT_TAIL(&ss->ts_defer_list, de, de_next);
	}

	return de;
}

/*
 * Delete (cancel) a deferred function call.
 */
void
sa_select_del_deferred_callback(void *handle)
{
	struct sa_defer_ent *de = handle;

	de->de_func = NULL;
}

/*
 * Cause select loop to exit.
 * This is invoked from a handler which wants the select loop to return
 * after the handler is finished.  For example, during receipt of a network
 * packet, the program may decide to clean up and exit, but in order to do
 * this cleanly, all lower-level protocol handlers should return first.
 */
void
sa_select_exit(void)
{
	sa_sel_state.ts_exit = 1;
}

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

