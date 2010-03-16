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

int use_syslog;
static int debug;

/*
 * Size of on-stack line buffers.
 * These shouldn't be to large for a kernel stack frame.
 */
#define SA_LOG_BUF_LEN  200	/* on-stack line buffer size */

void enable_syslog(int enable)
{
	use_syslog = enable;
}

void enable_debug_log(int enable)
{
	debug = enable;
}

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
 * debug log, controlled by static debug flag
 */
void
sa_log_debug(const char *format, ...)
{
	va_list arg;

	if (!debug)
		return;

	va_start(arg, format);
	sa_log_va(NULL, format, arg);
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
	if (use_syslog) {
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
