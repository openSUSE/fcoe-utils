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

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

static int log_syslog;
static int log_debug_level;
static char log_prefix[256];

void log_start(char *program, int daemon, int level)
{
	log_syslog = daemon;
	log_debug_level = level;
	strncpy(log_prefix, program, 256);
	log_prefix[255] = '\0';

	if (log_syslog)
		openlog(log_prefix, 0, LOG_DAEMON);
}

void log_stop()
{
	if (log_syslog)
		closelog();
}

void do_log(int priority, const char *fmt, va_list ap)
{
	if (log_syslog)
		vsyslog(priority, fmt, ap);
	else {
		printf("%s: ", log_prefix);
		vprintf(fmt, ap);
		printf("\n");
	}
}

void log_debug(int level, char *fmt, ...)
{
	va_list ap;
	if (log_debug_level >= level) {
		va_start(ap, fmt);
		do_log(LOG_DEBUG, fmt, ap);
		va_end(ap);
	}
}

void log_warn(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	do_log(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void log_err(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	do_log(LOG_ERR, fmt, ap);
	va_end(ap);
}

void _log_errno(const char *func, char *call, int errnum)
{
	log_err("%s %s: %s", func, call, strerror(errnum));
}

