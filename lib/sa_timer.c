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
