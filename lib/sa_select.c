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

#define NFC_NFDS        64

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
} sa_sel_state;

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
		if (tval.tv_sec == 0 && tval.tv_usec == 0)
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
