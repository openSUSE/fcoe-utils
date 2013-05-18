/*
 * Copyright (c) 2012-2013, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "fcoemon_utils.h"

#include <limits.h>

/*
 * Read a line from the specified file in the specified directory
 * into the buffer.  The file is opened and closed.
 * Any trailing white space is trimmed off.
 * This is useful for accessing /sys files.
 * Returns 0 or an error number.
 */
int
sa_sys_read_line(const char *dir, const char *file, char *buf, size_t len)
{
	FILE *fp;
	char file_name[256];
	char *cp;
	int rc = 0;

	snprintf(file_name, sizeof(file_name), "%s/%s", dir, file);
	fp = fopen(file_name, "r");
	if (fp == NULL)
		rc = -1;
	else {
		cp = fgets(buf, len, fp);
		if (cp == NULL) {
			fprintf(stderr,
				"%s: read error or empty file %s,"
				" errno=0x%x\n", __func__,
				file_name, errno);
			rc = -1;
		} else {

			/*
			 * Trim off trailing newline or other white space.
			 */
			cp = buf + strlen(buf);
			while (--cp >= buf && isspace(*cp))
				*cp = '\0';
		}
		fclose(fp);
	}
	return rc;
}

/*
 * Write a string to the specified file in the specified directory.
 * The file is opened and closed.
 * The string has a new-line appended to it.
 * This is useful for accessing /sys files.
 * Returns 0 or an error number.
 */
int
sa_sys_write_line(const char *dir, const char *file, const char *string)
{
	FILE *fp;
	char file_name[256];
	int rc = 0;

	snprintf(file_name, sizeof(file_name), "%s/%s", dir, file);
	fp = fopen(file_name, "w");
	if (fp == NULL) {
		fprintf(stderr, "%s: fopen of %s failed, errno=0x%x\n",
			__func__, file_name, errno);
		rc = -1;
	} else {
		rc = fprintf(fp, "%s\n", string);
		if (rc < 0)
			fprintf(stderr,
				"%s: write to %s of %s failed, errno=0x%x\n",
				__func__, file_name, string, errno);
		fclose(fp);
	}
	return rc;
}

int sa_sys_read_int(const char *dir, const char *file, int *vp)
{
	char buf[256];
	int rc;
	long val;
	char *endptr;

	rc = sa_sys_read_line(dir, file, buf, sizeof(buf));
	if (rc)
		return rc;

	val = strtol(buf, &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "%s: parse error. file %s/%s line '%s'\n",
			__func__, dir, file, buf);
		return -1;
	}
	if (val > INT_MAX  || val < INT_MIN)
		return ERANGE;

	*vp = val;
	return 0;
}

int
sa_sys_read_u32(const char *dir, const char *file, u_int32_t *vp)
{
	char buf[256];
	int rc;
	u_int32_t val;
	char *endptr;

	rc = sa_sys_read_line(dir, file, buf, sizeof(buf));
	if (rc == 0) {
		val = strtoul(buf, &endptr, 0);
		if (*endptr != '\0') {
			fprintf(stderr,
				"%s: parse error. file %s/%s line '%s'\n",
				__func__, dir, file, buf);
			rc = -1;
		} else
			*vp = val;
	}
	return rc;
}

int
sa_sys_read_u64(const char *dir, const char *file, u_int64_t *vp)
{
	char buf[256];
	int rc;
	u_int64_t val;
	char *endptr;

	rc = sa_sys_read_line(dir, file, buf, sizeof(buf));
	if (rc == 0) {
		val = strtoull(buf, &endptr, 0);
		if (*endptr != '\0') {
			fprintf(stderr,
				"%s: parse error. file %s/%s line '%s'\n",
				__func__, dir, file, buf);
			rc = -1;
		} else
			*vp = val;
	}
	return rc;
}

/*
 * Read through a directory and call a function for each entry.
 */
int
sa_dir_read(char *dir_name, int (*func)(struct dirent *dp, void *), void *arg)
{
	DIR *dir;
	struct dirent *dp;
	int error = 0;

	dir = opendir(dir_name);
	if (dir == NULL)
		error = errno;
	else {
		while ((dp = readdir(dir)) != NULL && error == 0) {
			if (dp->d_name[0] == '.' && (dp->d_name[1] == '\0' ||
			   (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
				continue;
			error = (*func)(dp, arg);
		}
		closedir(dir);
	}
	return error;
}

/*
 * Size of on-stack line buffers.
 * These shouldn't be to large for a kernel stack frame.
 */
#define SA_LOG_BUF_LEN  200	/* on-stack line buffer size */

static const u_int32_t sa_table_growth = 16;        /* entries to grow by */

/** sa_table_grow(tp, index) - add space to a table for index.
 *
 * @param tp pointer to sa_table structure.
 * @param index - new index past the end of the current table.
 * @returns new index, or -1 if table couldn't be grown.
 *
 * Note: if the table has never been used, and is still all zero, this works.
 *
 * Note: perhaps not safe for multithreading.  Caller can lock the table
 * externally, but reallocation can take a while, during which time the
 * caller may not wish to hold the lock.
 */
int
sa_table_grow(struct sa_table *tp, u_int32_t index)
{
	u_int32_t new_size;
	void **ap;

	if (index >= tp->st_size) {
		new_size = index + sa_table_growth;
		ap = realloc(tp->st_table, new_size * sizeof(*ap));
		if (ap == NULL)
			return -1;
		memset(ap + tp->st_size, 0,
			(new_size - tp->st_size) * sizeof(*ap));
		tp->st_table = ap;
		tp->st_size = new_size;
	}
	tp->st_limit = index + 1;
	return index;
}

/** sa_table_destroy(tp) - free memory used by table.
 *
 * @param tp pointer to sa_table structure.
 */
void
sa_table_destroy(struct sa_table *tp)
{
	if (tp->st_table) {
		free(tp->st_table);
		tp->st_table = NULL;
	}
	tp->st_limit = 0;
	tp->st_size = 0;
}

/** sa_table_destroy_all(tp) - free memory used by table, including entries.
 *
 * @param tp pointer to sa_table structure.
 */
void
sa_table_destroy_all(struct sa_table *tp)
{
	unsigned int  i;

	if (tp->st_table) {
		for (i = 0; i < tp->st_limit; i++) {
			if (tp->st_table[i]) {
				free(tp->st_table[i]);
				tp->st_table[i] = NULL;
			}
		}
	}
	sa_table_destroy(tp);
}

/** sa_table_iterate(tp, handler, arg)
 *
 * @param tp pointer to sa_table structure.
 * @param handler function to be called for each non-NULL entry.
 * @param arg argument for function.
 */
void
sa_table_iterate(struct sa_table *tp,
		 void (*handler)(void *ep, void *arg),
		 void *arg)
{
	unsigned int i;
	void *ep;

	for (i = 0; i < tp->st_limit; i++) {
		ep = tp->st_table[i];
		if (ep != NULL)
			(*handler)(ep, arg);
	}
}

/** sa_table_search(tp, match, arg)
 *
 * @param tp pointer to sa_table structure.
 * @param match function to compare entries with arg and
 *	 return non-NULL if match.
 * @param arg argument for match function.
 *
 * Note that the value found could actually be something not in the table
 * if the match function is doing something clever, like returning a
 * sub-structure of the table entry.
 */
void *
sa_table_search(struct sa_table *tp, void *(*match)(void *ep, void *arg),
	void *arg)
{
	unsigned int i;
	void *found = NULL;
	void *ep;

	for (i = 0; i < tp->st_limit; i++) {
		ep = tp->st_table[i];
		if (ep != NULL) {
			found = (*match)(ep, arg);
			if (found != NULL)
				break;
		}
	}
	return found;
}
