#ifndef LOG_H
#define LOG_H

void log_start(char *program, int daemon, int level);
void log_stop();
void do_log(int priority, const char *fmt, va_list ap);
void log_debug(int level, char *fmt, ...);
void log_warn(char *fmt, ...);
void log_err(char *fmt, ...);
void _log_errno(const char *func, char *call, int errnum);

#define log_errno(s) _log_errno(__func__, s, errno)

#endif /* LOG_H */

