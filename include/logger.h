#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <sys/syslog.h>

#include "compiler.h"

#define LOG_SPACE_SIZE (1 * 1024 * 1024)
#define LOG_SPACE_DEBUG_SIZE (32 * 1024 * 1024)
#define LOG_CLT_SPACE_DEBUG_SIZE (5 * 1024 * 1024)
#define MAX_MSG_SIZE 1024
#define MAX_THREAD_NAME_LEN     20

extern int soe_log_level;

enum log_dst_type {
	LOG_DST_DEFAULT,
	LOG_DST_STDOUT,
	LOG_DST_SYSLOG,
};

int log_init(char * argv, const char *progname, enum log_dst_type type, int level,
		char *outfile, int server, int maxlog);
void log_close(void);
void dump_logmsg(void *);
void log_write(int prio, const char *func, int line, const char *fmt, ...)
	__printf(4, 5);
	void set_thread_name(const char *name, bool show_idx);
	void get_thread_name(char *name);

#define soe_dump_variable(var) ({                \
		__soe_dump_variable(#var);               \
		})
int __soe_dump_variable(const char *var);
void soe_backtrace(void);

	/* sheep log priorities, compliant with syslog spec */
#define SOE_EMERG      LOG_EMERG
#define SOE_ALERT      LOG_ALERT
#define SOE_CRIT       LOG_CRIT
#define SOE_ERR        LOG_ERR
#define SOE_WARNING    LOG_WARNING
#define SOE_NOTICE     LOG_NOTICE
#define SOE_INFO       LOG_INFO
#define SOE_DEBUG      LOG_DEBUG
#define soe_emerg(fmt, args...) \
		log_write(SOE_EMERG, __func__, __LINE__, fmt, ##args)
#define soe_alert(fmt, args...) \
		log_write(SOE_ALERT, __func__, __LINE__, fmt, ##args)
#define soe_crit(fmt, args...) \
		log_write(SOE_CRIT, __func__, __LINE__, fmt, ##args)
#define soe_err(fmt, args...) \
		log_write(SOE_ERR, __func__, __LINE__, fmt, ##args)
#define soe_warn(fmt, args...) \
		log_write(SOE_WARNING, __func__, __LINE__, fmt, ##args)
#define soe_notice(fmt, args...) \
		log_write(SOE_NOTICE, __func__, __LINE__, fmt, ##args)
#define soe_info(fmt, args...) \
		log_write(SOE_INFO, __func__, __LINE__, fmt, ##args)

	/*
	 *  * 'args' must not contain an operation/function with a side-effect.  It won't
	 *   * be evaluated when the log level is not SOE_DEBUG.
	 *    */
#define soe_debug(fmt, args...)                                          \
		 log_write(SOE_DEBUG, __func__, __LINE__, fmt, ##args)

#define soe_assert(expr)                                         \
		({                                                              \
		 if (!(expr)) {                                          \
		 soe_emerg("Asserting `%s' failed.", #expr);      \
		 abort();                                        \
		 }                                                       \
		 })

static inline int loglevel_str2num(const char *str)
{
	static const char * const loglevel_table[] = {
		"emerg",
		"alert",
		"crit",
		"err",
		"warning",
		"notice",
		"info",
		"debug",
	};
	int i, max = ARRAY_SIZE(loglevel_table);

	for (i = 0; i < max; i++) {
		if (!strcmp(loglevel_table[i], str))
			break;
	}

	return i == max ? -1 : i;
}

void set_loglevel(int new_loglevel);
int get_loglevel(void);

extern pid_t logger_pid;
#endif  /* LOG_H */

