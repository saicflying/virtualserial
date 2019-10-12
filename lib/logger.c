
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include<sys/prctl.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/time.h>
#include <execinfo.h>
#include <linux/limits.h>

#include "list.h"
#include "util.h"
#include "logger.h"

static int  gl_maxlog = 2;
static bool colorize = true;
static const char * const log_color[] = {
	[SOE_EMERG] = TEXT_BOLD_RED,
	[SOE_ALERT] = TEXT_BOLD_RED,
	[SOE_CRIT] = TEXT_BOLD_RED,
	[SOE_ERR] = TEXT_BOLD_RED,
	[SOE_WARNING] = TEXT_BOLD_YELLOW,
	[SOE_NOTICE] = TEXT_BOLD_CYAN,
	[SOE_INFO] = TEXT_CYAN,
	[SOE_DEBUG] = TEXT_GREEN,
};

static const char * const log_prio_str[] = {
	[SOE_EMERG]   = "EMERG",
	[SOE_ALERT]   = "ALERT",
	[SOE_CRIT]    = "CRIT",
	[SOE_ERR]     = "ERROR",
	[SOE_WARNING] = "WARN",
	[SOE_NOTICE]  = "NOTICE",
	[SOE_INFO]    = "INFO",
	[SOE_DEBUG]   = "DEBUG",
};

static void dolog(int prio, const char *func, int line, const char *fmt,
		  va_list ap) __printf(4, 0);

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};

struct logarea {
	bool active;
	char *tail;
	char *start;
	char *end;
	int semid;
	union semun semarg;
	int fd;
};

#define FUNC_NAME_SIZE 32 /* according to C89, including '\0' */
struct logmsg {
	struct timeval tv;
	int prio;
	char func[FUNC_NAME_SIZE];
	int line;
	char worker_name[MAX_THREAD_NAME_LEN];
	int worker_idx;

	size_t str_len;
	char str[0];
};

static int log_fd = -1;
static __thread const char *worker_name;
static __thread int worker_idx;
static struct logarea *la;
static const char *log_name;
static char *log_nowname;
int soe_log_level = SOE_DEBUG;
static pid_t sheep_pid;
pid_t logger_pid = -1;
static key_t semkey;
static char *log_buff;

static int64_t max_logsize = 32 * 1024 * 1024;  /*500MB*/

static enum log_dst_type dst_type = LOG_DST_STDOUT;

void setproctitle(char * argv, char *title);

void setproctitle(char * argv, char *title)
{
	int len = strlen(argv);
	memset(argv, 0, len);
	strncpy(argv, title, len);  
	if (0 != prctl(PR_SET_NAME,title,0,0,0,0))
		syslog(LOG_WARNING, "error prctl, errno=%d, errstr=%s\n", errno, strerror(errno));
}
/*
 * block_sighup()
 *
 * used for protecting log_fd from SIGHUP rotation
 */
static void block_sighup(void)
{
	int ret;
	sigset_t new, old;

	sigemptyset(&new);
	sigemptyset(&old);
	sigaddset(&new, SIGHUP);
	ret = sigprocmask(SIG_BLOCK, &new, &old);
	if (ret < 0)
		syslog(LOG_ERR, "blocking SIGHUP failed\n");
}

static void unblock_sighup(void)
{
	int ret;
	sigset_t new, old;

	sigemptyset(&new);
	sigemptyset(&old);
	sigaddset(&new, SIGHUP);
	ret = sigprocmask(SIG_UNBLOCK, &new, &old);
	if (ret < 0)
		syslog(LOG_ERR, "unblock SIGHUP failed\n");
}

static const char *format_thread_name(char *str, size_t size, const char *name,
				      int idx)
{
	if (name && name[0] && idx)
		snprintf(str, size, "%s %d", name, idx);
	else if (name && name[0])
		snprintf(str, size, "%s", name);
	else
		snprintf(str, size, "main");

	return str;
}

static int server_log_formatter(char *buff, size_t size,
				const struct logmsg *msg, bool print_time)
{
	char *p = buff;
	struct tm tm;
	ssize_t len;
	char thread_name[MAX_THREAD_NAME_LEN];

	if (print_time) {
		localtime_r(&msg->tv.tv_sec, &tm);
		len = strftime(p, size, "%b %2d %H:%M:%S",
			       (const struct tm *)&tm);
		p += len;
		size -= len;
	
		len = snprintf(p, size, ".%lu ", msg->tv.tv_usec);
		p += len;
		size -= len;
	}

	len = snprintf(p, size, "%s%6s %s[%s] %s(%d) %s%s%s",
		       colorize ? log_color[msg->prio] : "",
		       log_prio_str[msg->prio],
		       colorize ? TEXT_YELLOW : "",
		       format_thread_name(thread_name, sizeof(thread_name),
					  msg->worker_name, msg->worker_idx),
		       msg->func, msg->line,
		       colorize ? log_color[msg->prio] : "",
		       msg->str, colorize ? TEXT_NORMAL : "");
	if (len < 0)
		len = 0;
	p += min((size_t)len, size - 1);

	return p - buff;
}

static int default_log_formatter(char *buff, size_t size,
				 const struct logmsg *msg, bool print_time)
{
	size_t len = min(size, msg->str_len);

	memcpy(buff, msg->str, len);

	return len;
}


static int logarea_init(int size)
{
	int shmid;

	shmid = shmget(IPC_PRIVATE, sizeof(struct logarea),
		       0644 | IPC_CREAT | IPC_EXCL);
	if (shmid == -1) {
		syslog(LOG_ERR, "shmget logarea failed: %m");
		return 1;
	}

	la = shmat(shmid, NULL, 0);
	if (!la) {
		syslog(LOG_ERR, "shmat logarea failed: %m");
		return 1;
	}

	shmctl(shmid, IPC_RMID, NULL);

	if (size < MAX_MSG_SIZE)
		size = LOG_SPACE_SIZE;

	shmid = shmget(IPC_PRIVATE, size, 0644 | IPC_CREAT | IPC_EXCL);
	if (shmid == -1) {
		syslog(LOG_ERR, "shmget msg failed: %m");
		shmdt(la);
		return 1;
	}

	la->start = shmat(shmid, NULL, 0);
	if (!la->start) {
		syslog(LOG_ERR, "shmat msg failed: %m");
		shmdt(la);
		return 1;
	}
	memset(la->start, 0, size);

	shmctl(shmid, IPC_RMID, NULL);

	la->end = la->start + size;
	la->tail = la->start;

	la->semid = semget(semkey, 1, 0666 | IPC_CREAT);
	if (la->semid < 0) {
		syslog(LOG_ERR, "semget failed: %m");
		shmdt(la->start);
		shmdt(la);
		return 1;
	}

	la->semarg.val = 1;
	if (semctl(la->semid, 0, SETVAL, la->semarg) < 0) {
		syslog(LOG_ERR, "semctl failed: %m");
		shmdt(la->start);
		shmdt(la);
		return 1;
	}

	return 0;
}

static void free_logarea(void)
{
	if (log_fd >= 0)
		close(log_fd);
	semctl(la->semid, 0, IPC_RMID, la->semarg);
	shmdt(la->start);
	shmdt(la);
}

/* this one can block under memory pressure */
static void log_syslog(const struct logmsg *msg)
{
	char str[MAX_MSG_SIZE];
	int len;

	len = server_log_formatter(str, sizeof(str) - 1, msg, log_fd >= 0);
	if (dst_type == LOG_DST_DEFAULT)
		str[len++] = '\n';
	else	/* LOG_DST_SYSLOG */
		str[len++] = '\0';

	block_sighup();

	if (log_fd >= 0)
		wwrite(log_fd, str, len);
	else
		syslog(msg->prio, "%s", str);

	unblock_sighup();
}

static void init_logmsg(struct logmsg *msg, struct timeval *tv,
				int prio, const char *func, int line)
{
	msg->tv = *tv;
	msg->prio = prio;
	pstrcpy(msg->func, FUNC_NAME_SIZE, func);
	msg->line = line;
	if (worker_name)
		pstrcpy(msg->worker_name, MAX_THREAD_NAME_LEN, worker_name);
	else
		msg->worker_name[0] = '\0';
	msg->worker_idx = worker_idx;
}

static void dolog(int prio, const char *func, int line,
		const char *fmt, va_list ap)
{
	char buf[sizeof(struct logmsg) + MAX_MSG_SIZE];
	char *str = buf + sizeof(struct logmsg);
	struct logmsg *msg = (struct logmsg *)buf;
	int len = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	len = vsnprintf(str, MAX_MSG_SIZE, fmt, ap);
	if (len < 0) {
		syslog(LOG_ERR, "vsnprintf failed");
		return;
	}
	msg->str_len = min(len, MAX_MSG_SIZE - 1);
	
	if (prio == SOE_EMERG) {
		syslog(LOG_ERR, "%s\n", str);
	} 

	if (la) {
		struct sembuf ops;

		ops.sem_num = 0;
		ops.sem_flg = SEM_UNDO;
		ops.sem_op = -1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop up failed: %m");
			return;
		}

		/* not enough space: drop msg */
		if (len + sizeof(struct logmsg) + 1 > la->end - la->tail)
			syslog(LOG_ERR, "enqueue: log area overrun, "
			       "dropping message\n");
		else {
			/* ok, we can stage the msg in the area */
			msg = (struct logmsg *)la->tail;
			init_logmsg(msg, &tv, prio, func, line);
			memcpy(msg->str, str, len + 1);
			msg->str_len = len;
			la->tail += sizeof(struct logmsg) + len + 1;
		}

		ops.sem_op = 1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop down failed: %m");
			return;
		}
	} else {
		char str_final[MAX_MSG_SIZE];

		init_logmsg(msg, &tv, prio, func, line);
		len = server_log_formatter(str_final, sizeof(str_final) - 1, msg,
				true);

		str_final[len++] = '\n';
		wwrite(fileno(stderr), str_final, len);
		fflush(stderr);
	}
}

static void rotate_log(void)
{
	int new_fd;
	int i;
	if (access(log_nowname, R_OK) == 0) {
		char old_logfile[256];
		char old_logfile_new[256];
		int ret;
		struct stat oldstat;
		/* step1. remove the soed.log.1	if exist */
		snprintf(old_logfile, sizeof(old_logfile),
				"%s.%d", log_nowname, gl_maxlog - 1);
		ret =  stat(old_logfile, &oldstat);
		if (!((ret < 0) && errno == -ENOENT)) {
			//syslog(LOG_INFO, "remove the old log file\n");
			remove(old_logfile);
		}
		for ( i = gl_maxlog - 2; i >= 1; i--) {
			snprintf(old_logfile, sizeof(old_logfile),
				"%s.%d", log_nowname, i);
			ret =  stat(old_logfile, &oldstat);
			if (!((ret < 0) && errno == -ENOENT)) {
				snprintf(old_logfile_new, sizeof(old_logfile_new),
						"%s.%d", log_nowname, i + 1);
				
				rename(old_logfile, old_logfile_new);
			}
		}
		rename(log_nowname, old_logfile);
	}
	new_fd = open(log_nowname, O_RDWR | O_CREAT | O_APPEND, 0644);
	if (new_fd < 0) {
		syslog(LOG_ERR, "failed to create new log file\n");
		exit(1);
	}

	if (dup2(new_fd, log_fd) < 0) {
		syslog(LOG_ERR, "failed to dup2 the log fd\n");
		exit(1);
	}
	close(new_fd);
}

void log_write(int prio, const char *func, int line, const char *fmt, ...)
{
	va_list ap;

	if (prio > soe_log_level)
		return;

	va_start(ap, fmt);
	dolog(prio, func, line, fmt, ap);
	va_end(ap);
}

static void log_flush(void)
{
	struct sembuf ops;
	size_t size, done = 0;
	const struct logmsg *msg;

	if (la->tail == la->start)
		return;

	ops.sem_num = 0;
	ops.sem_flg = SEM_UNDO;
	ops.sem_op = -1;
	if (semop(la->semid, &ops, 1) < 0) {
		syslog(LOG_ERR, "semop up failed: %m");
		exit(1);
	}

	size = la->tail - la->start;
	memcpy(log_buff, la->start, size);
	memset(la->start, 0, size);
	la->tail = la->start;

	ops.sem_op = 1;
	if (semop(la->semid, &ops, 1) < 0) {
		syslog(LOG_ERR, "semop down failed: %m");
		exit(1);
	}

	while (done < size) {
		msg = (const struct logmsg *)(log_buff + done);
		log_syslog(msg);
		done += sizeof(*msg) + msg->str_len + 1;
	}
}

static bool is_sheep_dead(int signo)
{
	return signo == SIGHUP;
}

static void crash_handler(int signo, siginfo_t *info, void *context)
{
	if (is_sheep_dead(signo))
		soe_err("soed pid %d exited unexpectedly.", sheep_pid);
	else {
		soe_err("logger pid %d exits unexpectedly (%s).", getpid(),
		       strsignal(signo));
		soe_backtrace();
	}

	log_flush();
	closelog();
	free_logarea();

	/* If the signal isn't caused by the logger crash, we simply exit. */
	if (is_sheep_dead(signo))
		exit(1);

	reraise_crash_signal(signo, 1);
}

static void sighup_handler(int signo, siginfo_t *info, void *context)
{
	rotate_log();
}

static void logger(char *log_dir, char *outfile)
{
	int fd;

	log_buff = wzalloc(la->end - la->start);

	if (dst_type == LOG_DST_DEFAULT) {
		log_fd = open(outfile, O_CREAT | O_RDWR | O_APPEND, 0644);
		if (log_fd < 0) {
			syslog(LOG_ERR, "failed to open %s\n", outfile);
			exit(1);
		}
	}
	la->active = true;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		syslog(LOG_ERR, "failed to open /dev/null: %m\n");
		exit(1);
	}

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	setsid();
	if (chdir(log_dir) < 0) {
		syslog(LOG_ERR, "failed to chdir to %s: %m\n", log_dir);
		exit(1);
	}

	while (la->active) {
		log_flush();

		block_sighup();

		if (dst_type == LOG_DST_DEFAULT && max_logsize) {
			off_t offset;

			offset = lseek(log_fd, 0, SEEK_END);
			if (offset < 0) {
				syslog(LOG_ERR, "sheep log error\n");
			} else {
				size_t log_size = (size_t)offset;
				if (log_size >= max_logsize)
					rotate_log();
			}
		}

		unblock_sighup();

		if (getppid() != sheep_pid)
			/* My parent (sheep process) is dead. */
			break;

		sleep(1);
	}

	log_flush();
	wfree(log_buff);
	free_logarea();
	exit(0);
}


int log_init(char * argv, const char *program_name, enum log_dst_type type, int level,
		     char *outfile, int server, int maxlog)
{
	char log_dir[PATH_MAX], tmp[PATH_MAX];
	int size = server?LOG_SPACE_DEBUG_SIZE:LOG_CLT_SPACE_DEBUG_SIZE;
	

	gl_maxlog = maxlog;
	max_logsize = server?LOG_SPACE_DEBUG_SIZE:LOG_CLT_SPACE_DEBUG_SIZE;
	dst_type = type;
	soe_log_level = level;

	log_name = program_name;
	log_nowname = outfile;
	pstrcpy(tmp, sizeof(tmp), outfile);
	pstrcpy(log_dir, sizeof(log_dir), dirname(tmp));

	colorize = false;
	semkey = random();

	switch (type) {
	case LOG_DST_STDOUT:
		if (is_stdout_console())
			colorize = true;
		break;
	case LOG_DST_SYSLOG:
		openlog(program_name, LOG_PID, LOG_DAEMON);
		/* fall through */
	case LOG_DST_DEFAULT:
		
		if (logarea_init(size)) {
			syslog(LOG_ERR, "failed to initialize the logger\n");
			return 1;
		}

		/*
		 * Store the pid of the sheep process for use by the death
		 * signal handler.  By the time the child is notified of
		 * the parents death the parent has been reparented to init
		 * and getppid() will always return 1.
		 */
		sheep_pid = getpid();
		logger_pid = fork();
		if (logger_pid < 0) {
			syslog(LOG_ERR, "failed to fork the logger process: %m\n");
			return 1;
		}

		if (logger_pid) {
			syslog(LOG_WARNING, "logger pid %d starting\n", logger_pid);
		}
		else {
			char pro_name[256];
			snprintf(pro_name, sizeof(pro_name), "%s logger", program_name);
			setproctitle(argv, pro_name);
			logger(log_dir, outfile);
		}
		break;
	default:
		soe_err("unknown type of log destination type: %d", type);
		return -1;
	}

	return 0;
}

void log_close(void)
{
	pid_t pid;

	if (!la)
		return;

	while (true) {
		la->active = false;
		pid = waitpid(logger_pid, NULL, WNOHANG);
		if (pid == 0) {
			usleep(100000);
			continue;
		} else if (pid > 0) {
			syslog(LOG_WARNING, "logger pid %d stopped\n",
					logger_pid);
			closelog();
			free_logarea();
			break;
		} else {
			syslog(LOG_ERR, "waitpid() failure\n");
			exit(1);
		}
	}
	
}

void set_thread_name(const char *name, bool show_idx)
{
	worker_name = name;
	if (show_idx)
		worker_idx = gettid();
}

void get_thread_name(char *name)
{
	format_thread_name(name, MAX_THREAD_NAME_LEN, worker_name, worker_idx);
}


#define SOE_MAX_STACK_DEPTH 1024

static bool check_gdb(void)
{
	return system("which gdb > /dev/null") == 0;
}

#define SOE_ARG_MAX (sysconf(_SC_ARG_MAX))

static int gdb_cmd(const char *cmd)
{
	char time_str[256], cmd_str[SOE_ARG_MAX];
	time_t ti;
	struct tm tm;

	if (!check_gdb()) {
		soe_debug("cannot find gdb");
		return -1;
	}

	time(&ti);
	localtime_r(&ti, &tm);
	strftime(time_str, sizeof(time_str), "%b %2d %H:%M:%S ", &tm);

	snprintf(cmd_str, sizeof(cmd_str),
		 "gdb -nw %s %d -batch >/dev/null 2>&1"
		 " -ex 'set logging on'"
		 " -ex 'echo \\n'"
		 " -ex 'echo ==\\n'"
		 " -ex 'echo == %s\\n'"
		 " -ex 'echo == program: %s\\n'"
		 " -ex 'echo == command: %s\\n'"
		 " -ex 'echo ==\\n'"
		 " -ex '%s'"
		 " -ex 'set logging off'",
		 my_exe_path(), getpid(), time_str, my_exe_path(), cmd, cmd);

	return system(cmd_str);
}

int __soe_dump_variable(const char *var)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "p %s", var);

	return gdb_cmd(cmd);
}

static int dump_stack_frames(void)
{
	return gdb_cmd("thread apply all where full");
}

__attribute__ ((__noinline__))
void soe_backtrace(void)
{
	void *addrs[SOE_MAX_STACK_DEPTH];
	int i, n = backtrace(addrs, ARRAY_SIZE(addrs));

	for (i = 1; i < n; i++) { /* addrs[0] is here, so skip it */
		void *addr = addrs[i];
		char cmd[SOE_ARG_MAX], info[256], **str;
		FILE *f;

		/*
		 * The called function is at the previous address
		 * because addr contains a return address
		 */
		addr = (void *)((char *)addr - 1);

		/* try to get a line number with addr2line if possible */
		snprintf(cmd, sizeof(cmd), "addr2line -s -e %s -f -i %p | "
			 "perl -e '@a=<>; chomp @a; print \"$a[1]: $a[0]\"'",
			 my_exe_path(), addr);
		f = popen(cmd, "r");
		if (!f)
			goto fallback;
		if (fgets(info, sizeof(info), f) == NULL)
			goto fallback_close;

		if (info[0] != '?' && info[0] != '\0') {
			soe_emerg("%s", chomp(info));
		}
		else
			goto fallback_close;

		pclose(f);
		continue;
		/*
		 * Failed to get a line number, so simply use
		 * backtrace_symbols instead
		 */
fallback_close:
		pclose(f);
fallback:
		str = backtrace_symbols(&addr, 1);
		soe_emerg("%s", *str);
		free(str);
	}

	/* dump the stack frames if possible*/
	dump_stack_frames();
}

void set_loglevel(int new_loglevel)
{
	soe_assert(SOE_EMERG <= new_loglevel && new_loglevel <= SOE_DEBUG);
	soe_log_level = new_loglevel;
}

int get_loglevel(void)
{
	return soe_log_level;
}
