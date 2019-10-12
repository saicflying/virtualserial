
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/watchdog.h>
#include "compiler.h"
#include "util.h"
#include "option.h"
#include "net.h"
#include "event.h"
#include "soe_priv.h"
#include "serial.h"
#include "license.h"
#include <sys/ioctl.h>
#include <dlfcn.h>

#define EPOLL_SIZE 4096
#define LOG_DIR_DEFAULT "/var/log"
#define LOG_FILE_NAME "soed.log"
#define SOE_PID_FILE    "/var/run/soed.pid" 
#define soe_dump_variable(var) ({                \
		__soe_dump_variable(#var);               \
		})

#define PACKAGE_VERSION "1.0.0.3"


static struct system_info __sys;
struct system_info *sys = &__sys;

static const char program_name[] = "soed";
static const char bind_help[] =
"Example:\n\t$ soed -b 192.168.1.1 ...\n"
"This tries to teach soed listen to NIC of 192.168.1.1.\n"
"\nExample:\n\t$ soed -b 0.0.0.0 ...\n"
"This tries to teach soed listen to all the NICs available. It can be useful\n"
"when you want sheep to response dog without specified address and port.\n";

static const char log_help[] =
"Example:\n\t$ soed -l dir=/var/log/,level=debug,format=server ...\n"
"Available arguments:\n"
"\tdir=: path to the location of soed.log\n"
"\tlevel=: log level of soed.log\n"
"\tdst=: log destination type\n\n"
"if dir is not specified, use metastore directory\n\n"
"Available log levels:\n"
"  Level      Description\n"
"  emerg      system has failed and is unusable\n"
"  alert      action must be taken immediately\n"
"  crit       critical conditions\n"
"  err        error conditions\n"
"  warning    warning conditions\n"
"  notice     normal but significant conditions\n"
"  info       informational notices\n"
"  debug      debugging messages\n"
"default log level is debug\n\n"
"Available log destination:\n"
"  DestinationType    Description\n"
"  default            dedicated file in a directory\n"
"  syslog             syslog of the system\n"
"  stdout             standard output\n";

static struct soe_option soe_options[] = {
	{'b', "bindaddr", true, "specify IP address of interface to listen on", bind_help},
	{'p', "port", true, "specify the TCP port on which to listen (default: 5000)"},
	{'l', "log", true,
 	 "specify the log level, the log directory and the log format"
	 "(log level default: 6 [SOE_INFO])", log_help},
	{'h', "help", false, "display this help and exit"},
	{'f', "foreground", false, "make the program run in foreground"},
};

static int log_level = SOE_INFO;

static void soelog_help(void)
{
	printf("Available log levels:\n"
			"  Level      Description\n"
			"  emerg      system has failed and is unusable\n"
			"  alert      action must be taken immediately\n"
			"  crit       critical conditions\n"
			"  err        error conditions\n"
			"  warning    warning conditions\n"
			"  notice     normal but significant conditions\n"
			"  info       informational notices\n"
			"  debug      debugging messages\n");
}

static int log_level_parser(const char *s)
{
	int level = loglevel_str2num(s);

	if (level < 0) {
		soe_err("Invalid log level '%s'", s);
		soelog_help();
		return -1;
	}

	log_level = level;
	return 0;
}

static char *logdir;

static int log_dir_parser(const char *s)
{
	logdir = realpath(s, NULL);
	if (!logdir) {
		soe_err("%m");
		exit(1);
	}
	return 0;
}


static int watchdogfd = 0;

static void * wdt_libhandle = NULL; 
#ifndef __ARM_ARCH
typedef long (*wdt_enable_t)(void);
#else
typedef long (*wdt_enable_t)(unsigned int);
#endif
typedef long (*wdt_settime_t)(int);
typedef long (*wdt_disable_t)(void);
typedef long (*wdt_feed_t)(void);
wdt_enable_t  zkwdt_enable = NULL;
wdt_settime_t zkwdt_settime = NULL;
wdt_disable_t zkwdt_disable = NULL;
wdt_feed_t    zkwdt_feed = NULL;

static int wdt_enable()
{
	int timeout = 10; /* 10 second time out */
#ifndef __ARM_ARCH
	watchdogfd = open("/dev/watchdog", O_WRONLY);
	if (watchdogfd < 0) {
#endif
		watchdogfd = 0;
		soe_info("can't find the standard watchdog, try to load zkty wdt");
#ifndef __ARM_ARCH
		wdt_libhandle = dlopen("/usr/lib/libzktybase.so", RTLD_LAZY); 			
#else
		wdt_libhandle = dlopen("/usr/local/lib/libzkty-hwlib.so", RTLD_LAZY); 			
#endif
		if (!wdt_libhandle) {
			soe_warn("can't find the libzaktybase.so, either, disable watchdog protection");
		} else {
#ifndef __ARM_ARCH
			zkwdt_enable = dlsym(wdt_libhandle, "TEC_WdtEnable");
			zkwdt_disable = dlsym(wdt_libhandle, "TEC_WdtDisable");
			zkwdt_settime = dlsym(wdt_libhandle, "TEC_WdtSetTime");
			zkwdt_feed = dlsym(wdt_libhandle, "TEC_WdtFeed");			
#else
			zkwdt_enable = dlsym(wdt_libhandle, "zkty_watchdog_enable");
			zkwdt_disable = dlsym(wdt_libhandle, "zkty_watchdog_disable");
			zkwdt_settime = dlsym(wdt_libhandle, "zkty_watchdog_settimeout");
			zkwdt_feed = dlsym(wdt_libhandle, "zkty_watchdog_kick");			
#endif
			if (zkwdt_enable == NULL || 
			    zkwdt_disable == NULL ||
			    zkwdt_settime == NULL ||
			    zkwdt_feed    == NULL) {
				soe_warn("can't find the wdt symbols in libzaktybase.so, disable watchdog protection");
				dlclose(wdt_libhandle);
				wdt_libhandle = NULL;
				return 0;
			}
#ifndef __ARM_ARCH
			if (zkwdt_enable() != 0) {
#else
			if (zkwdt_enable(timeout) != 0) {
#endif
				soe_warn("failed to enable zkty watchdog, disable watchdog protection");
				dlclose(wdt_libhandle);	
				wdt_libhandle = NULL;
			} else {
				zkwdt_feed();
				zkwdt_settime(timeout);
				soe_info("SOE watchdog timeout is %d seconds", timeout);
			}
		}
#ifndef __ARM_ARCH
	} else {
		ioctl(watchdogfd, WDIOC_SETTIMEOUT, &timeout);
		soe_info("SOE watchdog timeout is %d seconds", timeout);
	}
#endif
	return 0;
}

static void wdt_disable()
{
	if (watchdogfd) {
		write(watchdogfd, "V", 1);
		close(watchdogfd);
	} else {
		if (wdt_libhandle) {
			zkwdt_disable();
			dlclose(wdt_libhandle);	
			wdt_libhandle = NULL;
		}
	}
}

static void wdt_keepalive()
{
	if (watchdogfd > 0) {
		ioctl(watchdogfd, WDIOC_KEEPALIVE, 0);
	} else {
		if (wdt_libhandle) {
			zkwdt_feed();
		}
	}
}

static const char *log_dst = "default"; /* default: dedicated file */

static int log_dst_parser(const char *s)
{
	log_dst = s;
	return 0;
}

static struct option_parser log_parsers[] = {
	{ "level=", log_level_parser },
	{ "dir=", log_dir_parser },
	{ "dst=", log_dst_parser },
	{ NULL, NULL },
};

static void usage(int status)
{
	if (status) {
		const char *help = option_get_help(soe_options, optopt);

		if (help) {
			printf("%s", help);
			goto out;
		}

		soe_err("Try '%s --help' for more information.", program_name);
	} else {
		struct soe_option *opt;

		printf("Serial Over Ethernet daemon (version %s)\n"
				"Usage: %s [OPTION]... \n"
				"Options:\n", PACKAGE_VERSION, program_name);

		soe_for_each_option(opt, soe_options) {
			printf("  -%c, --%-18s%s\n", opt->ch, opt->name,
					opt->desc);
		}

		printf("\nTry '%s <option>', e.g., '%s -w', to get more detail "
				"about specific option\n", program_name, program_name);
	}
out:
	exit(status);
}


static int sigfd;

static void signal_handler(int listen_fd, int events, void *data)
{
        struct signalfd_siginfo siginfo;
        int uninitialized_var(ret);
        ret = read(sigfd, &siginfo, sizeof(siginfo));
        soe_assert(ret == sizeof(siginfo));
        soe_info("signal %d, ssi pid %d", siginfo.ssi_signo, siginfo.ssi_pid);
        switch (siginfo.ssi_signo) {
        case SIGTERM:
        case SIGINT:
                sys->status = SOE_STATUS_KILLED;
                break;
        default:
                soe_err("signal %d unhandled", siginfo.ssi_signo);
                break;
        }
}

static int init_signal(void)
{
        sigset_t mask;
        int ret, flag;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        ret = sigprocmask(SIG_BLOCK, &mask, NULL);
#ifdef _SYS_SIGNALFD_H
        sigfd = signalfd(-1, &mask, SFD_NONBLOCK);
        if (sigfd < 0) {
                soe_err("failed to create a signal fd: %m");
                return -1;
        }
#else
	sigfd = syscall(__NR_signalfd, -1, &mask,  _NSIG / 8);
	if (sigfd < 0) {
                soe_err("failed to create a signal fd: %m");
                return -1;
	}

	flag = fcntl(sigfd, F_GETFL, 0);
	flag |= O_NONBLOCK;
	if (fcntl(sigfd, F_SETFL, flag) < 0) {
                soe_err("failed to set nonblock: %m");
		close(sigfd);
		return -1; 
	}

#endif

        ret = register_event(sigfd, signal_handler, NULL);
        if (ret) {
                soe_err("failed to register signal handler (%d)", ret);
                return -1;
        }

        soe_info("register signal_handler for %d", sigfd);

        return 0;
}

static int create_pidfile(const char *filename)
{
        int fd;
        int len;
        char buffer[128];

        fd = open(filename, O_RDWR|O_CREAT|O_SYNC, 0600);
        if (fd == -1)
                return -1;

        if (lockf(fd, F_TLOCK, 0) == -1) {
                close(fd);
                return -1;
        }

        len = snprintf(buffer, sizeof(buffer), "%d\n", getpid());
        if (write(fd, buffer, len) != len) {
                close(fd);
                return -1;
        }

        /* keep pidfile open & locked forever */
        return 0;
}

static void sighup_handler(int signo, siginfo_t *info, void *context)
{
	if (unlikely(logger_pid == -1))
		return;

	/* forward SIGHUP for log rotating */
	kill(logger_pid, SIGHUP);
}

static void crash_handler(int signo, siginfo_t *info, void *context)
{
	soe_emerg("soed exits unexpectedly (%s), "
			"si pid %d, uid %d, errno %d, code %d",
			strsignal(signo), info->si_pid, info->si_uid,
			info->si_errno, info->si_code);

	soe_backtrace();
	soe_dump_variable(__sys);

	reraise_crash_signal(signo, 1);
}


static int lock_fd = 0;
static int lock_base_dir(void)
{
#define LOCK_PATH "/var/.soe.lock"
	char *lock_path;
	int ret = 0;

	lock_fd = open(LOCK_PATH, O_WRONLY|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (lock_fd < 0) {
		soe_err("failed to open lock file %s (%m)", LOCK_PATH);
		ret = -1;
		goto out;
	}

	if (lockf(lock_fd, F_TLOCK, 1) < 0) {
		if (errno == EACCES || errno == EAGAIN)
			soe_err("another soed daemon is running");
		else
			soe_err("failed to lock the daemon, errno=%d", errno);
		ret = -1;
		goto out;
	}

out:
	return ret;
}

static int lock_and_daemon(bool daemonize)
{
	int ret, devnull_fd = 0, status = 0;
	int pipefd[2];

	if (daemonize) {
		ret = pipe(pipefd);
		if (ret < 0)
			panic("pipe() for passing exit status failed: %m");


		switch (fork()) {
			case 0:
				break;
			case -1:
				panic("fork() failed during daemonize: %m");
				break;
			default:
				close(pipefd[1]);
				ret = read(pipefd[0], &status, sizeof(status));
				if (ret != sizeof(status))
					panic("read exit status failed: %m");

				close(pipefd[0]);
				_exit(status);
				break;
		}

		if (setsid() == -1) {
			soe_err("becoming a leader of a new session failed: %m");
			status = 1;
			goto end;
		}

		switch (fork()) {
			case 0:
				break;
			case -1:
				soe_err("fork() failed during daemonize: %m");
				status = 1;
				goto end;
			default:
				_exit(0);
				break;
		}

		if (chdir("/")) {
			soe_err("chdir to / failed: %m");
			status = 1;
			goto end;
		}

		devnull_fd = open("/dev/null", O_RDWR);
		if (devnull_fd < 0) {
			soe_err("opening /dev/null failed: %m");
			status = 1;
			goto end;
		}
	}

	ret = lock_base_dir();
	if (ret < 0) {
		status = 1;
	}

	if (daemonize) {
		/*
		 * now we can use base_dir/sheep.log for logging error messages,
		 * we can close 0, 1, and 2 safely
		 *
		 */
		dup2(devnull_fd, 0);
		dup2(devnull_fd, 1);
		dup2(devnull_fd, 2);

		close(devnull_fd);
end:
		close(pipefd[0]);
		ret = write(pipefd[1], &status, sizeof(status));
		if (ret != sizeof(status))
			panic("writing exit status failed: %m");
		close(pipefd[1]);
	}
	return status;
}

static int gl_verified = 0;
static void verify_lic(void) 
{
	identity_t id;
	int ret, len, fd = 0, i;
	char sha256[65], sha1val[41],verval[41], * plic = NULL, *ptmp;
	struct stat sts;
	uint32_t utmp;
	uint16_t lic[40];

	memset(sha256, 0, sizeof(sha256));
	memset(sha1val, 0, sizeof(sha1val));
	memset(verval, 0, sizeof(verval));
	ret = find_identity(&id, sha256);
	if (ret < 0) {
		gl_verified = 8;
		goto end;
	}

	strsha1(sha256, 64, sha1val);
	fd = open("/etc/soed/soed.lic", O_RDONLY);
	if (fd <= 0) {
		gl_verified = 2;
		fd = open("/etc/soed/license.dat", O_RDONLY);
		if (fd <= 0) {
			gl_verified = 4;
			goto end;
		}
	}
	
	ret = fstat(fd, &sts);
	if (ret < 0) {
		gl_verified = 6;
		goto end;
	}

	plic = malloc(sts.st_size);
	if (plic == NULL) {
		gl_verified = 8;
		goto end;
	}

	ret = read(fd, plic, sts.st_size);
	if (ret != sts.st_size) {
		gl_verified = 10;
		goto memend;
	}
	for (i = 0, ptmp = plic; i < 40;) {
		utmp = strtoul(ptmp, NULL, 16);
		lic[i] = utmp >> 16;
		lic[i+1] = utmp & 0xffff;
		i += 2;
		ptmp += 9;
	//	fprintf(stderr, "%08x", utmp);
	}
	
	rsa_decrypt(lic, 160,  verval); 
	if (memcmp(verval, sha1val, sizeof(verval)) == 0) {
		gl_verified = 1; 
	}
memend:
	free(plic);
end:
	if (!(gl_verified & 0x1)) {
		soe_err("license check failed, exit");	
		soe_err("if you have no license, please contact saicflying@163.com with the below identity");
		soe_err("%s", sha256);
	}
	if (fd > 0)
		close(fd);
}


static void feed_watchdog(void)
{
	
}


int main(int argc, char **argv)
{
	int ch, longindex, ret, port = SOE_LISTEN_PORT, io_port = SOE_LISTEN_PORT;
	bool  daemonize = true;
	struct option *long_options;
	const char * short_options;
	char * bindaddr = NULL, log_path[PATH_MAX];
	struct stat logdir_st;
	enum log_dst_type log_dst_type;
	int serial_num;
	clock_t tvnow, tvlast;
	int freq = sysconf(_SC_CLK_TCK);	
	
	install_crash_handler(crash_handler);
	signal(SIGPIPE, SIG_IGN);
	install_sighandler(SIGHUP, sighup_handler, false);

	long_options = build_long_options(soe_options);
	short_options = build_short_options(soe_options);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
					&longindex)) >= 0) {
		switch (ch) {
			case 'b':
				if (!inetaddr_is_valid(optarg))
					exit(1);
				bindaddr = optarg;
				break;
			case 'p':
				port = str_to_u16(optarg);
				if (errno != 0 || port < 1) {
					soe_err("Invalid port number '%s'", optarg);
					exit(1);
				}
				break;
			case 'l':
				if (option_parse(optarg, ",", log_parsers) < 0)
					exit(1);
				break;
			case 'h':
				usage(0);
				break;
			case 'f':
				daemonize = false;
				break;
			default:
				usage(1);
				break;
		}
	}

	if (!strcmp(log_dst, "default"))
		log_dst_type = LOG_DST_DEFAULT;
	else if (!strcmp(log_dst, "stdout"))
		log_dst_type = LOG_DST_STDOUT;
	else if (!strcmp(log_dst, "syslog"))
		log_dst_type = LOG_DST_SYSLOG;
	else {
		soe_err("invalid type of log destination: %s", log_dst);
		exit(1);
	}

	if (logdir) {
		if (log_dst_type != LOG_DST_DEFAULT) {
			soe_err("logdir (%s) is specified but logging"
					" destination is %s", logdir,
					log_dst_type == LOG_DST_STDOUT
					? "stdout" : "syslog");
			exit(1);
		}

		memset(&logdir_st, 0, sizeof(logdir_st));
		ret = stat(logdir, &logdir_st);
		if (ret < 0) {
			soe_err("stat() failed on %s, %m", logdir);
			exit(1);
		}

		if (!S_ISDIR(logdir_st.st_mode)) {
			soe_err("log dir: %s is not a directory", logdir);
			exit(1);
		}
	}
	
	snprintf(log_path, sizeof(log_path), "%s/" LOG_FILE_NAME,
			logdir?:LOG_DIR_DEFAULT);
	if (logdir) 
		wfree(logdir);

	srandom(port);

	if (daemonize && log_dst_type == LOG_DST_STDOUT)
		daemonize = false;

	if (lock_and_daemon(daemonize)) {
		goto end;
	}
#if 1	
	ret = log_init(argv[0], program_name, log_dst_type, log_level, log_path, 1, 6);
	if (ret) {
		goto end;
	}
#endif
	soe_info("Serial over uart is starting");

	verify_lic();

	if (!(gl_verified & 0x1)) {
		exit(-1);
	}
#if 1
	wdt_enable();
#endif	
	init_mem_leak_detection();	

	ret = init_event(EPOLL_SIZE);	
	if (ret) {
		goto cleanup_log;
	}

        ret = init_work_queue();
        if (ret)
                goto cleanup_events;

	ret = create_net_cache();
	if (ret)
		goto cleanup_queues;

	ret = init_signal();
	if (ret)
		goto cleanup_queues;

	ret = create_listen_port(bindaddr, port);
	if (ret) 
		goto cleanup_signal;

	soe_info("create pid file");
	if (create_pidfile(SOE_PID_FILE) != 0) {
		soe_err("failed to pid file '"SOE_PID_FILE"' - %m");
		goto cleanup_socks;
	}

	init_serial();
	soe_info("serial over ethernet daemon (version %s) started", PACKAGE_VERSION);
	tvlast = tvnow = times(NULL);
	while ((sys->status != SOE_STATUS_KILLED &&
			 sys->status != SOE_STATUS_SHUTDOWN)) {
		event_loop(3000);	
		tvnow = times(NULL);
		if (tvnow - tvlast > 3 * freq) {
			tvlast = tvnow;
			wdt_keepalive();
		}
	}
	
	soe_info("shutdown");
	soe_stop_thread();	
	cleanup_serial();	
	unlink(SOE_PID_FILE);
cleanup_socks:
	soe_info("Cleanup: sockets");
	cleanup_net();	
cleanup_signal:
	unregister_event(sigfd);
	close(sigfd);
cleanup_queues:
	cleanup_queue();
	soe_info("Cleanup queues");
cleanup_events:
	soe_info("Cleanup: events");
	events_close();
	soe_info("waiting for all the threads to be ended");
	soe_threads_join();
	soe_cache_cleanup();
	collect_mem_leak();	
cleanup_log:
	soe_info("Serial over uart is stopped");
	log_close();
	wdt_disable();	
end:
	if (lock_fd > 0) {
		close(lock_fd);
	}
	return 0;
}
