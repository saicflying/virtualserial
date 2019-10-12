#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/times.h>

#define panic(fmt, args...)                     \
	({                                              \
	 syslog(LOG_EMERG, "PANIC: " fmt, ##args);        \
	 abort();                                \
	 })

typedef struct soe_map_uart_s {
	int seq;
	int localline;
	int remoteline;
	char ipstr[200];
	int options;
	int valid;
	int status;
	clock_t mapping_time;
	pid_t pid;
}soe_map_uart_t;

void start_mapping(int i);
void stop_mapping(int i);

static soe_map_uart_t gl_uart_mapping[256]; 
static int gl_kfd;
static char * soe_map_path = "/usr/sbin/soe_map";

static int lock_fd = 0;
static int lock_base_dir(void)
{
#define LOCK_PATH "/var/.soe.mon.lock"
	char *lock_path;
	int ret = 0;

	lock_fd = open(LOCK_PATH, O_WRONLY|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (lock_fd < 0) {
		syslog(LOG_ERR, "failed to open lock file %s (%m)", LOCK_PATH);
		ret = -1;
		goto out;
	}

	if (lockf(lock_fd, F_TLOCK, 1) < 0) {
		if (errno == EACCES || errno == EAGAIN)
			syslog(LOG_ERR, "another soe_mon daemon is running");
		else
			syslog(LOG_ERR, "failed to lock the daemon, errno=%d", errno);
		ret = -1;
		goto out;
	}

out:
	return ret;
}


static int lock_and_daemon(int daemonize)
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
			panic("becoming a leader of a new session failed: %m");
			status = 1;
			goto end;
		}

		switch (fork()) {
			case 0:
				break;
			case -1:
				panic("fork() failed during daemonize: %m");
				status = 1;
				goto end;
			default:
				_exit(0);
				break;
		}

		if (chdir("/")) {
			panic("chdir to / failed: %m");
			status = 1;
			goto end;
		}

		devnull_fd = open("/dev/null", O_RDWR);
		if (devnull_fd < 0) {
			panic("opening /dev/null failed: %m");
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


char * trim_string(char * sz)
{
	char * tmp = sz;
	while(*tmp != '\0' && isspace(*tmp)) {
		tmp++;
	}
	return tmp;
}

soe_map_uart_t * find_the_uart(int ll, int seq)
{
	int i;
	int firstempty = -1;
	for(i = 0 ; i < sizeof(gl_uart_mapping) / sizeof(soe_map_uart_t); i++) {
		if (gl_uart_mapping[i].valid) {
			if (gl_uart_mapping[i].localline == ll ) {
				if (gl_uart_mapping[i].seq != seq) {
					return gl_uart_mapping + i;
				} else {
					syslog(LOG_INFO, "found the duplicated config for ttySOE%d", i);
					return NULL;
				}
			}
		} else {
			if (firstempty < 0) {
				firstempty = i;
			}
		}
	}
	if (firstempty >= 0)
		return gl_uart_mapping + firstempty;	
	return NULL;
}

void update_config(int seq)
{
	FILE * fp = fopen("/etc/soed/soe_map.conf", "r");
	char buf[256];
	int localline;
	int remoteline;
	char ipstr[200];
	int cnt;
	char * ptmp, *ptmp1;
	soe_map_uart_t * puart;
	if (fp) {
		memset(buf, 0, sizeof(buf));
		while (fgets(buf, sizeof(buf), fp)) {
			ptmp = trim_string(buf);
			if (*ptmp == '\0' || *ptmp == '#') {
				continue;
			} 
			if (!isdigit(*ptmp)) {
				continue;
			}
			localline = strtoul(ptmp, &ptmp1, 10);
			ptmp = trim_string(ptmp1);
			if (*ptmp == '\0' || *ptmp == '#') {
				continue;
			} 
			cnt = 0;
			while(*ptmp != '\0' && !isspace(*ptmp)) {
				if (cnt == sizeof(ipstr) - 1) {
					break;
				}
				ipstr[cnt] = *ptmp;
				ptmp++;
				cnt++;	
			}
			ipstr[cnt] = '\0';
			ptmp = trim_string(ptmp);	
			if (*ptmp == '\0' || *ptmp == '#') {
				continue;
			}
			if (!isdigit(*ptmp)) {
				continue;
			}
			remoteline = strtoul(ptmp, &ptmp1, 10);
			if (localline > 250 || localline < 0) {
				syslog(LOG_ERR, "can't map the ttySOE%d", localline); 
				continue;
			}
			puart = find_the_uart(localline, seq); 
			if (puart) {
				if (puart->valid) {
					if (!(puart->remoteline == remoteline && strcmp(puart->ipstr, ipstr) == 0)) {
						/* something changed */
						syslog(LOG_INFO, "config changed, map from %s:%d to %d is closed",
											puart->ipstr, puart->remoteline, puart->localline);
						if (puart->pid > 0) {
							kill(puart->pid, SIGTERM);
							puart->pid = 0;
						}
					}
				}
				puart->localline = localline;
				puart->remoteline = remoteline;
				strcpy(puart->ipstr, ipstr);
				puart->valid = 1;
				puart->seq = seq;
			}
		}
		fclose(fp);
	}
	for (cnt = 0; cnt < sizeof(gl_uart_mapping) / sizeof(soe_map_uart_t); cnt++) {
		if (gl_uart_mapping[cnt].valid && gl_uart_mapping[cnt].seq != seq) {
			/* stop the mapping */
			stop_mapping(cnt);	
			gl_uart_mapping[cnt].valid = 0;
		}
	}
}

int check_pid_status(int pid)
{
	char cmd[256], *ptmp;
	FILE * fp;
	int ret;
	snprintf(cmd, sizeof(cmd), "/proc/%d/status", pid);
	fp = fopen(cmd, "r");
	if (fp == NULL) {
		return -1;
	}
	while(fgets(cmd, sizeof(cmd), fp)) {
		ptmp = strstr(cmd, "State:");
		if (ptmp) {
			ptmp += 6;
			while(!isalpha(*ptmp)) {
				ptmp++;
			}
			switch(*ptmp) {
			case 'R':
			case 'S':
			case 'D':
				ret = 0;
				break;
			default:
				ret = -1;
			}
		}
	}
	pclose(fp);
	if (ret < -1) {
		kill(pid, SIGKILL);
	}
	return ret;
}

void stop_mapping(int i)
{	
	int cnt = 0;
	if (!gl_uart_mapping[i].valid) return;
	if (gl_uart_mapping[i].pid) {
		while( cnt < 10) {
			if ( cnt < 5) {
				kill(gl_uart_mapping[i].pid, SIGTERM);	
			} else {
				kill(gl_uart_mapping[i].pid, SIGKILL);	
			}
			if (check_pid_status(gl_uart_mapping[i].pid) < 0) {
				waitpid(gl_uart_mapping[i].pid, NULL, 0);
				gl_uart_mapping[i].pid = 0;
				return;
			}
			cnt++;
			sleep(1);
		}
		syslog(LOG_ERR, "Timeout when stop mapping (pid = %d)\n", gl_uart_mapping[i].pid);
		gl_uart_mapping[i].pid = 0;
	}
}

void start_mapping(int i)
{
	char *cargv[9];
	char argv2[10], argv4[10], argv6[200];
	char cmd[256];
	clock_t curtime;
	pid_t pid;
	if (!gl_uart_mapping[i].valid) return;
	if (gl_uart_mapping[i].pid) {
		int freq = sysconf(_SC_CLK_TCK);	
		if (check_pid_status(gl_uart_mapping[i].pid) == 0) {
			/* already mapping , waiting */	
			curtime = times(NULL);	
			if (curtime - gl_uart_mapping[i].mapping_time > freq * 100) {
				stop_mapping(i);
			} else {
				return;
			}
		} else {
			stop_mapping(i);
		}
	}
		
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "Failed to mapping serial from %s:%d to %d", gl_uart_mapping[i].ipstr,
							gl_uart_mapping[i].remoteline, gl_uart_mapping[i].localline);
	} else if (pid == 0) {
		setsid();
		int fd = open("/dev/null", O_WRONLY, 0);
		if (fd > 0) {
			close(0);
			close(1);
			close(2);
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
			close(fd);
		}
		snprintf(argv2, 10, "%d", gl_uart_mapping[i].remoteline);
		snprintf(argv4, 10, "%d", gl_uart_mapping[i].localline);
		snprintf(argv6, 200, "%s", gl_uart_mapping[i].ipstr);
		cargv[0] = soe_map_path;
		cargv[1] = "-p";
		cargv[2] = argv4;
		cargv[3] = "-r";
		cargv[4] = argv2; 
		cargv[5] = "-t";
		cargv[6] = argv6;
		cargv[7] = "-f";
		cargv[8] = NULL;
		if (execv(soe_map_path, cargv) < 0) {
			syslog(LOG_ERR, "soe_map_path:%s, Failed to mapping serial from %s:%d to %d with execv",soe_map_path,  gl_uart_mapping[i].ipstr,
							gl_uart_mapping[i].remoteline, gl_uart_mapping[i].localline);
			exit(-1);
		}
	} else {
		gl_uart_mapping[i].pid = pid;
		gl_uart_mapping[i].mapping_time = times(NULL);
		syslog(LOG_ERR, "Mapping serial from %s:%d to %d (pid=%d)", gl_uart_mapping[i].ipstr,
							gl_uart_mapping[i].remoteline, gl_uart_mapping[i].localline, pid);
	}
}

#define SOE_GET_MAPPING  _IO('Z', 2)
void check_status(void)
{
	int i, ret;
	struct stat stat_dev;
	char dev_name[256];
	if (!gl_kfd) {
		gl_kfd = open("/dev/soe", O_RDWR|O_SYNC);	
		if (gl_kfd <= 0) {
			syslog(LOG_ERR, "failed to open kernel module");
			gl_kfd = 0;
		}
	}

	for (i = 0; i < sizeof(gl_uart_mapping) / sizeof(soe_map_uart_t); i++) {
		if (gl_uart_mapping[i].valid) {
			snprintf(dev_name, sizeof(dev_name), "/dev/ttySOE%d", gl_uart_mapping[i].localline);
			ret = stat(dev_name, &stat_dev);
			if (ret < 0 && errno == ENOENT)  {
				start_mapping(i);	
			} else {
				if (gl_kfd) {
					ret = ioctl(gl_kfd, SOE_GET_MAPPING, gl_uart_mapping[i].localline); 	
					if (ret < 0) {
						syslog(LOG_INFO, "get mapping errnr: %d", errno);	
						if (errno == ENOTTY || errno == ENOMEM) {
							start_mapping(i);
						}
					}
				}
			}
		}
	}
}

int kill_soe_map(void)
{
	char kill_cmd[256];
	char buf[256];
	FILE * fp;

	char * ptmp, *pnext;
	int pid;
	int have_process = 0;
	syslog(LOG_INFO, "Kill all of the soe_map process");

	/* kill all of the soe_map process */
	snprintf(kill_cmd, sizeof(kill_cmd), "pidof soe_map");
retry_kill:
	fp = popen(kill_cmd, "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "Failed to kill the existing process");
		return -1;
	}	
	have_process = 0;
	memset(buf, 0, sizeof(buf));
	while(fgets(buf, sizeof(buf), fp)){
		have_process = 1;
		ptmp = trim_string(buf);					
		if (*ptmp == '\0') {
			have_process = 0;
			break;
		}

		do {
			pid = strtoul(ptmp, &pnext, 10);	
			kill(pid, SIGTERM);
			if (pnext) {
				ptmp = trim_string(pnext);	
			}
		} while (ptmp && (*ptmp != '\0'));
	}
	pclose(fp);
	if (have_process) {
	       usleep(100);
	       goto retry_kill;	
	}
	return 0;
}

static int gl_loop = 1;
void sighandler(int sig)
{
	gl_loop = 0;
}

int main(int argc, void *argv[])
{
	int gl_seq = 0;
	int daemonize = 1;
	int ret;
	if (argc >= 2) {
		soe_map_path = argv[1];
	}
	if (argc >= 3) {
		if (strncmp(argv[2], "-f", 2) == 0) {
			daemonize = 0;
		}
	}
	signal(SIGINT, sighandler);	
	signal(SIGTERM, sighandler);	

	openlog("soe_mon", LOG_PID, LOG_DAEMON);
	ret = system("modprobe soe_uart");	
	if (ret) {
		syslog(LOG_ERR, "failed to load the soe_uart module:%d\n", errno);
		closelog();
		return 0;
	}

	if (daemonize) {
		lock_and_daemon(1);
	}
	
	if (kill_soe_map() < 0) {
		closelog();
		return 0;	
	}
	
	while (gl_loop) {
		update_config(gl_seq++);
		check_status();
		sleep(1);
	}
	if (gl_kfd) {
		close(gl_kfd);
		gl_kfd = 0;
	}
	closelog();
	return 0;	
}
