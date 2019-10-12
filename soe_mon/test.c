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


static char * soe_map_path = "/usr/sbin/soe_map";

int main(int argc, void *argv[])
{
	char *cargv[8];
	char argv2[10], argv4[10], argv6[200];
	char cmd[256];

	setsid();

	snprintf(argv2, 10, "%d", 0);
	snprintf(argv4, 10, "%d", 0);
	snprintf(argv6, 200, "%s", "192.168.1.245");
	cargv[0] = soe_map_path;
	cargv[1] = "-r";
	cargv[2] = argv2; 
	cargv[3] = "-l";
	cargv[4] = argv4;
	cargv[5] = "-t";
	cargv[6] = argv6;
	cargv[7] = NULL;
	if (execv(soe_map_path, cargv) < 0) {
		exit(-1);
	}
	return 0;
}

