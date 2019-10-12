/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* This file contains shared functionalities for libsd.a */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <linux/falloc.h>

#include "util.h"

/*
 * If 'once' is true, the signal will be restored to the default state
 * after 'handler' is called.
 */
int install_sighandler(int signum, void (*handler)(int, siginfo_t *, void *),
	bool once)
{
	struct sigaction sa = {};

	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;

	if (once)
		sa.sa_flags = sa.sa_flags | SA_RESETHAND | SA_NODEFER;
	sigemptyset(&sa.sa_mask);

	return sigaction(signum, &sa, NULL);
}

int install_crash_handler(void (*handler)(int, siginfo_t *, void *))
{
	return install_sighandler(SIGSEGV, handler, true) ||
		install_sighandler(SIGABRT, handler, true) ||
		install_sighandler(SIGBUS, handler, true) ||
		install_sighandler(SIGILL, handler, true) ||
		install_sighandler(SIGFPE, handler, true) ||
		install_sighandler(SIGQUIT, handler, true);
}

/*
 * Re-raise the signal 'signo' for the default signal handler to dump
 * a core file, and exit with 'status' if the default handler cannot
 * terminate the process.  This function is expected to be called in
 * the installed signal handlers with install_crash_handler().
 */
void reraise_crash_signal(int signo, int status)
{
	int ret = raise(signo);

	/* We won't get here normally. */
	if (ret != 0)
		soe_emerg("failed to re-raise signal %d (%s).",
			  signo, strsignal(signo));
	else
		soe_emerg("default handler for the re-raised "
			  "signal %d (%s) didn't work as expected", signo,
			  strsignal(signo));

	exit(status);
}

