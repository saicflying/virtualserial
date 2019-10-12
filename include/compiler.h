

#ifndef SOE_COMPILER_H
#define SOE_COMPILER_H

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>
#include <fcntl.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 8
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#endif
#ifndef _SYS_SIGNALFD_H
struct signalfd_siginfo
{
  uint32_t ssi_signo;
  int32_t ssi_errno;
  int32_t ssi_code;
  uint32_t ssi_pid;
  uint32_t ssi_uid;
  int32_t ssi_fd;
  uint32_t ssi_tid;
  uint32_t ssi_band;
  uint32_t ssi_overrun;
  uint32_t ssi_trapno;
  int32_t ssi_status;
  int32_t ssi_int;
  uint64_t ssi_ptr;
  uint64_t ssi_utime;
  uint64_t ssi_stime;
  uint64_t ssi_addr;
  uint8_t __pad[48];
};
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define container_of(ptr, type, member) ({                      \
		        const typeof(((type *)0)->member) *__mptr = (ptr);      \
		        (type *)((char *)__mptr - offsetof(type, member)); })

#define __packed __attribute((packed))

#define asmlinkage  __attribute__((regparm(0)))

#define __printf(a, b) __attribute__((format(printf, a, b)))

#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int: -!!(condition); }))


#endif /* SOE_COMPILER_H */
