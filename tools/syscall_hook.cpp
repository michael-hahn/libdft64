#include "syscall_hook.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "tagmap.h"
#include "osutils.h"

#include <iostream>
#include <set>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <unistd.h>

/* default suffixes for dynamic shared libraries.
 * We will use suffixes to identify them to not track them. */
#define DLIB_SUFF       ".so"
#define DLIB_SUFF_ALT   ".so."
/* macros related to stdin/stdout/stderr */
#define STDFD_MAX ( MAX( MAX(STDIN_FILENO, STDOUT_FILENO), STDERR_FILENO ) + 1 )
#define IS_STDFD(fd) ( (fd == STDOUT_FILENO) || (fd == STDIN_FILENO) || (fd == STDERR_FILENO) )
/* Syscall descriptors. */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* Set of interesting descriptors to track. */
std::set<int> fdset;

/* We keep track of stdin offset. */
static unsigned int stdin_read_off = 0;

/* Analysis function: add taint source when open syscall is called. */
#define DEF_SYSCALL_OPEN
#include "syscall_args.h"
static void post_open_hook(THREADID tid, syscall_ctx_t *ctx) 
{
        if (unlikely(_FD < 0)) {
                LOG("ERROR: \t" + std::string(ctx->nr == __NR_creat ? "creat(" : "open(") + _PATHNAME + ", " + decstr(_FLAGS) + ", " + decstr(_MODE) + ") = " + decstr(_FD) + " (" + strerror(errno) + ")\n");
                return;
        }

        /* Resolve fd to full pathname, instead of syscall argument. */
        const std::string fdn = fdname(_FD);

        /* ignore dynamic shared libraries, and directory */
        //TODO: path_isdir uses stat, which seems to cause problems at runtime as 'stat' symbol cannot be referenced by the dynamic loader -- seems to be related to Pin.
        if (strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF) == NULL && strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF_ALT) == NULL /* && !path_isdir(fdn) */ ) {
                std::cout << "[OPEN] fd: " << fdn << std::endl;
                fdset.insert((int)ctx->ret);
        }
}
#define UNDEF_SYSCALL_OPEN
#include "syscall_args.h"

/* Analysis function: add taint source when openat syscall is called. */
/* int openat(int dirfd, const char *pathname, int flags, mode_t mode); */
static void post_openat_hook(THREADID tid, syscall_ctx_t *ctx) 
{
	// const int fd = ctx->ret;
	const std::string fdn = fdname(ctx->arg[SYSCALL_ARG1]);
	const char *file_name = (char *)ctx->arg[SYSCALL_ARG1];
	if (strstr((char *)file_name, DLIB_SUFF) == NULL && strstr((char *)file_name, DLIB_SUFF_ALT) == NULL) {
		std::cout << "[OPENAT] fd: " << fdn << std::endl;
		fdset.insert((int)ctx->ret);
	}
}

/* Analysis function: add taint source when read syscall is called. */
#define DEF_SYSCALL_READ
#include "syscall_args.h"
static void post_read_hook(THREADID tid, syscall_ctx_t *ctx)
{
	if (unlikely((long)ctx->ret < 0)) {
		LOG("Error reading from fd " + decstr(ctx->arg[SYSCALL_ARG0]) + ": " + strerror(errno) + "\n");
		return;
	}
	/* Define constants for better readability. */
	const size_t nr = ctx->ret;
	const int fd = ctx->arg[SYSCALL_ARG0];
	const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
	const size_t count = ctx->arg[SYSCALL_ARG2]; 

	/* We only set taint source on files that we care. */
	if (fdset.find(fd) != fdset.end()) {
		/* set tags on read bytes. */
		off_t read_offset_start = 0;
		size_t i = 0;

		if (!IS_STDFD(fd)) {
			read_offset_start = lseek(fd, 0, SEEK_CUR);
			if (unlikely(read_offset_start < 0)) {
				LOG("ERROR ON L " + decstr(__LINE__) + " lseek on fd " + decstr(fd) + ": " + strerror(errno));
				return;
			}
			read_offset_start -= nr;
		} else {
			read_offset_start = stdin_read_off;
			stdin_read_off += nr;
		}

		std::cout << "[READ] fd: " << decstr(fd)
			<< " addr: " << StringFromAddrint(buf)
			<< " offset: " << read_offset_start
			<< " size: " << nr << "/" << count
			<< std::endl;

		while (i < nr) {
			/* Taint set based on file offset. */
			// tag_t t = tag_alloc<tag_t>(read_off + i);
			/* We instead set taint based on fd.
			 * Each unique fd has a single unique taint.
			 */
			tag_t t = tag_alloc<tag_t>(fd);
			tagmap_setb(buf + i, t);
			std::cout << "[read]: tags[" << StringFromAddrint(buf+i) << "] : " << tag_sprint(tagmap_getb(buf+i)) << std::endl;
			i++;
		}
		tagmap_setb_reg(tid, DFT_REG_RAX, 0, BDD_LEN_LB);

	} else {
		/* clear tags for read bytes. */
		tagmap_clrn(buf, nr);
	}
}
#define UNDEF_SYSCALL_READ
#include "syscall_args.h"

/* int socket(int domain, int type, int protocol); */
static void post_socket_hook(THREADID tid, syscall_ctx_t *ctx)
{
	if (unlikely((long)ctx->ret < 0)) {
		return;
	}
	/* AF_INET and AF_INET6 descriptors are considered. */
	if (likely(ctx->arg[SYSCALL_ARG0] == AF_INET ||
		   ctx->arg[SYSCALL_ARG0] == AF_INET6)) {
		/* Add the file descriptor returned by the call. */
		std::cout << "[SOCKET]: " << ctx->ret << std::endl;
		fdset.insert((int)ctx->ret);
	}
}

/* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
/* int accept4(int sockfd, struct sockaddr *addr,
                   socklen_t *addrlen, int flags); */
static void post_accept_hook(THREADID tid, syscall_ctx_t *ctx)
{
	if (unlikely((long)ctx->ret < 0)) {
		return;
	}
	/* If the socket argument (returned from socket call) is considered,
	 * the return handle of accept(2) is also considered. */
	if (likely(fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())) {
		std::cout << "[ACCEPT]: " << ctx->ret << std::endl;
		fdset.insert((int)ctx->ret);
	}
}

void hook_syscall() {
	(void)syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
	(void)syscall_set_post(&syscall_desc[__NR_openat], post_openat_hook);
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
	(void)syscall_set_post(&syscall_desc[__NR_socket], post_socket_hook);
	(void)syscall_set_post(&syscall_desc[__NR_accept], post_accept_hook);
}
