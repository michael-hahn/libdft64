#ifndef __HOOKS_H__
#define __HOOKS_H__

/* System call hooks. 
 * Each hook must be specialized for each supported tag type. */

#include "libdft_api.h"
#include "pin.H"

/* open */
template<typename TagType> VOID post_open_hook(syscall_ctx_t *ctx);

/* read */
template<typename TagType> VOID post_read_hook(syscall_ctx_t *ctx);

/* write */
template<typename TagType> VOID post_write_hook(syscall_ctx_t *ctx);

/* socket-related */
template<typename TagType> VOID post_socketcall_hook(syscall_ctx_t *ctx);

#endif
