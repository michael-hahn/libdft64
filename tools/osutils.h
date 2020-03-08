///
/// @file
/// \brief Utility functions with OS-specific implementations.
///
#ifndef __OSUTILS_H__
#define __OSUTILS_H__

#include <iostream>
#include <string>

#include <assert.h>
#include <libgen.h>
#include <limits.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pin.H"
#include "libdft_api.h"

/* Platform specific white-lists.
 * Data coming from files matching these patterns are not tainted.
 */
#if defined(TARGET_LINUX)
#define DTRACKER_FILE_WHITELIST_RE "\\.so$|\\.so\\."
#define DTRACKER_PATH_WHITELIST_RE "^/proc/|^/lib/|^/usr/lib/|^/etc/|^/usr/share/"
#elif defined(TARGET_MAC)
#define DTRACKER_FILE_WHITELIST_RE "\\.dylib$"
#define DTRACKER_PATH_WHITELIST_RE NULL
#elif defined(TARGET_WINDOWS)
#define DTRACKER_FILE_WHITELIST_RE "\\.dll$"
#define DTRACKER_PATH_WHITELIST_RE NULL
#endif

///
/// @brief Determines if a filename is whitelisted.
///
/// Whitelisted files are not tainted by dtracker.
///	Without whitelisting, the slowdown factor because of taint
/// tracking is HUGE.
///
///	@param fname -- the filename to be checked.
/// @return 1 if the filename is whitelisted. 0 otherwise.
///
extern std::string filename;
inline int in_dtracker_whitelist(const std::string & fname) {
	// Note: basename() and dirname() may modify their arguments.
	//       For this, we create a duplicate of fname to give them.
	//       Also their return value should not be freed because it
	//       is either a pointer into fname or statically allocated.
        if(fname.find(filename) != std::string::npos){
		return 0;
	}else{
		return 1;
	}

/*
	char *fdup;
	// Check file patterns.
	if (DTRACKER_FILE_WHITELIST_RE != NULL && (fdup = strdup(fname.c_str()))) {
		int status = -1;
		regex_t re;
		char *bname = basename(fdup);

		if (regcomp(&re, DTRACKER_FILE_WHITELIST_RE, REG_EXTENDED|REG_NOSUB) == 0) {
			status = regexec(&re, bname, (size_t) 0, NULL, 0);
			regfree(&re);
		}
		free(fdup);
		if (status == 0) return 1;
	}

	// Check dir patterns.
	if (DTRACKER_PATH_WHITELIST_RE != NULL && (fdup = strdup(fname.c_str()))) {
		int status = -1;
		regex_t re;

		// We have to do this crap because dirname() does not append a /.
		char *dname_noslash = dirname(fdup);
		size_t dname_sz = (strlen(dname_noslash)+2)*sizeof(char);
		char *dname = (char *)malloc(dname_sz);

		if (dname != NULL && regcomp(&re, DTRACKER_PATH_WHITELIST_RE, REG_EXTENDED|REG_NOSUB) == 0) {
			snprintf(dname, dname_sz, "%s/", dname_noslash);
			status = regexec(&re, dname, (size_t) 0, NULL, 0);
			regfree(&re);
			free(dname);
		}
		free(fdup);
		if (status == 0) return 1;
	}

	return 0;
*/
}


///
/// @brief Retrieves the absolute path to a file, resolving any symlinks.
///
/// Currently only implemented for Linux/MacOS, for which the finction is
/// a simple wrapper over realpath(3). 
///
/// @param path -- a file path to be resolved.
/// @return A string representing the absolute path to the file or NULL.
inline std::string path_resolve(const std::string & path) {
#if defined(TARGET_LINUX) || defined(TARGET_MAC)
	char *crval = realpath(path.c_str(), NULL);
	if (crval != NULL) {
		std::string rval(crval);
		free(crval);
		return rval;
	}
	else {
		return NULL;
	}
#elif defined(TARGET_WINDOWS)
	assert(0);
	return NULL;
#endif
}

inline int path_isdir(const std::string & path) {
#if defined(TARGET_LINUX) || defined(TARGET_MAC)
	struct stat stats;
	return (stat(path.c_str(), &stats) == 0 && S_ISDIR(stats.st_mode));
#elif defined(TARGET_WINDOWS)
	assert(0);
	return -1;
#endif
}

inline int path_exists(const std::string & path) {
#if defined(TARGET_LINUX) || defined(TARGET_MAC)
	return (access(path.c_str(), F_OK) == 0);
#elif defined(TARGET_WINDOWS)
	assert(0);
	return -1;
#endif
}

///
/// @brief Resolves an open file descriptor to a filename.
///
/// Any symbolic links in the path are resolved. If an error occurs,
/// the respective error message is returned instead of the file path.
/// Because the function uses a static buffer, the file path may be
/// returned truncated ending with "...". 
///
///	@param fd -- the file descriptor to be resolved.
/// @return A string representing the full path to the file.
#if defined(TARGET_LINUX)

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#define __PROC_SELF_FD "/proc/self/fd"


std::string filename;

std::string fdname(int fd) {
	char ppath[PATH_MAX];
	char fpath[PATH_MAX];
	int w;

	/* create string for fd link path in /proc */
	w = snprintf(ppath, PATH_MAX*sizeof(char), "%s/%d", __PROC_SELF_FD, fd);
	assert(w < (int)(PATH_MAX*sizeof(char)));

	/* read link and return results */
	w = readlink(ppath, fpath, PATH_MAX*sizeof(char));
	if (w < 0) {
		return std::string(strerror(errno));
	}
	else if (w >= PATH_MAX) {
		/* terminate string and return */
		fpath[PATH_MAX-1] = '\0';
		return std::string(fpath)+std::string("...");
	}
	else {
		/* terminate string */
		fpath[w] = '\0';
		return std::string(fpath);
	}

	/* return something to make compiler happy */
	return NULL;
}

#elif defined(TARGET_MAC) || defined(TARGET_WINDOWS)

std::string fdname(int fd) {
	// Not implemented yet.
	// See: http://stackoverflow.com/a/13544447/277172 (Mac)
	//		http://stackoverflow.com/a/1188803/277172 (Windows)
	assert(0);
	return std::string("N/A");
}

#endif

#endif

/* vim: set noet ts=4 sts=4 sw=4 ai : */
