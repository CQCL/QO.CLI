/* Copyright 2023 Cambridge Quantum Computing Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define FD_TABLE_SIZE_METHOD1 // getdtablesize()
//#define FD_TABLE_SIZE_METHOD2 // sysconf()
//#define FD_TABLE_SIZE_METHOD3 // getrlimit()

#define _POSIX_SOURCE     // Needed in order to get fileno support from stdio.h

#ifdef FD_TABLE_SIZE_METHOD1 // getdtablesize()
//#define _DEFAULT_SOURCE   // Needed in order to get getdtablesize support from unistd.h
//#define _XOPEN_SOURCE_EXTENDED 1
//#define __USE_XOPEN_EXTENDED          // Needed in order to get getdtablesize support from unistd.h
//#define __USE_BSD                     // Needed in order to get getdtablesize support from unistd.h
extern int getdtablesize (void);  // Return the maximum number of file descriptors the current process could possibly have.
#endif

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#ifdef FD_TABLE_SIZE_METHOD3 // getrlimit()
#include <sys/resource.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#include <qo_decrypt/qo_crypto.h>
#include <qo_decrypt/qo_sanitise_files.h>

// Credit to https://www.oreilly.com/library/view/secure-programming-cookbook/0596003943/ch01s05.html

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

#ifdef _WIN32
#define _PATH_DEVNULL "nul"
#else
#define _PATH_DEVNULL "/dev/null"
#endif

static int OpenDevnull(int fd)
{
    FILE *f = 0;

    if      (fd == 0) f = freopen(_PATH_DEVNULL, "rb", stdin );
    else if (fd == 1) f = freopen(_PATH_DEVNULL, "wb", stdout);
    else if (fd == 2) f = freopen(_PATH_DEVNULL, "wb", stderr);
    return (f && fileno(f) == fd);
}

void SanitiseStdFiles(void)
{
#ifndef _WIN32
    int fd;
    struct stat st;

    // Make sure all open descriptors other than the standard ones are closed
    int fds;

#ifdef FD_TABLE_SIZE_METHOD1 // getdtablesize()
    fds = getdtablesize(); // Get the file descriptor table size
#endif
#ifdef FD_TABLE_SIZE_METHOD2 // sysconf()
    // SVr4, 4.4BSD (the getdtablesize() function first appeared in 4.2BSD). It is not specified in POSIX.1-2001; portable applications should employ sysconf(_SC_OPEN_MAX) instead of this call.
    fds = sysconf(_SC_OPEN_MAX);
#endif
#ifdef FD_TABLE_SIZE_METHOD3 // getrlimit()
    // The getdtablesize() function is equivalent to getrlimit() with the RLIMIT_NOFILE option.
    rlimit structure x = {0};
    fds = getrlimit(RLIMIT_NOFILE, &x); // RLIMIT_NOFILE = The maximum number of open file descriptors allowed for the process.
                                        // This number is one greater than the maximum value that may be assigned to a newly
                                        // created descriptor. (That is, it is one-based.) Any function that attempts to create
                                        // a new file descriptor beyond the limit will fail with an EMFILE errno.
#endif
    if (fds == -1)
    {
        fds = OPEN_MAX;
    }
    for (fd = 3;  fd < fds;  fd++)
    {
        close(fd);
    }

    // Verify that the standard descriptors are open.
    // If they're not, then attempt to open them using /dev/null.
    // If any are unsuccessful, abort.
    for (fd = 0;  fd < 3;  fd++)
    {
        if (fstat(fd, &st) == -1 && (errno != EBADF || !OpenDevnull(fd)))
        {
            fprintf(stderr, "FATAL: Failed to sanitise std file handles\n");
            abort();
        }
    }
#endif
}
