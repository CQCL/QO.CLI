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
///////////////////////////////////////////////////////////////////////////////
// Various synchronisation utilities
///////////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
#include <Windows.h>
#include <Synchapi.h>
#else
#include <unistd.h>
#include <libgen.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>


#include <qo_utils/qo_filelock.h>
#include <qo_utils/qo_logging.h>
#include <qo_utils/qo_string.h>

static int local_log(int loglevel, const char *formatStr, ...)
{
#define SPRINTF_TRACE_BUFSIZE 4096
    va_list va;
    char *pBuf;
    int rc;

    pBuf = malloc(SPRINTF_TRACE_BUFSIZE);
    if (!pBuf)
    {
        return -1;
    }
    va_start(va, formatStr);
    rc = vsnprintf(pBuf, SPRINTF_TRACE_BUFSIZE, formatStr, va);
    if (rc == -1 || rc >= SPRINTF_TRACE_BUFSIZE)
    {
        free(pBuf);
        return -1;
    }
    app_traceln(pBuf);

    if (loglevel & 0x01) fprintf(stderr, "%s", pBuf);
    if (loglevel & 0x02) app_tracef(pBuf);

    va_end(va);
    free(pBuf);
    return rc;
}

static bool __makeLockfileName(char *szLockFilePath, char *szFilename, char *szLockfileName, size_t cbLockfileName, int loglevel)
{
    char szResult[_MAX_PATH];

    if (!szFilename || !szLockfileName || !cbLockfileName)
    {
       local_log(loglevel, "__makeLockfileName Param error...\n");
       return false;
    }

    if (szLockFilePath == NULL)
    {
        // Create the file in the same location as szFilename, but with an additional .lock appended
        strcpy(szResult,szFilename);
        strcat(szResult,".lock");
    }
    else
    {
        // Create the file in the szLockFilePath location (e.g. /tmp).
        // The filename is the same as the base name in szFilename, but with an additional .lock appended.
        // If we have any problems, use szFilename with non-alphanumeric chars replaced with '_'
        // For example:
        //      Params "/tmp" and "/var/lib/ibrand/ibrand_data.bin"
        // becomes
        //      /tmp/ibrand_data.bin.lock
        // or
        //      /tmp/_var_lib_ibrand_ibrand_data_bin.lock

        // Try to get the basename of szFilename.
        char szFilenameWithoutPath[_MAX_PATH];

#ifdef _WIN32
        char pBasename[_MAX_PATH];
        // First get the base path, which doesn't include the extension
        errno_t err = _splitpath_s(szFilename, NULL, 0, NULL, 0, pBasename, _MAX_PATH, NULL, 0);
        if(err != 0)
        {
          local_log(loglevel, "_splitpath_s failed\n");
          return false;
        }

        size_t basePathLen = strlen(pBasename);

        // Then append the extension
        err = _splitpath_s(szFilename, NULL, 0, NULL, 0, NULL, 0, pBasename + basePathLen, _MAX_PATH - basePathLen);
        if(err != 0)
        {
          local_log(loglevel, "_splitpath_s failed\n");
          return false;
        }
#else
        char *pBasename = basename(szFilename); // basename() returns a pointer to internal static storage
#endif

        if (!pBasename || strcmp(pBasename,".")==0 || strcmp(pBasename,PATHSEPARATORSTR)==0 )
        {
            size_t ii;

            // Replace all non-alphanumeric chars with '_'
            qo_strlcpy(szFilenameWithoutPath, szFilename, sizeof(szFilenameWithoutPath));
            for (ii=0; ii<strlen(szFilenameWithoutPath); ii++)
            {
                if (!isalnum(szFilenameWithoutPath[ii]))
                   szFilenameWithoutPath[ii] = '_';
            }
        }
        else
            qo_strlcpy(szFilenameWithoutPath, pBasename, sizeof(szFilenameWithoutPath));

        // Build the filename
        strcpy(szResult,szLockFilePath);
        // Add separator (if it doesn't already exist)
        if (szLockFilePath[strlen(szLockFilePath)-1] != PATHSEPARATOR)
            strcat(szResult,PATHSEPARATORSTR);
        strcat(szResult,szFilenameWithoutPath);
        strcat(szResult,".lock");
    }
    local_log(loglevel, "__makeLockfileName(%s)...\n", szResult );
    qo_strlcpy(szLockfileName, szResult, cbLockfileName);
    return true;
}

void qo_waitForFileLock(char *szLockFilePath, char *szFilename, int loglevel)
{
    FILE *fLock;
    char szLockFilename[256];
    size_t bytesWritten;

    __makeLockfileName(szLockFilePath, szFilename, szLockFilename, sizeof(szLockFilename), loglevel);

    local_log(loglevel, "WaitForFileLock(%s)...\n", szLockFilename );
    for(;;)
    {
        if (qo_fileExists(szLockFilename))
        {
            local_log(loglevel, "qo_fileExists(%s). sleep(3)\n", szLockFilename );
#ifdef _WIN32
            Sleep(3000);
#else
            sleep(3);
#endif
            continue;
        }
        local_log(loglevel, "FileDoesNotExist(%s). Creating...\n", szLockFilename );
        fLock = fopen(szLockFilename,"wb");
        if (!fLock)
        {
            local_log(loglevel, "CreateFailed(%s). sleep(3)\n", szLockFilename );
#ifdef _WIN32
            Sleep(3000);
#else
            sleep(3);
#endif
            continue;
        }
        local_log(loglevel, "CreatedOK(%s). Writing...\n", szLockFilename );
        bytesWritten = fwrite("X",1,1,fLock);
        if (bytesWritten != 1)
        {
            fclose(fLock);
            local_log(loglevel, "WriteFailed(%s). sleep(3)\n", szLockFilename );
#ifdef _WIN32
            Sleep(3000);
#else
            sleep(3);
#endif

            continue;
        }
        local_log(loglevel, "WriteOk(%s). Closing...\n", szLockFilename );
        fclose(fLock);
        break;
    }
    local_log(loglevel, "WaitForFileLock(%s). LockedOk\n", szLockFilename );
}

void qo_releaseFileLock(char *szLockFilePath, char *szFilename, int loglevel)
{
    char szLockFilename[256];

    __makeLockfileName(szLockFilePath, szFilename, szLockFilename, sizeof(szLockFilename), loglevel);

    local_log(loglevel, "ReleaseFileLock(%s)...\n", szLockFilename );
    for(;;)
    {
        if (!qo_fileExists(szLockFilename))
        {
            local_log(loglevel, "FileDoesNotExist(%s). Returning\n", szLockFilename );
            return;
        }
        local_log(loglevel, "FileExistsOk(%s). Deleting...\n", szLockFilename );
        unlink(szLockFilename);
        local_log(loglevel, "DeleteOk(%s). DoubleChecking...\n", szLockFilename );
        if (qo_fileExists(szLockFilename))
        {
            local_log(loglevel, "DeleteFailed(%s). sleep(3)\n", szLockFilename );
#ifdef _WIN32
            Sleep(3000);
#else
            sleep(3);
#endif
            continue;
        }
        local_log(loglevel, "DeleteOk(%s).\n", szLockFilename );
        break;
    }
    local_log(loglevel, "ReleaseFileLock(%s). UnlockedOk\n", szLockFilename );
}
