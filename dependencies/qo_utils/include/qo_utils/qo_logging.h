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
// Some Useful Logging Utilities
// Copyright (c) 1998-2020 Jonathan Gilmore. All rights reserved.
// Original: J. Gilmore, Fri 02-Oct-1998, 16:11:57
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_QO_LOGGING_H_
#define _INCLUDE_QO_LOGGING_H_

#define DEBUG
//#define NDEBUG

#include "stdio.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(DEBUG) && !defined(NDEBUG)
#define dbg_stmnt(x)          x
#define dbg_printf(type, ...) (((type)&xdbg_current_types) ? printf(__VA_ARGS__) : 0)
#else // defined(DEBUG) && !defined(NDEBUG)
#define dbg_stmnt(x)
#define dbg_printf(...)
#endif // defined(DEBUG) && !defined(NDEBUG)

#define PRINTLN_INT(token)  printf(#token " = %d\n", token)
#define PRINTLN_UINT(token) printf(#token " = %u\n", token)
#define PRINTLN_ZSTR(token) printf(#token " = \"%s\"\n", token)
#define PRINTLN_CHAR(token) printf(#token " = '%c'\n", token)

///////////////////////////////////////////////////////////////////////////////
// Logging Functions
///////////////////////////////////////////////////////////////////////////////
typedef enum eOUTPUTFORMAT
{
    ALL_IN_PRETTY_HEX            = 0,
    NONDISPLAYABLE_IN_PRETTY_HEX = 1,
    ALL_IN_BASIC_HEX             = 2
} tOUTPUTFORMAT;

extern void app_trace_set_destination(bool toConsole, bool toLogfile, bool toSyslog);
extern void app_trace_set_logfilename(const char *szPath, const char *szFilename);
extern const char *app_trace_get_logfilename(const char *szFilename);
extern char *FormatData(char *szTarget, const char *szTitle, const unsigned char *pData, int cbData, tOUTPUTFORMAT fOutputFormat);
extern void app_trace_openlog(const char *ident, int logopt /* e.g. LOG_PID/LOG_CONS/LOG_PERROR */, int facility /* e.g. LOG_DAEMON/LOG_USER (Required for Syslog) */);
extern void app_trace_closelog(void);
extern void app_trace_hex(const char *pHeader, const unsigned char *pData, unsigned int cbData);
extern void app_trace_hexall(const char *pHeader, const unsigned char *pData, unsigned int cbData);
extern void app_traceln(const char *szString);
extern void app_trace(const char *szString);
extern int app_tracef(const char *formatStr, ...);
extern bool qo_getToken(const char *pSrcData, char *pDstField, int nFieldNum, int nDstFieldMaxLen);
extern void qo_dumpToFile(const char *szFilename, const unsigned char *p, size_t n);
extern const char *HttpResponseCodeCategory(int httpResponseCode);
extern const char *HttpResponseCodeDescription(int httpResponseCode);

#ifdef __cplusplus
}
#endif

#endif // _INCLUDE_QO_LOGGING_H_
