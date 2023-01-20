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
// Some Useful Utilities
// Copyright (c) 1998-2020 Jonathan Gilmore. All rights reserved.
// Original: J. Gilmore, Fri 02-Oct-1998, 16:11:57
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_QO_UTILS_H_
#define _INCLUDE_QO_UTILS_H_


#define DEBUG
//#define NDEBUG

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __linux__
   #define PATHSEPARATOR '/'
   #define PATHSEPARATORSTR "/"
   #define EOL "\n"
#elif _WIN32
   #define PATHSEPARATOR '\\'
   #define PATHSEPARATORSTR "\\"
   #define EOL "\r\n"
#endif

#ifndef _MAX_PATH
#define _MAX_PATH 128
#endif

#ifndef _MAX_URL
#define _MAX_URL 128
#endif

#ifndef __cplusplus
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#ifndef true
#define true 1
#define false 0
#endif
#ifndef BOOL
//typedef unsigned char BOOL;
#define BOOL unsigned char
#endif
#ifndef bool
//typedef unsigned char bool;
#define bool unsigned char
#endif
#else
#ifndef BOOL
//typedef unsigned char BOOL;
#define BOOL bool
#endif
#endif

#ifndef SET_BIT
#define SET_BIT(x,n)  ((x) |=  ((1)<<(n)))
#define CLR_BIT(x,n)  ((x) &= ~((1)<<(n)))
#define TEST_BIT(x,n) ((x) &   ((1)<<(n)))
#endif

#ifndef UNUSED_PARAM
#define UNUSED_PARAM(x) (void)(x)
#endif
#ifndef UNUSED_ITEM
#define UNUSED_ITEM(x) (void)(x)
#endif
#ifndef NOTUSED
#define NOTUSED(x) (void)(x)
#endif
#ifndef UNUSED_VAR
#define UNUSED_VAR(x)  (void)(x);
#endif

#define MINIMUM(a,b) (a<b?a:b)
#define MAXIMUM(a,b) (a>b?a:b)


typedef unsigned char   BYTE;           //  8-bit
typedef unsigned short  WORD;           // 16-bit
typedef unsigned long   DWORD;          // 32-bit
typedef BYTE *          PBYTE;
typedef WORD *          PWORD;
typedef DWORD *         PDWORD;

#ifndef LOBYTE
#define LOBYTE(w)                ((BYTE)(w))
#endif
#ifndef HIBYTE
#define HIBYTE(w)                ((BYTE)(((WORD)(w) >> 8) & 0xFF))
#endif
#ifndef LOWORD
#define LOWORD(d)                ((WORD)(d))
#endif
#ifndef HIWORD
#define HIWORD(d)                ((WORD)((((DWORD)(d)) >> 16) & 0xFFFF))
#endif

//#define LODWORD(q)               ((q).u.dwLowDword)
//#define HIDWORD(q)               ((q).u.dwHighDword)

#ifndef MAKEWORD
#define MAKEWORD(lb, hb)         ((WORD)(((BYTE)(lb)) | (((WORD)((BYTE)(hb))) << 8)))
#endif
#define MAKEDWORD(lw, hw)        ((DWORD)(((WORD)(lw)) | (((DWORD)((WORD)(hw))) << 16)))
#define MAKEDWORDB(b3,b2,b1,b0)  ((DWORD)((MAKEWORD(b0, b1)) | (((DWORD)(MAKEWORD(b2, b3))) << 16)))

#define UINT_MAX_DIGITS 20 // 0x7FFF FFFF FFFF FFFF = 9,223,372,036,854,775,807 ==> 19 digits for signed, 20 for unsigned.

typedef struct tagLSTRING
{
    size_t cbData;
    char *pData;
} tLSTRING;

extern int qo_errno; // We'll use the std errno values e.g. ENOMEM, EINVAL, ERANGE, ENOTSUPP, etc

extern const char *qo_utils_about(void);
extern const char *qo_utils_version(void);

///////////////////////////////////////////////////////////////////////////////
// Utility Functions
///////////////////////////////////////////////////////////////////////////////
extern int    qo_minimum(int x,int y);
extern char * qo_strrev(char *string);
extern void   qo_itoa(int data,char *dst,char non);
extern int    qo_abs(int x);

//extern char * qo_strlcpy(char *strDest, const char *strSource, size_t count);
extern size_t qo_strlcpy(char *strDest, const char *strSource, size_t count);
extern size_t qo_strlcat(char *strDest, const char *strSource, size_t count);

extern char * qo_strstri(char *pBuffer, char *pSearchStr);
extern int    qo_stricmp(char const *a, char const *b);
extern void   qo_translateCharactersInString(char *szString,char *szOldChars,char *szNewChars);
extern BOOL   qo_isInSetOfChars(int ch, char *szSetOfChars);
extern char * qo_trimTrailing(char *szStr, char *szSetOfChars);
extern char * qo_trimLeading(char *szStr, char *szSetOfChars);
extern BOOL   qo_isWhitespace(int ch);
extern char * qo_trimTrailingWhiteSpace(char *szStr);
extern char * qo_trimLeadingWhiteSpace(char *szStr);
extern char * qo_removeTrailingString(char *szStr, char *szStrToRemove);
extern char * qo_removeTrailingStringi(char *szStr, char *szStrToRemove);
extern long   qo_getFilesize(const char *szFilename);
extern bool   qo_fileExists(const char *szFilename);
extern int    qo_roundUp(int num, int multipleOf);
extern bool   qo_LStringJoin(tLSTRING *pDest, tLSTRING *pDataToAppend);
extern void   qo_LStringCleanseAndFree(tLSTRING *pItem);
extern void   qo_CleanseAndFree(uint8_t **ppBlock, size_t cbBlock);

#ifdef __cplusplus
}
#endif

#endif // _INCLUDE_QO_UTILS_H_
