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
// Copyright (c) 1998-2022 Jonathan Gilmore. All rights reserved.
// Original: J. Gilmore, Fri 02-Oct-1998, 16:11:57
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

//#pragma comment(lib, "qo_utils.lib")

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>


#include <qo_utils/qo_utils.h>
#include <qo_utils/qo_string.h>

//#include <qo_utils/qo_utils_project_config.h>
// Example contents of qo_utils_project_config.h
//     #define QO_UTILS_PROJECT_NAME       "qo_utils"
//     #define QO_UTILS_PROJECT_VER        "1.0.2"
//     #define QO_UTILS_PROJECT_VER_MAJOR  "1"
//     #define QO_UTILS_PROJECT_VER_MINOR  "0"
//     #define QO_UTILS_PROJECT_VER_PATCH  "2"

#define QO_LIB_LIBRARYNAME        "Quantum Origin Utilities Library"
#define QO_LIB_COPYRIGHT          "Copyright (c) 2021-2022 Cambridge Quantum. All rights reserved."
#define QO_LIB_LIBRARYNAME_LONG   QO_UTILS_PROJECT_NAME ": " QO_LIB_LIBRARYNAME " v" QO_UTILS_PROJECT_VER "\n" QO_LIB_COPYRIGHT "\n"
#define QO_LIB_ABOUT              QO_LIB_LIBRARYNAME_LONG


// Detail of last error
int qo_errno = 0; // We'll use the std errno values e.g. ENOMEM, EINVAL, ERANGE, ENOTSUPP, etc

const char *qo_utils_about(void)
{
    return QO_LIB_ABOUT;
}

const char *qo_utils_version(void)
{
    return QO_UTILS_PROJECT_VER;
}


///////////////////////////////////////////////////////////////////////////////
// Utility Functions
///////////////////////////////////////////////////////////////////////////////

int qo_minimum(int x, int y)
{
  return (x<y)?x:y;
}

size_t qo_minimum_size_t (size_t x, size_t y)
{
    return (x < y) ? x : y;
}

char *qo_strrev(char *string)
{
  char *start = string;
  char *left = string;

  while (*string++); // find end of string

  string -= 2;
  while (left < string)
  {
    char ch = *left;
    *left++ = *string;
    *string-- = ch;
  }
  return(start);
}

void qo_itoa(int data, char *pDest, char non)
{
  UNUSED_PARAM(non); // Avoid compiler warning
  sprintf(pDest,"%d",data);
}

int qo_abs(int x)
{
  return (x<0)?(-x):(x);
}

char *qo_strstri(char *pBuffer, char *pSearchStr)
{
  char *pBuffPtr = pBuffer;

  while (*pBuffPtr != 0x00)
  {
    char *pCompareOne = pBuffPtr;
    char *pCompareTwo = pSearchStr;

    while (tolower(*pCompareOne) == tolower(*pCompareTwo))
    {
      pCompareOne++;
      pCompareTwo++;

      if (*pCompareTwo == 0x00)
        return (char *)pBuffPtr;
    }
    pBuffPtr++;
  }
  return NULL;
}

int qo_stricmpL(char const *a, char const *b)
{
  while (*a)
  {
    int d = tolower(*a) - tolower(*b);
    if (d)
    {
        return d;
    }
    a++;
    b++;
  }
  return 0;
}

int qo_stricmpU(char const *a, char const *b)
{
  while (*a)
  {
    int d = toupper(*a) - toupper(*b);
    if (d)
    {
        return d;
    }
    a++;
    b++;
  }
  return 0;
}

int qo_stricmp(char const *a, char const *b)
{
    // https://stackoverflow.com/questions/5820810/case-insensitive-string-comp-in-c
    // Comparing as lower or as upper case:
    //    Both qo_stricmpL and qo_stricmpU will return 0 with qo_stricmpL("A", "a") and qo_stricmpU("A", "a").
    //    But qo_stricmpL("A", "_") and qo_stricmpU("A", "_") can return different signed results.
    //    This is because '_' is often between the upper and lower case letters, as it is in ASCII.
    // We'll arbitrarily choose lowercase.
    return qo_stricmpL(a, b);
}

void qo_translateCharactersInString(char *szString,char *szOldChars,char *szNewChars)
{
  unsigned int i;
  unsigned int j;
  unsigned int TranslationCharsLen;

  TranslationCharsLen = (unsigned int)qo_minimum_size_t(strlen(szOldChars),strlen(szNewChars));

  for (i=0; i<strlen(szString); i++)
  {

    // Debugging/Testing
    if ((szOldChars[0] == '.') && (szString[i] == ','))
      (void)szString[i]; // Dummy statement

    // Debugging/Testing
    if (szString[i] == '$')
      (void)szString[i]; // Dummy statement

    for (j=0; j<TranslationCharsLen; j++)
    {
       if (szString[i] == szOldChars[j])
         szString[i] = szNewChars[j];
    }
  }
}

BOOL qo_isInSetOfChars(int ch, char *szSetOfChars)
{
  unsigned int i;

  for (i=0; i<strlen(szSetOfChars); i++)
  {
    if (ch == szSetOfChars[i])
      return TRUE;
  }
  return FALSE;
}

char *qo_trimTrailing(char *szStr, char *szSetOfChars)
{
  while(strlen(szStr) && qo_isInSetOfChars(szStr[strlen(szStr)-1],szSetOfChars))
    szStr[strlen(szStr)-1] = 0;
  return szStr;
}

char *qo_trimLeading(char *szStr, char *szSetOfChars)
{
  qo_strrev(szStr);
  qo_trimTrailing(szStr,szSetOfChars);
  qo_strrev(szStr);
  return szStr;
}

BOOL qo_isWhitespace(int ch)
{
  if ((ch == ' ' ) ||
      (ch == '\t') ||
      (ch == '\r') ||
      (ch == '\n'))
    return TRUE;
  return FALSE;
}

char *qo_trimTrailingWhiteSpace(char *szStr)
{
  while(strlen(szStr) && qo_isWhitespace(szStr[strlen(szStr)-1]))
    szStr[strlen(szStr)-1] = 0;
  return szStr;
}

char *qo_trimLeadingWhiteSpace(char *szStr)
{
  qo_strrev(szStr);
  qo_trimTrailingWhiteSpace(szStr);
  qo_strrev(szStr);
  return szStr;
}

char *qo_removeTrailingString(char *szStr, char *szStrToRemove)
{
  if (szStr && strlen(szStr) && szStrToRemove && strlen(szStrToRemove))
  {
    char *p = strstr(szStr,szStrToRemove);
    if (p && (p==(szStr+strlen(szStr)-strlen(szStrToRemove))))
    {
       *p = 0;
    }
  }
  return szStr;
}

char *qo_removeTrailingStringi(char *szStr, char *szStrToRemove)
{
  if (szStr && strlen(szStr) && szStrToRemove && strlen(szStrToRemove))
  {
    char *p = qo_strstri(szStr,szStrToRemove);
    if (p && (p==(szStr+strlen(szStr)-strlen(szStrToRemove))))
    {
       *p = 0;
    }
  }
  return szStr;
}

//#define USE_STRLCPY

#ifdef USE_STRLCPY
// The strlcpy() function copies the null-terminated string from src to dst (up
// to size characters). The strlcat() function appends the null-terminated
// string src to the end of dst (but no more than size characters will be in the
// destination).
// Both functions guarantee that the destination string is null terminated for
// all nonzero-length buffers.
// The strlcpy() and strlcat() functions return the total length of the string
// they tried to create. For strlcpy() that is simply the length of the source;
// for strlcat() it is the length of the destination (before concatenation) plus
// the length of the source. To check for truncation, the programmer needs to
// verify that the return value is less than the size parameter. If the
// resulting string is truncated, the programmer now has the number of bytes
// needed to store the entire string and may reallocate and recopy.
//size_t strlcpy(char *dst, const char *src, size_t size);
//size_t strlcat(char *dst, const char *src, size_t size);
size_t qo_strlcpy(char *strDest, const char *strSource, size_t count)
{
  return strlcpy(strDest, strSource, count);
}
size_t qo_strlcat(char *strDest, const char *strSource, size_t count)
{
  return strlcat(strDest, strSource, count);
}

#else // USE_STRLCPY
size_t qo_strlcpy(char *strDest, const char *strSource, size_t count)
{
#if 0
  // Copies at most count bytes from strSource to strDest,
  // and always adds a trailing NULL.

  // In the clib function strncpy is never the right answer when you want your destination string to be zero-terminated.
  // strncpy is a function intended to be used with non-terminated fixed-width strings. More precisely, its purpose is
  // to convert a zero-terminated string to a non-terminated fixed-width string (by copying).
  // In other words, strncpy, on its own, is not useful here.

  // In the clib implementation of strncpy, if count is less than or equal to
  // the length of strSource, a null character is not appended automatically to strDest.
  // So we will use strncpy to copy the data, and explicitly add a terminating null.
  // N.B. Truncation may occur.
  // If strlcpy is implemented on your system, this may be a better choice.

  if (count > 0)
  {
      strncpy(strDest,strSource,count);
      if (count <= strlen(strSource))
        strDest[count-1] = 0;
  }
  return strDest;
#endif
  size_t srcLen = 0;
  if (strSource)
      srcLen = strlen(strSource);

  if (!strSource)
      return 0;  // Nothing to copy so we can't copy anything, but we do know how long the result would be if we could: zero.

  if (!strDest || count==0) // Real values are supplied?
      return srcLen;  // No target buffer. We can't copy anything, but we do know how long the result would be if we could.

  strDest[0] = 0;
  return qo_strlcat(strDest, strSource, count);
}

size_t qo_strlcat(char *strDest, const char *strSource, size_t count)
{
  // Background:
  // The original c library function strncat...
  //    char * strncat ( char * destination, const char * source, size_t num );
  // ...appends characters from one string onto another.
  // Specifically, it appends the first num characters of source to destination,
  // plus a terminating null-character.
  // If the length of the C string in source is less than num, only the content
  // up to the terminating null-character is copied (not the null itself).
  // This is often not useful.
  // Solution: Enter strlcat stage left.
  //     // size_t strlcat(char *dst, const char *src, size_t size);
  //     The strlcpy() function copies the null-terminated string from src to
  //     dst (up to size characters). The strlcat() function appends a
  //     null-terminated string src to the end of dst (but no more than num
  //     characters will be in the destination.
  //     The function guarantees that the destination string is null terminated
  //     for all nonzero-length buffers. The strlcat() function returns the
  //     total length of the string that it tried to create. i.e. the length of
  //     the destination (before concatenation) plus the length of the source.
  //     To check for truncation, the programmer needs to verify that the return
  //     value is less than the size parameter. If the resulting string is
  //     truncated, the programmer now has the number of bytes needed to store
  //     the entire string and may reallocate and recopy.
  // This is my implementation of strlcat

  size_t srcLen = 0;
  if (strSource)
      srcLen = strlen(strSource);
  size_t dstLen = 0;
  if (strDest)
      dstLen = strlen(strDest);

  if (!strSource)
  {
      //if (!strDest) // Real values are supplied?
      //    return 0;  // No source buffer and no target buffer so nothing to do, even on a retry;
      return dstLen + srcLen; // Nothing to copy so we can't copy anything, but we do know how long the result would be if we could.
  }

  if (!strDest) // Real values are supplied?
      //return 0;  // No target buffer so nothing to do, even on a retry;
      return dstLen + srcLen; // Nothing to copy so we can't copy anything, but we do know how long the result would be if we could.

  //size_t dstLen = strlen(strDest);

  if (!count) // Real values are supplied?
      //return dstLen; // No max bytes to copy, so return only the existing strlen;
      return dstLen + srcLen; // Nothing to copy so we can't copy anything, but we do know how long the result would be if we could.

  if (!strSource) // Real value are supplied?
      //return dstLen; // Nothing to append, so return only the existing strlen;
      return dstLen + srcLen; // Nothing to copy so we can't copy anything, but we do know how long the result would be if we could.


  size_t availableSpace = count - dstLen - 1;
  if (availableSpace == 0)
      return dstLen + srcLen; // Return the length of string if everything went smoothly. The caller can use this to reallocate a buffer of sufficient size (+1) and try again.

  char *pWhereToCopy = strDest + dstLen;
  size_t bytesToCopy = MINIMUM(availableSpace, srcLen);

  memcpy(pWhereToCopy, strSource, bytesToCopy);
  pWhereToCopy[bytesToCopy] = '\0';

  // Return the length of string if everything went smoothly. The caller can
  // compare the length of the returned string against the expected length, and
  // if truncation has occurred, can use this return value to reallocate a
  // buffer of sufficient size (retval+1) and try again.
  return dstLen + srcLen;
}
#endif // USE_STRLCPY

long qo_getFilesize(const char *szFilename)
{
    FILE *fIn;
    long filesize;

    // Open the file
    fIn = fopen(szFilename,"rb");
    if (fIn == NULL)
    {
        return -1;
    }

    fseek (fIn, 0, SEEK_END);
    filesize = (long)ftell(fIn);
    rewind(fIn);
    fclose(fIn);
    return filesize;
}

bool qo_fileExists(const char *szFilename)
/*+---------------------------------------------------------+*/
/*                                                           */
/*+---------------------------------------------------------+*/
{
#ifdef _WIN32
    if (_access_s(szFilename, 0) == 0)
#else
    if (access(szFilename, F_OK) != -1) // From unistd.h
#endif
    {
        // File exists
        return true;
    }
    // File does not exist
    return false;
}



// void qo_hashOfString(char *szSrcStr, char *szDstStr, size_t cbDstStr)
// {
//     struct MD5Context context;
//     unsigned char digest[16];
//     MD5Init(&context);
//     MD5Update(&context, szSrcStr, strlen(szSrcStr));
//     MD5Final(digest, &context);
//     qo_strlcpy(szDstStr, (char *)digest, cbDstStr);
// }

int qo_roundUp(int num, int multipleOf)
{
    // Return a number which is a whole multiple of N
    // e.g. newlen = RoundUp (oldlen, 16);

    int newlen = num;

    if (num % multipleOf)
    {
        newlen += multipleOf - (num % multipleOf);
    }
    return newlen;
}

bool qo_LStringJoin(tLSTRING *pDest, tLSTRING *pDataToAppend)
{
    tLSTRING joinedData;

    if (!pDest)
    {
        qo_errno = EINVAL;
        return false;
    }
    if (!pDataToAppend)
    {
        // Nothing to do
        return true;
    }
    if (pDataToAppend->pData == NULL || pDataToAppend->cbData == 0)
    {
        // Nothing to do
        return true;
    }

    joinedData.cbData = pDest->cbData + pDataToAppend->cbData;
    joinedData.pData = malloc(joinedData.cbData);
    if (joinedData.pData == NULL)
    {
        qo_errno = ENOMEM;
        return false;
    }
    // Copy in the original data
    if (pDest->cbData)
    {
        memcpy(joinedData.pData, pDest->pData, pDest->cbData);
    }
    // Append the additional data
    memcpy(joinedData.pData + pDest->cbData, pDataToAppend->pData, pDataToAppend->cbData);

    // Clean and Free up the original data
    qo_LStringCleanseAndFree(pDest);

    // Clean and Free up the appended data
    qo_LStringCleanseAndFree(pDataToAppend);

    // Return the joined data
    pDest->pData = joinedData.pData;
    pDest->cbData = joinedData.cbData;

    return true;
}

void qo_LStringCleanseAndFree(tLSTRING *pItem)
{
    // Similar to qo_CleanseAndFree(), except this acts on tLSTRING types
    if (pItem->pData)
    {
        if (pItem->cbData > 0)
            memset(pItem->pData, 0, pItem->cbData);
        free(pItem->pData);
        pItem->pData = NULL;
        pItem->cbData = 0;
    }
}

void qo_CleanseAndFree(uint8_t **ppBlock, size_t cbBlock)
{
    // Similar to qo_LStringCleanseAndFree() which acts on tLSTRING types
    if (ppBlock && *ppBlock)
    {
        if (cbBlock > 0)
            memset(*ppBlock, 0, cbBlock);
        free(*ppBlock);
        *ppBlock = NULL;
    }
}


// ----------------------------------------------------------------------------------------------------------------------------------------------------------------
