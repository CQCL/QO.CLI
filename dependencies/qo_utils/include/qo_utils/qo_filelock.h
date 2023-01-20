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
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_QO_FILELOCKLOGGING_H_
#define _INCLUDE_QO_FILELOCKLOGGING_H_

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////////////
// File Locking Functions
///////////////////////////////////////////////////////////////////////////////

#define FILELOCK_LOGLEVEL 0x00  // 0x00 is disabled, 0x01 is stdout, 0x02 is syslog

extern void qo_waitForFileLock(char *szLockFilePath, char *szFilename, int loglevel);
extern void qo_releaseFileLock(char *szLockFilePath, char *szFilename, int loglevel);

#ifdef __cplusplus
}
#endif

#endif // _INCLUDE_QO_FILELOCKLOGGING_H_
