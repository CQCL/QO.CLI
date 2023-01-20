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
// Various configuration utilities
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_QO_CONFIG_H_
#define _INCLUDE_QO_CONFIG_H_


#include "stdio.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_CFG_FLOOR 18000
#define ERC_CFG_PARAMETER_ERROR_CONFIG_ENVVAR         18010
#define ERC_CFG_NOENT_CONFIG_ENVVAR_NOT_FOUND         18020
#define ERC_CFG_NOMEM_CONFIG_FILE_PATH                18030
#define ERC_CFG_FILE_OPEN_FAILED                      18040
#define ERC_CFG_FILE_READ_FAILED                      18050
#define ERC_CFG_PARAM_ERROR_FILENAME_NOT_SPECIFIED    18060
#define ERC_CFG_NOENT_FILE_NOT_FOUND                  18070
#define ERC_CFG_FILE_SIZE_UNKNOWN                     18080
#define ERC_CFG_FILE_IS_EMPTY                         18090
#define ERC_CFG_NOMEM_TO_READ_FILE_CONTENTS           18100


///////////////////////////////////////////////////////////////////////////////
// Config Functions
///////////////////////////////////////////////////////////////////////////////
extern tERRORCODE qo_getFilenameFromEnvVar(const char *szConfigEnvVar, char **pszFilename);
extern tERRORCODE qo_readEntireConfigFileIntoMemory(const char *szConfigFilename, char **pszConfigFileContents);
extern tERRORCODE qo_readEntireConfigFileIntoMemoryEnv(const char *szConfigEnvVar, char **pszFilename, char **pszConfigFileContents);

#ifdef __cplusplus
}
#endif

#endif // _INCLUDE_QO_CONFIG_H_
