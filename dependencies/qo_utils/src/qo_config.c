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
///////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <qo_utils/qo_config.h>
#include <qo_utils/qo_logging.h>
#include <qo_utils/qo_string.h>

tERRORCODE qo_getFilenameFromEnvVar(const char *szConfigEnvVar, char **pszFilename)
{
    const char *szConfigfilePath;

    *pszFilename = NULL;

    if (!szConfigEnvVar)
    {
        //app_tracef("ERROR: Parameter error");
        return ERC_CFG_PARAMETER_ERROR_CONFIG_ENVVAR;
    }

    szConfigfilePath = getenv(szConfigEnvVar); // Returns a pointer into the current environment
    if (!szConfigfilePath)
    {
        app_tracef("ERROR: Cannot find environment variable: %s", szConfigEnvVar);
        return ERC_CFG_NOENT_CONFIG_ENVVAR_NOT_FOUND;
    }

    // Effectively, a strdup
    *pszFilename = malloc(strlen(szConfigfilePath) + 1);
    if (*pszFilename == NULL)
    {
        app_tracef("ERROR: Out of memory");
        return ERC_CFG_NOMEM_CONFIG_FILE_PATH;
    }
    strcpy(*pszFilename, szConfigfilePath);

    return ERC_OK;
}

/*---------------------------------------------------------------------------
 * Function:        __Config_ReadEntireFileIntoMemory
 * Description:     Read data on the configure file
 * Parameters:      pData - the buffer to be saved the data
 *                  numByte - the number of byte data to be read
 * Return:          none
 ---------------------------------------------------------------------------*/
static tERRORCODE __Config_ReadEntireFileIntoMemory (const char *szFilename, void *pData, unsigned int bytesToRead)
{
    FILE *fIn;
    int bytesRead = 0;

    fIn = fopen(szFilename, "rb");
    if (!fIn)
    {
        app_tracef("ERROR: Error %d opening file \"%s\" for reading", errno, szFilename);
        return ERC_CFG_FILE_OPEN_FAILED;
    }

    bytesRead = fread(pData, 1, bytesToRead, fIn);
    if (bytesRead == -1)
    {
        app_tracef("ERROR: Error %u attempting to read %u bytes from file \"%s\"", errno, bytesToRead, szFilename);
        fclose(fIn);
        return ERC_CFG_FILE_READ_FAILED;
    }

    fclose(fIn);
    //app_tracef("INFO: Configuration successfully read from \"%s\" (%d bytes)", szFilename, bytesRead );
    return ERC_OK;
}


static tERRORCODE __getFileInfo(const char *szFilename, long *pRetFilesize)
{
    tERRORCODE rc;

    *pRetFilesize = -1;

    if (!szFilename)
    {
        app_tracef("ERROR: Parameter error");
        return ERC_CFG_PARAM_ERROR_FILENAME_NOT_SPECIFIED;
    }

    rc = qo_fileExists(szFilename);
    if (rc == false)
    {
        app_tracef("ERROR: File not found: %s", szFilename);
        return ERC_CFG_NOENT_FILE_NOT_FOUND;
    }

    *pRetFilesize = qo_getFilesize(szFilename);
    if (*pRetFilesize < 0)
    {
        app_tracef("ERROR: Unable to determine size of file: %s", szFilename);
        return ERC_CFG_FILE_SIZE_UNKNOWN;
    }
    return ERC_OK;
}

tERRORCODE qo_readEntireConfigFileIntoMemory(const char *szConfigFilename, char **pszConfigFileContents)
{
    long filesize;
    tERRORCODE rc;

    *pszConfigFileContents = NULL;

    if (!szConfigFilename)
    {
        app_tracef("ERROR: Parameter error");
        return ERC_CFG_PARAM_ERROR_FILENAME_NOT_SPECIFIED;
    }

    rc = __getFileInfo(szConfigFilename, &filesize);
    if (rc != ERC_OK)
        return rc;
    if (filesize == 0)
    {
        app_tracef("ERROR: Empty file");
        return ERC_CFG_FILE_IS_EMPTY;
    }

    *pszConfigFileContents = malloc(filesize+1); // We will terminate the json string
    if (*pszConfigFileContents == NULL)
    {
        app_tracef("ERROR: Out of memory");
        return ERC_CFG_NOMEM_TO_READ_FILE_CONTENTS;
    }

    rc = __Config_ReadEntireFileIntoMemory(szConfigFilename, (unsigned char *)(*pszConfigFileContents), (unsigned int)filesize);
    if (rc != ERC_OK)
    {
        app_tracef("ERROR: Read failed");
        free(*pszConfigFileContents);
        return rc;
    }

    // Null terminate the json string
    (*pszConfigFileContents)[filesize] = '\0';

    // All is good.
    // The *pszConfigFileContents buffer point to malloc'd memory and ultimately needs to be free'd by the caller.

    return ERC_OK;
}
