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
// simple_json.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

/******************************************************************************************************************************************
 * Simple JSON Parser in C
 * Extremely simple JSON Parser library written in C
 *
 * Github:
 *    https://github.com/forkachild/C-Simple-JSON-Parser
 *
 * Features
 *     * Structured data (JSONObject, JSONPair, JSONValue)
 *     * Count of Key-Value pairs of current JSON
 *     * Recursive JSON parsing
 *     * JSONValue is a union whose type is stored as JSONValueType enum in its JSONPair
 *     * __BONUS__ string, bool and character data types introduced
 * Setup:
 *     Extremely simple setup.
 *     Just __copy__ `json.h` and `json.c` in your source folder and `#include "json.h"` in your source file
 *
 * Sample Code:
 *     See main() at the end of this file.
 *
 * FAQ:
 *     Q. What if JSON is poorly formatted with uneven whitespace
 *     A. Well, that is not a problem for this library
 *     Q. What if there is error in JSON
 *     A. That is when the function returns NULL
 *     Q. What is `_parseJSON` and how is it different from `parseJSON`
 *     A. '_parseJSON' is the internal `static` implementation not to be used outside the library
 *
 * If this helped you in any way you can buy me a beer at [PayPal](https://www.paypal.me/suhelchakraborty "Buy me a beer")
 ******************************************************************************************************************************************/

#include <stdlib.h>
#include <string.h>

#include <qo_utils/qo_utils.h>
#include <qo_utils/qo_logging.h>
#include <qo_utils/qo_json.h>

//#define DEBUG_MALLOC_USAGE

////////////////////////////////////////////////////////////
// Constants and macros
////////////////////////////////////////////////////////////
#define isWhitespace(x)                   ((x)=='\r' || (x)=='\n' || (x)=='\t' || (x)==' ')
#define advanceOverWhitespace(x)               while(isWhitespace(*(x))) { (x)++         }
#define advanceOverWhitespaceCalcOffset(x, y)  while(isWhitespace(*(x))) { (x)++; (y)++; }

#define QO_MIN(x,y) (((x)<(y))?(x):(y))

#ifndef DEBUG_MALLOC_USAGE
#define qo_new(x,purpose)                       (x *)malloc(sizeof(x))
#define qo_newWithSize(x, n,purpose)            (x *)malloc((n)*sizeof(x))
#define qo_renewWithSize(x1, x2, n,purpose)     (x2 *)realloc((x1),(n)*sizeof(x2))
#define qo_delete(x1)                           free(x1)
#else
#define qo_new(x,purpose)                       (x *)qo_malloc(sizeof(x),purpose)
#define qo_newWithSize(x,n,purpose)             (x *)qo_malloc((n) * sizeof(x),purpose)
#define qo_renewWithSize(x1,x2,n,purpose)       (x2 *)qo_realloc((x1), (n) * sizeof(x2),purpose)
#define qo_delete(x1)                           qo_free(x1)
#endif // DEBUG_MALLOC_USAGE

#ifdef DEBUG_MALLOC_USAGE
//#define DEBUG_HEAP_VERBOSE
//#define DEBUG_HEAP_VERYVERBOSE

#define MLOG_COUNT 200

#define MLOG_PURPOSE_ROOTOBJECT     ('O')
#define MLOG_PURPOSE_ROOTPAIR       ('P')
#define MLOG_PURPOSE_NEWKEY         ('K')
#define MLOG_PURPOSE_NEWCHILDOBJECT ('V')
#define MLOG_PURPOSE_NEWCHILDSTRING ('W')
#define MLOG_PURPOSE_NEWSTRINGVALUE ('S')
#define MLOG_PURPOSE_EXTENDPAIRS    ('X')
#endif // DEBUG_MALLOC_USAGE

#ifdef DEBUG_HEAP_VERBOSE
#define dbg_stmnt_hv1(x) (x)
#else
#define dbg_stmnt_hv1(x)
#endif

#ifdef DEBUG_HEAP_VERYVERBOSE
#define dbg_stmnt_hv2(x) x
#else
#define dbg_stmnt_hv2(x)
#endif

//#define DEBUG_SHOW_KEYS_AND_VALUES
#ifdef DEBUG_SHOW_KEYS_AND_VALUES
#define dbg_stmnt_hv3(x) (x)
#else
#define dbg_stmnt_hv3(x)
#endif

////////////////////////////////////////////////////////////
// Types
////////////////////////////////////////////////////////////
#ifdef DEBUG_MALLOC_USAGE
typedef struct tagMLOG
{
    void *       p;
    unsigned int n;
    char         s;
    char         y;
} tMLOG;
#endif // DEBUG_MALLOC_USAGE

////////////////////////////////////////////////////////////
// Local variables
////////////////////////////////////////////////////////////
#ifdef DEBUG_MALLOC_USAGE
tMLOG mlog[MLOG_COUNT] = {0};
unsigned int mlog_index = 0;
void *UNALLOCATED_PTR = (void *)(0x55555555);
#endif // DEBUG_MALLOC_USAGE

////////////////////////////////////////////////////////////
// Implementation
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
// Malloc section
////////////////////////////////////////////////////////////
#ifdef DEBUG_MALLOC_USAGE
void *qo_malloc(unsigned int size, char purpose)
{
    void *ptr;
    if (mlog_index >= MLOG_COUNT)
    {
        app_tracef("ERROR: Too many mallocs. Please increase MLOG_COUNT");
        return NULL;
    }
    ptr = malloc(size);
    if (!ptr)
    {
        app_tracef("ERROR: malloc failure size=%u purpose=%c", size, purpose);
        return NULL;
    }
    memset(ptr, 0, size);

    mlog[mlog_index].p = ptr;
    mlog[mlog_index].n = size;
    mlog[mlog_index].s = 'A'; // Allocated
    mlog[mlog_index].y = purpose;
    mlog_index++;

    return ptr;
}

void qo_free(void *ptr)
{
    unsigned int ii;
    unsigned int found = -1;

    for (ii=0;ii<MLOG_COUNT;ii++)
    {
        if ((mlog[ii].p == ptr) && (mlog[ii].s == 'A'))
        {
            found = ii;
            break;
        }
        else if (mlog[ii].p == ptr)
        {
            found = ii;
        }
    }
    if (found == -1)
    {
        app_tracef("ERROR: Attempted free of unknown ptr %p", ptr);
        return;
    }
    if (mlog[found].s != 'A')
    {
        app_tracef("ERROR: Attempted free of previously freed ptr %p", ptr);
        return;
    }
    if (mlog[found].p == UNALLOCATED_PTR || mlog[found].p == 0)
    {
        app_tracef("ERROR: Attempted free of invalid ptr %p", ptr);
        return;
    }
    mlog[found].s = 'F'; // Freed
    free(ptr);
}

void *qo_realloc(void *oldptr, unsigned int newsize, char newpurpose)
{
    void *newptr;
    unsigned int bytes_to_copy;
    unsigned int ii;
    unsigned int found = -1;

    for (ii=0;ii<MLOG_COUNT;ii++)
    {
        if (mlog[ii].p == oldptr)
        {
            found = ii;
            break;
        }
    }
    if (found == -1)
    {
        app_tracef("ERROR: Attempted realloc of unknown ptr %p", oldptr);
        return NULL;
    }
    if (mlog[found].s != 'A')
    {
        app_tracef("ERROR: Attempted realloc of previously freed ptr %p", oldptr);
        return NULL;
    }
    bytes_to_copy = QO_MIN(newsize, mlog[found].n);

    newptr = qo_malloc(newsize, newpurpose);
    if (!newptr)
    {
        app_tracef("ERROR: realloc failure size=%u purpose=%c", newsize, newpurpose);
        return NULL;
    }
    memset(newptr, 0, newsize);
    if (oldptr)
    {
        memcpy(newptr,oldptr, bytes_to_copy);
        qo_free(oldptr);
    }
    return newptr;
}

void qo_mloginit(void)
{
    unsigned int ii;

    for (ii=0;ii<MLOG_COUNT;ii++)
    {
        mlog[ii].p = UNALLOCATED_PTR;
        mlog[ii].n = 0;
        mlog[ii].s = '-';
        mlog[ii].y = '-';
    }
}

void qo_mlogdump(char *title)
{
    unsigned int ii;
    unsigned int countActive = 0;
    unsigned int countStatus[3] = {0};
    unsigned int countPurpose[8] = {0};

    app_tracef("### mlogdump %s",title);
    for (ii=0;ii<MLOG_COUNT;ii++)
    {
        switch (mlog[ii].s)
        {
            case 'A': countStatus[0]++; break;
            case 'F': countStatus[1]++; break;
            default : countStatus[2]++; break;
        }
        if (mlog[ii].s == 'A')
        {
            switch (mlog[ii].y)
            {
                case MLOG_PURPOSE_ROOTOBJECT     : countPurpose[0]++; break;
                case MLOG_PURPOSE_ROOTPAIR       : countPurpose[1]++; break;
                case MLOG_PURPOSE_NEWKEY         : countPurpose[2]++; break;
                case MLOG_PURPOSE_NEWCHILDOBJECT : countPurpose[3]++; break;
                case MLOG_PURPOSE_NEWCHILDSTRING : countPurpose[4]++; break;
                case MLOG_PURPOSE_NEWSTRINGVALUE : countPurpose[5]++; break;
                case MLOG_PURPOSE_EXTENDPAIRS    : countPurpose[6]++; break;
                default                          : countPurpose[7]++; break;
            }
        }

        if ((mlog[ii].p == UNALLOCATED_PTR) &&
            (mlog[ii].n == 0) &&
            (mlog[ii].s == '-') &&
            (mlog[ii].y == '-'))
        {
            continue;
        }
        app_tracef("    mlog[%3u]: p=%p n=%4u s=%c y=%c",ii, mlog[ii].p, mlog[ii].n, mlog[ii].s, mlog[ii].y);
        countActive++;
    }
    app_tracef("    mlog stats:");
    app_tracef("        Active mallocs              : %u/%u",countActive,(unsigned int)MLOG_COUNT);
    app_tracef("        Allocated/Freed/Other       : %u/%u/%u",countStatus[0],countStatus[1],countStatus[2]);
    app_tracef("        MLOG_PURPOSE_ROOTOBJECT     : %u", countPurpose[0]);
    app_tracef("        MLOG_PURPOSE_ROOTPAIR       : %u", countPurpose[1]);
    app_tracef("        MLOG_PURPOSE_NEWKEY         : %u", countPurpose[2]);
    app_tracef("        MLOG_PURPOSE_NEWCHILDOBJECT : %u", countPurpose[3]);
    app_tracef("        MLOG_PURPOSE_NEWCHILDSTRING : %u", countPurpose[4]);
    app_tracef("        MLOG_PURPOSE_NEWSTRINGVALUE : %u", countPurpose[5]);
    app_tracef("        MLOG_PURPOSE_EXTENDPAIRS    : %u", countPurpose[6]);
    app_tracef("        Other purpose               : %u", countPurpose[7]);
}

#endif // DEBUG_MALLOC_USAGE


////////////////////////////////////////////////////////////
// JSON section
////////////////////////////////////////////////////////////

// Forward Declarations
static JSONObject * _parseJSON(const char *, int *);

JSONObject *qo_parseJSON(const char * jsonString)
{
    int offset = 0;

#ifdef DEBUG_MALLOC_USAGE
    qo_mloginit();
#endif
    JSONObject *tempObj = _parseJSON(jsonString, &offset);
#ifdef DEBUG_MALLOC_USAGE
    qo_mlogdump("After parseJSON");
#endif

    return tempObj;
}

void qo_freeJSONFromMemory(JSONObject *obj)
{
    int i;

    if (obj)
    {
        dbg_stmnt_hv1(app_tracef("DEBUG: Found root object (ptr=%p)", obj));
        if (obj->pairs)
        {
            dbg_stmnt_hv1(app_tracef("DEBUG: Found array of %d pairs (ptr=%p)", obj->count, obj->pairs));
            for (i = 0; i < obj->count; i++)
            {
                if (obj->pairs[i].key != NULL)
                {
                    dbg_stmnt_hv1(app_tracef("DEBUG: Found key on pair %d (ptr=%p)", i, obj->pairs[i].key));
                    dbg_stmnt_hv2(app_tracef("DEBUG: (heap:free) key size=(%2d+1) ptr=%p key=\"%s\"",i,obj->pairs[i].key,obj->pairs[i].key));
                    qo_delete(obj->pairs[i].key);
                }
                if (obj->pairs[i].value != NULL)
                {
                    dbg_stmnt_hv1(app_tracef("DEBUG: Found value on pair %d (ptr=%p)", i, obj->pairs[i].value));
                    switch (obj->pairs[i].type)
                    {
                        case JSON_STRING:
                        {
                            dbg_stmnt_hv1(app_tracef("DEBUG: Found string on value on pair %d (ptr=%p)", i, obj->pairs[i].value->stringValue));
                            dbg_stmnt_hv2(app_tracef("DEBUG: (heap:free) strvalue size=(%2d+1) ptr=%p val=\"%s\"",i,obj->pairs[i].value->stringValue,obj->pairs[i].value->stringValue));
                            qo_delete(obj->pairs[i].value->stringValue);
                            break;
                        }
                        case JSON_OBJECT:
                        {
                            dbg_stmnt_hv1(app_tracef("DEBUG: Found childobj on value on pair %d (recursing with ptr=%p)", i, obj->pairs[i].value->jsonObject));
                            qo_freeJSONFromMemory(obj->pairs[i].value->jsonObject);
                            dbg_stmnt_hv1(app_tracef("DEBUG: Back from recursion of childobj on value on pair %d (recursing)", i));
                            break;
                        }
                    }
                    dbg_stmnt_hv1(app_tracef("DEBUG: We can now free the value struct on pair %d (ptr=%p)", i, obj->pairs[i].value));
                    dbg_stmnt_hv2(app_tracef("DEBUG: (heap:free) val size=(%2d+1) ptr=%p",0,obj->pairs[i].value));
                    qo_delete(obj->pairs[i].value);
                }
            }
            dbg_stmnt_hv1(app_tracef("DEBUG: We can now free the array of pairs (ptr=%p)", obj->pairs));
            dbg_stmnt_hv2(app_tracef("DEBUG: (heap:free) rootpairs array ptr=%p",obj));
            qo_delete(obj->pairs);
        }
        dbg_stmnt_hv1(app_tracef("DEBUG: We can now free the root object (ptr=%p)", obj));
        dbg_stmnt_hv2(app_tracef("DEBUG: (heap:free) rootobj ptr=%p",obj));
        qo_delete(obj);
    }
#ifdef DEBUG_MALLOC_USAGE
    qo_mlogdump("After qo_freeJSONFromMemory");
#endif
}

static int strNextOccurence(const char * str, char ch)
{
    int pos = 0;

    if (str == NULL)
        return -1;

    while (*str != ch && *str != '\0')
    {
        str++;
        pos++;
    }
    return (*str == '\0') ? -1 : pos;
}

#define JSON_STARTOFTEXT        '^' // Arbitrary character to indicate the beginning of the string
#define JSON_STARTOFOBJECT      '{'
#define JSON_STARTOFKEYSTRING   '"'
#define JSON_ENDOFKEYSTRING     '"'
#define JSON_KEYVALUESEPARATOR  ':'
#define JSON_STARTOFVALUESTRING '"'
#define JSON_ENDOFVALUESTRING   '"'
#define JSON_PAIRDELIMITER      ','
#define JSON_ENDOFOBJECT        '}'
#define JSON_ENDOFTEXT          '$' // Arbitrary character to indicate the end of the string

static JSONObject * _parseJSON(const char * str, int *pOffset)
{
    int _offset = 0;

    // Create new object
    JSONObject *obj = qo_new(JSONObject,MLOG_PURPOSE_ROOTOBJECT);
    dbg_stmnt_hv2(app_tracef("DEBUG: (heap:malloc) rootobj size=(%2lu) ptr=%p", (unsigned long)sizeof(JSONObject), obj));
    // Set number of keyvaluepairs in this object
    obj->count = 1;
    // Create the first keyvalue pair
    obj->pairs = qo_newWithSize(JSONPair, 1,MLOG_PURPOSE_ROOTPAIR);
    dbg_stmnt_hv2(app_tracef("DEBUG: (heap:malloc) rootpair size=(%2lu) ptr=%p", (unsigned long)sizeof(JSONPair), obj->pairs));

    char prevToken = JSON_STARTOFTEXT; // Arbitrary character to indicate the beginning of the string

    while (*str != '\0')
    {
        advanceOverWhitespaceCalcOffset(str, _offset);
        if (*str == JSON_STARTOFOBJECT)
        {
            // Start of new object
            if (prevToken != JSON_STARTOFTEXT && prevToken != JSON_PAIRDELIMITER)
            {
                app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c' (or SOT)", *str, prevToken);
                return NULL;
            }
            prevToken = JSON_STARTOFOBJECT;
            // Skip over the opening curlybrace
            str++;
            _offset++;
        }
        else if (*str == JSON_STARTOFKEYSTRING)
        {
            // Start of String
            if (prevToken != JSON_STARTOFOBJECT && prevToken != JSON_PAIRDELIMITER)
            {
                app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                return NULL;
            }
            prevToken = JSON_STARTOFKEYSTRING;

            // Skip over opening doublequote char
            str++;

            // Find closing doublequote char
            int i = strNextOccurence(str, JSON_ENDOFKEYSTRING);
            if (i <= 0)
            {
                // Closing doublequote char not found for key
                qo_freeJSONFromMemory(obj);
                return NULL;
            }

            if (prevToken != JSON_STARTOFKEYSTRING)
            {
                app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                return NULL;
            }
            prevToken = JSON_ENDOFKEYSTRING;

            // Store string as the key part of the keyvalue pair
            JSONPair tempPtr = obj->pairs[obj->count - 1];

            tempPtr.key = qo_newWithSize(char, i + 1,MLOG_PURPOSE_NEWKEY);
            if (tempPtr.key == NULL)
            {
                app_tracef("ERROR: Out of memory for tempPtr.key");
                return NULL;
            }
            memcpy(tempPtr.key, str, i * sizeof(char));
            tempPtr.key[i] = '\0';
            dbg_stmnt_hv2(app_tracef("DEBUG: (heap:malloc) newkey size=(%2d+1) ptr=%p key=\"%s\"",i,tempPtr.key,tempPtr.key));
            dbg_stmnt_hv3(app_tracef("DEBUG: newkey key=\"%s\"",tempPtr.key));

            // Skip over the found string, and closing doublequote char
            str += i + 1;
            _offset += i + 2; // extra 1 for the opening doublequote char

            // Look for colon char, ignoring everything between the '"' and the ':'.
            // i.e. separator between key and value
            i = strNextOccurence(str, JSON_KEYVALUESEPARATOR);
            if (i == -1)
            {
                // Colon char not found after key string
                return NULL;
            }

            if (prevToken != JSON_ENDOFKEYSTRING)
            {
                app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                return NULL;
            }
            prevToken = JSON_KEYVALUESEPARATOR;

            // Skip over the ignored chars, and the colon
            str += i + 1;
            _offset += i + 1;

            advanceOverWhitespaceCalcOffset(str, _offset);

            // Is the value another object, or a string?
            if (*str == JSON_STARTOFOBJECT)
            {
                int _offsetBeforeParsingChildObject = _offset;
                int _sizeOfChildObject;

                // The value is an object
                if (prevToken != JSON_KEYVALUESEPARATOR)
                {
                    app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                    return NULL;
                }
                prevToken = JSON_STARTOFOBJECT;

                tempPtr.value = qo_new(JSONValue,MLOG_PURPOSE_NEWCHILDOBJECT);
                if (tempPtr.value == NULL)
                {
                    app_tracef("ERROR: Out of memory for tempPtr.value");
                    return NULL;
                }
                dbg_stmnt_hv2(app_tracef("DEBUG: (heap:malloc) childobj size=(%2lu) ptr=%p", (unsigned long)sizeof(JSONValue), tempPtr.value));
                tempPtr.type = JSON_OBJECT;
                // Parse the object recursively
                tempPtr.value->jsonObject = _parseJSON(str, &_offset);
                if (tempPtr.value->jsonObject == NULL)
                {
                    // Value object not valid, for some or other reason
                    qo_freeJSONFromMemory(obj);
                    return NULL;
                }

                // Advance the string pointer by the size of the processed child object
                _sizeOfChildObject = _offset - _offsetBeforeParsingChildObject;
                str += _sizeOfChildObject;
                //str += _offset;
                // Everything from the { to the } has been consumed in recursion
                // So we Start with the { closing brace
                prevToken = JSON_ENDOFOBJECT;
            }
            else if (*str == JSON_STARTOFVALUESTRING)
            {
                // The value is a string
                if (prevToken != JSON_KEYVALUESEPARATOR)
                {
                    app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                    return NULL;
                }
                prevToken = JSON_STARTOFVALUESTRING;

                // Skip over the doublequote char
                str++;
                // Look for the closing doublequote char
                i = strNextOccurence(str, JSON_ENDOFVALUESTRING);
                if (i == -1)
                {
                    // Cannot find closing double quote char for value string
                    qo_freeJSONFromMemory(obj);
                    return NULL;
                }

                if (prevToken != JSON_STARTOFVALUESTRING)
                {
                    app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                    return NULL;
                }
                prevToken = JSON_ENDOFVALUESTRING;

                // Store the value string in the value portion of the keyvalue pair
                tempPtr.value = qo_new(JSONValue,MLOG_PURPOSE_NEWCHILDSTRING);
                dbg_stmnt_hv2(app_tracef("DEBUG: (heap:malloc) childstr size=(%2lu) ptr=%p", (unsigned long)sizeof(JSONValue), tempPtr.value));
                tempPtr.type = JSON_STRING;
                tempPtr.value->stringValue = qo_newWithSize(char, i + 1,MLOG_PURPOSE_NEWSTRINGVALUE);
                memcpy(tempPtr.value->stringValue, str, i * sizeof(char));
                tempPtr.value->stringValue[i] = '\0';
                dbg_stmnt_hv2(app_tracef("DEBUG: (heap:malloc) strval size=(%2d+1) ptr=%p val=\"%s\"",i,tempPtr.value->stringValue,tempPtr.value->stringValue));
                dbg_stmnt_hv3(app_tracef("DEBUG: val=\"%s\"",tempPtr.value->stringValue));

                // Skip over the string and the closing doublequote
                str += i + 1;
                _offset += i + 2;  // extra 1 for the opening doublequote char
            }
            // Insert object into array of objects
            obj->pairs[obj->count - 1] = tempPtr;
        }
        else if (*str == JSON_PAIRDELIMITER)
        {
            // Start of the next keyvalue pair
            if (prevToken != JSON_ENDOFOBJECT && prevToken != JSON_ENDOFVALUESTRING)
            {
                app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                return NULL;
            }
            prevToken = JSON_PAIRDELIMITER;

            // Increment the number of keyvalue pairs
            obj->count++;
            // Add another keyvalue pair to the object
            dbg_stmnt_hv2(app_tracef("DEBUG: (heap:free) val ptr=%p",obj->pairs));
            obj->pairs = qo_renewWithSize(obj->pairs, JSONPair, obj->count, MLOG_PURPOSE_EXTENDPAIRS);
            dbg_stmnt_hv2(app_tracef("DEBUG: (heap:realloc) extendpairs size=(%2lu+1) ptr=%p", (unsigned long)(sizeof(JSONPair)*obj->count), obj->pairs));

            // Skip over the comma
            str++;
            _offset++;
        }
        else if (*str == JSON_ENDOFOBJECT)
        {
            // End of object
            if (prevToken != JSON_ENDOFOBJECT && prevToken != JSON_ENDOFVALUESTRING)
            {
                app_tracef("ERROR: Error parsing JSON string - Unexpected '%c' after '%c'", *str, prevToken);
                return NULL;
            }
            prevToken = JSON_ENDOFOBJECT;

            // Skip over the closing brace
            str++; // (pedantic)
            _offset++;

            // Update parent offset
            (*pOffset) += _offset;

            return obj;
        }
        else
        {
            // Internal error (we should have caught all error possibilities, but justin case)
            // ignore leading junk e.g. "JSON:"
            str++;
            _offset++;
            //qo_freeJSONFromMemory(obj);
            //return NULL;
        }
    }
    if (prevToken != JSON_ENDOFOBJECT)
    {
        app_tracef("ERROR: Error parsing JSON string - Unexpected EOT after '%c'", prevToken);
        return NULL;
    }
    prevToken = JSON_ENDOFTEXT; // Arbitrary character to indicate the End Of Text
    UNUSED_ITEM(prevToken);

    // Premature end of input string?
    return obj;
}

////////////////////////////////////////////////////////////
// Testing section
////////////////////////////////////////////////////////////
//#define RUN_SAMPLE_CODE
#ifdef RUN_SAMPLE_CODE
int main(int argc, const char * argv[])
{
    int ii;
    (void)argc;
    (void)argv;

    /////////////////////////////////////////////////////////////////////
    // Simple
    // { "hello":"world", "key":"value" }
    // 0----+----1----+----2----+----3-
    /////////////////////////////////////////////////////////////////////
    const char * someJsonString = "{\"hello\":\"world\",\"key\":\"value\"}";
    JSONObject *json1 = qo_parseJSON(someJsonString);
    if (!json1)
    {
        xdbg_printf(XDBG_DEBUG_ERROR, "ERROR: Failed to parse JSON string\n");
        return 0;
    }
    xdbg_printf(XDBG_DEBUG_INFO, "Count: %i\n", json1->count);                                  // Count: 2
    xdbg_printf(XDBG_DEBUG_INFO, "Key: %s, Value: %s\n", json1->pairs[0].key,
                                                         json1->pairs[0].value->stringValue);   // Key: hello, Value: world

    /////////////////////////////////////////////////////////////////////
    // Recursive
    // {"name":{"first":"John", "last":"Doe"}, "age":"21"}
    // 0----+----1----+----2----+----3----+----4----+----
    //         0----+----1----+----2----+----
    /////////////////////////////////////////////////////////////////////
    const char * complexJsonString = "{\"name\":{\"first\":\"John\",\"last\":\"Doe\"},\"age\":\"21\"}";
    JSONObject *json2 = qo_parseJSON(complexJsonString);
    if (!json2)
    {
        xdbg_printf(XDBG_DEBUG_ERROR, "ERROR: Failed to parse JSON string\n");
        return 0;
    }
    for (ii=0; ii<json2->count; ii++)
    {
        xdbg_printf(XDBG_DEBUG_INFO, "Key-Value pair %d is a %s\n", ii, (json2->pairs[ii].type == JSON_STRING)?"string":"JSON object");
    }
    //JSONObject *nameJson = json2->pairs[0].value->jsonObject;
    //xdbg_printf(XDBG_DEBUG_INFO, "First name: %s\n", nameJson->pairs[0].value->stringValue);
    //xdbg_printf(XDBG_DEBUG_INFO, "Last name: %s\n", nameJson->pairs[1].value->stringValue);

    return 0;
}
#endif // RUN_SAMPLE_CODE
