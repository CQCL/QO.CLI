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

#ifndef _INCLUDE_QO_JSON_H_
#define _INCLUDE_QO_JSON_H_

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __cplusplus
#ifndef bool
//typedef unsigned char  bool;
#define bool unsigned char
#endif
#ifndef true
#define true  (1)
#define false (0)
#endif
#ifndef TRUE
#define TRUE  true
#define FALSE false
#endif
#endif

struct _jsonobject;
struct _jsonpair;
union _jsonvalue;

typedef enum
{
    JSON_STRING = 0,
    JSON_OBJECT
} JSONValueType;

typedef struct _jsonobject
{
    struct _jsonpair *pairs;
    int count;
} JSONObject;

typedef struct _jsonpair
{
    char * key;
    union _jsonvalue *value;
    JSONValueType type;
} JSONPair;

typedef union _jsonvalue
{
    char * stringValue;
    struct _jsonobject *jsonObject;
} JSONValue;

///////////////////////////////////////////////////////////////////////////////
// JSON Config File Functions
///////////////////////////////////////////////////////////////////////////////
extern JSONObject *qo_parseJSON(const char *);
extern void qo_freeJSONFromMemory(JSONObject *);

#ifdef __cplusplus
}
#endif

#endif // _INCLUDE_QO_JSON_H_

