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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <qo_decrypt/qo_crypto.h>

// Idea borrowed from:
//    https://stackoverflow.com/questions/5698002/how-does-one-securely-clear-stdstring
// OpenSSL went through a couple of iterations of securely erasing
// a string until it settled on this approach:
// Pointer to memset is volatile so that compiler must de-reference
// the pointer and can't assume that it points to any function in
// particular (such as memset, which it then might further "optimize").

typedef void* (*memset_t)(void*, int, size_t);
static volatile memset_t memset_func = memset;


void Cleanse(void *ptr, size_t len)
{
    memset_func(ptr, 0, len);
}


void CleanseString(char *pSecretStr, size_t cbSecretStr)
{
    Cleanse(pSecretStr, cbSecretStr);
}


#ifdef __cplusplus
#include <string>
#include <vector>

void CleanseStdString(std::string& secretStr)
{
    secretStr.resize(secretStr.capacity(), 0);
    Cleanse(&secretStr[0], secretStr.size());
    secretStr.clear();
}

void CleanseStdVector(std::vector<uint8_t>& secretVec)
{
    secretVec.resize(secretVec.capacity(), 0);
    Cleanse(&secretVec[0], secretVec.size());
    secretVec.clear();
}
#endif
