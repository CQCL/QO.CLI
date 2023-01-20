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
#ifndef CQCL_QO_CLEANSE_H
#define CQCL_QO_CLEANSE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void Cleanse(void* ptr, size_t len);
extern void CleanseString(char *pSecretStr, size_t cbSecretStr);

#ifdef __cplusplus
}
#endif


#ifdef __cplusplus
#include <string>
#include <vector>

extern void CleanseStdString(std::string& secretStr);
extern void CleanseStdVector(std::vector<uint8_t>& secretVec);
#endif


#endif //CQCL_QO_CLEANSE_H
