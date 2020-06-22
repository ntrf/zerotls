/*
tinyTLS / zeroTLS project

Copyright 2015-2020 Nesterov A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef RIJNDAEL_H_
#define RIJNDAEL_H_

int rijndaelSetupEncrypt(unsigned int *rk, const unsigned int * key, int keybits);
int rijndaelSetupDecrypt(unsigned int *rk, const unsigned int * key, int keybits);
void rijndaelEncrypt(const unsigned int *rk, int nrounds, const unsigned char plaintext[16], unsigned char ciphertext[16]);
void rijndaelDecrypt(const unsigned int *rk, int nrounds, const unsigned char ciphertext[16], unsigned char plaintext[16]);

#define AES_KEYLENGTH(keybits) ((keybits) >> 3)
#define AES_RKLENGTH(keybits)  (((keybits) >> 3) + 28)
#define AES_NROUNDS(keybits)   (((keybits) / 32) + 6)

#endif