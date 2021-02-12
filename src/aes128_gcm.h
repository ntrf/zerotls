/*
tinyTLS / zeroTLS project

Copyright 2015-2021 Nesterov A.

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


#ifndef TINYTLS_AES_GCM_H_
#define TINYTLS_AES_GCM_H_

#include "hash/hash.h"

#include "cipherstate.h"
#include "aes/rijndael.h"

struct AES128_GCM : CipherState
{
	// How much data is prefixed to an otherwise aligned packet
	static const size_t lead = 8; // header 5 bytes + explicit nonce 8 bytes

	static const int macSize = 4;

	uint32_t IV[1];

	uint32_t encRk[AES_RKLENGTH(128)];
	uint32_t macKey[4]; // GMAC key, generated via AES(K, 0)

	// return minimum space required for encrypted packet

	uint32_t seq_num_low;
	uint32_t seq_num_high;

	AES128_GCM();

	void InitEnc(uint8_t * aeskey, uint8_t * aesIV);
	inline void InitDec(uint8_t * aeskey, uint8_t * aesIV)
	{
		InitEnc(aeskey, aesIV);
	}

	int32_t WrapPacket(uint8_t * output, uint8_t type, const uint8_t * data, unsigned length);
	int32_t UnWrapPacket(uint8_t * output, uint8_t type, const uint8_t * data, unsigned length);
};


#endif