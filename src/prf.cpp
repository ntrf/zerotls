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

#include <string.h>

#include "hash/hash.h"

/*  From RFC 5246
	TLS 1.2 PRF computation

        PRF(secret, label, seed) = P_SHA256(secret, label + seed);
		
        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                               HMAC_hash(secret, A(2) + seed) +
                               HMAC_hash(secret, A(3) + seed) + ...

    A() is defined as:
        A(0) = seed
        A(i) = HMAC_hash(secret, A(i-1))
*/
void PrfGenBlock_v1_2(
	uint8_t * output, size_t outLen,
	const uint8_t * secret, size_t sectretLen,
	const char * label, const uint8_t * seed, size_t seedLen)
{
	unsigned labelLen = strlen(label);

	const unsigned char * const secret_begin = secret;
	unsigned int secretKey[16];

	if (sizeof(secretKey) >= sectretLen) {
		memcpy(secretKey, secret_begin, sectretLen);
		memset((uint8_t*)secretKey + sectretLen, 0, sizeof(secretKey) - sectretLen);
	} else {
		//### calculate sha1 for hash
		// for now - it's bad condition
		// TLS never uses keys longer than 24 bytes
		return;
	}

	unsigned int A[8];

	unsigned char * outPos = output;
	unsigned int outRem = outLen;

	// calculate A1
	HMACSHA256_State PState;
	HmacSha256_Init(&PState, secretKey);
	HmacSha256_Update(&PState, (const uint8_t*)label, labelLen);
	HmacSha256_Update(&PState, (const uint8_t*)seed, seedLen);
	HmacSha256_Finish(&PState, A);

	goto after_a1_sha1;

	unsigned int R[8];

	do {
		// calculate AN
		HmacSha256_Init(&PState, secretKey);
		HmacSha256_Update(&PState, (const uint8_t*)A, sizeof(A));
		HmacSha256_Finish(&PState, A);

	after_a1_sha1:

		//### clone the decoder state
		// calculate HMAC
		HmacSha256_Init(&PState, secretKey);
		HmacSha256_Update(&PState, (const uint8_t*)A, sizeof(A));
		HmacSha256_Update(&PState, (const uint8_t*)label, labelLen);
		HmacSha256_Update(&PState, (const uint8_t*)seed, seedLen);
		HmacSha256_Finish(&PState, R);

		// a bit more complicated as we need to XOR results
		if (outRem >= sizeof(R)) {
			memcpy(outPos, R, sizeof(R));
			outRem -= sizeof(R);
			outPos += sizeof(R);
		} else {
			memcpy(outPos, R, outRem);
			outRem = 0;
		}
	} while(outRem > 0);
}
