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

/* HMAC.CPP
 * Simple implementation of HMAC based on wikipedia description
 * look for original code here: 
 * http://en.wikipedia.org/wiki/HMAC#Implementation
 */
#include <string.h>

#include "hash.h"

//#define TEST_MODULE

void HmacMd5(uint32_t result[4],const uint32_t key[16], const uint8_t * data, uint32_t length)
{
	uint32_t xkey[20]; // for step2: 0..15 = key  16..19 = step1 hash

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x36363636;

	MD5_State run1;
	md5Init(&run1);

	md5Update(&run1, (const uint8_t*)xkey, 16 * sizeof(uint32_t));
	md5Update(&run1, data, length);

	md5Finish(&run1, xkey + 16);

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x5c5c5c5c;

	md5Init(&run1);
	md5Update(&run1, (const uint8_t*)xkey, 20 * sizeof(uint32_t));
	md5Finish(&run1, result);

	memset(xkey, 0, sizeof(xkey));
}

void HmacMd5_Init(HMACMD5_State * state, const uint32_t key[16])
{
	uint32_t xkey[16];

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x36363636;

	md5Init(&state->md5State);
	md5Update(&state->md5State, (const uint8_t*)xkey, 16 * sizeof(uint32_t));

	for(uint32_t i = 0; i < 16; ++i)
		state->key[i] = key[i] ^ 0x5c5c5c5c;	
}

void HmacMd5_Update(HMACMD5_State * state, const uint8_t * data, uint32_t length)
{
	md5Update(&state->md5State, data, length);
}

void HmacMd5_Finish(HMACMD5_State * state, uint32_t result[4])
{
	uint32_t xkey[20];

	memcpy(xkey, state->key, sizeof(uint32_t) * 16);
	md5Finish(&state->md5State, xkey + 16);
	
	MD5_State run2;
	md5Init(&run2);
	md5Update(&run2, (const uint8_t*)xkey, 20 * sizeof(uint32_t));
	md5Finish(&run2, result);

	memset(xkey, 0, sizeof(xkey));
}


void HmacSha1(uint32_t result[5],const uint32_t key[16], const uint8_t * data, uint32_t length)
{
	uint32_t xkey[21]; // for step2: 0..15 = key  16..20 = step1 hash

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x36363636;

	SHA1_State run1;
	sha1Init(&run1);
	
	sha1Update(&run1, (const uint8_t*)xkey, 16 * sizeof(uint32_t));
	sha1Update(&run1, data, length);

	sha1Finish(&run1, xkey + 16);

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x5c5c5c5c;

	sha1Init(&run1);
	sha1Update(&run1, (const uint8_t*)xkey, 21 * sizeof(uint32_t));
	sha1Finish(&run1, result);

	memset(xkey, 0, sizeof(xkey));
}

void HmacSha1_Init(HMACSHA1_State * state, const uint32_t key[16])
{
	uint32_t xkey[16];

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x36363636;

	sha1Init(&state->sha1State);
	sha1Update(&state->sha1State, (const uint8_t*)xkey, 16 * sizeof(uint32_t));

	for(uint32_t i = 0; i < 16; ++i)
		state->key[i] = key[i] ^ 0x5c5c5c5c;
}

void HmacSha1_Update(HMACSHA1_State * state, const uint8_t * data, uint32_t length)
{
	sha1Update(&state->sha1State, data, length);
}

void HmacSha1_Finish(HMACSHA1_State * state, uint32_t result[5])
{
	uint32_t xkey[21];

	memcpy(xkey, state->key, sizeof(uint32_t) * 16);
	sha1Finish(&state->sha1State, xkey + 16);
	
	SHA1_State run2;
	sha1Init(&run2);
	sha1Update(&run2, (const uint8_t*)xkey, 21 * sizeof(uint32_t));
	sha1Finish(&run2, result);

	memset(xkey, 0, sizeof(xkey));
}

void HmacSha1_Reset(HMACSHA1_State * state, const HMACSHA1_State * from)
{
	memcpy(state->key, from->key, sizeof(state->key));
	state->sha1State.full_len = from->sha1State.full_len;
	state->sha1State.buf_len = from->sha1State.buf_len;
	memcpy(state->sha1State.buf, from->sha1State.buf, state->sha1State.buf_len);
	memcpy(state->sha1State.sha1state, from->sha1State.sha1state, sizeof(state->sha1State.sha1state));
}

void HmacSha256(uint32_t result[8],const uint32_t key[16], const uint8_t * data, uint32_t length)
{
	uint32_t xkey[24]; // for step2: 0..15 = key  16..23 = step1 hash

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x36363636;

	SHA256_State run1;
	sha256Init(&run1);
	
	sha256Update(&run1, (const uint8_t*)xkey, 16 * sizeof(uint32_t));
	sha256Update(&run1, data, length);

	sha256Finish(&run1, xkey + 16);

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x5c5c5c5c;

	sha256Init(&run1);
	sha256Update(&run1, (const uint8_t*)xkey, 21 * sizeof(uint32_t));
	sha256Finish(&run1, result);

	memset(xkey, 0, sizeof(xkey));
}

void HmacSha256_Init(HMACSHA256_State * state, const uint32_t key[16])
{
	uint32_t xkey[16];

	for(uint32_t i = 0; i < 16; ++i)
		xkey[i] = key[i] ^ 0x36363636;

	sha256Init(&state->state);
	sha256Update(&state->state, (const uint8_t*)xkey, 16 * sizeof(uint32_t));

	for(uint32_t i = 0; i < 16; ++i)
		state->key[i] = key[i] ^ 0x5c5c5c5c;
}

void HmacSha256_Update(HMACSHA256_State * state, const uint8_t * data, uint32_t length)
{
	sha256Update(&state->state, data, length);
}

void HmacSha256_Finish(HMACSHA256_State * state, uint32_t result[8])
{
	uint32_t xkey[24];

	memcpy(xkey, state->key, sizeof(uint32_t) * 16);
	sha256Finish(&state->state, xkey + 16);
	
	SHA256_State run2;
	sha256Init(&run2);
	sha256Update(&run2, (const uint8_t*)xkey, 24 * sizeof(uint32_t));
	sha256Finish(&run2, result);

	memset(xkey, 0, sizeof(xkey));
}

void HmacSha256_Reset(HMACSHA256_State * state, const HMACSHA256_State * from)
{
	memcpy(state->key, from->key, sizeof(state->key));
	state->state.full_len = from->state.full_len;
	state->state.buf_len = from->state.buf_len;
	memcpy(state->state.buf, from->state.buf, state->state.buf_len);
	memcpy(state->state.sha256state, from->state.sha256state, sizeof(state->state.sha256state));
}

#ifdef TEST_MODULE
#include <stdio.h>
extern void PrintHex(const uint8_t *buf, size_t size, int shift);

int main()
{
	uint32_t result[5];
	uint32_t key[16];

	memset(key, 0, sizeof(key));

	HmacMd5(result, key, (const uint8_t *)"", 0);

	printf("hmac_md5(\"\",\"\") = %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3]);

	HMACMD5_State state;

	HmacMd5_Init(&state, key);
	HmacMd5_Update(&state, (const uint8_t *)"", 0);
	HmacMd5_Finish(&state, result);

	printf("hmac_md5(\"\",\"\") = %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3]);

	strcpy((char *)key,"key");
		
	HmacMd5(result, key, (const uint8_t *)"The quick brown fox jumps over the lazy dog", 43);

	printf("hmac_md5(\"key\",\"The quick brown fox jumps over the lazy dog\") = %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3]);

	PrintHex((unsigned char*)result, sizeof(result), 0);

	HmacSha1(result, key, (const uint8_t *)"The quick brown fox jumps over the lazy dog", 43);

	printf("hmac_sha1(\"key\",\"The quick brown fox jumps over the lazy dog\") = %08x %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3], result[4]);

	PrintHex((unsigned char*)result, sizeof(result), 0);

	{
		HMACSHA1_State state;
		HmacSha1_Init(&state, key);
		HmacSha1_Update(&state, (const uint8_t *)"The quick brown fox jumps over the lazy dog", 43);
		HmacSha1_Finish(&state, result);

		printf("hmac_sha1(\"key\",\"The quick brown fox jumps over the lazy dog\") = %08x %08x %08x %08x %08x\n",
			result[0], result[1], result[2], result[3], result[4]);

		PrintHex((unsigned char*)result, sizeof(result), 0);
	}

	return 0;
}
#endif
