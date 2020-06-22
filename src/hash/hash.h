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


#ifndef TINYTLS_HASH_H_
#define TINYTLS_HASH_H_

#include <stdint.h>

// MD5 implementation

struct MD5_State
{
	uint32_t md5state[4];
	uint8_t buf[64];
	uint32_t buf_len;
	uint32_t full_len;
};

void md5Init(MD5_State * state);
void md5Update(MD5_State * state, const uint8_t * input, uint32_t length);
void md5Finish(MD5_State * state, uint32_t result[4]);

// SHA1 implementation

struct SHA1_State
{
	uint32_t sha1state[5];
	uint8_t buf[64];
	uint32_t buf_len;
	uint32_t full_len;
};

void sha1Init(SHA1_State * state);
void sha1Update(SHA1_State * state, const uint8_t * input, uint32_t length);
void sha1Finish(SHA1_State * state, uint32_t result[5]);

// SHA256 implementation

struct SHA256_State
{
	uint32_t sha256state[8];
	uint8_t buf[64];
	uint32_t buf_len;
	uint32_t full_len;
};

void sha256Init(SHA256_State * state);
void sha256Update(SHA256_State * state, const uint8_t * input, uint32_t length);
void sha256Finish(SHA256_State * state, uint32_t result[8]);

// SHA512 implementation

struct SHA512_State
{
	uint64_t sha512state[8];
	uint8_t buf[128];
	uint32_t buf_len;
	uint32_t full_len;
};

void sha512Init(SHA512_State * state);
void sha512Update(SHA512_State * state, const uint8_t * input, uint32_t length);
void sha512Finish(SHA512_State * state, uint32_t result[16]);

// SHA384 imlementation
void sha384Init(SHA512_State * state);
void sha384Finish(SHA512_State * state, uint32_t result[12]);

// HMAC with MD5
void HmacMd5(uint32_t result[4],const uint32_t key[16], const uint8_t * data, uint32_t length);


// HMAC with MD5 for long messages

struct HMACMD5_State
{
	MD5_State md5State;
	uint32_t key[16];
};

void HmacMd5_Init(HMACMD5_State * state, const uint32_t key[16]);
void HmacMd5_Update(HMACMD5_State * state, const uint8_t * data, uint32_t length);
void HmacMd5_Finish(HMACMD5_State * state, uint32_t result[4]);
void HmacMd5_Reset(HMACMD5_State * state, const HMACMD5_State * from);

struct HMACSHA1_State
{
	SHA1_State sha1State;
	uint32_t key[16];
};

void HmacSha1(uint32_t result[5],const uint32_t key[16], const uint8_t * data, uint32_t length);
void HmacSha1_Init(HMACSHA1_State * state, const uint32_t key[16]);
void HmacSha1_Update(HMACSHA1_State * state, const uint8_t * data, uint32_t length);
void HmacSha1_Finish(HMACSHA1_State * state, uint32_t result[5]);
void HmacSha1_Reset(HMACSHA1_State * state, const HMACSHA1_State * from);

struct HMACSHA256_State
{
	SHA256_State state;
	uint32_t key[16];
};

void HmacSha256(uint32_t result[8],const uint32_t key[16], const uint8_t * data, uint32_t length);
void HmacSha256_Init(HMACSHA256_State * state, const uint32_t key[16]);
void HmacSha256_Update(HMACSHA256_State * state, const uint8_t * data, uint32_t length);
void HmacSha256_Finish(HMACSHA256_State * state, uint32_t result[8]);
void HmacSha256_Reset(HMACSHA256_State * state, const HMACSHA256_State * from);

#endif