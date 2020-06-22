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
#include <stdint.h>

#include "hash/hash.h"

#include "signature.h"

// See: https://tools.ietf.org/html/rfc3447#page-53
static const uint8_t pkcs1[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1};

// Source: PKCS #1: RSA Cryptography Specifications
// See: https://tools.ietf.org/html/rfc3447#page-51
int GetSignatureAlgorithmType(const uint8_t * oid, uint32_t length)
{
	if ((length == sizeof(pkcs1) + 1) && (memcmp(oid, pkcs1, sizeof(pkcs1)) == 0)) {
		oid += sizeof(pkcs1);
		if (*oid == 1) { // Encryption
			return PKCS1_RSAES;
		} else if (*oid == 4) { // MD5
			return PKCS1_SSA_MD5;
		} else if (*oid == 5) { // SHA1
			return PKCS1_SSA_SHA1;
		} else if (*oid == 11) { // SHA256
			return PKCS1_SSA_SHA256;
		} else if (*oid == 12) { //SHA384
			return PKCS1_SSA_SHA384;
		} else if (*oid == 13) { //SHA512
			return PKCS1_SSA_SHA512;
		}
		//NOTICE: there is not sense in supporting MD2 hashing algorithm
	}
	return SIGTYPE_UNKNOWN;
}

int GetSignatureSize(int sigtype)
{
	switch (sigtype) {
		case PKCS1_SSA_SHA1: return 20;
		case PKCS1_SSA_SHA256: return 32;
		case PKCS1_SSA_SHA384: return 48;
		case PKCS1_SSA_SHA512: return 64;
		default: return 0;
	}
}

int ComputeSignatureHash(int sigtype, const uint8_t * data, unsigned length, uint32_t * hash)
{
	if (sigtype == PKCS1_SSA_MD5) {
		if (hash) {
			MD5_State state;
			md5Init(&state);
			md5Update(&state, data, length);
			md5Finish(&state, hash);
		}
		return 4;
	} else if (sigtype == PKCS1_SSA_SHA1) {
		if (hash) {
			SHA1_State state;
			sha1Init(&state);
			sha1Update(&state, data, length);
			sha1Finish(&state, hash);
		}
		return 5;
	} else if (sigtype == PKCS1_SSA_SHA256) {
		if (hash) {
			SHA256_State state;
			sha256Init(&state);
			sha256Update(&state, data, length);
			sha256Finish(&state, hash);
		}
		return 8;
	} else if (sigtype == PKCS1_SSA_SHA384) {
		if (hash) {
			SHA512_State state;
			sha384Init(&state);
			sha512Update(&state, data, length);
			sha384Finish(&state, hash);
		}
		return 12;
	} else if (sigtype == PKCS1_SSA_SHA512) {
		if (hash) {
			SHA512_State state;
			sha512Init(&state);
			sha512Update(&state, data, length);
			sha512Finish(&state, hash);
		}
		return 16;
	} else {
		return 0;
	}
}