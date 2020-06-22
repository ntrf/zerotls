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

/* PKCS1.CPP
 * Cryptographic primitives for RSA cryptosystem (PKCS #1)
 *  - RSAES-PKCS1-v1_5 encryption
 *  - RSASSA-PKCS1-v1_5 signature verification
 *  - RSASSA-PKCS1-v1_5 signature generation
 * Notice: current implementation only supports public exponents no 
 * larger than 2^{32} - 1
 */

//#define TEST_MODULE
//#define TEST_MODULE2

#include <string.h>
#include <stdint.h>

//#include "../internal.h"
#include "../context.h"
#include "../tls.h"

#include "../hash/hash.h"
#include "../signature.h"

#include "bigint.h"

#include "pkcs1.h"

/* Encryption */

void EncryptRSA(uint8_t * pfrKey, uint8_t * out, unsigned int size, const PKCS1_RSA_PublicKey & Key, const uint8_t * data, unsigned length)
{
	unsigned char * buf = out;

	unsigned int seedsize = size - 3 - length;

	buf[0] = 0;
	buf[1] = 2;
	buf[2 + seedsize] = 0;

	PrfGenBlock_v1_2(buf + 2, seedsize, pfrKey, 32, "rsapad", data, length);
	for (unsigned int x = 0; x < seedsize; ++x) {
		if (buf[2 + x] == 0) buf[2 + x] = 0xFF;
	}

	memcpy(buf+3+seedsize, data, length);

	{
		unsigned exponent = 0;

		if (Key.exponent.length <= sizeof(unsigned)) { // BAD
			unsigned l = 0;
			for (; l < Key.exponent.length; ++l) {
				exponent = (exponent << 8) + Key.exponent.data[l];
			}
		}

		//### this is a mess
		uint32_t * datablock = (uint32_t*)align(out + size + 31, 16);

		MontgomeryReductionContext mr_ctx;
		mr_ctx.Prepare(datablock, Key.modulus.data, Key.modulus.length, size / 4, true);
		mr_ctx.ExpMod_Fnum((uint32_t *)out, (const uint32_t *)buf, exponent, true);
	}
}

/* Signature verification */
#if 0
#define OID_2B(x) (0x80 | ((X) >> 7)), (x & 127)
#define OID_3B(x) (0x80 | ((X) >> 14)), (0x80 | ((X) >> 7) & 127), (x & 127)

#define ASN_NULL 0x05, 0x00
#define ASN_SEQUENCE(L) 0x30, (L)
#define ASN_OID(L) 0x06, (L)
#define ASN_OCTETSTRING(L) 0x04, (L)


// See: https://tools.ietf.org/html/rfc3447#page-53
static const uint8_t pkcs1[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1};

static const uint8_t rsaMd5DigestInfo[34-16] = {
	ASN_SEQUENCE(32), 
	ASN_SEQUENCE(12), 
	ASN_OID(8), 
	(40 + 2), 0x86, 0x48, 0x86, 0xF7, 0x0D, 2, 5, 
	ASN_NULL,
	ASN_OCTETSTRING(16)
};
static const uint8_t rsaSha1DigestInfo[35 - 20] = {
	ASN_SEQUENCE(33), 
	ASN_SEQUENCE(9), 
	ASN_OID(5), 
	(40 + 3), 14, 3, 2, 26, 
	ASN_NULL,
	ASN_OCTETSTRING(20)
};
static const uint8_t rsaSha256DigestInfo[51 - 32] = {
	ASN_SEQUENCE(49),
	ASN_SEQUENCE(13), 
	ASN_OID(9), 
	(80 + 16), 0x86, 0x48, 1, 101, 3, 4, 2, 1, 
	ASN_NULL,
	ASN_OCTETSTRING(32)
};
static const uint8_t rsaSha384DigestInfo[67 - 48] = {
	ASN_SEQUENCE(65),
	ASN_SEQUENCE(13),
	ASN_OID(9),
	(80 + 16), 0x86, 0x48, 1, 101, 3, 4, 2, 2,
	ASN_NULL,
	ASN_OCTETSTRING(48)
};
static const uint8_t rsaSha512DigestInfo[83 - 64] = {
	ASN_SEQUENCE(81),
	ASN_SEQUENCE(13),
	ASN_OID(9),
	(80 + 16), 0x86, 0x48, 1, 101, 3, 4, 2, 3,
	ASN_NULL,
	ASN_OCTETSTRING(64)
};

int VerifyRSASignatureHash(ztlsContext * ctx, const BinarySlice & signature, unsigned int size, const PKCS1_RSA_PublicKey & Key, int sigtype, const uint32_t * hash)
{
	unsigned N = 0;

	if (sigtype == PKCS1_SSA_TLSVERIFY) {
		N = size - 16 - 20 - 1;
	} else if (sigtype == PKCS1_SSA_MD5) {
		N = size - sizeof(rsaMd5DigestInfo)-16 - 1;
	} else if (sigtype == PKCS1_SSA_SHA1) {
		N = size - sizeof(rsaSha1DigestInfo)-20 - 1;
	} else if (sigtype == PKCS1_SSA_SHA256) {
		N = size - sizeof(rsaSha256DigestInfo)-32 - 1;
	} else if (sigtype == PKCS1_SSA_SHA384) {
		N = size - sizeof(rsaSha384DigestInfo)-48 - 1;
	} else if (sigtype == PKCS1_SSA_SHA512) {
		N = size - sizeof(rsaSha512DigestInfo)-64 - 1;
	} else {
		return -1;
	}

	//unsigned char * buf = new unsigned char[size];
	Binary buf;

	int valid = 0;
	{
		unsigned exponent = 0;

		if (Key.exponent.length <= sizeof(unsigned)) { // BAD
			unsigned l = 0;
			for (; l < Key.exponent.length; ++l) {
				exponent = (exponent << 8) + Key.exponent.data[l];
			}
		}

		buf.alloc(size);

		ctx->Prepare(Key.modulus.data, Key.modulus.length, size / 4, true);
		ctx->ExpMod_Fnum((uint32_t *)buf.data, (const uint32_t *)signature.data, exponent, true);
	}

	if (buf[0] != 0 || buf[1] != 1) {
		return 0;
	}

	// bytes 2 .. N-1 are full of FF
	// byte N == 0
	// bytes N+1 .. size-1 equal to prefix
	// notice: this design protects against timing attacks
	int y = 0xFF;
	for (unsigned i = 2; i < N; ++i) y &= buf[i];
	if (y != 0xFF) {
		return 0;
	}

	if (buf[N] != 0x00) {
		return 0;
	}

	++N;

	if (sigtype == PKCS1_SSA_TLSVERIFY) {
		// special case for TLS CertificateVerify
		valid = (memcmp(buf.data + N, hash, sizeof(uint32_t) * 9) == 0) ? 1 : 0;
	} else if (sigtype == PKCS1_SSA_MD5) {
		if (memcmp(buf.data + N, rsaMd5DigestInfo, sizeof(rsaMd5DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaMd5DigestInfo);

		valid = (memcmp(buf.data + N, hash, sizeof(uint32_t) * 4) == 0) ? 1 : 0;
	} else if (sigtype == PKCS1_SSA_SHA1) {
		if (memcmp(buf.data + N, rsaSha1DigestInfo, sizeof(rsaSha1DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaSha1DigestInfo);

		valid = (memcmp(buf.data + N, hash, sizeof(uint32_t) * 5) == 0) ? 1 : 0;
	} else if (sigtype == PKCS1_SSA_SHA256) {
		if (memcmp(buf.data + N, rsaSha256DigestInfo, sizeof(rsaSha256DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaSha256DigestInfo);
		
		valid = (memcmp(buf.data + N, hash, sizeof(uint32_t) * 8) == 0) ? 1 : 0;
	} else if (sigtype == PKCS1_SSA_SHA384) {
		if (memcmp(buf.data + N, rsaSha384DigestInfo, sizeof(rsaSha384DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaSha384DigestInfo);

		valid = (memcmp(buf.data + N, hash, sizeof(uint32_t) * 12) == 0) ? 1 : 0;
	} else if (sigtype == PKCS1_SSA_SHA512) {
		if (memcmp(buf.data + N, rsaSha512DigestInfo, sizeof(rsaSha512DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaSha512DigestInfo);

		valid = (memcmp(buf.data + N, hash, sizeof(uint32_t) * 16) == 0) ? 1 : 0;
	}

	return valid;
}

int VerifyRSASignature(ztlsContext * ctx, const BinarySlice & signature, unsigned int size, const PKCS1_RSA_PublicKey & Key, int sigtype, const uint8_t * data, unsigned length)
{
	uint32_t hash[16];
	size_t hash_size = ComputeSignatureHash(sigtype, data, length, hash);
	if (hash_size == 0) {
		return -1;
	}

	return VerifyRSASignatureHash(ctx, signature, size, Key, sigtype, hash);
}
#endif

#if 0
// Sign message with RSA-
int GenerateRSASignatureHash(struct MontgomeryReductionContext * ctx, Binary & signature, unsigned int size, const PKCS1_RSA_PrivateKey & Key, int sigtype, const uint32_t * hash)
{
	unsigned N = 0;

	if (sigtype == PKCS1_SSA_TLSVERIFY) {
		N = size - 20 - 16 - 1;
	} else if (sigtype == PKCS1_SSA_MD5) {
		N = size - sizeof(rsaMd5DigestInfo)-16 - 1;
	} else if (sigtype == PKCS1_SSA_SHA1) {
		N = size - sizeof(rsaSha1DigestInfo)-20 - 1;
	} else if (sigtype == PKCS1_SSA_SHA256) {
		N = size - sizeof(rsaSha256DigestInfo)-32 - 1;
	} else if (sigtype == PKCS1_SSA_SHA384) {
		N = size - sizeof(rsaSha384DigestInfo)-48 - 1;
	} else if (sigtype == PKCS1_SSA_SHA512) {
		N = size - sizeof(rsaSha512DigestInfo)-64 - 1;
	} else {
		return -1;
	}

	if (N < 3) return -1;

	Binary buf;
	buf.alloc(size);
	signature.alloc(size);

	// build mandatory part of signature
	buf[0] = 0;
	buf[1] = 1;
	memset(buf.data + 2, 0xFF, N - 2);
	buf[N] = 0;
	
	++N;
	if (sigtype == PKCS1_SSA_TLSVERIFY) {
		// special case for TLS CertificateVerify
		memcpy(buf.data + N, hash, sizeof(uint32_t) * 9);
	} else if (sigtype == PKCS1_SSA_MD5) {
		memcpy(buf.data + N, rsaMd5DigestInfo, sizeof(rsaMd5DigestInfo));
		N += sizeof(rsaMd5DigestInfo);
		memcpy(buf.data + N, hash, sizeof(uint32_t) * 4);
	} else if (sigtype == PKCS1_SSA_SHA1) {
		memcpy(buf.data + N, rsaSha1DigestInfo, sizeof(rsaSha1DigestInfo));
		N += sizeof(rsaSha1DigestInfo);
		memcpy(buf.data + N, hash, sizeof(uint32_t) * 5);
	} else if (sigtype == PKCS1_SSA_SHA256) {
		memcpy(buf.data + N, rsaSha256DigestInfo, sizeof(rsaSha256DigestInfo));
		N += sizeof(rsaSha256DigestInfo);
		memcpy(buf.data + N, hash, sizeof(uint32_t) * 8);
	} else if (sigtype == PKCS1_SSA_SHA384) {
		memcpy(buf.data + N, rsaSha384DigestInfo, sizeof(rsaSha384DigestInfo));
		N += sizeof(rsaSha384DigestInfo);
		memcpy(buf.data + N, hash, sizeof(uint32_t) * 12);
	} else if (sigtype == PKCS1_SSA_SHA512) {
		memcpy(buf.data + N, rsaSha512DigestInfo, sizeof(rsaSha512DigestInfo));
		N += sizeof(rsaSha512DigestInfo);
		memcpy(buf.data + N, hash, sizeof(uint32_t) * 16);
	} else {
		return -1;
	}

	// ### workaround this limitation
	if ((Key.priv_exp.length & 3) != 0)
		return -1;

	ctx->Prepare(Key.modulus.data, Key.modulus.length, size / 4, true);
	ctx->ExpMod((uint32_t *)signature.data, (const uint32_t *)buf.data, (const uint32_t*)Key.priv_exp.data, Key.priv_exp.length / 4, true);
	return 1;
}

int GenerateRSASignature(struct MontgomeryReductionContext * ctx, Binary & signature, unsigned int size, const PKCS1_RSA_PrivateKey & Key, int sigtype, const uint8_t * data, unsigned length)
{
	uint32_t hash[16];
	size_t hash_size = ComputeRSASignatureHash(sigtype, data, length, hash);
	if (hash_size == 0) {
		return -1;
	}

	return GenerateRSASignatureHash(ctx, signature, size, Key, sigtype, hash);
}
#endif

#if TEST_MODULE
#include <stdio.h>

unsigned char Modulus[] = {
	0xa8, 0xb3, 0xb2, 0x84, 0xaf, 0x8e, 0xb5, 0x0b, 0x38, 0x70, 0x34, 0xa8, 0x60, 0xf1, 0x46, 0xc4, 
	0x91, 0x9f, 0x31, 0x87, 0x63, 0xcd, 0x6c, 0x55, 0x98, 0xc8, 0xae, 0x48, 0x11, 0xa1, 0xe0, 0xab, 
	0xc4, 0xc7, 0xe0, 0xb0, 0x82, 0xd6, 0x93, 0xa5, 0xe7, 0xfc, 0xed, 0x67, 0x5c, 0xf4, 0x66, 0x85, 
	0x12, 0x77, 0x2c, 0x0c, 0xbc, 0x64, 0xa7, 0x42, 0xc6, 0xc6, 0x30, 0xf5, 0x33, 0xc8, 0xcc, 0x72, 
	0xf6, 0x2a, 0xe8, 0x33, 0xc4, 0x0b, 0xf2, 0x58, 0x42, 0xe9, 0x84, 0xbb, 0x78, 0xbd, 0xbf, 0x97, 
	0xc0, 0x10, 0x7d, 0x55, 0xbd, 0xb6, 0x62, 0xf5, 0xc4, 0xe0, 0xfa, 0xb9, 0x84, 0x5c, 0xb5, 0x14, 
	0x8e, 0xf7, 0x39, 0x2d, 0xd3, 0xaa, 0xff, 0x93, 0xae, 0x1e, 0x6b, 0x66, 0x7b, 0xb3, 0xd4, 0x24, 
	0x76, 0x16, 0xd4, 0xf5, 0xba, 0x10, 0xd4, 0xcf, 0xd2, 0x26, 0xde, 0x88, 0xd3, 0x9f, 0x16, 0xfb 
};

unsigned Exponent = 65537;

unsigned char Message[] = {
	0x75, 0x0c, 0x40, 0x47, 0xf5, 0x47, 0xe8, 0xe4, 0x14, 0x11, 0x85, 0x65, 0x23, 0x29, 0x8a, 0xc9, 
	0xba, 0xe2, 0x45, 0xef, 0xaf, 0x13, 0x97, 0xfb, 0xe5, 0x6f, 0x9d, 0xd5 
};

unsigned char Seed[] = {
	0xac, 0x47, 0x28, 0xa8, 0x42, 0x8c, 0x1e, 0x52, 0x24, 0x71, 0xa8, 0xdf, 0x73, 0x5a, 0x8e, 0x92,
	0x92, 0xaf, 0x0d, 0x55, 0xbc, 0xb7, 0x3a, 0x12, 0xac, 0x32, 0xc2, 0x64, 0xf3, 0x88, 0x1c, 0x7c,
	0x8a, 0x71, 0x0f, 0x70, 0xfe, 0xb1, 0x04, 0x85, 0xc8, 0x37, 0x0f, 0x78, 0x1f, 0xff, 0xd0, 0x21,
	0x81, 0x6f, 0x05, 0x87, 0x39, 0x76, 0x6d, 0xa0, 0xa9, 0xc9, 0xdb, 0x0e, 0xae, 0x7e, 0x9a, 0x25,
	0xb6, 0xc4, 0x33, 0x18, 0xd0, 0xca, 0xac, 0x23, 0x65, 0x22, 0xca, 0x31, 0x0f, 0x17, 0xfc, 0x52,
	0xad, 0x42, 0x29, 0xc8, 0x3a, 0x24, 0xe9, 0xe5, 0x45, 0xeb, 0x35, 0xe9, 0x82, 0x6d, 0x55, 0x9f,
	0x57
};

unsigned char Result[] = {
	0x68, 0x42, 0xe5, 0xe2, 0xcc, 0x00, 0x41, 0xd6, 0xb0, 0xc8, 0x1a, 0x56, 0x2c, 0x39, 0xa6, 0x17,
	0x37, 0x9a, 0x51, 0x5c, 0xab, 0x74, 0xab, 0xcb, 0x26, 0x19, 0xc7, 0x74, 0x0a, 0x54, 0x1d, 0x95,
	0x55, 0xdd, 0x91, 0x65, 0x97, 0x5b, 0xf8, 0xa3, 0xeb, 0xd0, 0xd0, 0x45, 0x66, 0x61, 0xdf, 0xb1,
	0xa6, 0x86, 0x1b, 0xa2, 0x33, 0x22, 0x69, 0x93, 0x0e, 0x0d, 0xb5, 0x14, 0xfc, 0xa0, 0x73, 0x3e,
	0xeb, 0x9c, 0x40, 0x57, 0x13, 0xeb, 0x1f, 0x9d, 0x76, 0x80, 0x33, 0xed, 0x29, 0x3e, 0x1e, 0x08,
	0x1a, 0x12, 0x5f, 0x32, 0xdd, 0xb9, 0xea, 0x52, 0xed, 0xbe, 0x27, 0x5c, 0x4a, 0xf6, 0x0f, 0x8a,
	0x7b, 0xf8, 0x32, 0xbd, 0x22, 0x75, 0x61, 0xc2, 0x08, 0xdc, 0x00, 0x31, 0xa8, 0x4b, 0x50, 0x12,
	0xc9, 0xdd, 0x9f, 0x74, 0x45, 0x9d, 0xcb, 0x07, 0x0b, 0xdb, 0xe1, 0x3c, 0xfa, 0x8c, 0x2d, 0x50,
};

extern void PrintHex(const unsigned char *buf, unsigned int size, int shift);

int main()
{
	unsigned char buf[128];

	buf[0] = 0;
	buf[1] = 2;
	memcpy(buf + 2, Seed, 128 - 3 - sizeof(Message));
	buf[128 - 1 - sizeof(Message)] = 0;
	memcpy(buf + 128 - sizeof(Message), Message, sizeof(Message));

	MontgomeryReductionContext mr_ctx;
	mr_ctx.Prepare(Modulus, 128, 128 / 4, true);
	mr_ctx.ExpMod_Fnum((uint32_t *)buf, (const uint32_t *)buf, Exponent, true);

	bool match = memcmp(buf, Result, 128) == 0;
	
	PrintHex(buf, 128, 0);
	printf("%s\n", match ? "Match" : "!!!! Mismatch  !!!!");

	return match ? 0 : -1;
}

#endif

#ifdef TEST_MODULE2
#include <stdio.h>

const uint8_t Modulus[128] = {
	0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17, 0x58, 0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41, 0xd1,
	0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52, 0xa4, 0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9, 0x91,
	0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1, 0x62, 0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88, 0xa3,
	0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91, 0xcb, 0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1, 0xdf,
	0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b, 0x2b, 0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63, 0x77,
	0xc0, 0x92, 0x1c, 0xb2, 0x3c, 0x27, 0x0a, 0x70, 0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19, 0xf1,
	0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35, 0xf2, 0x92, 0x80, 0xe1, 0x38, 0x6b, 0x6f, 0x64, 0xc4,
	0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c, 0xe8, 0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21, 0x37,
};

const uint8_t PublicExponent[3] = { 1, 0, 1 };

const uint8_t PrivateExponent[128] = {
	0x33, 0xa5, 0x04, 0x2a, 0x90, 0xb2, 0x7d, 0x4f, 0x54, 0x51, 0xca, 0x9b, 0xbb, 0xd0, 0xb4, 0x47,
	0x71, 0xa1, 0x01, 0xaf, 0x88, 0x43, 0x40, 0xae, 0xf9, 0x88, 0x5f, 0x2a, 0x4b, 0xbe, 0x92, 0xe8,
	0x94, 0xa7, 0x24, 0xac, 0x3c, 0x56, 0x8c, 0x8f, 0x97, 0x85, 0x3a, 0xd0, 0x7c, 0x02, 0x66, 0xc8,
	0xc6, 0xa3, 0xca, 0x09, 0x29, 0xf1, 0xe8, 0xf1, 0x12, 0x31, 0x88, 0x44, 0x29, 0xfc, 0x4d, 0x9a,
	0xe5, 0x5f, 0xee, 0x89, 0x6a, 0x10, 0xce, 0x70, 0x7c, 0x3e, 0xd7, 0xe7, 0x34, 0xe4, 0x47, 0x27,
	0xa3, 0x95, 0x74, 0x50, 0x1a, 0x53, 0x26, 0x83, 0x10, 0x9c, 0x2a, 0xba, 0xca, 0xba, 0x28, 0x3c,
	0x31, 0xb4, 0xbd, 0x2f, 0x53, 0xc3, 0xee, 0x37, 0xe3, 0x52, 0xce, 0xe3, 0x4f, 0x9e, 0x50, 0x3b,
	0xd8, 0x0c, 0x06, 0x22, 0xad, 0x79, 0xc6, 0xdc, 0xee, 0x88, 0x35, 0x47, 0xc6, 0xa3, 0xb3, 0x25,
};

const char Message[] = "Test message";

int main()
{
	MontgomeryReductionContext mrctx;

	Binary signature;
	Binary mod;
	Binary pub;
	Binary priv;

	mod.alloc(128); memcpy(mod.data, Modulus, 128);
	pub.alloc(3); memcpy(pub.data, PublicExponent, 3);
	priv.alloc(128); memcpy(priv.data, PrivateExponent, 128);

	GenerateRSASignature(&mrctx, signature, 128, mod, priv, PKCS1_SSA_SHA1, (const uint8_t *)Message, sizeof(Message));

	PrintHex(signature.data, signature.length, 0);
	int ver = VerifyRSASignature(&mrctx, signature, 128, mod, pub, PKCS1_SSA_SHA1, (const uint8_t *)Message, sizeof(Message));

	printf("%s\n", (ver == 1) ? "VERIFIED" : "NOT VERIFIED");

	return (ver == 1) ? 0 : -1;
}

#endif