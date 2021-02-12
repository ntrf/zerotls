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

#include <stdint.h>
#include <string.h>

#include "intutils.h"
#include "simd_ssse3.h"

#include <wmmintrin.h>
#include "gcm/ghash_cmul2.h"

#include "aes128_gcm.h"

extern void PrintHex(const unsigned char *buf, unsigned int size, int shift);

// TLS_RSA_WITH_AES_128_GCM_SHA256
// Only works on Intel processors, but it's entirely safe

AES128_GCM::AES128_GCM()
	: seq_num_low(0), seq_num_high(0)
{
}

void AES128_GCM::InitEnc(uint8_t * aeskey, uint8_t * aesIV)
{
	uint32_t key[8];
	memcpy(key, aeskey, sizeof(key));

	uint8_t zero[16] = { 0 };

	rijndaelSetupEncrypt(encRk, (uint32_t*)key, 128);
	rijndaelEncrypt(encRk, 10, zero, (uint8_t *)macKey);

	// This will pre-multiply the key
	ghashProcessBase(macKey);

	IV[0] = *(uint32_t*)aesIV;

	seq_num_low = 0;
	seq_num_high = 0;
}

int32_t AES128_GCM::WrapPacket(uint8_t * output, uint8_t type, const uint8_t * data, unsigned length)
{
	uint32_t nonce[4];
	nonce[0] = IV[0];
	nonce[1] = seq_num_low;
	nonce[2] = seq_num_high;

	uint32_t ciphertext[4];

	// copy the "IV"
	// i'm just abusing the serial number
	memcpy(output, nonce + 1, sizeof(uint32_t) * 2);

	uint32_t * outWordPtr = (uint32_t*)(output + 8);
	uint32_t * ptWordPtr = (uint32_t *)data;

	// number of full blocks
	size_t lenBlocks = length >> 4;

	__m128i hvalue = simd_load(macKey);
	__m128i xvalue = simd_zero();

	{
		__m128i ad = _mm_set_epi32(
			seq_num_high, seq_num_low,
			(type << 24) | 0x00030300 | ((length >> 8) & 0xFF), 
			(length << 24));

#if _DEBUG
//		simd_storeBE(ad, (uint8_t*)ciphertext);
//		PrintHex((const uint8_t*)ciphertext, 16, 0);
#endif

		xvalue = _mm_xor_si128(xvalue, ad);
		xvalue = ghashCmul(xvalue, hvalue);
	}

	size_t index = 2;

	// start by encrypting the first block
	for (; lenBlocks; --lenBlocks, ++index) {
		// encrypt the block
		nonce[3] = bswap32(index);
		rijndaelEncrypt(encRk, AES_NROUNDS(128), (const uint8_t *)nonce, (uint8_t *)ciphertext);

		// generate the ciphertext
		*outWordPtr++ = *ptWordPtr++ ^ ciphertext[0];
		*outWordPtr++ = *ptWordPtr++ ^ ciphertext[1];
		*outWordPtr++ = *ptWordPtr++ ^ ciphertext[2];
		*outWordPtr++ = *ptWordPtr++ ^ ciphertext[3];

		// calculate hash
		xvalue = simd_xorBytesBE(xvalue, outWordPtr - 4);
		xvalue = ghashCmul(xvalue, hvalue);
	}

	// process the last block
	size_t last = length & (16 - 1);
	if (!!last) {
		nonce[3] = bswap32(index);
		rijndaelEncrypt(encRk, AES_NROUNDS(128), (const uint8_t *)nonce, (uint8_t *)ciphertext);

		uint8_t * outBytePtr = (uint8_t*)outWordPtr;
		uint8_t * ptBytePtr = (uint8_t*)ptWordPtr;
		for (size_t i = 0; i < last; ++i) {
			*outBytePtr++ = *ptBytePtr++ ^ ((uint8_t*)ciphertext)[i];
		}
	}

	// tag whitenning value
	nonce[3] = bswap32(1);
	rijndaelEncrypt(encRk, AES_NROUNDS(128), (const uint8_t *)nonce, (uint8_t *)ciphertext);

	{
		__m128i lenHash = _mm_set_epi32(0, 13 << 3, 0, length << 3);
		xvalue = _mm_xor_si128(xvalue, lenHash);
		xvalue = ghashCmul(xvalue, hvalue);
	}

	xvalue = simd_xorBytesBE(xvalue, ciphertext);

	simd_storeBE(xvalue, output + 8 + length);

	seq_num_low += 1;
	if (seq_num_low == 0) seq_num_high += 1;

	return length + 8 + 16;
}

int32_t AES128_GCM::UnWrapPacket(uint8_t * output, uint8_t type, const uint8_t * data, unsigned length)
{
	// MUST have at least IV + tag
	if (length < 16 + 8)
		return -1;

	size_t plainLen = length - 8 - 16;

	uint32_t nonce[4];
	nonce[0] = IV[0];
	nonce[1] = ((uint32_t*)data)[0];
	nonce[2] = ((uint32_t*)data)[1];

	uint32_t ciphertext[4];

	// Veryify the GHash first, then decrypt
	__m128i hvalue = simd_load(macKey);
	__m128i xvalue = simd_zero();

	{
		__m128i ad = _mm_set_epi32(
			seq_num_high, seq_num_low,
			(type << 24) | 0x00030300 | ((plainLen >> 8) & 0xFF),
			(plainLen << 24));

		xvalue = _mm_xor_si128(xvalue, ad);
		xvalue = ghashCmul(xvalue, hvalue);
	}

	uint32_t * cipPtr = (uint32_t*)(data + 8);
	uint32_t * ptPtr = (uint32_t*)output;

	// process full blocks
	uint32_t index = 2;
	for (size_t lenBlocks = plainLen >> 4; lenBlocks > 0; --lenBlocks, ++index) {
		nonce[3] = bswap32(index);
		rijndaelEncrypt(encRk, AES_NROUNDS(128), (const uint8_t *)nonce, (uint8_t *)ciphertext);

		xvalue = simd_xorBytesBE(xvalue, cipPtr);
		xvalue = ghashCmul(xvalue, hvalue);

		*ptPtr++ = cipPtr[0] ^ ciphertext[0];
		*ptPtr++ = cipPtr[1] ^ ciphertext[1];
		*ptPtr++ = cipPtr[2] ^ ciphertext[2];
		*ptPtr++ = cipPtr[3] ^ ciphertext[3];

		cipPtr += 4;
	}

	// process last block
	size_t last = plainLen & 15;
	if (!!last)
	{
		nonce[3] = bswap32(index);
		rijndaelEncrypt(encRk, AES_NROUNDS(128), (const uint8_t *)nonce, (uint8_t *)ciphertext);

#if 1
		//### This is cheating, but there is a block of 16 bytes immediately following 
		//    the ciphertext, so we won't fly out of bounds. As for inputs, they should
		//    be ready to accept 16 bytes of lead.
		ptPtr[0] = cipPtr[0] ^ ciphertext[0];
		ptPtr[1] = cipPtr[1] ^ ciphertext[1];
		ptPtr[2] = cipPtr[2] ^ ciphertext[2];
		ptPtr[3] = cipPtr[3] ^ ciphertext[3];
#else
		{
			uint8_t * ptBytePtr = (uint8_t *)ptPtr;
			uint8_t * cipBytePtr = (uint8_t *)cipPtr;
			for (size_t i = 0; i < last; ++i) {
				*ptBytePtr++ = *cipBytePtr++ ^ ((uint8_t*)ciphertext)[i];
			}
		}
#endif
		{
			ciphertext[0] = ciphertext[1] = ciphertext[2] = ciphertext[3] = 0;
			uint8_t * tmpPtr = (uint8_t *)ciphertext;
			uint8_t * cipBytePtr = (uint8_t *)cipPtr;
			for (size_t i = 0; i < last; ++i) {
				*tmpPtr++ = *cipBytePtr++;
			}

			xvalue = simd_xorBytesBE(xvalue, ciphertext);
			xvalue = ghashCmul(xvalue, hvalue);
		}
	}

	nonce[3] = bswap32(1);
	rijndaelEncrypt(encRk, AES_NROUNDS(128), (const uint8_t *)nonce, (uint8_t *)ciphertext);

	{
		__m128i lenHash = _mm_set_epi32(0, 13 << 3, 0, plainLen << 3);
		xvalue = _mm_xor_si128(xvalue, lenHash);
		xvalue = ghashCmul(xvalue, hvalue);
	}

	xvalue = simd_xorBytesBE(xvalue, ciphertext);
	simd_storeBE(xvalue, (uint8_t*)ciphertext);

	{
		uint32_t * tag = (uint32_t*)(data + length - 16);
		uint32_t v = (tag[0] ^ ciphertext[0]) | (tag[1] ^ ciphertext[1]) | 
			(tag[2] ^ ciphertext[2]) | (tag[3] ^ ciphertext[3]);
		if (v != 0)
			return -1;
	}

	seq_num_low += 1;
	if (seq_num_low == 0) seq_num_high += 1;

	return plainLen;
}

#if 0

// Gathered with wireshark between Nginx and Firefox

uint8_t key_seed[] = {
	0x53, 0x81, 0xc7, 0x52, 0xd9, 0x3c, 0xbe, 0xe6,
	0x10, 0xb7, 0x6c, 0xc2, 0xa9, 0xb7, 0x77, 0x45,
	0xa6, 0x57, 0xb4, 0x8a, 0xfb, 0x24, 0x5d, 0xdb,
	0x11, 0xc1, 0xf8, 0xaf, 0x72, 0xed, 0x99, 0x70,
	0xa3, 0x2e, 0x2a, 0x09, 0x1e, 0x6f, 0x38, 0x62,
	0xec, 0x53, 0x4e, 0x7f, 0xd2, 0xd2, 0x59, 0xab,
	0xcd, 0x93, 0x67, 0x9a, 0x93, 0x1c, 0x51, 0x98,
	0x83, 0xc1, 0xb0, 0xd0, 0xe5, 0x1d, 0xf1, 0xe0
};

uint8_t master_secret[] = {
	0xfd, 0x00, 0xb1, 0x26, 0xb8, 0x0c, 0xfb, 0xe8,
	0x61, 0x9f, 0x40, 0x2f, 0x4d, 0x2e, 0xd8, 0x0d,
	0x54, 0xd0, 0xcc, 0xef, 0x50, 0x85, 0x23, 0xcd,

	0x5f, 0x43, 0x23, 0x16, 0x8f, 0xa5, 0x74, 0xda,
	0x8f, 0x45, 0x42, 0x63, 0xd2, 0x46, 0x9f, 0x10,
	0xfa, 0x8b, 0x6f, 0x6b, 0x39, 0xf0, 0xc1, 0x59
};

uint8_t verifyKeys[] = {
	0xfd, 0xf9, 0x8c, 0xe8, 0x84, 0xb2, 0xd5, 0xf3,
	0xd2, 0x4f, 0x23, 0x5c, 0xf6, 0xb0, 0x39, 0xc1,
	0xe2, 0xf0, 0xdd, 0x5e, 0x30, 0x5e, 0x13, 0xe9,
	0x75, 0x3b, 0x6d, 0x26, 0x0e, 0xe4, 0xfb, 0x47,
	0xe3, 0x99, 0xc7, 0x8b, 0x56, 0x56, 0xdb, 0x97,
	0xa8, 0x58, 0x3f, 0x24, 0x5f, 0x84, 0x17, 0xc1,
	0x16, 0x5f, 0xc5, 0xd8, 0x64, 0x4d, 0xcd, 0x62,
	0x8f, 0x84, 0xaf, 0x7d, 0xd4, 0x1d, 0x1a, 0xed,
	0xc0, 0x9b, 0x22, 0x38, 0xae, 0x74, 0x52, 0x18,
	0x59, 0x08, 0x9d, 0x49, 0xf7, 0xea, 0xc9, 0xa8,
	0x14, 0xdf, 0x26, 0x99, 0xbd, 0x05, 0xf9, 0x18,
	0xda, 0x85, 0xdc, 0x06, 0x55, 0xa4, 0x05, 0x80,
	0x8d, 0x97, 0x6c, 0x2b, 0x2c, 0x76, 0xfc, 0x59,
};

uint8_t plaintext[] = {
	0x14, 0x00, 0x00, 0x0c, 0xe6, 0x0e, 0x16, 0xcf, 0x87, 0x78, 0x89, 0x79, 0x28, 0x73, 0x25, 0xe5,
	0x40, 0x5d, 0xaa, 0xa3, 0xa9, 0x45, 0xce, 0xc4, 0x40, 0xee, 0x25, 0x4a, 0x1d, 0x89, 0xd5, 0x44,
	0xf4, 0xcc, 0x9d, 0x75, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

uint8_t MacHead[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0x16, 0x03, 0x01, 0x00, 0x10
};

uint8_t cyphertext[] = {
	0x35, 0xde, 0x87, 0x69, 0xc4, 0x17, 0x58, 0x0a, 0xe6, 0x44, 0x88, 0x47, 0x74, 0x01, 0xd1, 0x14,
	0xfe, 0x18, 0x43, 0xdf, 0xc8, 0x2a, 0x25, 0x95, 0x12, 0xa2, 0x99, 0xfc, 0x28, 0xf1, 0x40, 0x5d,
	0xf7, 0x40, 0xdd, 0x83, 0xf6, 0x26, 0xd5, 0xf5, 0x8b, 0x4c, 0xa8, 0xba, 0x8c, 0xdb, 0x9c, 0x96
};

void main()
{
	Binary key_block;

	key_block.alloc(32 * 2 + 16 * 2 + 16 * 2);
	PrfGenerateBlock_v1_0(key_block.data, key_block.length, master_secret, 48, "key expansion", key_seed, 64);

	uint8_t * client_MAC_secret = key_block.data + 0;
	uint8_t * client_key = key_block.data + 40;
	uint8_t * client_IV = key_block.data + 40 + 32;

	AES128_GCM active_encryption;



	active_encryption.Init(client_key, client_IV, client_MAC_secret);

	Binary out;
	active_encryption.WrapPacket(out, TestClientFinishedPacket, plaintext, 16);

	for (unsigned i = 0; i < 48; ++i) {
		out.data[i] -= cyphertext[i];
	}
	PrintHex(out.data, out.length, 0);
}
#endif