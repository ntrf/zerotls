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

/* SHA1.CPP
 * Unrolled SHA-1 (160 bit) implementation based on SHA-1 pseudocode from wikipedia 
 * look for original code here: 
 * http://en.wikipedia.org/wiki/SHA1#SHA-1_pseudocode
 */

#include <string.h>

#include "hash.h"

//#define TEST_MODULE

#include "../intutils.h"

#define INPUT_RD(i) bswap32(input[i])
#define NEXT_RD(i) rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]),1)

#define SHA1ROUND(a,b,c,d,e, RD, F, K, i) \
	w[i] = RD(i); \
	e = rol((a), 5) + F(b,c,d) + (e) + (K) + (w[i]); \
	b = ror((b), 2);

#define f1(b,c,d) (((b) & (c)) | (~(b) & (d)))
#define f2(b,c,d) ((b) ^ (c) ^ (d))
#define f3(b,c,d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))

#define k1 0x5A827999
#define k2 0x6ED9EBA1
#define k3 0x8F1BBCDC
#define k4 0xCA62C1D6

// ### need no-byteswap alternative for HMAC

static void sha1InternalUpdate(uint32_t sha1state[5], const uint32_t *input, uint32_t length)
{
	register uint32_t A = sha1state[0];
	register uint32_t B = sha1state[1];
	register uint32_t C = sha1state[2];
	register uint32_t D = sha1state[3];
	register uint32_t E = sha1state[4];
	
	// ### this could be no longer than 16 values
	// ### also needs to be burned after use
	uint32_t w[80];

	while(length > 0)
	{
		// rounds 0 .. 19
		SHA1ROUND(A,B,C,D,E, INPUT_RD, f1, k1, 0)
		SHA1ROUND(E,A,B,C,D, INPUT_RD, f1, k1, 1)
		SHA1ROUND(D,E,A,B,C, INPUT_RD, f1, k1, 2)
		SHA1ROUND(C,D,E,A,B, INPUT_RD, f1, k1, 3)
		SHA1ROUND(B,C,D,E,A, INPUT_RD, f1, k1, 4)
		SHA1ROUND(A,B,C,D,E, INPUT_RD, f1, k1, 5)
		SHA1ROUND(E,A,B,C,D, INPUT_RD, f1, k1, 6)
		SHA1ROUND(D,E,A,B,C, INPUT_RD, f1, k1, 7)
		SHA1ROUND(C,D,E,A,B, INPUT_RD, f1, k1, 8)
		SHA1ROUND(B,C,D,E,A, INPUT_RD, f1, k1, 9)
		SHA1ROUND(A,B,C,D,E, INPUT_RD, f1, k1, 10)
		SHA1ROUND(E,A,B,C,D, INPUT_RD, f1, k1, 11)
		SHA1ROUND(D,E,A,B,C, INPUT_RD, f1, k1, 12)
		SHA1ROUND(C,D,E,A,B, INPUT_RD, f1, k1, 13)
		SHA1ROUND(B,C,D,E,A, INPUT_RD, f1, k1, 14)
		SHA1ROUND(A,B,C,D,E, INPUT_RD, f1, k1, 15)
		SHA1ROUND(E,A,B,C,D, NEXT_RD , f1, k1, 16) 
		SHA1ROUND(D,E,A,B,C, NEXT_RD , f1, k1, 17) 
		SHA1ROUND(C,D,E,A,B, NEXT_RD , f1, k1, 18) 
		SHA1ROUND(B,C,D,E,A, NEXT_RD , f1, k1, 19) 

		// rounds 20 .. 39
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k2, 20)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k2, 21)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k2, 22)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k2, 23)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k2, 24)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k2, 25)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k2, 26)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k2, 27)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k2, 28)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k2, 29)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k2, 30)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k2, 31)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k2, 32)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k2, 33)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k2, 34)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k2, 35)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k2, 36)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k2, 37)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k2, 38)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k2, 39)

		// rounds 40 .. 59
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f3, k3, 40)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f3, k3, 41)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f3, k3, 42)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f3, k3, 43)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f3, k3, 44)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f3, k3, 45)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f3, k3, 46)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f3, k3, 47)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f3, k3, 48)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f3, k3, 49)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f3, k3, 50)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f3, k3, 51)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f3, k3, 52)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f3, k3, 53)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f3, k3, 54)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f3, k3, 55)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f3, k3, 56)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f3, k3, 57)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f3, k3, 58)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f3, k3, 59)
		
		// rounds 60 .. 79
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k4, 60)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k4, 61)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k4, 62)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k4, 63)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k4, 64)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k4, 65)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k4, 66)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k4, 67)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k4, 68)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k4, 69)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k4, 70)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k4, 71)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k4, 72)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k4, 73)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k4, 74)
		SHA1ROUND(A,B,C,D,E, NEXT_RD, f2, k4, 75)
		SHA1ROUND(E,A,B,C,D, NEXT_RD, f2, k4, 76)
		SHA1ROUND(D,E,A,B,C, NEXT_RD, f2, k4, 77)
		SHA1ROUND(C,D,E,A,B, NEXT_RD, f2, k4, 78)
		SHA1ROUND(B,C,D,E,A, NEXT_RD, f2, k4, 79)
		
		A += sha1state[0];
		B += sha1state[1];
		C += sha1state[2];
		D += sha1state[3];
		E += sha1state[4];
	
		sha1state[0] = A;
		sha1state[1] = B;
		sha1state[2] = C;
		sha1state[3] = D;
		sha1state[4] = E;

		input += 16;
		length -= 64;
	}
}	

void sha1Init(SHA1_State * state)
{
	state->sha1state[0] = 0x67452301;
	state->sha1state[1] = 0xEFCDAB89;
	state->sha1state[2] = 0x98BADCFE;
	state->sha1state[3] = 0x10325476;
	state->sha1state[4] = 0xC3D2E1F0;
	
	memset(state->buf, 0, sizeof(state->buf));
	state->buf_len = 0;
	state->full_len = 0;
}

void sha1Update(SHA1_State * state, const uint8_t * input, uint32_t length)
{
	if(length == 0)
		return;

	int l;
	state->full_len += length;
	
	if(state->buf_len > 0)
	{
		l = state->buf_len;
		if(length + l < 64) //not enough to fill buffer
		{
			memcpy(&state->buf[l], input, length);
			state->buf_len += length;
			return; //not enough to update
		}
		memcpy(&state->buf[l], input, 64 - l);
		length -= 64 - l;
		input += 64 - l;
		
		//hash buffered block
		sha1InternalUpdate(state->sha1state, (uint32_t *)state->buf, 64);
	}
	
	//transfrom most of block in the middle
	l = length & ~0x3f;
	sha1InternalUpdate(state->sha1state, (uint32_t *)input, l);
	
	//copy rest to buffer
	length &= 0x3f;
	if(length > 0)
	{
		input += l;
		memcpy(state->buf, input, length);
	}
	state->buf_len = length;
}

void sha1Finish(SHA1_State * state, uint32_t result[5])
{
	int l = 64 - state->buf_len - 1;
	
	uint8_t * p = state->buf + state->buf_len;

	uint32_t full = state->full_len * 8;

	*p++ = 0x80;
	if(l >= 8) {
		memset(p, 0, l - 8);
	}else{
		memset(p, 0, l);
		sha1InternalUpdate(state->sha1state, (uint32_t *)state->buf, 64);
		memset(state->buf, 0, 64 - 8);
	}
	*((uint32_t*)&state->buf[64 - 8]) = 0;
	*((uint32_t*)&state->buf[64 - 4]) = bswap32(full); // Big-endian
	sha1InternalUpdate(state->sha1state, (uint32_t *)state->buf, 64);
	
	// ### i'm planing to use this for HMAC so byteswap is not usefull
	result[0] = bswap32(state->sha1state[0]);
	result[1] = bswap32(state->sha1state[1]);
	result[2] = bswap32(state->sha1state[2]);
	result[3] = bswap32(state->sha1state[3]);
	result[4] = bswap32(state->sha1state[4]);
}

#ifdef TEST_MODULE
#include <stdio.h>

//### implement verification of results
int main()
{
	SHA1_State state;
	uint32_t result[5]; //bytes will be swaped in each value

	sha1Init(&state);
	sha1Update(&state, (uint8_t*)"", 0);
	sha1Finish(&state, result);
	
	printf("sha1(\"\") = %08x %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3], result[4]);

	sha1Init(&state);
	sha1Update(&state, (uint8_t*)"abc", 3);
	sha1Finish(&state, result);
	
	printf("sha1(\"abc\") = %08x %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3], result[4]);

	sha1Init(&state);
	sha1Update(&state, (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
	sha1Finish(&state, result);
	
	printf("sha1(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") = %08x %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3], result[4]);

	sha1Init(&state);
	sha1Update(&state, (uint8_t*)"The quick brown fox jumps over the lazy dog", 43);
	sha1Finish(&state, result);
	
	printf("sha1(\"The quick brown fox jumps over the lazy dog\") = %08x %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3], result[4]);

	return 0;
}
#endif