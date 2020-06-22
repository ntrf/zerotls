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

/* MD5.CPP
 * Unrolled MD5 implementation based on MD5 pseudocode from wikipedia
 * look for original code here: 
 * http://en.wikipedia.org/wiki/MD5#Pseudocode
 */

#include <string.h>

#include "hash.h"

//#define TEST_MODULE

#include "../intutils.h"

#define RD1(i) (input[(i)])
#define RD2(i) (input[(5*(i) + 1) & 15])
#define RD3(i) (input[(3*(i) + 5) & 15])
#define RD4(i) (input[(7*(i)) & 15])

#define f1(b,c,d) (((b) & (c)) | (~(b) & (d)))
#define f2(b,c,d) (((d) & (b)) | (~(d) & (c)))
#define f3(b,c,d) ((b) ^ (c) ^ (d))
#define f4(b,c,d) ((c) ^ ((b) | ~(d)))


#define MD5ROUND(a,b,c,d, RD, F, S, i) \
	w[i] = RD(i); \
	a = rol(a + F(b,c,d) + (Ktable[i]) + (w[i]), S) + b;


#define MD5ROUNDS1(a,b,c,d, i) \
	MD5ROUND(a,b,c,d, RD1, f1, 7,  i) \
	MD5ROUND(d,a,b,c, RD1, f1, 12, i+1) \
	MD5ROUND(c,d,a,b, RD1, f1, 17, i+2) \
	MD5ROUND(b,c,d,a, RD1, f1, 22, i+3) 

#define MD5ROUNDS2(a,b,c,d, i) \
	MD5ROUND(a,b,c,d, RD2, f2, 5,  i) \
	MD5ROUND(d,a,b,c, RD2, f2, 9,  i+1) \
	MD5ROUND(c,d,a,b, RD2, f2, 14, i+2) \
	MD5ROUND(b,c,d,a, RD2, f2, 20, i+3) 

#define MD5ROUNDS3(a,b,c,d, i) \
	MD5ROUND(a,b,c,d, RD3, f3, 4,  i) \
	MD5ROUND(d,a,b,c, RD3, f3, 11, i+1) \
	MD5ROUND(c,d,a,b, RD3, f3, 16, i+2) \
	MD5ROUND(b,c,d,a, RD3, f3, 23, i+3) 

#define MD5ROUNDS4(a,b,c,d, i) \
	MD5ROUND(a,b,c,d, RD4, f4, 6,  i) \
	MD5ROUND(d,a,b,c, RD4, f4, 10, i+1) \
	MD5ROUND(c,d,a,b, RD4, f4, 15, i+2) \
	MD5ROUND(b,c,d,a, RD4, f4, 21, i+3) 


static const uint32_t Ktable[] =
{ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

static void md5InternalUpdate(uint32_t md5state[4], uint32_t *input, uint32_t length)
{
	register uint32_t A = md5state[0];
	register uint32_t B = md5state[1];
	register uint32_t C = md5state[2];
	register uint32_t D = md5state[3];
	
	// ### as with sha1 implementation this could be smaller
	uint32_t w[64];

	while(length > 0)
	{
		// rounds 0 .. 15
		MD5ROUNDS1(A,B,C,D, 0)
		MD5ROUNDS1(A,B,C,D, 4)
		MD5ROUNDS1(A,B,C,D, 8)
		MD5ROUNDS1(A,B,C,D, 12)
		
		// rounds 16 .. 31
		MD5ROUNDS2(A,B,C,D, 16)
		MD5ROUNDS2(A,B,C,D, 20)
		MD5ROUNDS2(A,B,C,D, 24)
		MD5ROUNDS2(A,B,C,D, 28)

		// rounds 31 .. 47
		MD5ROUNDS3(A,B,C,D, 32)
		MD5ROUNDS3(A,B,C,D, 36)
		MD5ROUNDS3(A,B,C,D, 40)
		MD5ROUNDS3(A,B,C,D, 44)

		// rounds 48 .. 63
		MD5ROUNDS4(A,B,C,D, 48)
		MD5ROUNDS4(A,B,C,D, 52)
		MD5ROUNDS4(A,B,C,D, 56)
		MD5ROUNDS4(A,B,C,D, 60)

		A += md5state[0];
		B += md5state[1];
		C += md5state[2];
		D += md5state[3];
		
		md5state[0] = A;
		md5state[1] = B;
		md5state[2] = C;
		md5state[3] = D;
		
		input += 16;
		length -= 64;
	}
}	


void md5Init(MD5_State * state)
{
	state->md5state[0] = 0x67452301;
	state->md5state[1] = 0xEFCDAB89;
	state->md5state[2] = 0x98BADCFE;
	state->md5state[3] = 0x10325476;
	
	memset(state->buf, 0, sizeof(state->buf));
	state->buf_len = 0;
	state->full_len = 0;
}

void md5Update(MD5_State * state, const uint8_t * input, uint32_t length)
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
		md5InternalUpdate(state->md5state, (uint32_t *)state->buf, 64);
	}
	
	//transfrom most of block in the middle
	l = length & ~0x3f;
	md5InternalUpdate(state->md5state, (uint32_t *)input, l);
	
	//copy rest to buffer
	length &= 0x3f;
	if(length > 0)
	{
		input += l;
		memcpy(state->buf, input, length);
	}
	state->buf_len = length;
}

void md5Finish(MD5_State * state, uint32_t result[4])
{
	int l = 64 - state->buf_len - 1;
	
	uint8_t * p = state->buf + state->buf_len;

	uint32_t full = state->full_len * 8;

	*p++ = 0x80;
	if(l >= 8) {
		memset(p, 0, l - 8);
	}else{
		memset(p, 0, l);
		md5InternalUpdate(state->md5state, (uint32_t *)state->buf, 64);
		memset(state->buf, 0, 64 - 8);
	}
	*((uint32_t*)&state->buf[64 - 8]) = full; // Little-endian
	*((uint32_t*)&state->buf[64 - 4]) = 0;
	md5InternalUpdate(state->md5state, (uint32_t *)state->buf, 64);
	
	result[0] = (state->md5state[0]);
	result[1] = (state->md5state[1]);
	result[2] = (state->md5state[2]);
	result[3] = (state->md5state[3]);
}

#ifdef TEST_MODULE
#include <stdio.h>

//### implement verification of results
int main()
{
	MD5_State state;
	uint32_t result[4]; //bytes will be swaped in each value

	md5Init(&state);
	md5Update(&state, (const uint8_t*)"", 0);
	md5Finish(&state, result);
	
	printf("md5(\"\") = %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3]);

	md5Init(&state);
	md5Update(&state, (const uint8_t*)"abc", 3);
	md5Finish(&state, result);
	
	printf("md5(\"abc\") = %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3]);

	md5Init(&state);
	md5Update(&state, (const uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
	md5Finish(&state, result);
	
	printf("md5(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") = %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3]);

	md5Init(&state);
	md5Update(&state, (const uint8_t*)"The quick brown fox jumps over the lazy dog", 43);
	md5Finish(&state, result);
	
	printf("md5(\"The quick brown fox jumps over the lazy dog\") = %08x %08x %08x %08x\n",
		result[0], result[1], result[2], result[3]);

	return 0;
}
#endif
