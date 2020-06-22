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

/* SHA256.CPP
 * Unrolled SHA-256 (256 bit) implementation based on SHA-2 pseudocode from wikipedia 
 * look for original code here: 
 * http://en.wikipedia.org/wiki/Sha-2#Pseudocode
 */

#include <string.h>

#include "hash.h"

//#define TEST_MODULE

#include "../intutils.h"

#define INPUT_RD(i) bswap32(input[i])
#define NEXT_RD(i) (w[i-16] + w[i-7] + \
(ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3)) + \
(ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >> 10)))

#define SHA256ROUND(a,b,c,d,e,f,g,h, RD, i) \
	w[i] = RD(i); \
	h += f1(e,f,g) + w[i] + Kx[i] + f4(e); \
	d += h; \
	h += f2(a,b,c) + f3(a);

#define f1(e,f,g) (((e) & (f)) ^ (~(e) & (g)))
#define f2(a,b,c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define f3(a) (ror((a),2) ^ ror((a),13) ^ ror((a),22))
#define f4(e) (ror((e),6) ^ ror((e),11) ^ ror((e),25))


static const uint32_t Kx[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ### need no-byteswap alternative for HMAC

static void sha256InternalUpdate(uint32_t sha256state[8], const uint32_t *input, uint32_t length)
{
	uint32_t A = sha256state[0];
	uint32_t B = sha256state[1];
	uint32_t C = sha256state[2];
	uint32_t D = sha256state[3];
	uint32_t E = sha256state[4];
	uint32_t F = sha256state[5];
	uint32_t G = sha256state[6];
	uint32_t H = sha256state[7];
	
	// ### this could be no longer than 16 values
	// ### also needs to be burned after use
	uint32_t w[64];

	while(length > 0)
	{
		// rounds 0 .. 15
		SHA256ROUND(A,B,C,D,E,F,G,H, INPUT_RD, 0x00)
		SHA256ROUND(H,A,B,C,D,E,F,G, INPUT_RD, 0x01)
		SHA256ROUND(G,H,A,B,C,D,E,F, INPUT_RD, 0x02)
		SHA256ROUND(F,G,H,A,B,C,D,E, INPUT_RD, 0x03)
		SHA256ROUND(E,F,G,H,A,B,C,D, INPUT_RD, 0x04)
		SHA256ROUND(D,E,F,G,H,A,B,C, INPUT_RD, 0x05)
		SHA256ROUND(C,D,E,F,G,H,A,B, INPUT_RD, 0x06)
		SHA256ROUND(B,C,D,E,F,G,H,A, INPUT_RD, 0x07)
		SHA256ROUND(A,B,C,D,E,F,G,H, INPUT_RD, 0x08)
		SHA256ROUND(H,A,B,C,D,E,F,G, INPUT_RD, 0x09)
		SHA256ROUND(G,H,A,B,C,D,E,F, INPUT_RD, 0x0A)
		SHA256ROUND(F,G,H,A,B,C,D,E, INPUT_RD, 0x0B)
		SHA256ROUND(E,F,G,H,A,B,C,D, INPUT_RD, 0x0C)
		SHA256ROUND(D,E,F,G,H,A,B,C, INPUT_RD, 0x0D)
		SHA256ROUND(C,D,E,F,G,H,A,B, INPUT_RD, 0x0E)
		SHA256ROUND(B,C,D,E,F,G,H,A, INPUT_RD, 0x0F)

		// rounds 16 .. 31
		SHA256ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x10)
		SHA256ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x11)
		SHA256ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x12)
		SHA256ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x13)
		SHA256ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x14)
		SHA256ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x15)
		SHA256ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x16)
		SHA256ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x17)
		SHA256ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x18)
		SHA256ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x19)
		SHA256ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x1A)
		SHA256ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x1B)
		SHA256ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x1C)
		SHA256ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x1D)
		SHA256ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x1E)
		SHA256ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x1F)

		// rounds 32 .. 47
		SHA256ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x20)
		SHA256ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x21)
		SHA256ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x22)
		SHA256ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x23)
		SHA256ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x24)
		SHA256ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x25)
		SHA256ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x26)
		SHA256ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x27)
		SHA256ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x28)
		SHA256ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x29)
		SHA256ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x2A)
		SHA256ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x2B)
		SHA256ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x2C)
		SHA256ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x2D)
		SHA256ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x2E)
		SHA256ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x2F)

		// rounds 48 .. 63
		SHA256ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x30)
		SHA256ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x31)
		SHA256ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x32)
		SHA256ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x33)
		SHA256ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x34)
		SHA256ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x35)
		SHA256ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x36)
		SHA256ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x37)
		SHA256ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x38)
		SHA256ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x39)
		SHA256ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x3A)
		SHA256ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x3B)
		SHA256ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x3C)
		SHA256ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x3D)
		SHA256ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x3E)
		SHA256ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x3F)
		
		A += sha256state[0];
		B += sha256state[1];
		C += sha256state[2];
		D += sha256state[3];
		E += sha256state[4];
		F += sha256state[5];
		G += sha256state[6];
		H += sha256state[7];
	
		sha256state[0] = A;
		sha256state[1] = B;
		sha256state[2] = C;
		sha256state[3] = D;
		sha256state[4] = E;
		sha256state[5] = F;
		sha256state[6] = G;
		sha256state[7] = H;

		input += 16;
		length -= 64;
	}
}	

void sha256Init(SHA256_State * state)
{
	state->sha256state[0] = 0x6a09e667;
	state->sha256state[1] = 0xbb67ae85;
	state->sha256state[2] = 0x3c6ef372;
	state->sha256state[3] = 0xa54ff53a;
	state->sha256state[4] = 0x510e527f;
	state->sha256state[5] = 0x9b05688c;
	state->sha256state[6] = 0x1f83d9ab;
	state->sha256state[7] = 0x5be0cd19;
	
	memset(state->buf, 0, sizeof(state->buf));
	state->buf_len = 0;
	state->full_len = 0;
}

void sha256Update(SHA256_State * state, const uint8_t * input, uint32_t length)
{
	int l;
	if(length == 0)
		return;
	
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
		sha256InternalUpdate(state->sha256state, (uint32_t *)state->buf, 64);
	}
	
	//transfrom most of block in the middle
	l = length & ~0x3f;
	sha256InternalUpdate(state->sha256state, (uint32_t *)input, l);
	
	//copy rest to buffer
	length &= 0x3f;
	if(length > 0)
	{
		input += l;
		memcpy(state->buf, input, length);
	}
	state->buf_len = length;
}

void sha256Finish(SHA256_State * state, uint32_t result[8])
{
	int l = 64 - state->buf_len - 1;
	
	uint8_t * p = state->buf + state->buf_len;

	uint32_t full = state->full_len * 8;

	*p++ = 0x80;
	if(l >= 8) {
		memset(p, 0, l - 8);
	}else{
		memset(p, 0, l);
		sha256InternalUpdate(state->sha256state, (uint32_t *)state->buf, 64);
		memset(state->buf, 0, 64 - 8);
	}
	*((uint32_t*)&state->buf[64 - 8]) = 0;
	*((uint32_t*)&state->buf[64 - 4]) = bswap32(full); // Big-endian
	sha256InternalUpdate(state->sha256state, (uint32_t *)state->buf, 64);
	
	// ### i'm planing to use this for HMAC so byteswap is not usefull
	result[0] = bswap32(state->sha256state[0]);
	result[1] = bswap32(state->sha256state[1]);
	result[2] = bswap32(state->sha256state[2]);
	result[3] = bswap32(state->sha256state[3]);
	result[4] = bswap32(state->sha256state[4]);
	result[5] = bswap32(state->sha256state[5]);
	result[6] = bswap32(state->sha256state[6]);
	result[7] = bswap32(state->sha256state[7]);
}

#ifdef TEST_MODULE
#include <stdio.h>

extern const char * hexBlock(const uint8_t * value, int len);

//### implement verification of results
int main()
{
	SHA256_State state;
	uint32_t result[8]; //bytes will be swaped in each value

	sha256Init(&state);
	sha256Update(&state, (uint8_t*)"", 0);
	sha256Finish(&state, result);
	
	printf("sha256(\"\") = %64s\n", 
		   hexBlock((uint8_t*)&result[0], sizeof(result)));
	printf(" correct     %64s\n", 
		   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	sha256Init(&state);
	sha256Update(&state, (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
	sha256Finish(&state, result);
	
	printf("sha256(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") = %64s\n",
		   hexBlock((uint8_t*)&result[0], sizeof(result)));
	printf(" correct                                                             %64s\n", 
		   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

	sha256Init(&state);
	sha256Update(&state, (uint8_t*)"The quick brown fox jumps over the lazy dog", 43);
	sha256Finish(&state, result);
	
	printf("sha256(\"The quick brown fox jumps over the lazy dog\") = %64s\n",
		   hexBlock((uint8_t*)&result[0], sizeof(result)));
	printf(" correct                                                %64s\n", 
		   "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

	return 0;
}
#endif