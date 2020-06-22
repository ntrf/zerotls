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

/* SHA384.CPP
 * Unrolled SHA-384 (384 bit) implementation based on SHA-2 pseudocode from wikipedia 
 * look for original code here: 
 * http://en.wikipedia.org/wiki/Sha-2#Pseudocode
 */

// NOTICE: This implementation does not handle messages of more than 2^32 bytes

// This implementation is very slow on 32bit platforms

#include <string.h>

#include "hash.h"

//#define TEST_MODULE

#include "../intutils.h"

#define INPUT_RD(i) (((uint64_t)bswap32(input[2*i]) << 32) | (uint64_t)bswap32(input[2*i + 1]))
#define NEXT_RD(i) (w[i-16] + w[i-7] + \
(ror64(w[i-15], 1) ^ ror64(w[i-15], 8) ^ (w[i-15] >> 7)) + \
(ror64(w[i-2], 19) ^ ror64(w[i-2], 61) ^ (w[i-2] >> 6)))

#define SHA512ROUND(a,b,c,d,e,f,g,h, RD, i) \
	w[i] = RD(i); \
	h += f1(e,f,g) + w[i] + Kx[i] + f4(e); \
	d += h; \
	h += f2(a,b,c) + f3(a);

#define f1(e,f,g) (((e) & (f)) ^ (~(e) & (g)))
#define f2(a,b,c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define f3(a) (ror64((a),28) ^ ror64((a),34) ^ ror64((a),39))
#define f4(e) (ror64((e),14) ^ ror64((e),18) ^ ror64((e),41))


static const uint64_t Kx[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
	0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
	0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
	0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
	0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
	0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const size_t BLOCKSIZE = 128;
static const size_t LENGTH_SIZE = 16;

// ### need no-byteswap alternative for HMAC

static void sha512InternalUpdate(uint64_t sha512state[8], const uint32_t * input, uint64_t length)
{
	uint64_t A = sha512state[0];
	uint64_t B = sha512state[1];
	uint64_t C = sha512state[2];
	uint64_t D = sha512state[3];
	uint64_t E = sha512state[4];
	uint64_t F = sha512state[5];
	uint64_t G = sha512state[6];
	uint64_t H = sha512state[7];
	
	// ### this could be no longer than 16 values
	// ### also needs to be burned after use
	uint64_t w[80];

	while(length > 0)
	{
		// rounds 0 .. 15
		SHA512ROUND(A,B,C,D,E,F,G,H, INPUT_RD, 0x00)
		SHA512ROUND(H,A,B,C,D,E,F,G, INPUT_RD, 0x01)
		SHA512ROUND(G,H,A,B,C,D,E,F, INPUT_RD, 0x02)
		SHA512ROUND(F,G,H,A,B,C,D,E, INPUT_RD, 0x03)
		SHA512ROUND(E,F,G,H,A,B,C,D, INPUT_RD, 0x04)
		SHA512ROUND(D,E,F,G,H,A,B,C, INPUT_RD, 0x05)
		SHA512ROUND(C,D,E,F,G,H,A,B, INPUT_RD, 0x06)
		SHA512ROUND(B,C,D,E,F,G,H,A, INPUT_RD, 0x07)
		SHA512ROUND(A,B,C,D,E,F,G,H, INPUT_RD, 0x08)
		SHA512ROUND(H,A,B,C,D,E,F,G, INPUT_RD, 0x09)
		SHA512ROUND(G,H,A,B,C,D,E,F, INPUT_RD, 0x0A)
		SHA512ROUND(F,G,H,A,B,C,D,E, INPUT_RD, 0x0B)
		SHA512ROUND(E,F,G,H,A,B,C,D, INPUT_RD, 0x0C)
		SHA512ROUND(D,E,F,G,H,A,B,C, INPUT_RD, 0x0D)
		SHA512ROUND(C,D,E,F,G,H,A,B, INPUT_RD, 0x0E)
		SHA512ROUND(B,C,D,E,F,G,H,A, INPUT_RD, 0x0F)

		// rounds 16 .. 31
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x10)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x11)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x12)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x13)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x14)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x15)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x16)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x17)
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x18)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x19)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x1A)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x1B)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x1C)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x1D)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x1E)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x1F)

		// rounds 32 .. 47
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x20)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x21)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x22)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x23)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x24)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x25)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x26)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x27)
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x28)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x29)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x2A)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x2B)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x2C)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x2D)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x2E)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x2F)

		// rounds 48 .. 63
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x30)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x31)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x32)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x33)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x34)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x35)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x36)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x37)
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x38)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x39)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x3A)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x3B)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x3C)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x3D)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x3E)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x3F)

		// rounds 64 .. 79
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x40)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x41)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x42)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x43)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x44)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x45)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x46)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x47)
		SHA512ROUND(A,B,C,D,E,F,G,H, NEXT_RD, 0x48)
		SHA512ROUND(H,A,B,C,D,E,F,G, NEXT_RD, 0x49)
		SHA512ROUND(G,H,A,B,C,D,E,F, NEXT_RD, 0x4A)
		SHA512ROUND(F,G,H,A,B,C,D,E, NEXT_RD, 0x4B)
		SHA512ROUND(E,F,G,H,A,B,C,D, NEXT_RD, 0x4C)
		SHA512ROUND(D,E,F,G,H,A,B,C, NEXT_RD, 0x4D)
		SHA512ROUND(C,D,E,F,G,H,A,B, NEXT_RD, 0x4E)
		SHA512ROUND(B,C,D,E,F,G,H,A, NEXT_RD, 0x4F)
		
		A += sha512state[0];
		B += sha512state[1];
		C += sha512state[2];
		D += sha512state[3];
		E += sha512state[4];
		F += sha512state[5];
		G += sha512state[6];
		H += sha512state[7];
	
		sha512state[0] = A;
		sha512state[1] = B;
		sha512state[2] = C;
		sha512state[3] = D;
		sha512state[4] = E;
		sha512state[5] = F;
		sha512state[6] = G;
		sha512state[7] = H;

		input += BLOCKSIZE / sizeof(*input);
		length -= BLOCKSIZE;
	}
}	

void sha512Init(SHA512_State * state)
{
	state->sha512state[0] = 0x6a09e667f3bcc908ULL;
	state->sha512state[1] = 0xbb67ae8584caa73bULL;
	state->sha512state[2] = 0x3c6ef372fe94f82bULL;
	state->sha512state[3] = 0xa54ff53a5f1d36f1ULL;
	state->sha512state[4] = 0x510e527fade682d1ULL;
	state->sha512state[5] = 0x9b05688c2b3e6c1fULL;
	state->sha512state[6] = 0x1f83d9abfb41bd6bULL;
	state->sha512state[7] = 0x5be0cd19137e2179ULL;
	
	memset(state->buf, 0, sizeof(state->buf));
	state->buf_len = 0;
	state->full_len = 0;
}

void sha384Init(SHA512_State * state)
{
	state->sha512state[0] = 0xcbbb9d5dc1059ed8ULL;
	state->sha512state[1] = 0x629a292a367cd507ULL;
	state->sha512state[2] = 0x9159015a3070dd17ULL;
	state->sha512state[3] = 0x152fecd8f70e5939ULL;
	state->sha512state[4] = 0x67332667ffc00b31ULL;
	state->sha512state[5] = 0x8eb44a8768581511ULL;
	state->sha512state[6] = 0xdb0c2e0d64f98fa7ULL;
	state->sha512state[7] = 0x47b5481dbefa4fa4ULL;

	memset(state->buf, 0, sizeof(state->buf));
	state->buf_len = 0;
	state->full_len = 0;
}

void sha512Update(SHA512_State * state, const uint8_t * input, uint32_t length)
{
	if(length == 0)
		return;

	int l;
	state->full_len += length;
	
	if (state->buf_len > 0) {
		l = state->buf_len;
		if (length + l < BLOCKSIZE) { //not enough to fill buffer
			memcpy(&state->buf[l], input, length);
			state->buf_len += length;
			return; //not enough to update
		}
		memcpy(&state->buf[l], input, BLOCKSIZE - l);
		length -= BLOCKSIZE - l;
		input += BLOCKSIZE - l;

		//hash buffered block
		sha512InternalUpdate(state->sha512state, (uint32_t *)state->buf, BLOCKSIZE);
	}
	
	//transfrom most of block in the middle
	l = length & ~(BLOCKSIZE - 1);
	sha512InternalUpdate(state->sha512state, (uint32_t *)input, l);
	
	//copy rest to buffer
	length &= (BLOCKSIZE - 1);
	if (length > 0) {
		input += l;
		memcpy(state->buf, input, length);
	}
	state->buf_len = length;
}

void sha512Finish(SHA512_State * state, uint32_t result[16])
{
	int l = BLOCKSIZE - state->buf_len - 1;
	
	uint8_t * p = state->buf + state->buf_len;

	uint32_t full = state->full_len * 8;

	*p++ = 0x80;
	if (l >= LENGTH_SIZE) {
		memset(p, 0, l - LENGTH_SIZE);
	}else{
		memset(p, 0, l);
		sha512InternalUpdate(state->sha512state, (uint32_t *)state->buf, BLOCKSIZE);
		memset(state->buf, 0, BLOCKSIZE - LENGTH_SIZE);
	}
	*((uint64_t*)&state->buf[BLOCKSIZE - 16]) = 0;
	*((uint32_t*)&state->buf[BLOCKSIZE - 8]) = 0;
	*((uint32_t*)&state->buf[BLOCKSIZE - 4]) = bswap32(full); // Big-endian
	sha512InternalUpdate(state->sha512state, (uint32_t *)state->buf, BLOCKSIZE);
	
	// ### i'm planing to use this for HMAC so byteswap is not usefull
	const uint32_t * res = (const uint32_t*)&state->sha512state[0];

	result[0] = bswap32(res[0 ^ 1]);
	result[1] = bswap32(res[1 ^ 1]);
	result[2] = bswap32(res[2 ^ 1]);
	result[3] = bswap32(res[3 ^ 1]);
	result[4] = bswap32(res[4 ^ 1]);
	result[5] = bswap32(res[5 ^ 1]);
	result[6] = bswap32(res[6 ^ 1]);
	result[7] = bswap32(res[7 ^ 1]);
	result[8] = bswap32(res[8 ^ 1]);
	result[9] = bswap32(res[9 ^ 1]);
	result[10] = bswap32(res[10 ^ 1]);
	result[11] = bswap32(res[11 ^ 1]);
	result[12] = bswap32(res[12 ^ 1]);
	result[13] = bswap32(res[13 ^ 1]);
	result[14] = bswap32(res[14 ^ 1]);
	result[15] = bswap32(res[15 ^ 1]);
}

void sha384Finish(SHA512_State * state, uint32_t result[12])
{
	int l = BLOCKSIZE - state->buf_len - 1;

	uint8_t * p = state->buf + state->buf_len;

	uint32_t full = state->full_len * 8;

	*p++ = 0x80;
	if (l >= LENGTH_SIZE) {
		memset(p, 0, l - LENGTH_SIZE);
	}else{
		memset(p, 0, l);
		sha512InternalUpdate(state->sha512state, (uint32_t *)state->buf, BLOCKSIZE);
		memset(state->buf, 0, BLOCKSIZE - LENGTH_SIZE);
	}
	*((uint64_t*)&state->buf[BLOCKSIZE - 16]) = 0;
	*((uint32_t*)&state->buf[BLOCKSIZE - 8]) = 0;
	*((uint32_t*)&state->buf[BLOCKSIZE - 4]) = bswap32(full); // Big-endian
	sha512InternalUpdate(state->sha512state, (uint32_t *)state->buf, BLOCKSIZE);

	// ### i'm planing to use this for HMAC so byteswap is not usefull
	const uint32_t * res = (const uint32_t*)&state->sha512state[0];

	result[0] = bswap32(res[0 ^ 1]);
	result[1] = bswap32(res[1 ^ 1]);
	result[2] = bswap32(res[2 ^ 1]);
	result[3] = bswap32(res[3 ^ 1]);
	result[4] = bswap32(res[4 ^ 1]);
	result[5] = bswap32(res[5 ^ 1]);
	result[6] = bswap32(res[6 ^ 1]);
	result[7] = bswap32(res[7 ^ 1]);
	result[8] = bswap32(res[8 ^ 1]);
	result[9] = bswap32(res[9 ^ 1]);
	result[10] = bswap32(res[10 ^ 1]);
	result[11] = bswap32(res[11 ^ 1]);
}

#ifdef TEST_MODULE
#include <stdio.h>

extern const char * hexBlock(const uint8_t * value, int len);

//### implement verification of results
int main()
{
	SHA512_State state;
	uint32_t result[16]; //bytes will be swaped in each value

	sha512Init(&state);
	sha512Update(&state, (uint8_t*)"", 0);
	sha512Finish(&state, result);
	
	printf("sha512(\"\") =\n output  %128s\n", 
		   hexBlock((uint8_t*)&result[0], sizeof(result)));
	printf(" correct %128s\n", 
		   "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

	sha512Init(&state);
	sha512Update(&state, (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
	sha512Finish(&state, result);
	
	printf("sha512(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") =\n output  %128s\n",
		   hexBlock((uint8_t*)&result[0], sizeof(result)));
	printf(" correct %128s\n", 
		   "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");

	sha512Init(&state);
	sha512Update(&state, (uint8_t*)"The quick brown fox jumps over the lazy dog", 43);
	sha512Finish(&state, result);
	
	printf("sha512(\"The quick brown fox jumps over the lazy dog\") =\n output  %128s\n",
		   hexBlock((uint8_t*)&result[0], sizeof(result)));
	printf(" correct %128s\n", 
		   "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");

	size_t million = 1000000;
	char * buf = new char[million + 1];
	memset(buf, 'a', million);
	buf[million] = 0;

	sha512Init(&state);
	sha512Update(&state, (uint8_t*)buf, million);
	sha512Finish(&state, result);

	printf("sha512(million of 'a') =\n output  %128s\n",
		   hexBlock((uint8_t*)&result[0], sizeof(result)));
	printf(" correct %128s\n",
		   "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");

	sha384Init(&state);
	sha512Update(&state, (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
	sha384Finish(&state, result);

	printf("sha384(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") =\n output  %96s\n",
		   hexBlock((uint8_t*)&result[0], 48));
	printf(" correct %96s\n",
		   "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");

	sha384Init(&state);
	sha512Update(&state, (uint8_t*)buf, million);
	sha384Finish(&state, result);

	printf("sha384(million of 'a') =\n output  %96s\n",
		   hexBlock((uint8_t*)&result[0], 48));
	printf(" correct %96s\n",
		   "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");

	delete[] buf;

	return 0;
}
#endif