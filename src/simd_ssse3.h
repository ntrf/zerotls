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

/*
Implementations of some potentially platform-agnostic SIMD functions.

This file contains the implmentation for x86/x64 SSSE3.
*/
#ifndef ZEROTLS_SIMD_SSSE3_H_
#define ZEROTLS_SIMD_SSSE3_H_

#include <tmmintrin.h>

static inline __m128i simd_zero()
{
	return _mm_setzero_si128();
}

static inline __m128i simd_load(const uint32_t * val)
{
	uint32_t h3 = val[0];
	uint32_t h2 = val[1];
	uint32_t h1 = val[2];
	uint32_t h0 = val[3];

	return _mm_set_epi32(h3, h2, h1, h0);
}

static inline __m128i simd_loadBE(const uint32_t * val)
{
	uint32_t h3 = bswap32(val[0]);
	uint32_t h2 = bswap32(val[1]);
	uint32_t h1 = bswap32(val[2]);
	uint32_t h0 = bswap32(val[3]);

	return _mm_set_epi32(h3, h2, h1, h0);
}

static inline __m128i simd_xorBytes(__m128i x, const uint32_t * val)
{
	uint32_t h3 = val[0];
	uint32_t h2 = val[1];
	uint32_t h1 = val[2];
	uint32_t h0 = val[3];

	__m128i target = _mm_set_epi32(h3, h2, h1, h0);
	return _mm_xor_si128(x, target);
}

static inline __m128i simd_xorBytesBE(__m128i x, const uint32_t * val)
{
	uint32_t h3 = bswap32(val[0]);
	uint32_t h2 = bswap32(val[1]);
	uint32_t h1 = bswap32(val[2]);
	uint32_t h0 = bswap32(val[3]);

	__m128i target = _mm_set_epi32(h3, h2, h1, h0);
	return _mm_xor_si128(x, target);
}

static inline void simd_store(const __m128i x, uint8_t * res)
{
	uint32_t x0 = ((uint32_t*)&x)[0];
	uint32_t x1 = ((uint32_t*)&x)[1];
	uint32_t x2 = ((uint32_t*)&x)[2];
	uint32_t x3 = ((uint32_t*)&x)[3];

	((uint32_t*)res)[0] = x3;
	((uint32_t*)res)[1] = x2;
	((uint32_t*)res)[2] = x1;
	((uint32_t*)res)[3] = x0;
}

static inline void simd_storeBE(const __m128i x, uint8_t * res)
{
	//### figure out how to do byte reversal in SSE
	uint32_t x0 = ((uint32_t*)&x)[0];
	uint32_t x1 = ((uint32_t*)&x)[1];
	uint32_t x2 = ((uint32_t*)&x)[2];
	uint32_t x3 = ((uint32_t*)&x)[3];

	((uint32_t*)res)[0] = bswap32(x3);
	((uint32_t*)res)[1] = bswap32(x2);
	((uint32_t*)res)[2] = bswap32(x1);
	((uint32_t*)res)[3] = bswap32(x0);
}

#endif