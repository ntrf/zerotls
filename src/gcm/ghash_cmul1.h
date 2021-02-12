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
This is historic file containing an implementation and (more importantly)
explanation of reduction in GF(2^128) field over x^128 + x^7 + x^2 + x^1.
Unfortunately GCM designers were weird people and decided to number bits
backwards. On little-endian platforms, which are the most common these 
days, it leds to inconsitentcy of correct byte order with incorrect bit
order. Eventually i've decided to use another implementation, that does
byte shuffle, but can work with reversed order of bits.

This is loosely based on Intel's application note "Intel® Carry-Less
Multiplication Instruction and its Usage for Computing the GCM Mode".
Most of the explanation done in the paper poorly translates to an actual
code within the same paper.

If only all internet standard authors were aware of popularity of LE 
platforms...
*/

// Requires Core i3/i5/i7 Westmere
// Tested on Sandy Bridge i5-2500
// (some names can be trademarks)
#include <wmmintrin.h>

static void cmulType1(const uint8_t * h, const uint8_t * x, uint8_t * res)
{
	__m128i sourceH;
	__m128i sourceX;

	// Reverse all the bits for H
	{
		uint32_t h0 = reverseBits8((h[3] << 24) + (h[2] << 16) + (h[1] << 8) + h[0]);
		uint32_t h1 = reverseBits8((h[7] << 24) + (h[6] << 16) + (h[5] << 8) + h[4]);
		uint32_t h2 = reverseBits8((h[11] << 24) + (h[10] << 16) + (h[9] << 8) + h[8]);
		uint32_t h3 = reverseBits8((h[15] << 24) + (h[14] << 16) + (h[13] << 8) + h[12]);

		((uint32_t*)&sourceH)[0] = h0;
		((uint32_t*)&sourceH)[1] = h1;
		((uint32_t*)&sourceH)[2] = h2;
		((uint32_t*)&sourceH)[3] = h3;
	}

	// Reverse bits for X
	{
		uint32_t x0 = reverseBits8((x[3] << 24) + (x[2] << 16) + (x[1] << 8) + x[0]);
		uint32_t x1 = reverseBits8((x[7] << 24) + (x[6] << 16) + (x[5] << 8) + x[4]);
		uint32_t x2 = reverseBits8((x[11] << 24) + (x[10] << 16) + (x[9] << 8) + x[8]);
		uint32_t x3 = reverseBits8((x[15] << 24) + (x[14] << 16) + (x[13] << 8) + x[12]);

		((uint32_t*)&sourceX)[0] = x0;
		((uint32_t*)&sourceX)[1] = x1;
		((uint32_t*)&sourceX)[2] = x2;
		((uint32_t*)&sourceX)[3] = x3;
	}

#if 0
	// Multiply -- 4 components
	auto y00 = _mm_clmulepi64_si128(sourceH, sourceX, 0x00);
	auto y01 = _mm_clmulepi64_si128(sourceH, sourceX, 0x01);
	auto y10 = _mm_clmulepi64_si128(sourceH, sourceX, 0x10);
	auto y11 = _mm_clmulepi64_si128(sourceH, sourceX, 0x11);

	// combine two components in the middle
	auto mid = _mm_xor_si128(y01, y10);  // mid = y01 ^ y10;
	auto midsl = _mm_slli_si128(mid, 8); // lo = y00 ^ (mid << 64);
	auto lo = _mm_xor_si128(y00, midsl); //
	auto midsr = _mm_srli_si128(mid, 8); // hi = y11 ^ (mid >> 64);
	auto hi = _mm_xor_si128(y11, midsr); //
#else
	// Kratsuba-like multiplication:
	//
	//   [a:b] * [c:d] = (a*w + b) * (c*w + d) =
	//   a*c*w2 + (a*d + b*c)*w + c*d
	//
	// We need to know a*d + b*c.
	//   
	//   (a + b)*(c + d) = a*c + a*d + b*c + c*d
	//
	// Substitute:  X = a*c, Y = b*d
	//
	//   [a:b] * [c:d] = X*w2 + (a*d + b*c)*w + Y =
	//   X*w2 + Y + w*((a+b)*(c+d) - X - Y)
	// 

	auto y00 = _mm_clmulepi64_si128(sourceH, sourceX, 0x00);
	auto y11 = _mm_clmulepi64_si128(sourceH, sourceX, 0x11);

	auto shufH = _mm_shuffle_epi32(sourceH, _MM_SHUFFLE(1, 0, 3, 2));
	auto shufX = _mm_shuffle_epi32(sourceX, _MM_SHUFFLE(1, 0, 3, 2));

	shufH = _mm_xor_si128(sourceH, shufH);
	shufX = _mm_xor_si128(sourceX, shufX);

	auto ym = _mm_clmulepi64_si128(shufH, shufX, 0x00);
	ym = _mm_xor_si128(ym, y00);
	ym = _mm_xor_si128(ym, y11);

	auto midsl = _mm_slli_si128(ym, 8);
	auto midsr = _mm_srli_si128(ym, 8);

	auto lo = _mm_xor_si128(y00, midsl);
	auto hi = _mm_xor_si128(y11, midsr);
#endif

	// The result is [hi:lo], but we still need to reduce it

	// 
	// Every time we remove a bit from the "hi" part, we also alter bits in the "lo" part. It 
	// might seem that we should simply subtract "hi * r" from the low part, but that's not true.
	// In the process of removing highest bits in the "hi" part, we also alter lower bits of
	// it. What we need to do is predict how we will modify those bits before we can use an
	// entire top part to alter the result.
	// 
	// Let g = r + w^n, where w is our word size and n is arbitrary.
	//
	// GHASH has a very small  r = 1 + x + x^2 + x^7 , which allows us to compute the influence
	// in small blocks of 64 bits. We're basically going to apply the entire method one block
	// at a time:
	//
	//   1) hi' = hi - hi[top 64] * r >> 128
	//      lo' = lo - hi[top 64] * r
	//      -- top 64 are now considered to be cleared
	//
	//   2) lo" = lo' - hi' * r
	//      -- top 128 are now considered to be cleared
	//
	// Because of the limitation of SSE, we can't shift across 64-bit boundaries. This means
	// we have to figure out a SIMD way of doing both operations at the same time. Let's
	// relabel our values with 64 bit-integers.
	//
	//             | remove a      | remove b          | remove a*r/w
	//   hi /  a   | a - a         | a - a             | 
	//      \  b   | b - a*r / w   | b - b - a*r/w     | 
	//   lo /  c   | c - a*r % w   | c - b*r/w - a*r%w | c - b*r/w - a*r%w - a*r*r/w/w
	//      \  d   | d             | d - b*r%w         | d - b*r%w - a*r*r/w%w
	//
	// Note, that a < w and r*r < w (15 bits < 64 bits), which leads to a*r*r/w/w being 0.
	// In the end we get these formulas:
	//
	//   c* = c - b*r/w - a*r%w
	//   d* = d - b*r%w - a*r*r/w%w
	//
	// By introducing b' = b - a*r/w we can simplify a bit:
	//
	//   c* = c - b*r/w - a*r%w
	//   d* = d - b'*r%w
	//
	// There are only 4 bits set in r so we can replace multiplication with shifts and xor. We
	// can perform these operations in two steps:
	//
	//   b' = b - a*r/w = b + (a << 7 >> 64) + (a << 2 >> 64) + (a << 1 >> 64) + (a << 0 >> 64)
	//   c' = c - b*r/w = c + (b << 7 >> 64) + (b << 2 >> 64) + (b << 1 >> 64) + (b << 0 >> 64)
	//   -- note, that the last term evaluates to 0
	//
	//   c* = c' - a*r%w = c' + low64(a << 7) + low64(a << 2) + low64(a << 1) + a
	//   d* = d - b'*r%w = d + low64(b' << 7) + low64(b' << 2) + low64(b' << 1) + b
	//
	// This whole method can also work with 32-bit and 96-bit parts, in which case it can be 
	// applied to 32i*4 vectors, as opposed by 64i*2. I don't know if there is any reason to do
	// this on x64. Intel's reference lists almost identical latencies for both cases.
	//
	auto ab_sh1 = _mm_srli_epi64(hi, 64 - 1); // hi = [a : b]
	auto ab_sh2 = _mm_srli_epi64(hi, 64 - 2);
	auto ab_sh3 = _mm_srli_epi64(hi, 64 - 7);

	ab_sh2 = _mm_xor_si128(ab_sh2, ab_sh1);
	ab_sh3 = _mm_xor_si128(ab_sh2, ab_sh3);

	auto br_hi = _mm_slli_si128(ab_sh3, 8); // [b * r / w :     0    ]
	auto ar_hi = _mm_srli_si128(ab_sh3, 8); // [    0     : a * r / w]

	auto ab_1 = _mm_xor_si128(ar_hi, hi); // [a : b']
	auto c_1_d = _mm_xor_si128(br_hi, lo); // [c' : d]

	auto ab_1_sh1 = _mm_slli_epi64(ab_1, 1);
	auto ab_1_sh2 = _mm_slli_epi64(ab_1, 2);
	auto ab_1_sh3 = _mm_slli_epi64(ab_1, 7);
	ab_1_sh1 = _mm_xor_si128(ab_1_sh2, ab_1_sh1);
	ab_1_sh3 = _mm_xor_si128(ab_1, ab_1_sh3);
	auto ab_r_low = _mm_xor_si128(ab_1_sh1, ab_1_sh3); // [a*r%w : b'*r%w]

	// finally add it to low part
	lo = _mm_xor_si128(ab_r_low, c_1_d); // [c' + a*r%w : d + b'*r%w]

	sourceX = lo;

	// Reverse bits for X
	{
		uint32_t x0 = reverseBits8(((uint32_t*)&sourceX)[0]);
		uint32_t x1 = reverseBits8(((uint32_t*)&sourceX)[1]);
		uint32_t x2 = reverseBits8(((uint32_t*)&sourceX)[2]);
		uint32_t x3 = reverseBits8(((uint32_t*)&sourceX)[3]);

		res[15] = (uint8_t)(x3 >> 24);
		res[14] = (uint8_t)(x3 >> 16);
		res[13] = (uint8_t)(x3 >> 8);
		res[12] = (uint8_t)(x3);
		res[11] = (uint8_t)(x2 >> 24);
		res[10] = (uint8_t)(x2 >> 16);
		res[9] = (uint8_t)(x2 >> 8);
		res[8] = (uint8_t)(x2);
		res[7] = (uint8_t)(x1 >> 24);
		res[6] = (uint8_t)(x1 >> 16);
		res[5] = (uint8_t)(x1 >> 8);
		res[4] = (uint8_t)(x1);
		res[3] = (uint8_t)(x0 >> 24);
		res[2] = (uint8_t)(x0 >> 16);
		res[1] = (uint8_t)(x0 >> 8);
		res[0] = (uint8_t)(x0);
	}
}
