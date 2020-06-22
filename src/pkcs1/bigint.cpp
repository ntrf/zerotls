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

/* BIGINT.CPP
 * Montgomery reduction and exponentation
 * This code is used for fast computations of RSA signatures and encryption
 *
 * note: "<x>" means "x is big integer"
 */

#include <string.h>
#include <stdlib.h>

#include "../intutils.h"

#include <assert.h>

#include "bigint.h"

//#define TEST_MODULE

// Context uses one big buffer
//  n : uint32_t[size]
//  t : uint32_t[size + 2]
//  rr : uint32_t[size * 2 + 1]
//  p : uint32_t[size]
//  w : uint32_t[size]
// 
//  TOTAL : uint32_t[size * 6 + 3]

#define N_SIZE(S) ((S))
#define T_SIZE(S) ((S)+2)
#define RR_SIZE(S) ((S)+(S)+1)
#define P_SIZE(S) ((S))
#define W_SIZE(S) ((S))

#define N_OFFSET(S) (0)
#define T_OFFSET(S) (N_OFFSET(S) + N_SIZE(S))
#define RR_OFFSET(S) (T_OFFSET(S) + T_SIZE(S))
#define P_OFFSET(S) (RR_OFFSET(S) + RR_SIZE(S))
#define W_OFFSET(S) (P_OFFSET(S) + P_SIZE(S))
#define TOTAL_CONTEXT_SIZE(S) (W_OFFSET(S) + W_SIZE(S))


MontgomeryReductionContext::MontgomeryReductionContext()
	: size(0)
{}

/// Reduced extended GCD algorithm
/// This implementation is designed for computing
/// (A^{-1} mod W)
/// where W is machine word size. uint32_t in this case
static uint32_t InvModWord(uint32_t a, uint32_t * y)
{
	uint32_t t0 = 0, t1 = 1, tt;

	assert(a != 0);

	// calaulate W - a
	uint32_t b = 0 - a;
	// q will be 1 less
	// so we start with t0 = - t1 * 1
	t0 = -1;

	for (;;) {
		// calculate gdc remainder
		uint32_t r = b % a;
		uint32_t q = b / a;

		if (r == 0) break;

		b = a;
		a = r;

		tt = t0 - t1 * q;

		t0 = t1; t1 = tt;
	}

	*y = t1;

	return b;
}


#define hi64(X) (uint64_t)((uint32_t)((X) >> 32))
#define his64(X) (uint64_t)((int64_t)(int32_t)((X) >> 32))
#define lo64(X) (uint32_t)((X) & 0xFFffFFff)

void MontgomeryReductionContext::MontMul_CIOS(uint32_t * r, const uint32_t * a, const uint32_t * b)
{
	uint32_t i, j;

	uint32_t m;
	uint64_t C;
	
	const uint32_t s = size;

	for (i = 0; i < s + 2; ++i) {
		t[i] = 0;
	}

	for (i = 0; i < s; ++i) {
		uint32_t bi = b[i];

		// compute <t> += <a> * b.i
		C = (uint64_t)t[0] + (uint64_t)a[0] * (uint64_t)bi;
		t[0] = lo64(C);
		for (j = 1; j < s; ++j) {
			C = (uint64_t)t[j] + (uint64_t)a[j] * (uint64_t)bi + hi64(C);
			t[j] = lo64(C);
		}
		C = (uint64_t)t[s] + hi64(C);
		t[s] = lo64(C);
		t[s + 1] = hi64(C);

		// compute m
		m = (t[0] * k);

		// compute <t> += m * <n'>
		//         <t> >>= sizeof(WORD);
		C = (uint64_t)t[0] + (uint64_t)m * (uint64_t)n[0];
		assert(lo64(C) == 0);
		for (j = 1; j < s; ++j) {
			C = (uint64_t)t[j] + (uint64_t)m * (uint64_t)n[j] + hi64(C);
			t[j - 1] = lo64(C);
		}
		C = (uint64_t)t[s] + hi64(C);
		t[s - 1] = lo64(C);
		t[s] = t[s + 1] + hi64(C);
		t[s + 1] = 0;
	}

	// compute <r> = <t> - <n>
	C = 0;
	// subtract
	for (i = 0; i < s; ++i) {
		C = (uint64_t)t[i] - (uint64_t)n[i] + his64(C);
		r[i] = lo64(C);
	}
	C = (uint64_t)t[s] + his64(C);

#if 1
	// constant time
	/*
	high bits of C will be either 0 (if <t> >= <n>) or 0xffFFffFF (otherwise)
	can use C as a mask for result
	*/
	m = his64(C);
	assert(m == 0 || m == ~0);
	for (i = 0; i < s; ++i) r[i] ^= (r[i] ^ t[i]) & m;
#else
	if (lo64(C) == 0) {
		return;
	}

	for (i = 0; i < s; ++i) r[i] = t[i];
#endif

}

void MontgomeryReductionContext::MontDecode_CIOS(uint32_t * r, const uint32_t * a)
{
	uint32_t i, j;

	uint32_t m;
	uint64_t C;

	const uint32_t s = size;

	for (i = 0; i < s + 2; ++i) {
		t[i] = a[i];
	}
	t[s] = 0;
	t[s + 1] = 0;

	for (i = 0; i < s; ++i) {
		// compute m
		m = (t[0] * k);

		// compute <t> += m * <n'>
		//         <t> >>= sizeof(WORD);
		C = (uint64_t)t[0] + (uint64_t)m * (uint64_t)n[0];
		for (j = 1; j < s; ++j) {
			C = (uint64_t)t[j] + (uint64_t)m * (uint64_t)n[j] + hi64(C);
			t[j - 1] = lo64(C);
		}
		C = (uint64_t)t[s] + hi64(C);
		t[s - 1] = lo64(C);
		t[s] = t[s + 1] + hi64(C);
	}

	// compute <r> = <t> - <n>
	C = 0;
	// multiply and subtract
	for (i = 0; i < s; ++i) {
		C = (uint64_t)t[i] - (uint64_t)n[i] + his64(C);
		r[i] = lo64(C);
	}
	C = (uint64_t)t[s] + his64(C);

#if 1
	// constant time
	/*
		high bits of C will be either 0 (if <t> >= <n>) or 0xffFFffFF (otherwise)
		can use C as a mask for result
	*/
	m = his64(C);
	assert(m == 0 || m == ~0);
	for (i = 0; i < s; ++i) r[i] ^= (r[i] ^ t[i]) & m;
#else
	if (lo64(C) == 0) {
		return;
	}

	for (i = 0; i < s; ++i) r[i] = t[i];
#endif
}

#if 1
#  define read64(X) (*(uint64_t*)&(X))
#else
#  define read64(X) \
	((((uint64_t)*((uint32_t*)&(X) + 1)) << 32ULL) + \
	((uint64_t)*((uint32_t*)&(X) + 0)))
#endif

/// Simple remainder computation for big numbers
///
/// computes a = a % v;
/// needs temporary buffer t
static void longmod(uint32_t * a, uint32_t m, uint32_t * v, uint32_t n, uint32_t * t)
{
	uint32_t i;
	int32_t j;

	uint32_t d = v[n - 1];

	uint64_t uX = read64(a[m - 2]);

	for (j = m - n - 1; j >= 0;) {
		if (uX < d) { 
			--j; 
			uX = read64(a[j + n - 1]);
			continue; 
		}

		uint32_t qx;

		// check for quotient overflow
		if ((uX >> 32) > d) {
			qx = 0x7FffFFff;
		} else {
			qx = (uint32_t)(uX / (uint64_t)d);
			uint32_t rx = (uint32_t)(uX - (qx * (uint64_t)d));

			// leave enough digits for any possible divisor
			// this might cause overflow in next iteration
			// Here is how it works:
			//   we know that: 
			//     d = DH * 2^(n) + X
			//   where X < 2^(n), but in worst case X = 2^(n) - 1
			//  
			//   when we subtract worst case divisor we actualy will subtract
			//     u - d * q = u - DH * q * 2^{n} + X * q = 
			//     = u - DH * q * 2^{n} - (2^{n} - 1) * q = 
			//     = UH * 2^{n} + Y - DH * q * 2^{n} - (2^{n} - 1) * q = 
			//     = [we already computed first digit as r = UH - DH * q] =
			//     = r * 2^{n} - 2^{n} * q + 1 * q + Y = 
			//     = (r - q) * 2^{n} + q + Y
			//   So to keep result positive we need to make sure that
			//     r >= q
			//   This prevents 'add back if we subtracted too much' case
			//   but adds additional step at the end and forces qx to overflow
			//
			//   code bellow is effectively the same as:
			//     while (qx > rx) {
			//       qx -= 1; rx += d;
			//     }
			//   but without cycles
			if (qx > rx) {
				qx -= (qx - rx) / (d + 1) + 1;
			}
		}

		uint64_t C = 0;
		uint64_t M = 0;
		// multiply and subtract
		for (i = 0; i < n; ++i) {
			M = (uint64_t)qx * (uint64_t)v[i] + hi64(M);
			C = (uint64_t)a[i + j] - (M & 0xFFffFFff) + his64(C);
			assert((int32_t)(C >> 32) == 0 || (int32_t)(C >> 32) == 0xffFFffFF);
			a[i + j] = lo64(C);
		}
		C = (uint64_t)a[n + j] - hi64(M) + his64(C);
		assert(hi64(C) == 0);
		a[n + j] = lo64(C);
		
		uX = (C << 32ULL) + (uint64_t)a[n + j - 1];
	}

	// we might need no more than 
	// one additional subtraction to make

	uint64_t C = 0;
	// multiply and subtract
	for (i = 0; i < n; ++i) {
		C = (uint64_t)a[i] - (uint64_t)v[i] + his64(C);
		t[i] = lo64(C);
	}
	C = a[n] + his64(C);
	t[n] = lo64(C);

	if (hi64(C) != 0) {
		return;
	}

	for (i = 0; i < n; ++i) a[i] = t[i];
}

size_t MontgomeryReductionContext::GetAllocationSize(unsigned vlen)
{
	return (TOTAL_CONTEXT_SIZE(vlen)) * 4;
}

void MontgomeryReductionContext::Prepare(uint32_t * datablock, const uint8_t * pn, unsigned nlen, unsigned vlen, bool netByteOrder)
{
	//1) reallocate common buffer
	this->n = &datablock[N_OFFSET(vlen)];
	this->t = &datablock[T_OFFSET(vlen)];
	this->rr = &datablock[RR_OFFSET(vlen)];
	this->p = &datablock[P_OFFSET(vlen)];
	this->w = &datablock[W_OFFSET(vlen)];

	this->size = vlen;

	//2) copy new N
	if (!netByteOrder) {
		int rem = sizeof(uint32_t)* vlen - nlen;
		if (rem >= 0) {
			memcpy(this->n, pn, nlen);
			memset(this->n + nlen, 0, rem);
		} else {
			memcpy(this->n, pn, sizeof(uint32_t)* vlen);
		}
	} else {
		// need to extract last (!) vlen * sizeof(uint32_t) bytes from stream
		// those can be unaligned - so we have to process them byte-by-byte.
		//
		// this is what we get for listening to byte order purists
		const unsigned mask = sizeof(uint32_t) - 1;

		uint32_t c = 0;
		uint32_t * wp = this->n;
		unsigned p = nlen;
		for (; p > 3;) {
			if (wp >= &this->n[vlen])
				break;

			p -= 4;
#ifdef TINYTLS_UNALIGNED_MEMORY_ACCESS
			c = bswap32(*(uint32_t*)&pn[p]);
#else
			c = (pn[p] << 24) + (pn[p + 1] << 16) + (pn[p + 2] << 8) + pn[p + 3];
#endif
			*wp++ = c;
		}

		if (wp < &this->n[vlen]) {
			//### bad code
			c = 0;
			for (unsigned x = 0; x < p; ++x) {
				c = (c << 8) + pn[x];
			}
			while (wp < &this->n[vlen]) {
				*wp++ = c;
				c = 0;
			}
		}
	}

	//3) set new R * R
	memset(this->rr, 0, sizeof(uint32_t)* (vlen + vlen));
	this->rr[vlen + vlen] = 1;
	
	//4) calculate new `k`
	// where `k` comes from this relation:
	//   RR^{-1} = 1 (mod N)
	//   RR^{-1} = kN + 1
	// fowever scince we use CIOS algorithm in Montgomery reduction
	// we can use k mod 2^{32} instead
	InvModWord(this->n[0], &k);
	k = 0 - k;

	//5) calculate R^{2} (mod N)
	longmod(this->rr, vlen + vlen + 1, this->n, vlen, t);
}

/// Montgomery exponentation for Fermat numbers
///
/// This function only works for exponents in form 2^{n} + 1.
/// Scince this function works with such narrow subset of all exponents
/// it is not suitable for secret exponentation, but it's usefull for 
/// RSA public-key operations such as signature verification
void MontgomeryReductionContext::ExpMod_Fnum(uint32_t * r, const uint32_t * a, unsigned exponent, bool netByteOrder)
{
	assert((exponent & 1) != 0);
	assert(((exponent - 2) & (exponent)) == 1);

	if (netByteOrder) {
		const uint32_t * rd = &a[size - 1];
		for (unsigned i = 0; i < size; ++i) {
			p[i] = bswap32(*rd--);
		}
		MontMul_CIOS(w, p, rr); // W = Ar
	} else {
		MontMul_CIOS(w, a, rr); // W = Ar
	}

	memcpy(p, w, sizeof(*p) * size);

	for (; exponent >= 2; exponent >>= 1) {
		MontMul_CIOS(p, p, p); // P = P^{2}
	}

	MontMul_CIOS(w, w, p); // W = WP
	if (!netByteOrder) {
		MontDecode_CIOS(r, w); // R = Wr^{-1}
	} else {
		MontDecode_CIOS(p, w); // R = Wr^{-1}
		const uint32_t * rd = &p[size - 1];
		for (unsigned i = 0; i < size; ++i) {
			r[i] = bswap32(*rd--);
		}
	}
}

/// Montgomery exponentation
///
/// This function works for any exponent value
/// Usefull for DH key exchange or client certificate proof
/// UNIMPLEMENTED
void MontgomeryReductionContext::ExpMod(uint32_t * r, const uint32_t * a, const uint32_t * exponent, unsigned explen, bool netByteOrder)
{
	const uint32_t * exp = exponent;

	// we assume exponent has lsb set
	uint32_t run = 0;
	uint32_t mask = 1;

	if (netByteOrder) {
		const uint32_t * rd = &a[size - 1];
		for (unsigned i = 0; i < size; ++i) {
			p[i] = bswap32(*rd--);
		}
		MontMul_CIOS(w, p, rr); // W = Ar
		exp += (explen - 1);
		run = bswap32(*exp);
	} else {
		MontMul_CIOS(w, a, rr); // W = Ar
		run = *exp;
	}

	assert((run & 1) != 0);
	memcpy(p, w, sizeof(*p) * size);

	// #### SIDE CHANNEL ATTACK is possible!
	// #### REWRITE TO TABLE MULTIPLICATION
	if (netByteOrder) {
		for (;;) {
			mask <<= 1;
			if (mask == 0) {
				// load more bits from exponent
				--exp;
				if (exp < exponent) break;
				run = bswap32(*exp);
				mask = 1;
			}

			// generate next power of two
			MontMul_CIOS(p, p, p); // P = P^{2}

			if ((run & mask) != 0) {
				MontMul_CIOS(w, w, p); // W = WP
			}
		}
	} else {
		for (;;) {
			// generate new power of two
			MontMul_CIOS(p, p, p); // P = P^{2}

			mask <<= 1;
			if (mask == 0) {
				// load more bits from exponent
				++exp;
				if (exp >= exponent + explen) break;
				run = *exp;
				mask = 1;
			}

			if ((run & mask) != 0) {
				MontMul_CIOS(w, w, p); // W = WP
			}
		}
	}

	if (!netByteOrder) {
		MontDecode_CIOS(r, w); // R = Wr^{-1}
	} else {
		MontDecode_CIOS(p, w); // R = Wr^{-1}
		const uint32_t * rd = &p[size - 1];
		for (unsigned i = 0; i < size; ++i) {
			r[i] = bswap32(*rd--);
		}
	}
}

#ifdef TEST_MODULE

int main(int argc, char ** argv)
{
	// REMOVED
	return 0;
}

#endif