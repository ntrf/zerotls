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


#ifndef TINYTLS_BIGINT_H_
#define TINYTLS_BIGINT_H_

#include <stdint.h>

struct MontgomeryReductionContext
{
	uint32_t size;

	uint32_t k;

	uint32_t * n;  // stores modulus
	uint32_t * t;  // temporary buffer for redution
	uint32_t * rr; // R^{2} (mod N), used for transforming values into Montgomery form
	uint32_t * p;  // temporary buffer for exponentation function
	uint32_t * w;  // temporary buffer for exponentation function

	MontgomeryReductionContext();

	static size_t GetAllocationSize(unsigned vlen);

	void MontMul_CIOS(uint32_t * r, const uint32_t * a, const uint32_t * b);
	void MontDecode_CIOS(uint32_t * r, const uint32_t * a);

	void Prepare(uint32_t * datablock, const uint8_t * n, unsigned nlen, unsigned vlen, bool netByteOrder = false);

	void ExpMod_Fnum(uint32_t * r, const uint32_t * a, unsigned exponent, bool netByteOrder = false);
	void ExpMod(uint32_t * r, const uint32_t * a, const uint32_t * exponent, unsigned explen, bool netByteOrder = false);
};

#endif