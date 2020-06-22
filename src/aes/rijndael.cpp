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

#include "../intutils.h"
#include "rijndael.h"

#include "aes_tables.h"

static const uint32_t rcon[] =
{
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000,
};

const uint32_t M1 = 0x000000FF;
const uint32_t M2 = 0x0000FF00;
const uint32_t M3 = 0x00FF0000;
const uint32_t M4 = 0xFF000000;

int rijndaelSetupEncrypt(uint32_t * expkey, const uint32_t * key, int keybits)
{
	uint32_t round = 0;
	uint32_t lk;

	int i = 0;

	expkey[0] = bswap32(key[0]);
	expkey[1] = bswap32(key[1]);
	expkey[2] = bswap32(key[2]);
	expkey[3] = bswap32(key[3]);

	if (keybits == 128) {
		const int N = 4;

		lk = expkey[N - 1];

		for (; i < 10; ++i) {
			lk = (EncTabN[(lk >> 16) & 0xff] & M4) ^ (EncTabN[(lk >> 8) & 0xff] & M3) ^ (EncTabN[lk & 0xff] & M2) ^ (EncTabN[lk >> 24] & M1) ^ rcon[i];
			expkey[N + 0] = (lk ^= expkey[0]);
			expkey[N + 1] = (lk ^= expkey[1]);
			expkey[N + 2] = (lk ^= expkey[2]);
			expkey[N + 3] = (lk ^= expkey[3]);

			expkey += N;
		}
		return 10;
	}
	return 0;
}

int rijndaelSetupDecrypt(uint32_t *expkey, const uint32_t *key, int keybits)
{
	int nrounds, i, j;
	uint32_t temp;

	// expand the cipher key:
	nrounds = rijndaelSetupEncrypt(expkey, key, keybits);

	// invert the order of the round keys:
	for (i = 0, j = 4 * nrounds; i < j; i += 4, j -= 4) {
		temp = expkey[i]; expkey[i] = expkey[j]; expkey[j] = temp;
		temp = expkey[i + 1]; expkey[i + 1] = expkey[j + 1]; expkey[j + 1] = temp;
		temp = expkey[i + 2]; expkey[i + 2] = expkey[j + 2]; expkey[j + 2] = temp;
		temp = expkey[i + 3]; expkey[i + 3] = expkey[j + 3]; expkey[j + 3] = temp;
	}

	// apply the inverse MixColumn transform to all round keys but the first and the last:
	for (i = 1; i < nrounds; i++) {
		expkey += 4;
		expkey[0] =
			DeTab4[EncTabN[(expkey[0] >> 24)] & 0xff] ^
			DeTab3[EncTabN[(expkey[0] >> 16) & 0xff] & 0xff] ^
			DeTab2[EncTabN[(expkey[0] >> 8) & 0xff] & 0xff] ^
			DeTab1[EncTabN[(expkey[0]) & 0xff] & 0xff];
		expkey[1] =
			DeTab4[EncTabN[(expkey[1] >> 24)] & 0xff] ^
			DeTab3[EncTabN[(expkey[1] >> 16) & 0xff] & 0xff] ^
			DeTab2[EncTabN[(expkey[1] >> 8) & 0xff] & 0xff] ^
			DeTab1[EncTabN[(expkey[1]) & 0xff] & 0xff];
		expkey[2] =
			DeTab4[EncTabN[(expkey[2] >> 24)] & 0xff] ^
			DeTab3[EncTabN[(expkey[2] >> 16) & 0xff] & 0xff] ^
			DeTab2[EncTabN[(expkey[2] >> 8) & 0xff] & 0xff] ^
			DeTab1[EncTabN[(expkey[2]) & 0xff] & 0xff];
		expkey[3] =
			DeTab4[EncTabN[(expkey[3] >> 24)] & 0xff] ^
			DeTab3[EncTabN[(expkey[3] >> 16) & 0xff] & 0xff] ^
			DeTab2[EncTabN[(expkey[3] >> 8) & 0xff] & 0xff] ^
			DeTab1[EncTabN[(expkey[3]) & 0xff] & 0xff];
	}
	return nrounds;
}

void rijndaelEncrypt(const uint32_t * k, int nrounds, const uint8_t inp[16], uint8_t outp[16])
{
	uint32_t a0, b0, c0, d0, a1, b1, c1, d1;

	a0 = bswap32(*(uint32_t*)(inp + 0)) ^ k[0];
	b0 = bswap32(*(uint32_t*)(inp + 4)) ^ k[1];
	c0 = bswap32(*(uint32_t*)(inp + 8)) ^ k[2];
	d0 = bswap32(*(uint32_t*)(inp + 12)) ^ k[3];

	// round 1:
	a1 = EncTab4[a0 >> 24] ^ EncTab3[(b0 >> 16) & 0xff] ^ EncTab2[(c0 >> 8) & 0xff] ^ EncTab1[d0 & 0xff] ^ k[4];
	b1 = EncTab4[b0 >> 24] ^ EncTab3[(c0 >> 16) & 0xff] ^ EncTab2[(d0 >> 8) & 0xff] ^ EncTab1[a0 & 0xff] ^ k[5];
	c1 = EncTab4[c0 >> 24] ^ EncTab3[(d0 >> 16) & 0xff] ^ EncTab2[(a0 >> 8) & 0xff] ^ EncTab1[b0 & 0xff] ^ k[6];
	d1 = EncTab4[d0 >> 24] ^ EncTab3[(a0 >> 16) & 0xff] ^ EncTab2[(b0 >> 8) & 0xff] ^ EncTab1[c0 & 0xff] ^ k[7];
	k += 8;
	// round 2:
	a0 = EncTab4[a1 >> 24] ^ EncTab3[(b1 >> 16) & 0xff] ^ EncTab2[(c1 >> 8) & 0xff] ^ EncTab1[d1 & 0xff] ^ k[0];
	b0 = EncTab4[b1 >> 24] ^ EncTab3[(c1 >> 16) & 0xff] ^ EncTab2[(d1 >> 8) & 0xff] ^ EncTab1[a1 & 0xff] ^ k[1];
	c0 = EncTab4[c1 >> 24] ^ EncTab3[(d1 >> 16) & 0xff] ^ EncTab2[(a1 >> 8) & 0xff] ^ EncTab1[b1 & 0xff] ^ k[2];
	d0 = EncTab4[d1 >> 24] ^ EncTab3[(a1 >> 16) & 0xff] ^ EncTab2[(b1 >> 8) & 0xff] ^ EncTab1[c1 & 0xff] ^ k[3];

	// round 3:
	a1 = EncTab4[a0 >> 24] ^ EncTab3[(b0 >> 16) & 0xff] ^ EncTab2[(c0 >> 8) & 0xff] ^ EncTab1[d0 & 0xff] ^ k[4];
	b1 = EncTab4[b0 >> 24] ^ EncTab3[(c0 >> 16) & 0xff] ^ EncTab2[(d0 >> 8) & 0xff] ^ EncTab1[a0 & 0xff] ^ k[5];
	c1 = EncTab4[c0 >> 24] ^ EncTab3[(d0 >> 16) & 0xff] ^ EncTab2[(a0 >> 8) & 0xff] ^ EncTab1[b0 & 0xff] ^ k[6];
	d1 = EncTab4[d0 >> 24] ^ EncTab3[(a0 >> 16) & 0xff] ^ EncTab2[(b0 >> 8) & 0xff] ^ EncTab1[c0 & 0xff] ^ k[7];
	k += 8;
	// round 4:
	a0 = EncTab4[a1 >> 24] ^ EncTab3[(b1 >> 16) & 0xff] ^ EncTab2[(c1 >> 8) & 0xff] ^ EncTab1[d1 & 0xff] ^ k[0];
	b0 = EncTab4[b1 >> 24] ^ EncTab3[(c1 >> 16) & 0xff] ^ EncTab2[(d1 >> 8) & 0xff] ^ EncTab1[a1 & 0xff] ^ k[1];
	c0 = EncTab4[c1 >> 24] ^ EncTab3[(d1 >> 16) & 0xff] ^ EncTab2[(a1 >> 8) & 0xff] ^ EncTab1[b1 & 0xff] ^ k[2];
	d0 = EncTab4[d1 >> 24] ^ EncTab3[(a1 >> 16) & 0xff] ^ EncTab2[(b1 >> 8) & 0xff] ^ EncTab1[c1 & 0xff] ^ k[3];

	// round 5:
	a1 = EncTab4[a0 >> 24] ^ EncTab3[(b0 >> 16) & 0xff] ^ EncTab2[(c0 >> 8) & 0xff] ^ EncTab1[d0 & 0xff] ^ k[4];
	b1 = EncTab4[b0 >> 24] ^ EncTab3[(c0 >> 16) & 0xff] ^ EncTab2[(d0 >> 8) & 0xff] ^ EncTab1[a0 & 0xff] ^ k[5];
	c1 = EncTab4[c0 >> 24] ^ EncTab3[(d0 >> 16) & 0xff] ^ EncTab2[(a0 >> 8) & 0xff] ^ EncTab1[b0 & 0xff] ^ k[6];
	d1 = EncTab4[d0 >> 24] ^ EncTab3[(a0 >> 16) & 0xff] ^ EncTab2[(b0 >> 8) & 0xff] ^ EncTab1[c0 & 0xff] ^ k[7];
	k += 8;
	// round 6:
	a0 = EncTab4[a1 >> 24] ^ EncTab3[(b1 >> 16) & 0xff] ^ EncTab2[(c1 >> 8) & 0xff] ^ EncTab1[d1 & 0xff] ^ k[0];
	b0 = EncTab4[b1 >> 24] ^ EncTab3[(c1 >> 16) & 0xff] ^ EncTab2[(d1 >> 8) & 0xff] ^ EncTab1[a1 & 0xff] ^ k[1];
	c0 = EncTab4[c1 >> 24] ^ EncTab3[(d1 >> 16) & 0xff] ^ EncTab2[(a1 >> 8) & 0xff] ^ EncTab1[b1 & 0xff] ^ k[2];
	d0 = EncTab4[d1 >> 24] ^ EncTab3[(a1 >> 16) & 0xff] ^ EncTab2[(b1 >> 8) & 0xff] ^ EncTab1[c1 & 0xff] ^ k[3];

	// round 7:
	a1 = EncTab4[a0 >> 24] ^ EncTab3[(b0 >> 16) & 0xff] ^ EncTab2[(c0 >> 8) & 0xff] ^ EncTab1[d0 & 0xff] ^ k[4];
	b1 = EncTab4[b0 >> 24] ^ EncTab3[(c0 >> 16) & 0xff] ^ EncTab2[(d0 >> 8) & 0xff] ^ EncTab1[a0 & 0xff] ^ k[5];
	c1 = EncTab4[c0 >> 24] ^ EncTab3[(d0 >> 16) & 0xff] ^ EncTab2[(a0 >> 8) & 0xff] ^ EncTab1[b0 & 0xff] ^ k[6];
	d1 = EncTab4[d0 >> 24] ^ EncTab3[(a0 >> 16) & 0xff] ^ EncTab2[(b0 >> 8) & 0xff] ^ EncTab1[c0 & 0xff] ^ k[7];
	k += 8;
	// round 8:
	a0 = EncTab4[a1 >> 24] ^ EncTab3[(b1 >> 16) & 0xff] ^ EncTab2[(c1 >> 8) & 0xff] ^ EncTab1[d1 & 0xff] ^ k[0];
	b0 = EncTab4[b1 >> 24] ^ EncTab3[(c1 >> 16) & 0xff] ^ EncTab2[(d1 >> 8) & 0xff] ^ EncTab1[a1 & 0xff] ^ k[1];
	c0 = EncTab4[c1 >> 24] ^ EncTab3[(d1 >> 16) & 0xff] ^ EncTab2[(a1 >> 8) & 0xff] ^ EncTab1[b1 & 0xff] ^ k[2];
	d0 = EncTab4[d1 >> 24] ^ EncTab3[(a1 >> 16) & 0xff] ^ EncTab2[(b1 >> 8) & 0xff] ^ EncTab1[c1 & 0xff] ^ k[3];

	// round 9:
	a1 = EncTab4[a0 >> 24] ^ EncTab3[(b0 >> 16) & 0xff] ^ EncTab2[(c0 >> 8) & 0xff] ^ EncTab1[d0 & 0xff] ^ k[4];
	b1 = EncTab4[b0 >> 24] ^ EncTab3[(c0 >> 16) & 0xff] ^ EncTab2[(d0 >> 8) & 0xff] ^ EncTab1[a0 & 0xff] ^ k[5];
	c1 = EncTab4[c0 >> 24] ^ EncTab3[(d0 >> 16) & 0xff] ^ EncTab2[(a0 >> 8) & 0xff] ^ EncTab1[b0 & 0xff] ^ k[6];
	d1 = EncTab4[d0 >> 24] ^ EncTab3[(a0 >> 16) & 0xff] ^ EncTab2[(b0 >> 8) & 0xff] ^ EncTab1[c0 & 0xff] ^ k[7];
	k += 8;

	// round 10: last round
	a0 = (EncTabN[a1 >> 24] & M4) ^ (EncTabN[(b1 >> 16) & 0xff] & M3) ^ (EncTabN[(c1 >> 8) & 0xff] & M2) ^ (EncTabN[d1 & 0xff] & M1) ^ k[0];
	b0 = (EncTabN[b1 >> 24] & M4) ^ (EncTabN[(c1 >> 16) & 0xff] & M3) ^ (EncTabN[(d1 >> 8) & 0xff] & M2) ^ (EncTabN[a1 & 0xff] & M1) ^ k[1];
	c0 = (EncTabN[c1 >> 24] & M4) ^ (EncTabN[(d1 >> 16) & 0xff] & M3) ^ (EncTabN[(a1 >> 8) & 0xff] & M2) ^ (EncTabN[b1 & 0xff] & M1) ^ k[2];
	d0 = (EncTabN[d1 >> 24] & M4) ^ (EncTabN[(a1 >> 16) & 0xff] & M3) ^ (EncTabN[(b1 >> 8) & 0xff] & M2) ^ (EncTabN[c1 & 0xff] & M1) ^ k[3];

	*(uint32_t*)(outp + 0) = bswap32(a0);
	*(uint32_t*)(outp + 4) = bswap32(b0);
	*(uint32_t*)(outp + 8) = bswap32(c0);
	*(uint32_t*)(outp + 12) = bswap32(d0);
}

void rijndaelDecrypt(const uint32_t * k, int nrounds, const uint8_t inp[16], uint8_t outp[16])
{
	uint32_t a0, b0, c0, d0, a1, b1, c1, d1;

	a0 = bswap32(*(uint32_t*)(inp + 0)) ^ k[0];
	b0 = bswap32(*(uint32_t*)(inp + 4)) ^ k[1];
	c0 = bswap32(*(uint32_t*)(inp + 8)) ^ k[2];
	d0 = bswap32(*(uint32_t*)(inp + 12)) ^ k[3];

	// round 1:
	a1 = DeTab4[a0 >> 24] ^ DeTab3[(d0 >> 16) & 0xff] ^ DeTab2[(c0 >> 8) & 0xff] ^ DeTab1[b0 & 0xff] ^ k[4];
	b1 = DeTab4[b0 >> 24] ^ DeTab3[(a0 >> 16) & 0xff] ^ DeTab2[(d0 >> 8) & 0xff] ^ DeTab1[c0 & 0xff] ^ k[5];
	c1 = DeTab4[c0 >> 24] ^ DeTab3[(b0 >> 16) & 0xff] ^ DeTab2[(a0 >> 8) & 0xff] ^ DeTab1[d0 & 0xff] ^ k[6];
	d1 = DeTab4[d0 >> 24] ^ DeTab3[(c0 >> 16) & 0xff] ^ DeTab2[(b0 >> 8) & 0xff] ^ DeTab1[a0 & 0xff] ^ k[7];
	k += 8;
	// round 2:
	a0 = DeTab4[a1 >> 24] ^ DeTab3[(d1 >> 16) & 0xff] ^ DeTab2[(c1 >> 8) & 0xff] ^ DeTab1[b1 & 0xff] ^ k[0];
	b0 = DeTab4[b1 >> 24] ^ DeTab3[(a1 >> 16) & 0xff] ^ DeTab2[(d1 >> 8) & 0xff] ^ DeTab1[c1 & 0xff] ^ k[1];
	c0 = DeTab4[c1 >> 24] ^ DeTab3[(b1 >> 16) & 0xff] ^ DeTab2[(a1 >> 8) & 0xff] ^ DeTab1[d1 & 0xff] ^ k[2];
	d0 = DeTab4[d1 >> 24] ^ DeTab3[(c1 >> 16) & 0xff] ^ DeTab2[(b1 >> 8) & 0xff] ^ DeTab1[a1 & 0xff] ^ k[3];

	// round 3:
	a1 = DeTab4[a0 >> 24] ^ DeTab3[(d0 >> 16) & 0xff] ^ DeTab2[(c0 >> 8) & 0xff] ^ DeTab1[b0 & 0xff] ^ k[4];
	b1 = DeTab4[b0 >> 24] ^ DeTab3[(a0 >> 16) & 0xff] ^ DeTab2[(d0 >> 8) & 0xff] ^ DeTab1[c0 & 0xff] ^ k[5];
	c1 = DeTab4[c0 >> 24] ^ DeTab3[(b0 >> 16) & 0xff] ^ DeTab2[(a0 >> 8) & 0xff] ^ DeTab1[d0 & 0xff] ^ k[6];
	d1 = DeTab4[d0 >> 24] ^ DeTab3[(c0 >> 16) & 0xff] ^ DeTab2[(b0 >> 8) & 0xff] ^ DeTab1[a0 & 0xff] ^ k[7];
	k += 8;
	// round 4:
	a0 = DeTab4[a1 >> 24] ^ DeTab3[(d1 >> 16) & 0xff] ^ DeTab2[(c1 >> 8) & 0xff] ^ DeTab1[b1 & 0xff] ^ k[0];
	b0 = DeTab4[b1 >> 24] ^ DeTab3[(a1 >> 16) & 0xff] ^ DeTab2[(d1 >> 8) & 0xff] ^ DeTab1[c1 & 0xff] ^ k[1];
	c0 = DeTab4[c1 >> 24] ^ DeTab3[(b1 >> 16) & 0xff] ^ DeTab2[(a1 >> 8) & 0xff] ^ DeTab1[d1 & 0xff] ^ k[2];
	d0 = DeTab4[d1 >> 24] ^ DeTab3[(c1 >> 16) & 0xff] ^ DeTab2[(b1 >> 8) & 0xff] ^ DeTab1[a1 & 0xff] ^ k[3];

	// round 5:
	a1 = DeTab4[a0 >> 24] ^ DeTab3[(d0 >> 16) & 0xff] ^ DeTab2[(c0 >> 8) & 0xff] ^ DeTab1[b0 & 0xff] ^ k[4];
	b1 = DeTab4[b0 >> 24] ^ DeTab3[(a0 >> 16) & 0xff] ^ DeTab2[(d0 >> 8) & 0xff] ^ DeTab1[c0 & 0xff] ^ k[5];
	c1 = DeTab4[c0 >> 24] ^ DeTab3[(b0 >> 16) & 0xff] ^ DeTab2[(a0 >> 8) & 0xff] ^ DeTab1[d0 & 0xff] ^ k[6];
	d1 = DeTab4[d0 >> 24] ^ DeTab3[(c0 >> 16) & 0xff] ^ DeTab2[(b0 >> 8) & 0xff] ^ DeTab1[a0 & 0xff] ^ k[7];
	k += 8;
	// round 6:
	a0 = DeTab4[a1 >> 24] ^ DeTab3[(d1 >> 16) & 0xff] ^ DeTab2[(c1 >> 8) & 0xff] ^ DeTab1[b1 & 0xff] ^ k[0];
	b0 = DeTab4[b1 >> 24] ^ DeTab3[(a1 >> 16) & 0xff] ^ DeTab2[(d1 >> 8) & 0xff] ^ DeTab1[c1 & 0xff] ^ k[1];
	c0 = DeTab4[c1 >> 24] ^ DeTab3[(b1 >> 16) & 0xff] ^ DeTab2[(a1 >> 8) & 0xff] ^ DeTab1[d1 & 0xff] ^ k[2];
	d0 = DeTab4[d1 >> 24] ^ DeTab3[(c1 >> 16) & 0xff] ^ DeTab2[(b1 >> 8) & 0xff] ^ DeTab1[a1 & 0xff] ^ k[3];

	// round 7:
	a1 = DeTab4[a0 >> 24] ^ DeTab3[(d0 >> 16) & 0xff] ^ DeTab2[(c0 >> 8) & 0xff] ^ DeTab1[b0 & 0xff] ^ k[4];
	b1 = DeTab4[b0 >> 24] ^ DeTab3[(a0 >> 16) & 0xff] ^ DeTab2[(d0 >> 8) & 0xff] ^ DeTab1[c0 & 0xff] ^ k[5];
	c1 = DeTab4[c0 >> 24] ^ DeTab3[(b0 >> 16) & 0xff] ^ DeTab2[(a0 >> 8) & 0xff] ^ DeTab1[d0 & 0xff] ^ k[6];
	d1 = DeTab4[d0 >> 24] ^ DeTab3[(c0 >> 16) & 0xff] ^ DeTab2[(b0 >> 8) & 0xff] ^ DeTab1[a0 & 0xff] ^ k[7];
	k += 8;
	// round 8:
	a0 = DeTab4[a1 >> 24] ^ DeTab3[(d1 >> 16) & 0xff] ^ DeTab2[(c1 >> 8) & 0xff] ^ DeTab1[b1 & 0xff] ^ k[0];
	b0 = DeTab4[b1 >> 24] ^ DeTab3[(a1 >> 16) & 0xff] ^ DeTab2[(d1 >> 8) & 0xff] ^ DeTab1[c1 & 0xff] ^ k[1];
	c0 = DeTab4[c1 >> 24] ^ DeTab3[(b1 >> 16) & 0xff] ^ DeTab2[(a1 >> 8) & 0xff] ^ DeTab1[d1 & 0xff] ^ k[2];
	d0 = DeTab4[d1 >> 24] ^ DeTab3[(c1 >> 16) & 0xff] ^ DeTab2[(b1 >> 8) & 0xff] ^ DeTab1[a1 & 0xff] ^ k[3];

	// round 9:
	a1 = DeTab4[a0 >> 24] ^ DeTab3[(d0 >> 16) & 0xff] ^ DeTab2[(c0 >> 8) & 0xff] ^ DeTab1[b0 & 0xff] ^ k[4];
	b1 = DeTab4[b0 >> 24] ^ DeTab3[(a0 >> 16) & 0xff] ^ DeTab2[(d0 >> 8) & 0xff] ^ DeTab1[c0 & 0xff] ^ k[5];
	c1 = DeTab4[c0 >> 24] ^ DeTab3[(b0 >> 16) & 0xff] ^ DeTab2[(a0 >> 8) & 0xff] ^ DeTab1[d0 & 0xff] ^ k[6];
	d1 = DeTab4[d0 >> 24] ^ DeTab3[(c0 >> 16) & 0xff] ^ DeTab2[(b0 >> 8) & 0xff] ^ DeTab1[a0 & 0xff] ^ k[7];
	k += 8;

	// round 10: last round
	a0 = (DeTabN[a1 >> 24] & M4) ^ (DeTabN[(d1 >> 16) & 0xff] & M3) ^ (DeTabN[(c1 >> 8) & 0xff] & M2) ^ (DeTabN[b1 & 0xff] & M1) ^ k[0];
	b0 = (DeTabN[b1 >> 24] & M4) ^ (DeTabN[(a1 >> 16) & 0xff] & M3) ^ (DeTabN[(d1 >> 8) & 0xff] & M2) ^ (DeTabN[c1 & 0xff] & M1) ^ k[1];
	c0 = (DeTabN[c1 >> 24] & M4) ^ (DeTabN[(b1 >> 16) & 0xff] & M3) ^ (DeTabN[(a1 >> 8) & 0xff] & M2) ^ (DeTabN[d1 & 0xff] & M1) ^ k[2];
	d0 = (DeTabN[d1 >> 24] & M4) ^ (DeTabN[(c1 >> 16) & 0xff] & M3) ^ (DeTabN[(b1 >> 8) & 0xff] & M2) ^ (DeTabN[a1 & 0xff] & M1) ^ k[3];

	*(uint32_t*)(outp + 0) = bswap32(a0);
	*(uint32_t*)(outp + 4) = bswap32(b0);
	*(uint32_t*)(outp + 8) = bswap32(c0);
	*(uint32_t*)(outp + 12) = bswap32(d0);
}
