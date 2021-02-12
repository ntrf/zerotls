//
// Ntrf: I'm not claiming copyright on this file. It's an adoptation of some 
//       other work. I've used it only as a reference implementation.
//
// Source can be found here:
//   https://github.com/mko-x/SharedAES-GCM/blob/master/Sources/gcm.c
//
// THIS SOURCE CODE IS HEREBY PLACED INTO THE PUBLIC DOMAIN FOR THE GOOD OF ALL
//
// NO COPYRIGHT IS CLAIMED IN THIS WORK, HOWEVER, NEITHER IS ANY WARRANTY MADE
// REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE. USE IT AT YOUR OWN RISK.
//
// ... or if you're in one of the jurisdictions, that does not recognize work 
// as public domain for alive authors, then apply Apache 2.0 as the rest of 
// the library.
//

static const uint64_t last4[16] = {
	0x0000ULL,
	0x1c20ULL,
	0x3840ULL,
	0x2460ULL,
	0x7080ULL,
	0x6ca0ULL,
	0x48c0ULL,
	0x54e0ULL,
	0xe100ULL,
	0xfd20ULL,
	0xd940ULL,
	0xc560ULL,
	0x9180ULL,
	0x8da0ULL,
	0xa9c0ULL,
	0xb5e0ULL
};

struct GhashContext
{
	uint64_t HH[16];
	uint64_t HL[16];
};

static void gcm_init(GhashContext *ctx, const uint8_t h[16])
{
	int i, j;
	uint64_t hi, lo;
	uint64_t vl, vh;

	hi = bswap32(((const uint32_t*)h)[0]);
	lo = bswap32(((const uint32_t*)h)[1]);
	vh = (uint64_t)hi << 32 | lo;

	hi = bswap32(((const uint32_t*)h)[2]);
	lo = bswap32(((const uint32_t*)h)[3]);
	vl = (uint64_t)hi << 32 | lo;

	ctx->HL[8] = vl;                // 8 = 1000 corresponds to 1 in GF(2^128)
	ctx->HH[8] = vh;
	ctx->HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
	ctx->HL[0] = 0;

	for (i = 4; i > 0; i >>= 1) {
		uint32_t T = (uint32_t)(vl & 1) * 0xe1000000U;
		vl = (vh << 63) | (vl >> 1);
		vh = (vh >> 1) ^ ((uint64_t)T << 32);
		ctx->HL[i] = vl;
		ctx->HH[i] = vh;
	}
	for (i = 2; i < 16; i <<= 1) {
		uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
		vh = *HiH;
		vl = *HiL;
		for (j = 1; j < i; j++) {
			HiH[j] = vh ^ ctx->HH[j];
			HiL[j] = vl ^ ctx->HL[j];
		}
	}
}

static void gcm_mult(GhashContext *ctx,
					 const uint8_t x[16],    // pointer to 128-bit input vector
					 uint8_t output[16])    // pointer to 128-bit output vector
{
	int i;
	uint64_t zh, zl;

	zh = 0;
	zl = 0;

	for (i = 15; i >= 0; i--) {
		int lo = x[i] & 0x0f;

		int rem = zl & 0x0f;
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);
		zh ^= (uint64_t)last4[rem] << 48;
		zh ^= ctx->HH[lo];
		zl ^= ctx->HL[lo];

		int hi = x[i] >> 4;

		rem = (uint8_t)(zl & 0x0f);
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);
		zh ^= (uint64_t)last4[rem] << 48;
		zh ^= ctx->HH[hi];
		zl ^= ctx->HL[hi];
	}
	((uint32_t*)output)[0] = (uint32_t)(zh >> 32ULL);
	((uint32_t*)output)[1] = (uint32_t)(zh);
	((uint32_t*)output)[2] = (uint32_t)(zl >> 32ULL);
	((uint32_t*)output)[3] = (uint32_t)(zl);
}
