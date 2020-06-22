/*
tinyTLS project

Copyright 2014 Nesterov A.

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

// S-box taken form "Federal Information Processing Standards Publication 197"
// http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
var fwd_s_box = [
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];

var rev_s_box = new Array(256);
for (var i = 0; i < 256; ++i) {
	rev_s_box[fwd_s_box[i]] = i;
}

//Rijndael round is:
// - SubBytes (using tables above)
// - ShiftRows
// - MixColumns
// - AddRoundKey

// we can combine theese operations into a series of table substitutions:

//     s_box_expand(x) => sbox(x.4) << 24 | sbox(x.3) << 16 | sbox(x.2) << 8 | sbox(x.1);
//     SubBytes([a, b, c, d]) => [s_box_expand(a), s_box_expand(b), sbox_expand(c), sbox_expand(d)];

//     ShiftRows([a, b, c, d]) => [
//	    	(d.4 << 24) + (c.3 << 16) + (b.2 << 8) + (a.1),
//	    	(a.4 << 24) + (d.3 << 16) + (c.2 << 8) + (b.1),
//	    	(b.4 << 24) + (a.3 << 16) + (d.2 << 8) + (c.1),
//	    	(c.4 << 24) + (b.3 << 16) + (a.2 << 8) + (d.1)
//	    ]
       
//     mix_column(x) => mult_matrix([2,3,1,1, 1,2,3,1, 1,1,2,3, 3,1,1,2], x)
//     MixColumns([a, b, c, d]) => [mix_column(a), mix_column(b), mix_column(c), mix_column(d)];

// now let's put it all together:
//     mix4(x) => mult_vector([2,1,1,3], x)
//     mix3(x) => mult_vector([3,2,1,1], x)
//     mix2(x) => mult_vector([1,3,2,1], x)
//     mix1(x) => mult_vector([1,1,3,2], x)
//     mix_column(x) => mix4(x.4) ^ mix3(x.3) ^ mix2(x.2) ^ mix1(x.1)
//     ShiftRows_MixColumns([a, b, c, d]) => [
//	    	mix4(d.4) ^ mix3(c.3) ^ mix2(b.2) ^ mix1(a.1),
//	    	mix4(a.4) ^ mix3(d.3) ^ mix2(c.2) ^ mix1(b.1),
//	    	mix4(b.4) ^ mix3(a.3) ^ mix2(d.2) ^ mix1(c.1),
//	    	mix4(c.4) ^ mix3(b.3) ^ mix2(a.2) ^ mix1(d.1)
//     ]
//     
//     SubBytes_ShiftRows_MixColumns([a, b, c, d]) => [
//	    	mix4(sbox(d.4)) ^ mix3(sbox(c.3)) ^ mix2(sbox(b.2)) ^ mix1(sbox(a.1)),
//	    	mix4(sbox(a.4)) ^ mix3(sbox(d.3)) ^ mix2(sbox(c.2)) ^ mix1(sbox(b.1)),
//	    	mix4(sbox(b.4)) ^ mix3(sbox(a.3)) ^ mix2(sbox(d.2)) ^ mix1(sbox(c.1)),
//	    	mix4(sbox(c.4)) ^ mix3(sbox(b.3)) ^ mix2(sbox(a.2)) ^ mix1(sbox(d.1))
//     ]

//     smix4(x) => mult_vector([2,1,1,3], sbox(x))
//     smix3(x) => mult_vector([3,2,1,1], sbox(x))
//     smix2(x) => mult_vector([1,3,2,1], sbox(x))
//     smix1(x) => mult_vector([1,1,3,2], sbox(x))
//     SubBytes_ShiftRows_MixColumns([a, b, c, d]) => [
//	    	smix4(d.4) ^ smix3(c.3) ^ smix2(b.2) ^ smix1(a.1),
//	    	smix4(a.4) ^ smix3(d.3) ^ smix2(c.2) ^ smix1(b.1),
//	    	smix4(b.4) ^ smix3(a.3) ^ smix2(d.2) ^ smix1(c.1),
//	    	smix4(c.4) ^ smix3(b.3) ^ smix2(a.2) ^ smix1(d.1)
//     ]

var gentable = function(fn) {
	var table = [];
	for(var i = 0; i < 256; ++i) {
		table.push(fn(i));
	}
	return table;
};

function hex(number) {
    if (number < 0) {
    	number = 0xFFFFFFFF + number + 1;
    }
    var r = number.toString(16);
	while(r.length < 8) {
		r = '0' + r;
	}
	return r;
}

var mul2 = function(x) { return (((x & 0x80) ? 0x1b : 0) ^ (x << 1)) & 0xFF; }
var mul3 = function(x) { return (((x & 0x80) ? 0x1b : 0) ^ (x << 1) ^ x) & 0xFF; }

var smix1 = function(k) { var x = fwd_s_box[k & 0xff]; return (mul2(x)) ^ (mul3(x) << 8) ^ (x << 16) ^ (x << 24); }
var smix2 = function(k) { var x = fwd_s_box[k & 0xff]; return (x) ^ (mul2(x) << 8) ^ (mul3(x) << 16) ^ (x << 24); }
var smix3 = function(k) { var x = fwd_s_box[k & 0xff]; return (x) ^ (x << 8) ^ (mul2(x) << 16) ^ (mul3(x) << 24); }
var smix4 = function(k) { var x = fwd_s_box[k & 0xff]; return (mul3(x)) ^ (x << 8) ^ (x << 16) ^ (mul2(x) << 24); }

var snomix = function(k) { var x = fwd_s_box[k & 0xff]; return (x) ^ (x << 8) ^ (x << 16) ^ (x << 24); }

var smix1_table = gentable(smix1);
var smix2_table = gentable(smix2);
var smix3_table = gentable(smix3);
var smix4_table = gentable(smix4);
var smix5_table = gentable(snomix);

// Inverse is a bit more complex:
// Inverse round is:
//   - AddRoundKey
//   - InvMixColumns
//   - InvShiftRows
//   - InvSubBytes
// But we are not taking this path. Instead we use a different order:
//   - InvMixColumns
//   - AddMixedRoundKey
//   - InvShiftRows
//   - InvSubBytes
// Key is pre-transformed with InvMixColumns. Now We borrow operations form previous rounds:
//    === round 1 ===
//    - AddRoundKey
//    - InvShiftRows     -.
//    - InvSubBytes       | 
//    === round 2 ===     | we now use this operations as "reverese round"
//    - InvMixColumns     |
//    - AddMixedRoundKey -'
// Scince SubBytes and ShiftRows are independent operations we can swap them:
//    - InvSubBytes
//    - InvShiftRows
//    - InvMixColumns
// And this is almost the same as forward round
//     ismix4(x) => mult_vector([14,9,13,11], isbox(x))
//     ismix3(x) => mult_vector([11,14,9,13], isbox(x))
//     ismix2(x) => mult_vector([13,11,14,9], isbox(x))
//     ismix1(x) => mult_vector([9,13,11,14], isbox(x))
//     InvSubBytes_InvShiftRows_InvMixColumns([a, b, c, d]) => [
//	    	ismix4(b.4) ^ ismix3(c.3) ^ ismix2(d.2) ^ ismix1(a.1),
//	    	ismix4(c.4) ^ ismix3(d.3) ^ ismix2(a.2) ^ ismix1(b.1),
//	    	ismix4(d.4) ^ ismix3(a.3) ^ ismix2(b.2) ^ ismix1(c.1),
//	    	ismix4(a.4) ^ ismix3(b.3) ^ ismix2(c.2) ^ ismix1(d.1)
//     ]

var mul9 = function(x) { return mul2(mul2(mul2(x))) ^ x; }
var mul11 = function(x) { return mul2(mul2(mul2(x))) ^ mul2(x) ^ x; }
var mul13 = function(x) { return mul2(mul2(mul2(x))) ^ mul2(mul2(x)) ^ x; }
var mul14 = function(x) { return mul2(mul2(mul2(x))) ^ mul2(mul2(x)) ^ mul2(x); }

var ismix1 = function(k) { var x = rev_s_box[k & 0xff]; return (mul14(x)) ^ (mul11(x) << 8) ^ (mul13(x) << 16) ^ (mul9(x) << 24); }
var ismix2 = function(k) { var x = rev_s_box[k & 0xff]; return (mul9(x)) ^ (mul14(x) << 8) ^ (mul11(x) << 16) ^ (mul13(x) << 24); }
var ismix3 = function(k) { var x = rev_s_box[k & 0xff]; return (mul13(x)) ^ (mul9(x) << 8) ^ (mul14(x) << 16) ^ (mul11(x) << 24); }
var ismix4 = function(k) { var x = rev_s_box[k & 0xff]; return (mul11(x)) ^ (mul13(x) << 8) ^ (mul9(x) << 16) ^ (mul14(x) << 24); }

var isnomix = function(k) { var x = rev_s_box[k & 0xff]; return (x) ^ (x << 8) ^ (x << 16) ^ (x << 24); }

var ismix1_table = gentable(ismix1);
var ismix2_table = gentable(ismix2);
var ismix3_table = gentable(ismix3);
var ismix4_table = gentable(ismix4);
var ismix5_table = gentable(isnomix);


/////////////////// Code generator

function generateTableCode(name, fn)
{
	var result = "const static uint32_t " + name + "[] = {\n";
	
	for(var u = 0; u < 64; ++u) {
		result += "\t0x" + hex(fn(u * 4 + 0)) + "U, "
		result += "0x" + hex(fn(u * 4 + 1)) + "U, "
		result += "0x" + hex(fn(u * 4 + 2)) + "U, "
		result += "0x" + hex(fn(u * 4 + 3)) + "U,"
		if ((u & 3) == 0) result += " //" + (u >> 2).toString(16);
		result += "\n";
	}
	
	result += "};\n\n";
	return result;
}

/*
	const uint32_t M1 = 0x000000FF;
	const uint32_t M2 = 0x0000FF00;
	const uint32_t M3 = 0x00FF0000;
	const uint32_t M4 = 0xFF000000;

	void expandKeyEnc(uint32_t * expkey, uint32_t key[4])
	{
		uint32_t round = KEY_ROUNDS;
		uint32_t lk;
	
		expkey[0] = bswap32(key[0]);
		expkey[1] = bswap32(key[1]);
		expkey[2] = bswap32(key[2]);
		expkey[3] = bswap32(key[3]);
		
		lk = key[3];
		
		for (round = 0; round < KEY_ROUNDS; ++round) {
			//1) sub-bytes, rotate and add 'rcon' (operations are order-independent)
			lk = (EncTabN[(lk >> 16) & 0xff] & M4) ^ (EncTabN[(lk >> 8) & 0xff] & M3) ^ (EncTabN[lk & 0xFF] & M2) ^ (EncTabN[lk >> 24] & M1) ^ rcon[round];
			
			//2) xor with previous key
			expkey[0 + N] = lk ^= expkey[0];
			
			//3) calculate the rest of the keys
			expkey[1 + N] = lk ^= expkey[1];
			expkey[2 + N] = lk ^= expkey[2];
			expkey[3 + N] = lk ^= expkey[3];
			
			expkey += N;
		}
	}

	void encrypt(uint32_t * inp, uint32_t * out, uint32_t * expkey)
	{
		uint32_t rounds;
		uint32_t a0, b0, c0, d0, a1, b1, c1, d1;
		uint32_t * k = expkey;
		
		a0 = bswap32(inp[0]) ^ k[0];
		b0 = bswap32(inp[1]) ^ k[1];
		c0 = bswap32(inp[2]) ^ k[2];
		d0 = bswap32(inp[3]) ^ k[3];
		
		for (rounds = MAX_ROUNDS; ; rounds -= 2) {
			// round N: (a0,b0,c0,d0) -> (a1,b1,c1,d1)
			a1 = EncTab4[a0 >> 24] ^ EncTab3[(b0 >> 16) & 0xff] ^ EncTab2[(c0 >> 8) & 0xff] ^ EncTab1[d0 & 0xff] ^ k[4];
			b1 = EncTab4[b0 >> 24] ^ EncTab3[(c0 >> 16) & 0xff] ^ EncTab2[(d0 >> 8) & 0xff] ^ EncTab1[a0 & 0xff] ^ k[5];
			c1 = EncTab4[c0 >> 24] ^ EncTab3[(d0 >> 16) & 0xff] ^ EncTab2[(a0 >> 8) & 0xff] ^ EncTab1[b0 & 0xff] ^ k[6];
			d1 = EncTab4[d0 >> 24] ^ EncTab3[(a0 >> 16) & 0xff] ^ EncTab2[(b0 >> 8) & 0xff] ^ EncTab1[c0 & 0xff] ^ k[7];
			
			k += 8;
			if (rounds == 0) break;
			
			// round N+1: (a0,b0,c0,d0) -> (a1,b1,c1,d1)
			a0 = EncTab4[a1 >> 24] ^ EncTab3[(b1 >> 16) & 0xff] ^ EncTab2[(c1 >> 8) & 0xff] ^ EncTab1[d1 & 0xff] ^ k[0];
			b0 = EncTab4[b1 >> 24] ^ EncTab3[(c1 >> 16) & 0xff] ^ EncTab2[(d1 >> 8) & 0xff] ^ EncTab1[a1 & 0xff] ^ k[1];
			c0 = EncTab4[c1 >> 24] ^ EncTab3[(d1 >> 16) & 0xff] ^ EncTab2[(a1 >> 8) & 0xff] ^ EncTab1[b1 & 0xff] ^ k[2];
			d0 = EncTab4[d1 >> 24] ^ EncTab3[(a1 >> 16) & 0xff] ^ EncTab2[(b1 >> 8) & 0xff] ^ EncTab1[c1 & 0xff] ^ k[3];
		}
		
		// last round: (a0,b0,c0,d0) -> (a1,b1,c1,d1)
		a0 = (EncTabN[a1 >> 24] & M4) ^ (EncTabN[(b1 >> 16) & 0xff] & M3) ^ (EncTabN[(c1 >> 8) & 0xff] & M2) ^ (EncTabN[d1 & 0xff] & M1) ^ k[0];
		b0 = (EncTabN[b1 >> 24] & M4) ^ (EncTabN[(c1 >> 16) & 0xff] & M3) ^ (EncTabN[(d1 >> 8) & 0xff] & M2) ^ (EncTabN[a1 & 0xff] & M1) ^ k[1];
		c0 = (EncTabN[c1 >> 24] & M4) ^ (EncTabN[(d1 >> 16) & 0xff] & M3) ^ (EncTabN[(a1 >> 8) & 0xff] & M2) ^ (EncTabN[b1 & 0xff] & M1) ^ k[2];
		d0 = (EncTabN[d1 >> 24] & M4) ^ (EncTabN[(a1 >> 16) & 0xff] & M3) ^ (EncTabN[(b1 >> 8) & 0xff] & M2) ^ (EncTabN[c1 & 0xff] & M1) ^ k[3];
		
		out[0] = a0;
		out[1] = b0;
		out[2] = c0;
		out[3] = d0;
	}

*/

console.log(generateTableCode("EncTab1", smix1));
console.log(generateTableCode("EncTab2", smix2));
console.log(generateTableCode("EncTab3", smix3));
console.log(generateTableCode("EncTab4", smix4));
console.log(generateTableCode("EncTabN", snomix));

console.log(generateTableCode("DeTab1", ismix1));
console.log(generateTableCode("DeTab2", ismix2));
console.log(generateTableCode("DeTab3", ismix3));
console.log(generateTableCode("DeTab4", ismix4));
console.log(generateTableCode("DeTabN", isnomix));

