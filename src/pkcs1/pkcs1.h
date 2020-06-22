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

/* PKCS1.H
 * Header file for RSA cryptosystem (PKCS #1)
 */

#ifndef TINYTLS_PKCS1_H_
#define TINYTLS_PKCS1_H_

struct BinarySlice
{
	size_t length;
	const uint8_t * data;
};

struct PKCS1_RSA_PublicKey{
	BinarySlice exponent;
	BinarySlice modulus;
};

void EncryptRSA(uint8_t * pfrKey, uint8_t * out, unsigned int size, const PKCS1_RSA_PublicKey & Key, const uint8_t * data, unsigned length);

int VerifyRSASignatureHash(struct MontgomeryReductionContext * ctx, const BinarySlice & signature, unsigned int size, const PKCS1_RSA_PublicKey & Key, int sigtype, const uint32_t * hash);
int VerifyRSASignature(struct MontgomeryReductionContext * ctx, const BinarySlice & signature, unsigned int size, const PKCS1_RSA_PublicKey & Key, int sigtype, const uint8_t * data, unsigned length);

#if 0
// Simplified private key. More efficient CRT-key can be extracted instead.
struct PKCS1_RSA_PrivateKey
{
	TinyTLS::Binary priv_exp;
	TinyTLS::Binary pub_exp;
	TinyTLS::Binary modulus;
};

int GenerateRSASignatureHash(struct MontgomeryReductionContext * ctx, TinyTLS::Binary & signature, unsigned int size, const PKCS1_RSA_PrivateKey & Key, int sigtype, const uint32_t * hash);
int GenerateRSASignature(struct MontgomeryReductionContext * ctx, TinyTLS::Binary & signature, unsigned int size, const PKCS1_RSA_PrivateKey & Key, int sigtype, const uint8_t * data, unsigned length);
#endif

#endif