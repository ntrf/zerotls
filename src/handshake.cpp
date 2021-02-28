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

#include <stdint.h>
#include <memory.h>
//#include <stdio.h>

// Using standart library for time. Used in client_random during 
// handshake. Scince standard does not require this to be exact we 
// can just use libc implemenetation instead of OS implementation.
#include <time.h>

#include "intutils.h"

#include "hash/hash.h"

#include "random.h"
#include "context.h"

#include "signature.h"
#include "x509.h"

#include "pkcs1/pkcs1.h"
#include "pkcs1/bigint.h"

//-------------------------------------
// Updated implementation
#include "aes_hmac_sha.h"
#include "aes128_gcm.h"
#include "tls.h"

struct CertificateEntry
{
	uint32_t subjectHash[5];
	uint32_t issuerHash[5];
	uint16_t dataOffset;
	uint16_t publicKeySize;
	uint16_t signatureSize;
	uint16_t hashSize;

	uint8_t keyType;
	uint8_t signType;
	uint16_t restricted;

	int32_t chainLength;
};

static const int MaxCertificates = 8;

extern void PrintHex(const uint8_t *buf, size_t size, int shift);
extern void writeKeyLogClientRandom(const uint8_t * random, const uint8_t * master);

PROGMEM static const uint8_t clientHelloP1[] = {
	22, 0x03, 0x03, 0x00, 0x00, // Handshake, TLS 1.2 (=SSL3.3), empty length
	1, 0x0, 0x0, 0x0, // Client Hello, empty length

	0x3, 0x3, // Version
};

PROGMEM static const uint8_t clientHelloP2[] = {
	0, 4, //cipher_suites
	//0x00, 0x2f,  // TLS_RSA_WITH_AES_128_CBC_SHA
	//0x00, 0x3c,  // TLS_RSA_WITH_AES_128_CBC_SHA256
	0x00, 0x9C,    // TLS_RSA_WITH_AES_128_GCM_SHA256
	//0xC0, 0x13,  // TLS_ECDHE_RSA_AES_128_CBC_SHA
	0x00, 0xFF,    // TLS_EMPTY_RENEGOTIATION_INFO_SCSV

	1, //compression_methods
	0
};

PROGMEM static const uint8_t clientHelloP3[] = {
	0, 1, 0, 1, 1, // MaxFragmentLength 
	0, 28, 0, 2, 2, 0, // RecordSizeLimit
	//0,10, 0,4, 0,2,  0,29, // ECC Supported curves
	//0,11, 0,2, 1, 0, // ECC uncompressed points only
	0, 13, 0, 8, 0, 6, 4, 1, 5, 1, 6, 1, // compatible certificates
	//0,16, 0,2, 'h', '2', // ALPN HTTP/2
	//0,23, 0,0, // ext. master secret
};

int StartHandshake(ztlsContextImpl *ctx, ztlsHsState *hs, SystemRandomNumberGenerator * crng, const char *sni)
{
	// we aren't using send buffer directly
	ctx->SetupSendBuffer(0);

	uint8_t *limit = ctx->RecvLimit();
	uint8_t *packet = ctx->RecvBuffer() + hs->HsOffset;

	// this is a dumb check, but better do it now
	if (packet + 256 > limit)
		return -1;

	hs->state = 0;
	hs->slicesFullSize = 0;
	hs->HsLength = 0;

	ctx->flags = 0;
	ctx->crypto = 0;

	// Reset the hash
	sha256Init(&hs->finishHash);

	//generate client random
	crng->GenerateRandomBytes(hs->prfKey, sizeof(hs->prfKey));
	PrfGenBlock_v1_2(hs->random + 4, 28, hs->prfKey, sizeof(hs->prfKey), "cli random", hs->prfKey, 0);
	*(uint32_t*)hs->random = bswap32((uint32_t)time(NULL));

	// making a handshake packet
	uint8_t *pw = packet;
	memcpy(pw, clientHelloP1, sizeof(clientHelloP1));
	pw += sizeof(clientHelloP1);

	// random
	memcpy(pw, hs->random, 32);
	pw += 32;

	// No session id support -- we're going all-in with session tickets
	*pw++ = 0;

	// caps
	memcpy(pw, clientHelloP2, sizeof(clientHelloP2));
	pw += sizeof(clientHelloP2);

	// extensions
	uint8_t *extSize = pw;
	pw += 2;

	// SNI
	size_t snilen = strlen(sni);
	*pw++ = 0; *pw++ = 0; // type
	*pw++ = 0; *pw++ = snilen + 5; // length
	*pw++ = 0; *pw++ = snilen + 3; // server_name_list
	*pw++ = 0; *pw++ = 0; *pw++ = snilen; // ServerName.name_type + HostName.length
	memcpy(pw, sni, snilen);
	pw += snilen;

	// other extensions
	memcpy(pw, clientHelloP3, sizeof(clientHelloP3));
	pw += sizeof(clientHelloP3);

	size_t extlen = pw - (extSize + 2);
	extSize[0] = (extlen >> 8) & 0xFF;
	extSize[1] = extlen & 0xFF;

	// overall packet length
	size_t packlen = pw - packet;
	size_t payloadlen = packlen - 5;
	pw = &packet[3];
	*pw++ = (payloadlen >> 8) & 0xFF;
	*pw++ = payloadlen & 0xFF;

	pw = &packet[7];
	payloadlen -= 4;
	*pw++ = (payloadlen >> 8) & 0xFF;
	*pw++ = payloadlen & 0xFF;

	//PrintHex(packet, packlen, 0);

	if (pw > limit)
		return ZTLS_ERR_OVERFLOW;

	sha256Update(&hs->finishHash, packet + 5, packlen - 5);

	return ::ztlsLinkSend(ctx->socket, packet, packlen);
}

int ProcessServerHello(ztlsContextImpl * ctx, ztlsHsState * hs, const uint8_t * data, size_t length)
{
	const uint8_t *pr = data;
	const uint8_t *end = data + length;

	// version
	// + random
	// + empty session
	// + cipher suites
	// + at least one extension
	if (length < 42)
		return ZTLS_ERR_BADMSG;

	// check maximum version
	if (pr[0] < 3 || (pr[0] == 3 && pr[1] < 3)) {
		return ZTLS_ERR_INSECURE;
	}

	// copy random
	memcpy(hs->random + 32, pr + 2, 32);

	// skip the session id
	//### implement it?
	pr += 0x23 + pr[0x22];
	if (pr >= end)
		return ZTLS_ERR_BADMSG;

	//### check selected cipher suite
	if (pr[0] == 0xC0 && pr[1] == 0x13) {
		// ECDSA / AES128_CBC_SHA1
	} else if (pr[0] == 0 && pr[1] == 0x2f) {
		// RSA / AES128_CBC_SHA1
		return ZTLS_ERR_UNSUPPORTED;
	} else if (pr[0] == 0 && pr[1] == 0x9c) {
		// RSA / AES128_GCM_SHA256
	} else {
		return ZTLS_ERR_UNSUPPORTED;
	}
	if (pr[2] != 0) {
		return ZTLS_ERR_INSECURE;
	}

	pr += 3;
	if (pr >= end - 2) {
		return ZTLS_ERR_UNSUPPORTED;
	}

	// extensions
	size_t len = pr[0] + pr[1];
	if (end < pr + 2 + len) {
		return ZTLS_ERR_UNSUPPORTED;
	}

	// in case TLS protocol continues to grow past "extensions" field
	pr += 2;
	end = pr + len;

	int supported = 0;

	// check that all of the extensions are supported
	for (; pr < end;) {
		int type = (pr[0] << 8) + pr[1];
		size_t elen = (pr[2] << 8) + pr[3];

		if (type == 1 || type == 28) {
			supported |= 1;
		}
		pr += 4 + elen;
	}

//	if (supported != 1) {
//		return ZTLS_ERR_UNSUPPORTED;
//	}

	hs->state |= HANDSHAKE_HELLO;

	return 1;
}

//### error checks?
static int AllocCertificateStorage(ztlsContextImpl * ctx, ztlsHsState * hs)
{
	size_t slice = ctx->SetupSendBuffer(sizeof(CertificateEntry) * MaxCertificates);

	hs->certList.count = 0;
	hs->certList.offset = slice;

	return 1;
}

// This function basicly copies everything out, so we can use all the info later 
// without having to store giant certificates
//### needs time check
//### SNI!!!
static int ProcessCertificate(ztlsContextImpl * ctx, ztlsHsState * hs, const uint8_t * data, size_t length, const char * sni)
{
	CertificateInfo cert;
	int res = ExtractCertificateInfo(&cert, length, data, sni);
	if (res <= 0) {
		return ZTLS_ERR_BAD_CERTIFICATE;
	}

	int index = hs->certList.count;
	if (index >= MaxCertificates) {
		return ZTLS_ERR_OVERFLOW;
	}

	CertificateEntry * ce = (CertificateEntry*)((uint8_t*)ctx + hs->certList.offset);
	ce += index;

	// compute how much memory to dalloc
	size_t sigHashSize = GetSignatureSize(cert.signType);
	size_t slice = ctx->sendBufferOffset - (cert.signature.length + cert.publicKey.length + sigHashSize);

	uint8_t *target = (uint8_t*)ctx + slice;

	uint8_t *tip = ctx->RecvBuffer() + ctx->recvOffset + ctx->recvSize;

	//### check limits
	// Don't overwrite the received data
	if (tip > target) {
		return ZTLS_ERR_OVERFLOW;
	}

	ce->signType = cert.signType;
	ce->keyType = cert.keyType;
	ce->restricted = cert.restricted;
	ce->chainLength = cert.chainLength;

	if (cert.issuer.length <= 20) {
		memset(ce->issuerHash, 0, 20);
		memcpy(ce->issuerHash, cert.issuer.data, cert.issuer.length);
	} else {
		SHA1_State h;
		sha1Init(&h);
		sha1Update(&h, cert.issuer.data, cert.issuer.length);
		sha1Finish(&h, ce->issuerHash);
	}
	if (cert.subject.length <= 20) {
		memset(ce->subjectHash, 0, 20);
		memcpy(ce->subjectHash, cert.subject.data, cert.subject.length);
	} else {
		SHA1_State h;
		sha1Init(&h);
		sha1Update(&h, cert.subject.data, cert.subject.length);
		sha1Finish(&h, ce->subjectHash);
	}

	ce->dataOffset = slice;
	ce->publicKeySize = cert.publicKey.length;
	ce->signatureSize = cert.signature.length;
	ce->hashSize = sigHashSize;

	memcpy(target, cert.publicKey.data, cert.publicKey.length);
	target += cert.publicKey.length;
	memcpy(target, cert.signature.data, cert.signature.length);
	target += cert.signature.length;
	int computedSize = ComputeSignatureHash(cert.signType, data + cert.payloadOffset, cert.payloadLength, (uint32_t*)target);
	computedSize *= 4;

	if (computedSize != sigHashSize) {
		return ZTLS_ERR_BAD_CERTIFICATE;
	}

	hs->certList.count++;
	ctx->sendBufferOffset = slice;

	return 1;
}

static int VerifyCertificates(ztlsContextImpl *ctx, ztlsHsState *hs)
{
	if (!(hs->state & HANDSHAKE_SERVER_CERT))
		return ZTLS_ERR_BADMSG;

	// attempt to restore certificate data
	CertificateEntry * celist = (CertificateEntry*)((uint8_t*)ctx + hs->certList.offset);
	CertificateEntry * ce = celist;
	int selectedCert = -1;
	for (int i = 0; i < hs->certList.count; ++i, ++ce) {
#if 0
		printf("cert #%d: i=%08x%08x%08x%08x%08x s=%08x%08x%08x%08x%08x r=%04x t=%d\n",
			   i, ce->issuerHash[0], ce->issuerHash[1], ce->issuerHash[2],
			   ce->issuerHash[3], ce->issuerHash[4],
			   ce->subjectHash[0], ce->subjectHash[1], ce->subjectHash[2],
			   ce->subjectHash[3], ce->subjectHash[4],
			   ce->restricted, ce->signType);
#endif
		if (ce->restricted & CERT_DOMAIN_MATCH) {
			selectedCert = i;
		}
	}

	if (selectedCert < 0 || selectedCert > hs->certList.count) {
		return ZTLS_ERR_BAD_CERTIFICATE;
	}

	ce = &celist[selectedCert];

	hs->publicKey.length = ce->publicKeySize;
	hs->publicKey.offset = ce->dataOffset;
	hs->publicKey.type = ce->keyType;

	// Attempt to compact the key, so we have more room for future allocations
	size_t pklen = ce->publicKeySize;

	uint8_t * source = (uint8_t*)ctx + ce->dataOffset;
	uint8_t * target = ctx->CalcSendBuffer(pklen);

	// This should not fail. Ever. Even if the selected public key is 8K RSA key,
	// so it's bigger than the entire table, there is still a block with RSA signature
	// right bellow it, which should be at least as big as a public key itself.
	//
	// If someone actually uses 8K RSA keys, you can always use $5 pipe wrench.
	if (source + 16 > target) {
		return ZTLS_ERR_OVERFLOW;
	}

	memmove(target, source, pklen);
	hs->publicKey.offset = target - (uint8_t*)ctx;
	ctx->sendBufferOffset = target - (uint8_t*)ctx;

	hs->state |= HANDSHAKE_SERVER_KEY;

	return 1;
}

static int ProcessServerDone(ztlsContextImpl *ctx, ztlsHsState * hs)
{
	// check we don't have any handshake messages pending
	if (hs->HsLength != 4 || ctx->recvSize != hs->HsLength) {
		return ZTLS_ERR_BADMSG;
	}

	hs->state |= HANDSHAKE_SERVER_DONE;

	const uint32_t required = (HANDSHAKE_HELLO | HANDSHAKE_SERVER_CERT | HANDSHAKE_SERVER_KEY | HANDSHAKE_SERVER_DONE);

	if ((hs->state & required) != required || !!(hs->state & HANDSHAKE_RESUMED)) {
		ctx->SendAlertPlain(2, AlertType::unexpected_message);
		return ZTLS_ERR_TAMPERED;
	}

	return 1;
}

PROGMEM static const uint8_t ClientKeyExchangeRsa1[] = {
	22, 0x03, 0x03, 0x00, 0x00, // Record header
	16, 0x0, 0x0, 0x0, // Handshake: ClientKeyExchange
	0, 0,
};

static int MakeClientKeyExchange(ztlsContextImpl *ctx, ztlsHsState * hs, uint8_t * dest)
{
	PKCS1_RSA_PublicKey keyComp;
	if (Extract_PKCS1_RSA_PublicKeyComponents(&keyComp, hs->publicKey.length,
		(uint8_t *)ctx + hs->publicKey.offset) < 0) {
		return ZTLS_ERR_UNSUPPORTED;
	}

	// 1024 RSA is minimum for ANY security
	// 768 bit RSA can be broken in 1 month with Amazon EC2 instances
	if (keyComp.modulus.length < 128)
		return ZTLS_ERR_INSECURE;

	// sometimes modulus values is larger by one or two bytes for no reason
	// round down to multiple of 4
	unsigned resLen = keyComp.modulus.length & ~0x3;

	uint8_t pms[48];
	PrfGenBlock_v1_2(pms, 48, hs->prfKey, 64, "pms", hs->random, sizeof(hs->random));
	pms[0] = 0x03;
	pms[1] = 0x03;

	//printf("pms:\n");
	//PrintHex(pms, sizeof(pms), 0);

	uint8_t * pw = dest;
	uint8_t * limit = ctx->RecvLimit();
	memcpy(pw, ClientKeyExchangeRsa1, sizeof(ClientKeyExchangeRsa1));

	pw[9] = (resLen >> 8) & 0xFF;
	pw[10] = resLen & 0xFF;

	size_t plen = resLen + 2;
	pw[7] = (plen >> 8) & 0xFF;
	pw[8] = plen & 0xFF;

	plen += 4;
	pw[3] = (plen >> 8) & 0xFF;
	pw[4] = plen & 0xFF;

	pw += sizeof(ClientKeyExchangeRsa1);

	// checking limits
	if (pw + resLen + 32 + MontgomeryReductionContext::GetAllocationSize((resLen + 3) / 4) >= limit)
		return ZTLS_ERR_OVERFLOW;

	// encrypt pms
	EncryptRSA(hs->prfKey, pw, resLen, keyComp, pms, sizeof(pms));
	pw += resLen;

	sha256Update(&hs->finishHash, dest + 5, pw - dest - 5);

	// generate master secret ... in the same array
	PrfGenBlock_v1_2(hs->masterKey, 48, pms, 48, "master secret", hs->random, sizeof(hs->random));

	// dump the secret
	writeKeyLogClientRandom((uint8_t*)hs->random, hs->masterKey);

	//printf("master secret:\n");
	//PrintHex(ctx->masterKey, 48, 0);

	return pw - dest;
}


static int ApplyMasterKey(ztlsContextImpl * ctx, ztlsHsState * hs, uint8_t * scratchBlock)
{
	//### does not support rekeying
	if (ctx->flags & StateFlags::Flag_KeyReady)
		return 1;

	const size_t keysize = 128; // hopefully enough for any cipher

	uint8_t * keyblock = align(scratchBlock, 16);
	uint8_t * limit = ctx->RecvLimit();
	if (keyblock + keysize + 64 > limit)
		return ZTLS_ERR_OVERFLOW;

	// This seed is flipped for no reason
	uint8_t *key_seed = keyblock;
	memcpy(key_seed, hs->random + 32, 32);
	memcpy(key_seed + 32, hs->random, 32);

	keyblock += 64;

	//generate key material
	//key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random);
	PrfGenBlock_v1_2(keyblock, keysize, hs->masterKey, 48, "key expansion", key_seed, 64);

#ifdef _DEBUG
	//printf("key material:\n");
	//PrintHex(keyblock, keysize, 0);
#endif

#if 0
	AES128_HMAC_SHA * enc_context = (AES128_HMAC_SHA*)ctx->Ciphers(0);

	//TLS 1.2:
	//TLS_RSA_WITH_AES_128_CBC_SHA256
	//  client_write_MAC_secret[SecurityParameters.mac_key_length]   32 b
	//  server_write_MAC_secret[SecurityParameters.mac_key_length]   32 b
	//  client_write_key[SecurityParameters.enc_key_length]          16 b
	//  server_write_key[SecurityParameters.enc_key_length]          16 b
	//  client_write_IV[SecurityParameters.fixed_iv_length]          16 b
	//  server_write_IV[SecurityParameters.fixed_iv_length]          16 b

	const size_t mac_key_size = 32;
	const size_t enc_key_length = 16;
	const size_t fixed_iv_length = 16;

	uint8_t * client_MAC_secret = keyblock + 0;
	uint8_t * server_MAC_secret = keyblock + mac_key_size;
	uint8_t * client_key = keyblock + mac_key_size * 2;
	uint8_t * server_key = keyblock + mac_key_size * 2 + enc_key_length;
	uint8_t * client_IV = keyblock + mac_key_size * 2 + enc_key_length * 2;
	uint8_t * server_IV = keyblock + mac_key_size * 2 + enc_key_length * 2 + fixed_iv_length;

	enc_context[0].InitEnc(client_key, client_IV, client_MAC_secret);
	enc_context[1].InitDec(server_key, server_IV, server_MAC_secret);
#elif 0
	AES128_HMAC_SHA * enc_context = (AES128_HMAC_SHA*)ctx->Ciphers(0);

	//TLS_RSA_WITH_AES_128_CBC_SHA
	//  client_write_MAC_secret[SecurityParameters.mac_key_length]   20 b
	//  server_write_MAC_secret[SecurityParameters.mac_key_length]   20 b
	//  client_write_key[SecurityParameters.enc_key_length]          16 b
	//  server_write_key[SecurityParameters.enc_key_length]          16 b
	//  client_write_IV[SecurityParameters.fixed_iv_length]          16 b
	//  server_write_IV[SecurityParameters.fixed_iv_length]          16 b

	const size_t mac_key_size = 20;
	const size_t enc_key_length = 16;
	const size_t fixed_iv_length = 16;

	uint8_t * client_MAC_secret = keyblock + 0;
	uint8_t * server_MAC_secret = keyblock + mac_key_size;
	uint8_t * client_key = keyblock + mac_key_size * 2;
	uint8_t * server_key = keyblock + mac_key_size * 2 + enc_key_length;
	uint8_t * client_IV = keyblock + mac_key_size * 2 + enc_key_length * 2;
	uint8_t * server_IV = keyblock + mac_key_size * 2 + enc_key_length * 2 + fixed_iv_length;

	enc_context[0].InitEnc(client_key, client_IV, client_MAC_secret);
	enc_context[1].InitDec(server_key, server_IV, server_MAC_secret);
#else

	//TLS 1.2:
	//TLS_RSA_WITH_AES_128_GCM_SHA256
	//  client_write_MAC_secret[SecurityParameters.mac_key_length]   0 b
	//  server_write_MAC_secret[SecurityParameters.mac_key_length]   0 b
	//  client_write_key[SecurityParameters.enc_key_length]          16 b
	//  server_write_key[SecurityParameters.enc_key_length]          16 b
	//  client_write_IV[SecurityParameters.fixed_iv_length]          4 b
	//  server_write_IV[SecurityParameters.fixed_iv_length]          4 b
	AES128_GCM * enc_context = (AES128_GCM*)ctx->Ciphers(0);

	const size_t mac_key_size = 0;
	const size_t enc_key_length = 16;
	const size_t fixed_iv_length = 4;

	uint8_t * client_MAC_secret = keyblock + 0;
	uint8_t * server_MAC_secret = keyblock + mac_key_size;
	uint8_t * client_key = keyblock + mac_key_size * 2;
	uint8_t * server_key = keyblock + mac_key_size * 2 + enc_key_length;
	uint8_t * client_IV = keyblock + mac_key_size * 2 + enc_key_length * 2;
	uint8_t * server_IV = keyblock + mac_key_size * 2 + enc_key_length * 2 + fixed_iv_length;

	enc_context[0].InitEnc(client_key, client_IV);
	enc_context[1].InitDec(server_key, server_IV);
#endif

	ctx->flags |= StateFlags::Flag_KeyReady;

	return 1;
}

PROGMEM static const uint8_t ClientFinishedRsa1[] = {
	20, 0, 0, 12, // Handshake: Finished
};

PROGMEM static const uint8_t CCS[] = {
	20, 3, 3, 0, 1, // Change Cipher Spec
	1
};

static int SendClientFinished(ztlsContextImpl * ctx, ztlsHsState * hs, uint8_t * dest)
{
	// Key should be ready by this point
	if (!(ctx->flags & StateFlags::Flag_KeyReady))
		return ZTLS_ERR_TAMPERED;

	const size_t verify_message_length = 12;

	AES128_GCM * enc_context = (AES128_GCM*)ctx->Ciphers(0);

	uint8_t * packet = dest;
	uint8_t * limit = ctx->RecvLimit();

	// very rough estimate of space needed
	if (packet + 128 > limit)
		return ZTLS_ERR_OVERFLOW;

	memcpy(packet, CCS, sizeof(CCS));

	uint8_t *packetplain = align(packet + sizeof(CCS) + ctx->fragOffset, 16);
	uint8_t * pw = packetplain;

	memcpy(pw, ClientFinishedRsa1, sizeof(ClientFinishedRsa1));
	pw += sizeof(ClientFinishedRsa1);

	// make a copy of running hash
	uint32_t hash[8];
	{
		SHA256_State hscopy;
		memcpy(&hscopy, &hs->finishHash, sizeof(hs->finishHash));
		sha256Finish(&hscopy, hash);
	}

	{
		PrfGenBlock_v1_2(pw, 12, hs->masterKey, sizeof(hs->masterKey), "client finished", (uint8_t*)hash, sizeof(hash));
		pw += 12;
	}

	size_t lengthplain = pw - packetplain;

	sha256Update(&hs->finishHash, packetplain, lengthplain);

	// Now we need to encrypt it
	pw = packet + sizeof(CCS);
	pw[0] = HEAD_HANDSHAKE;
	pw[1] = 3;
	pw[2] = 3;

	size_t size = enc_context->WrapPacket(pw + 5, HEAD_HANDSHAKE, packetplain, lengthplain);

	pw[3] = 0;
	pw[4] = size;

	pw += size + 5;

	// I don't like that this is destructive, but there is a very little chance of shooting through
	if (pw > limit)
		return ZTLS_ERR_OVERFLOW;

	return pw - packet;
}

int FinishClientHandshake(ztlsContextImpl * ctx, ztlsHsState * hs)
{
	// Inputs: 
	// - certificate public key or server key share (verified)
	// - session id
	// - client and server random

	// Allocating crypto
	//### make this configurable
	ctx->SetupEncryption(sizeof(AES128_GCM));

	uint8_t * dbase = ctx->RecvBuffer() + hs->HsOffset;

	int r;
	//### handshake state relocation

	uint8_t * dw = dbase;

	r = MakeClientKeyExchange(ctx, hs, dw);
	if (r <= 0)
		return r;

	dw += r;

	r = ApplyMasterKey(ctx, hs, dw);
	if (r <= 0)
		return r;

	// Next flight from server should contain CCS
	ctx->flags |= StateFlags::Flag_ExpectingCCS;

	r = SendClientFinished(ctx, hs, dw);
	if (r <= 0)
		return r;

	dw += r;
	r = ::ztlsLinkSend(ctx->socket, dbase, dw - dbase);
	if (r < 0)
		return r;

	hs->state |= HANDSHAKE_CLIENT_FINISHED;

	return r;
}

static int ProcessServerKeyExchange(ztlsContextImpl * ctx, ztlsHsState * hs, uint8_t * data, size_t length)
{
	if (length < 4)
		return ZTLS_ERR_BADMSG;

	// check the curve
	if (data[0] != 3 || data[1] != 0x00 || data[2] != 0x1d)
		return ZTLS_ERR_UNSUPPORTED;

	// check the curve size
	if (data[3] != 0x20)
		return ZTLS_ERR_BADMSG;

	// compute signature location
	size_t offset = data[3] + 4;
	if (length < offset + 4)
		return ZTLS_ERR_BADMSG;

	size_t signatureSize = (data[offset + 2] << 8) + data[offset + 3];
	if (length != offset + 4 + signatureSize)
		return ZTLS_ERR_BADMSG;

	if (data[offset + 1] != 1) // RSA
		return ZTLS_ERR_UNSUPPORTED;

	// get the signature scheme
	int sigType = SIGTYPE_UNKNOWN;
	uint32_t hash[16];
	switch (data[offset]) {
	case 4:
		sigType = PKCS1_SSA_SHA256;
		{
			SHA256_State st;
			sha256Init(&st);
			sha256Update(&st, hs->random, 64);
			sha256Update(&st, data, offset);
			sha256Finish(&st, hash);
		}
		break;
	case 5:
		sigType = PKCS1_SSA_SHA384;
		{
			SHA512_State st;
			sha384Init(&st);
			sha512Update(&st, hs->random, 64);
			sha512Update(&st, data, offset);
			sha384Finish(&st, hash);
		}
		break;
	case 6:
		sigType = PKCS1_SSA_SHA512;
		{
			SHA512_State st;
			sha512Init(&st);
			sha512Update(&st, hs->random, 64);
			sha512Update(&st, data, offset);
			sha512Finish(&st, hash);
		}
		break;
	default:
		return ZTLS_ERR_INSECURE;
	}

	PKCS1_RSA_PublicKey keyComp;
	if (Extract_PKCS1_RSA_PublicKeyComponents(&keyComp, hs->publicKey.length,
		(uint8_t *)ctx + hs->publicKey.offset) < 0) {
		return ZTLS_ERR_UNSUPPORTED;
	}

	// minimum size
	if (keyComp.modulus.length < 128)
		return ZTLS_ERR_INSECURE;

	// sometimes modulus values is larger by one or two bytes for no reason
	// round down to multiple of 4
	unsigned resLen = keyComp.modulus.length & ~0x3;

	if (resLen != signatureSize)
		return ZTLS_ERR_BADMSG;

	// end of the received packet
	uint8_t * temp = ctx->RecvBuffer() + ctx->recvOffset + ctx->recvSize;
		
	//### check buffer

	// signature verification
	int res = VerifyRSASignatureHash(temp, data + offset + 4, resLen, keyComp, sigType, hash);
	if (res <= 0)
		return ZTLS_ERR_TAMPERED;

	//### do something with received key

	return 1;
}

static int ProcessServerFinished(ztlsContextImpl * ctx, ztlsHsState * hs, const uint8_t * data, size_t length)
{
	if (length != 12)
		return ZTLS_ERR_BADMSG;

	uint32_t hash[8];
	{
		SHA256_State hscopy;
		memcpy(&hscopy, &hs->finishHash, sizeof(hs->finishHash));
		sha256Finish(&hscopy, hash);
	}

	uint8_t finishedBody[12];

	PrfGenBlock_v1_2(finishedBody, 12, hs->masterKey, 48, "server finished", (uint8_t*)hash, sizeof(hash));

	uint8_t diff = 0;
	for (int i = 0; i < 12; ++i) {
		diff |= finishedBody[i] ^ data[i];
	}

	if (diff != 0)
		return ZTLS_ERR_TAMPERED;

	hs->state |= HANDSHAKE_SERVER_FINISHED;

	if (hs->state & HANDSHAKE_CLIENT_FINISHED) {
		ctx->flags |= StateFlags::Flag_HandshakeComplete;

		ctx->SetupSendBuffer(ctx->sendBufferExpanded);
	} else {
		//### resumption client finished
	}

	return 1;
}

int Handshake(ztlsContextImpl * ctx, ztlsHsState * hs, const char * sni)
{
	int r;
	while (1) {
		if (ctx->flags & StateFlags::Flag_Closed) {
			return hs->HsError; //### We need to decode alerts
		}

		// If handshake is complete
		if (ctx->isReady())
			return 1;

		r = ctx->ReceiveHandshakeMessage(hs);
		if (r == 0)
			return 0;

		if (r < 0) {
			//printf("ReceiveHandshakeMessage => %d\n", r);
			break;
		}

		// We've received something new
		uint8_t * data = ctx->RecvBuffer() + hs->HsOffset;
		if (ctx->recvHead.type == HEAD_CCS) {
			if (ctx->crypto != 0 || !(ctx->flags & StateFlags::Flag_KeyReady)) {
				r = ZTLS_ERR_TAMPERED;
				break;
			}

			// enable crypto
			//### support more than one cipher
			ctx->crypto = 1;
		} else if (ctx->recvHead.type == HEAD_ALERT) {
			//### decode some alerts
			r = ZTLS_ERR_BADMSG;
			break;
		} else if (ctx->recvHead.type == HEAD_HANDSHAKE) {
			bool finished = false;
			bool validateCerts = false;
			size_t nextSlice = 0;

			switch (hs->HsType) {
			case HandshakeType::server_hello:
				r = ProcessServerHello(ctx, hs, data + 4, hs->HsLength - 4);
				break;
			case HandshakeType::server_hello_done:
				r = ProcessServerDone(ctx, hs);
				finished = true;
				break;
			case HandshakeType::certificate:
			{
				// Definitely not a legit packet
				if (hs->HsLength <= 3) {
					r = ZTLS_ERR_BAD_CERTIFICATE;
					break;
				}

				size_t full = hs->slicesFullSize;

				//printf("slice (%04x length, %04x remaining):\n", hs->HsLength, full);

				// First slice
				if (full == 0 && hs->HsLength == 6 + 4) {
					// Read full size
					full = (data[4] << 16) + (data[5] << 8) + data[6];
					size_t mlength = (data[1] << 16) + (data[2] << 8) + data[3];
					//printf("full = %04x, mlength = %04x\n", full, mlength);
					if (full <= 3 || full != mlength - 3) {
						// There should be at least one certificate and there 
						// should be no other fields in the message
						r = ZTLS_ERR_BAD_CERTIFICATE;
						break;
					}

					full -= 3; // remove the first element length
					AllocCertificateStorage(ctx, hs);
				} else if (full < hs->HsLength) {
					r = ZTLS_ERR_BAD_CERTIFICATE;
					break;
				} else {
					// remove full size of receive data
					full -= hs->HsLength;

					size_t l = hs->HsLength;
					if (full > 0)
						l -= 3;

					//printf("certificate:\n");
					//PrintHex(data, l, 0);

					r = ProcessCertificate(ctx, hs, data, l, sni);
					hs->state |= HANDSHAKE_SERVER_CERT;
				}
				hs->slicesFullSize = full;

				if (full > 0) {
					// prepare to receive next slice
					uint8_t * dnext = data + hs->HsLength - 3;
					nextSlice = (dnext[0] << 8) + (dnext[1] << 8) + dnext[2] + 3;
					if (nextSlice > full)
						nextSlice = full;
				} else {
					// if not -- we're done slicing
					nextSlice = 0;

					validateCerts = true;
				}
				break;
			}
			case HandshakeType::server_key_exchange:
				r = ProcessServerKeyExchange(ctx, hs, data + 4, hs->HsLength - 4);
				break;
			case HandshakeType::finished:
				r = ProcessServerFinished(ctx, hs, data + 4, hs->HsLength - 4);
				break;
			default:
				r = ZTLS_ERR_BADMSG;
			}

			// update the running hash
			sha256Update(&hs->finishHash, data, hs->HsLength);

			ctx->ConsumeHandshakeMessage(hs, nextSlice);

			// verify certificate chain (unless we had some other error)
			//### move it WAY lower, so we can use memory for BigInt computations
			if (r > 0 && validateCerts) {
				r = VerifyCertificates(ctx, hs);
			}

			// note: we don't return anything on "tampered" as that code should never be caused 
			// by a legitimate handshake
			switch (r) {
			case ZTLS_ERR_BADMSG:
				ctx->SendAlertPlain(2, AlertType::unexpected_message);
				break;
			case ZTLS_ERR_BAD_CERTIFICATE:
				ctx->SendAlertPlain(2, AlertType::bad_certificate);
				break;
			case ZTLS_ERR_INSECURE:
				ctx->SendAlertPlain(2, AlertType::insufficient_security);
				break;
			case ZTLS_ERR_UNSUPPORTED:
			case ZTLS_ERR_OVERFLOW:
				ctx->SendAlertPlain(2, AlertType::internal_error);
				break;
			}

			if (r < 0)
				break;

			if (finished) {
				// send out all the stuff
				r = FinishClientHandshake(ctx, hs);
				if (r <= 0)
					return r;
			}

			if (r == 0) {
				// If any messages are waiting to be sent -- send them
				return 0;
			}
		}

	}

	if (r < 0) {
		hs->HsError = r;
		ctx->flags = StateFlags::Flag_Closed;
	}

	return r;
}
